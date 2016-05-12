#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#    Copyright 2015 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
tools module
"""

import os
import logging
import sys
import threading
from multiprocessing import Process, Queue, BoundedSemaphore
import subprocess
import yaml


slowpipe = '''
import sys
import time
while 1:
    a = sys.stdin.read(int(1250*%s))
    if a:
        sys.stdout.write(a)
        time.sleep(0.01)
    else:
        break
'''


def interrupt_wrapper(f):
    def wrapper(*args, **kwargs):
        try:
            f(*args, **kwargs)
        except KeyboardInterrupt:
            logging.warning('Interrupted, exiting.')
        except Exception as e:
            logging.error('Error: %s' % e, exc_info=True)
            for k in dir(e):
                '''debug: print all exception attrs except internal
                and except 'message', which is deprecated since Python 2.6'''
                if not k.startswith('__') and k != 'message':
                    v = getattr(e, k)
                    logging.debug('Error details: %s = %s' % (k, v))
    return wrapper


class RunItem():
    def __init__(self, target, args, key=None):
        self.target = target
        self.args = args
        self.process = None
        self.queue = None
        self.key = key


class SemaphoreProcess(Process):
    def __init__(self, semaphore, target, args, queue=None):
        Process.__init__(self)
        self.semaphore = semaphore
        self.target = target
        self.args = args
        self.queue = queue

    def run(self):
        try:
            result = self.target(**self.args)
            if self.queue:
                self.queue.put_nowait(result)
        except Exception as error:
            logging.exception(error)
            if self.queue:
                self.queue.put_nowait(error)
        finally:
            logging.debug('finished call: %s' % self.target)
            self.semaphore.release()
            logging.debug('semaphore released')


def run_batch(item_list, maxthreads, dict_result=False):
    def cleanup():
        logging.debug('cleanup processes')
        for run_item in item_list:
            if run_item.process:
                run_item.process.terminate()
    semaphore = BoundedSemaphore(maxthreads)
    try:
        for run_item in item_list:
            semaphore.acquire(True)
            run_item.queue = Queue()
            p = SemaphoreProcess(target=run_item.target,
                                 semaphore=semaphore,
                                 args=run_item.args,
                                 queue=run_item.queue)
            run_item.process = p
            p.start()
        for run_item in item_list:
            run_item.result = run_item.queue.get()
            if isinstance(run_item.result, Exception):
                logging.error('%s, exiting' % run_item.result)
                cleanup()
                sys.exit(42)
            run_item.process.join()
            run_item.process = None
        if dict_result:
            result = {}
            for run_item in item_list:
                result[run_item.key] = run_item.result
            return result
        else:
            return [run_item.result for run_item in item_list]
    except KeyboardInterrupt:
        cleanup()
        raise KeyboardInterrupt()


def get_dir_structure(rootdir):
    """
    Creates a nested dictionary that represents the folder structure of rootdir
    """
    dir = {}
    try:
        rootdir = rootdir.rstrip(os.sep)
        start = rootdir.rfind(os.sep) + 1
        for path, dirs, files in os.walk(rootdir):
            folders = path[start:].split(os.sep)
            subdir = dict.fromkeys(files)
            parent = reduce(dict.get, folders[:-1], dir)
            parent[folders[-1]] = subdir
    except:
        logging.error('failed to create list of the directory: %s' % rootdir)
        sys.exit(1)
    return dir


def load_yaml_file(filename):
    try:
        with open(filename, 'r') as f:
            return yaml.load(f)
    except IOError as e:
        logging.error("load_conf: I/O error(%s): file: %s; msg: %s" %
                      (e.errno, e.filename, e.strerror))
        sys.exit(1)
        # return e
    except ValueError:
        logging.error("load_conf: Could not convert data")
        sys.exit(1)
    except yaml.parser.ParserError as e:
        logging.error("load_conf: Could not parse %s:\n%s" %
                      (filename, str(e)))
        sys.exit(1)


def mdir(directory):
    if not os.path.exists(directory):
        logging.debug('creating directory %s' % directory)
        try:
            os.makedirs(directory)
        except:
            logging.error("Can't create a directory: %s" % directory)
            sys.exit(3)


def launch_cmd(command, timeout, input=None):
    def _timeout_terminate(pid):
        try:
            os.kill(pid, 15)
            logging.error("launch_cmd: pid %d killed by timeout" % pid)
        except:
            pass

    logging.info('launch_cmd: command %s' % command)
    p = subprocess.Popen(command,
                         shell=True,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    timeout_killer = None
    try:
        timeout_killer = threading.Timer(timeout, _timeout_terminate, [p.pid])
        timeout_killer.start()
        outs, errs = p.communicate(input=input)
    except:
        try:
            p.kill()
        except:
            pass
        outs, errs = p.communicate()
        logging.error("command: %s err: %s, returned: %s" %
                      (command, errs, p.returncode))
    finally:
        if timeout_killer:
            timeout_killer.cancel()
    logging.debug("ssh return: err:%s\nouts:%s\ncode:%s" %
                  (errs, outs, p.returncode))
    logging.info("ssh return: err:%s\ncode:%s" %
                 (errs, p.returncode))
    return outs, errs, p.returncode


def ssh_node(ip, command='', ssh_opts=[], env_vars=[], timeout=15,
             filename=None, inputfile=None, outputfile=None,
             prefix='nice -n 19 ionice -c 3'):
    if type(ssh_opts) is list:
        ssh_opts = ' '.join(ssh_opts)
    if type(env_vars) is list:
        env_vars = ' '.join(env_vars)
    if (ip in ['localhost', '127.0.0.1']) or ip.startswith('127.'):
        logging.info("skip ssh")
        bstr = "%s timeout '%s' bash -c " % (
               env_vars, timeout)
    else:
        logging.info("exec ssh")
        # base cmd str
        bstr = "timeout '%s' ssh -t -T %s '%s' '%s' " % (
               timeout, ssh_opts, ip, env_vars)
    if filename is None:
        cmd = bstr + '"' + prefix + ' ' + command + '"'
    else:
        cmd = bstr + " '%s bash -s' < '%s'" % (prefix, filename)
    if inputfile is not None:
        cmd = bstr + '"' + prefix + " " + command + '" < ' + inputfile
        logging.info("ssh_node: inputfile selected, cmd: %s" % cmd)
    if outputfile is not None:
        cmd += ' > "' + outputfile + '"'
    cmd = ("trap 'kill $pid' 15; " +
           "trap 'kill $pid' 2; " + cmd + '&:; pid=$!; wait $!')
    return launch_cmd(cmd, timeout)


def get_files_rsync(ip, data, ssh_opts, dpath, timeout=15):
    if type(ssh_opts) is list:
        ssh_opts = ' '.join(ssh_opts)
    if (ip in ['localhost', '127.0.0.1']) or ip.startswith('127.'):
        logging.info("skip ssh rsync")
        cmd = ("timeout '%s' rsync -avzr --files-from=- / '%s'"
               " --progress --partial --delete-before" %
               (timeout, dpath))
    else:
        cmd = ("timeout '%s' rsync -avzr -e 'ssh %s"
               " -oCompression=no' --files-from=- '%s':/ '%s'"
               " --progress --partial --delete-before"
               ) % (timeout, ssh_opts, ip, dpath)
    logging.debug("command:%s\ndata:\n%s" % (cmd, data))
    if data == '':
        return cmd, '', 127
    return launch_cmd(cmd, timeout, input=data)


def get_file_scp(ip, file, ddir, timeout=600, recursive=False):
    ddir = ddir.rstrip('/') + '/'
    if '/' in file.lstrip('/'):
        subpath = ddir + file.lstrip('/')[:file.rfind('/')-1]
        mdir(subpath)
    r = '-r ' if recursive else ''
    cmd = "timeout '%s' scp %s'%s':'%s' '%s'" % (timeout, r, ip, file, ddir)
    return launch_cmd(cmd, timeout)


def free_space(destdir, timeout):
    cmd = ("df %s --block-size K 2> /dev/null"
           " | tail -n 1 | awk '{print $2}' | sed 's/K//g'") % (destdir)
    return launch_cmd(cmd, timeout)


# wrap non-list into list
def w_list(value):
    return value if type(value) == list else [value]

if __name__ == '__main__':
    exit(0)
