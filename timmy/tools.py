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

from flock import FLock
from pipes import quote
from tempfile import gettempdir
from timmy.env import project_name
import Queue
import json
import logging
import multiprocessing as mp
import os
import signal
import subprocess
import sys
import threading
import traceback
import yaml

logger = logging.getLogger(project_name)
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


def signal_wrapper(f):
    def wrapper(*args, **kwargs):
        setup_handle_sig()
        try:
            f(*args, **kwargs)
        except Exception as e:
            if not logger.handlers:
                logging.basicConfig()
            logger.error('Error: %s' % e, exc_info=True)
            for k in dir(e):
                '''debug: print all exception attrs except internal
                and except 'message', which is deprecated since Python 2.6'''
                if not k.startswith('__') and k != 'message':
                    v = getattr(e, k)
                    logger.debug('Error details: %s = %s' % (k, v))
            sys.exit(113)
    return wrapper


def handle_sig_usr1(sig, frame):
    debug_msg = 'Pid %d received USR1, printing current stack:'
    logger.critical(debug_msg % os.getpid())
    for line in traceback.format_stack(frame):
        for subline in line.splitlines():
            logger.critical(subline.rstrip())


def main_handle_sig(sig, frame):
    sig_msg = 'main application received signal %d, sending to children'
    logger.warning(sig_msg % sig)
    pids, errs, code = launch_cmd('pgrep -P %d' % os.getpid(), 2)
    if pids:
        for pid in pids.splitlines():
            try:
                os.kill(int(pid), sig)
            except OSError:
                pass
    sys.exit(sig)


def sub_handle_sig(sig, frame):
    sig_msg = 'subprocess received signal %d, sending to children, pid: %d'
    logger.warning(sig_msg % (sig, os.getpid()))
    signal.signal(sig, signal.SIG_IGN)
    try:
        os.killpg(os.getpid(), sig)
    except OSError:
        pass
    sys.exit(sig)


def setup_handle_sig(subprocess=False):
    if os.getpid() != os.getpgrp():
        os.setpgrp()
    sig_handler = main_handle_sig if not subprocess else sub_handle_sig
    for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        signal.signal(sig, sig_handler)
    signal.signal(signal.SIGUSR1, handle_sig_usr1)


def run_with_lock(f):
    def wrapper(*args, **kwargs):
        lock = FLock(os.path.join(gettempdir(), 'timmy_%s.lock' % f.__name__))
        if not lock.lock():
            logger.warning('Unable to obtain lock, skipping "%s"' %
                           f.__name__)
            return ''
        f(*args, **kwargs)
        lock.unlock()
    return wrapper


class RunItem():
    def __init__(self, target, args=None, key=None, logger=None):
        self.target = target
        self.args = args
        self.key = key
        self.process = None
        self.queue = None
        self.logger = logger or logging.getLogger(project_name)


class SemaphoreProcess(mp.Process):
    def __init__(self, semaphore, target, args=None, queue=None, logger=None):
        mp.Process.__init__(self)
        self.logger = logger or logging.getLogger(project_name)
        self.semaphore = semaphore
        self.target = target
        if not args:
            args = {}
        self.args = args
        self.queue = queue

    def run(self):
        setup_handle_sig(subprocess=True)
        fin_msg = 'finished subprocess, pid: %s'
        sem_msg = 'semaphore released by subprocess, pid: %s'
        try:
            result = self.target(**self.args)
            if self.queue:
                self.queue.put_nowait(result)
        except Exception as error:
            if self.queue:
                self.queue.put_nowait(error)
                self.queue.put_nowait(traceback.format_exc())
        finally:
            self.logger.debug(fin_msg % self.pid)
            self.semaphore.release()
            self.logger.debug(sem_msg % self.pid)


def run_batch(item_list, maxthreads, dict_result=False):
    exc_msg = 'exception in subprocess, pid: %s, details:'
    rem_msg = 'removing reference to finished subprocess, pid: %s'
    emp_msg = 'subprocess did not return results, pid: %s'

    def cleanup(launched):
        logger.info('cleaning up running subprocesses')
        for proc in launched.values():
            logger.debug('terminating subprocess, pid: %s' % proc.pid)
            proc.terminate()
            proc.join()

    def get_result(proc, key, results):
        try:
            results[key] = proc.queue.get(block=False)
        except Queue.Empty:
            if not proc.is_alive():
                logger.warning(emp_msg % proc.pid)

    def collect_results(l, join=False):
        results = {}
        remove_procs = []
        for key, proc in l.items():
            if not proc.is_alive() or join:
                logger.debug('joining subprocess, pid: %s' % proc.pid)
                while proc.is_alive():
                    get_result(proc, key, results)
                    proc.join(timeout=1)
                if key not in results:
                    get_result(proc, key, results)
                if key in results and isinstance(results[key], Exception):
                    exc_text = proc.queue.get()
                    logger.critical(exc_msg % proc.pid)
                    for line in exc_text.splitlines():
                        logger.critical('____%s' % line)
                    cleanup(l)
                    sys.exit(109)
                remove_procs.append(key)
        for key in remove_procs:
            logger.debug(rem_msg % key)
            l.pop(key)
        return results

    semaphore = mp.BoundedSemaphore(maxthreads)
    launched = {}
    results = {}
    if not dict_result:
        key = 0
    for run_item in item_list:
        results.update(collect_results(launched))
        semaphore.acquire(block=True)
        p = SemaphoreProcess(target=run_item.target,
                             semaphore=semaphore,
                             args=run_item.args,
                             queue=mp.Queue())
        p.start()
        if dict_result:
            launched[run_item.key] = p
            logger.debug('started subprocess, pid: %s, func: %s, key: %s' %
                         (p.pid, run_item.target, run_item.key))
        else:
            launched[key] = p
            key += 1
            logger.debug('started subprocess, pid:%s, func:%s, key:%s' %
                         (p.pid, run_item.target, key))

    results.update(collect_results(launched, True))
    if dict_result:
        return results
    else:
        return results.values()


def load_json_file(filename):
    """
    Loads json data from file
    """
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except IOError as e:
        logger.critical("I/O error(%s): file: %s; msg: %s" %
                        (e.errno, e.filename, e.strerror))
        sys.exit(107)
    except ValueError:
        logger.critical("Could not convert data", exc_info=True)
        sys.exit(108)


def load_yaml_file(filename):
    """
    Loads yaml data from file
    """
    try:
        with open(filename, 'r') as f:
            return yaml.load(f)
    except IOError as e:
        logger.critical("I/O error(%s): file: %s; msg: %s" %
                        (e.errno, e.filename, e.strerror))
        sys.exit(102)
    except ValueError:
        logger.critical("Could not convert data", exc_info=True)
        sys.exit(103)
    except yaml.parser.ParserError as e:
        logger.critical("Could not parse %s:\n%s" %
                        (filename, str(e)))
        sys.exit(105)


def mdir(directory):
    """
    Creates a directory if it doesn't exist
    """
    if directory and not os.path.exists(directory):
        logger.debug('creating directory %s' % directory)
        try:
            os.makedirs(directory)
        except OSError:
            logger.critical("Can't create a directory: %s" % directory)
            sys.exit(110)


def launch_cmd(cmd, timeout, input=None, ok_codes=None, decode=True):
    def _timeout_terminate(pid):
        try:
            os.kill(pid, 15)
            logger.error("launch_cmd: pid %d killed by timeout" % pid)
        except OSError:
            pass

    logger.debug('cmd: %s' % cmd)
    p = subprocess.Popen(cmd,
                         shell=True,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, close_fds=True)
    timeout_killer = None
    outs = None
    errs = None
    try:
        timeout_killer = threading.Timer(timeout, _timeout_terminate, [p.pid])
        timeout_killer.start()
        outs, errs = p.communicate(input=input)
        errs = errs.rstrip('\n')
        if decode:
            outs = outs.decode('utf-8')
            errs = errs.decode('utf-8')
    finally:
        if timeout_killer:
            timeout_killer.cancel()
        input = input.decode('utf-8') if input else None
        logger.debug(('___command: %s\n'
                      '_______pid: %s\n'
                      '_exit_code: %s\n'
                      '_____stdin: %s\n'
                      '____stderr: %s') % (cmd, p.pid, p.returncode, input,
                                           errs))
    return outs, errs, p.returncode


def ssh_node(ip, command='', ssh_opts=None, env_vars=None, timeout=15,
             filename=None, inputfile=None, outputfile=None,
             ok_codes=None, input=None, prefix=None, decode=True):
    if not ssh_opts:
        ssh_opts = ''
    if not env_vars:
        env_vars = ''
    if type(ssh_opts) is list:
        ssh_opts = ' '.join(ssh_opts)
    if type(env_vars) is list:
        env_vars = ' '.join(env_vars)
    if (ip in ['localhost', '127.0.0.1']) or ip.startswith('127.'):
        logger.debug("skip ssh")
        bstr = "%s timeout '%s' bash -c " % (
               env_vars, timeout)
    else:
        bstr = "timeout '%s' ssh -T %s '%s' '%s' " % (
               timeout, ssh_opts, ip, env_vars)
    if filename is None:
        cmd = '%s %s' % (bstr, quote(prefix + ' ' + command))
        if inputfile is not None:
            '''inputfile and stdin will not work together,
            give priority to inputfile'''
            input = None
            cmd = "%s < '%s'" % (cmd, inputfile)
    else:
        cmd = "%s'%s bash -s' < '%s'" % (bstr, prefix, filename)
    if outputfile is not None:
        cmd = "%s > '%s'" % (cmd, outputfile)
    logger.info("cmd: %s" % cmd)
    cmd = ("input=\"$(cat | xxd -p)\"; trap 'kill $pid' 15; " +
           "trap 'kill $pid' 2; echo -n \"$input\" | xxd -r -p | " + cmd +
           ' &:; pid=$!; wait $!')
    return launch_cmd(cmd, timeout, input=input,
                      ok_codes=ok_codes, decode=decode)


def get_files_rsync(ip, data, ssh_opts, rsync_opts, dpath, timeout=15):
    if type(ssh_opts) is list:
        ssh_opts = ' '.join(ssh_opts)
    if type(rsync_opts) is list:
        rsync_opts = ' '.join(rsync_opts)
    if (ip in ['localhost', '127.0.0.1']) or ip.startswith('127.'):
        logger.info("skip ssh rsync")
        cmd = ("timeout '%s' rsync %s --include-from=- / '%s' --exclude='*'" %
               (timeout, rsync_opts, dpath))
    else:
        cmd = ("timeout '%s' rsync %s -e 'ssh %s -oCompression=no' "
               "--include-from=- '%s':/ '%s' --exclude='*'" %
               (timeout, rsync_opts, ssh_opts, ip, dpath))
    logger.debug("command:%s\ndata:\n%s" % (cmd, data))
    if data == '':
        return cmd, '', 127
    return launch_cmd(cmd, timeout, input=data)


def get_file_scp(ip, file, ddir, ssh_opts, timeout=600, recursive=False):
    if type(ssh_opts) is list:
        ssh_opts = ' '.join(ssh_opts)
    dest = os.path.split(os.path.normpath(file).lstrip(os.path.sep))[0]
    ddir = os.path.join(os.path.normpath(ddir), dest)
    mdir(ddir)
    r = '-r ' if recursive else ''
    cmd = ("timeout '%s' scp %s -p -q %s'%s':'%s' '%s'" %
           (timeout, ssh_opts, r, ip, file, ddir))
    return launch_cmd(cmd, timeout)


def put_file_scp(ip, file, dest, ssh_opts, timeout=600, recursive=True):
    if type(ssh_opts) is list:
        ssh_opts = ' '.join(ssh_opts)
    r = '-r ' if recursive else ''
    cmd = ("timeout '%s' scp %s -p -q %s'%s' '%s':'%s'" %
           (timeout, ssh_opts, r, file, ip, dest))
    return launch_cmd(cmd, timeout)


def free_space(destdir, timeout):
    cmd = ("df %s --block-size K 2> /dev/null"
           " | tail -n 1 | awk '{print $4}' | sed 's/K//g'") % (destdir)
    return launch_cmd(cmd, timeout)


# wrap non-list into list
def w_list(value):
    return value if type(value) == list else [value]


def all_pairs(items, one_way=False):
    def incomplete(items_set, paired_dict):
        for paired_set in paired_dict.values():
            if items_set.difference(paired_set):
                return True

    items_set = set(items)
    pairs = []
    paired = {}
    for i in items_set:
        paired[i] = set([i])
    while incomplete(items_set, paired):
        busy = set()
        current_pairs = []
        for i in items_set:
            if items_set.difference(paired[i]) and i not in busy:
                can_pair = items_set.difference(busy).difference(paired[i])
            if can_pair:
                pair_i = can_pair.pop()
                current_pairs.append([i, pair_i])
                busy.add(i)
                busy.add(pair_i)
                paired[i].add(pair_i)
                if one_way:
                    paired[pair_i].add(i)
        pairs.append(current_pairs)
    return pairs


if __name__ == '__main__':
    sys.exit(0)
