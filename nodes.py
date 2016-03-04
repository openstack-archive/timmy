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
main module
"""

import argparse
import flock
import json
import os
import logging
import sys
import threading
from tools import *


ckey = 'cmds'
fkey = 'files'
lkey = 'logs'
varlogdir = '/var/log'


class Node(object):

    def __init__(self, node_id, mac, cluster, roles, os_platform,
                 online, status, ip, flogs=False):
        self.node_id = node_id
        self.mac = mac
        self.cluster = cluster
        self.roles = roles
        self.os_platform = os_platform
        self.online = online
        self.status = status
        self.ip = ip
        self.files = {}
        self.data = {}
        self.logsize = 0
        # include logs from the command 'find /var/log/ ...'
        self.flogs = flogs
        self.mapcmds = {}

    def set_files(self, dirname, key, ds, version):
        files = []
        for role in self.roles:
            if 'by-role' in ds[key] and role in ds[key]['by-role'].keys():
                for f in ds[key]['by-role'][role]:
                    files += [os.path.join(dirname, key, 'by-role', role, f)]
            if (('release-'+version in ds[key].keys()) and
                    (role in ds[key]['release-'+version].keys())):
                for f in ds[key]['release-'+version][role]:
                        files += [os.path.join(dirname, key,
                                               'release-'+version, role, f)]
            if 'by-os' in ds[key]:
                for f in ds[key]['by-os'][self.os_platform].keys():
                    files += [os.path.join(dirname, key, 'by-os',
                                           self.os_platform, f)]
            if 'default' in ds[key] and 'default' in ds[key]['default']:
                for f in ds[key]['default']['default'].keys():
                    files += [os.path.join(dirname, key, 'default', 'default', f)]
        self.files[key] = sorted(set(files))
        logging.debug('set_files:\nkey: %s, node: %s, file_list: %s' %
                      (key, self.node_id, self.files[key]))

    def checkos(self, filename):
        bname = str(os.path.basename(filename))
        logging.debug('check os: node: %s, filename %s' %
                      (self.node_id, filename))
        if bname[0] == '.':
            if self.os_platform in bname:
                logging.info('os %s in filename %s' %
                             (self.os_platform, filename))
                return True
            else:
                return False
        return True

    def exclude_non_os(self):
        for key in self.files.keys():
            self.files[key] = [f for f in self.files[key] if self.checkos(f)]

    def add_files(self, dirname, key, ds):
        for role in self.roles:
            if 'once-by-role' in ds[key] and role in ds[key]['once-by-role'].keys():
                for f in ds[key]['once-by-role'][role]:
                    self.files[key] += [os.path.join(dirname, key,
                                                     'once-by-role', role, f)]
        self.files[key] = sorted(set(self.files[key]))
        logging.debug('add files:\nnode: %s, key: %s, files:\n%s' %
                      (self.node_id, key, self.files[key]))

    def exec_cmd(self, label, sshvars, sshopts, odir='info', timeout=15, fake=False):
        sn = 'node-%s' % self.node_id
        cl = 'cluster-%s' % self.cluster
        logging.debug('%s/%s/%s/%s' % (odir, label, cl, sn))
        ddir = os.path.join(odir, label, cl, sn)
        mdir(ddir)
        for f in self.files[label]:
            logging.info('node:%s(%s), exec: %s' % (self.node_id, self.ip, f))
            if not fake:
                outs, errs, code = ssh_node(ip=self.ip,
                                            filename=f,
                                            sshvars=sshvars,
                                            sshopts=sshopts,
                                            timeout=timeout,
                                            command=''
                                           )
                if code != 0:
                    logging.error("node: %s, ip: %s, cmdfile: %s,"
                                  " code: %s, error message: %s" %
                                  (self.node_id, self.ip, f, code, errs))
            dfile = os.path.join(ddir, 'node-%s-%s-%s' %
                                 (self.node_id, self.ip, os.path.basename(f)))
            logging.info('outfile: %s' % dfile)
            self.mapcmds[os.path.basename(f)] = dfile
            if not fake:
                try:
                    with open(dfile, 'w') as df:
                        df.write(outs)
                except:
                    logging.error("Can't write to file %s" % dfile)

    def du_logs(self, label, sshopts, odir='info', timeout=15):
        logging.info('node:%s(%s), filelist: %s' %
                     (self.node_id, self.ip, label))
        cmd = 'du -b %s' % self.data[label].replace('\n', ' ')
        logging.info('node: %s, logs du-cmd: %s' % (self.node_id, cmd))
        outs, errs, code = ssh_node(ip=self.ip,
                                    command=cmd,
                                    sshopts=sshopts,
                                    sshvars='',
                                    timeout=timeout)
        if code != 0:
            logging.warning("node: %s, ip: %s, cmdfile: %s, "
                            "code: %s, error message: %s" %
                            (self.node_id, self.ip, label, code, errs))
        if code == 124:
            logging.error("node: %s, ip: %s, command: %s, "
                          "timeout code: %s, error message: %s" %
                          (self.node_id, self.ip, label, code, errs))
            # mark node as offline
            self.online = False
        if self.online:
            size = 0
            for s in outs.splitlines():
                size += int(s.split()[0])
            self.logsize = size
            logging.info("node: %s, ip: %s, size: %s" %
                         (self.node_id, self.ip, self.logsize))

    def get_files(self, label, logdir, sshopts, odir='info', timeout=15):
        logging.info('node:%s(%s), filelist: %s' %
                     (self.node_id, self.ip, label))
        sn = 'node-%s' % self.node_id
        cl = 'cluster-%s' % self.cluster
        ddir = os.path.join(odir, label, cl, sn)
        mdir(ddir)
        # logging.info(self.data)
        outs, errs, code = get_files_rsync(ip=self.ip,
                                           data=self.data[label],
                                           sshopts=sshopts,
                                           dpath=ddir,
                                           timeout=timeout)
        if code != 0:
            logging.warning("get_files: node: %s, ip: %s, label: %s, "
                            "code: %s, error message: %s" %
                            (self.node_id, self.ip, label, code, errs))

    def get_data_from_files(self, key):
        self.data[key] = ''
        for fname in self.files[key]:
            try:
                with open(fname, 'r') as dfile:
                    self.data[key] += '\n'+"".join(line for line in dfile
                                                   if (not line.isspace() and
                                                       line[0] != '#'))
            except:
                logging.error('could not read file: %s' % fname)
            logging.debug('node: %s, key: %s, data:\n%s' %
                          (self.node_id, key, self.data[key]))

    def log_size_from_find(self, template, sshopts, odir, timeout=5):
        logging.info('template find: %s' % template)
        cmd = ("find '%s' -type f \( %s \) -exec du -b {} +" %
               (varlogdir, str(template)))
        logging.info('node: %s, logs du-cmd: %s' % (self.node_id, cmd))
        outs, errs, code = ssh_node(ip=self.ip,
                                    command=cmd,
                                    sshopts=sshopts,
                                    sshvars='',
                                    timeout=timeout)
        if code == 124:
            logging.error("node: %s, ip: %s, command: %s, "
                          "timeout code: %s, error message: %s" %
                          (self.node_id, self.ip, cmd, code, errs))
            self.logsize = -1
            return -1
        size = 0
        for s in outs.splitlines():
            size += int(s.split()[0])
        self.logsize = size
        logging.info("log size from find: node: %s, ip: %s, size: %s bytes" %
                     (self.node_id, self.ip, self.logsize))
        return self.logsize

    def print_files(self):
        for k in self.files.keys():
            print('key: %s' % (k))
            for f in self.files[k]:
                print(f)
            print('\n')

    def __str__(self):
        if self.status in ['ready', 'discover'] and self.online:
            my_id = self.node_id
        else:
            my_id = '#' + str(self.node_id)

        templ = '{0} {1.cluster} {1.ip} {1.mac} {1.os_platform} '
        templ += '{2} {1.online} {1.status}'
        return templ.format(my_id, self, ','.join(self.roles))


class Nodes(object):
    """Class nodes """

    def __init__(self, cluster, extended, conf, destdir, filename=None):
        self.dirname = conf.rqdir.rstrip('/')
        if (not os.path.exists(self.dirname)):
            logging.error("directory %s doesn't exist" % (self.dirname))
            sys.exit(1)
        self.files = get_dir_structure(conf.rqdir)[os.path.basename(self.dirname)]
        self.fuelip = conf.fuelip
        self.sshopts = conf.ssh['opts']
        self.sshvars = conf.ssh['vars']
        self.timeout = conf.timeout
        self.conf = conf
        self.destdir = destdir
        self.get_version()
        self.cluster = cluster
        self.logdir = conf.logdir
        self.extended = extended
        logging.info('extended: %s' % self.extended)
        if filename is not None:
            try:
                with open(filename, 'r') as json_data:
                    self.njdata = json.load(json_data)
            except:
                logging.error("Can't load data from file %s" % filename)
                sys.exit(6)
        else:
            self.njdata = json.loads(self.get_nodes())
        self.load_nodes()

    def get_nodes(self):
        fuel_node_cmd = 'fuel node list --json'
        nodes_json, err, code = ssh_node(ip=self.fuelip,
                                         command=fuel_node_cmd,
                                         sshopts=self.sshopts,
                                         sshvars='DUMMY=""',
                                         timeout=self.timeout,
                                         filename=None)
        if code != 0:
            logging.error("Can't get fuel node list %s" % err)
            sys.exit(4)
        return nodes_json

    def load_nodes(self):
        node = Node(node_id=0,
                    cluster=0,
                    mac='n/a',
                    os_platform='centos',
                    roles=['fuel'],
                    status='ready',
                    online=True,
                    ip=self.fuelip)
        self.nodes = {self.fuelip: node}
        for node in self.njdata:
            if self.conf.hard_filter:
                pass
            node_roles = node.get('roles')
            if not node_roles:
                roles = ['None']
            elif isinstance(node_roles, list):
                roles = node_roles
            else:
                roles = str(node_roles).split(', ')
            node_ip = str(node['ip'])
            keys = "cluster mac os_platform status online".split()
            params = {'node_id': node['id'],
                      'roles': roles,
                      'ip': node_ip}
            for key in keys:
                params[key] = node[key]
            self.nodes[node_ip] = Node(**params)

    def get_version(self):
        cmd = "awk -F ':' '/release/ {print \$2}' /etc/nailgun/version.yaml"
        release, err, code = ssh_node(ip=self.fuelip,
                                      command=cmd,
                                      sshopts=self.sshopts,
                                      sshvars='',
                                      timeout=self.timeout,
                                      filename=None)
        if code != 0:
            logging.error("Can't get fuel version %s" % err)
            sys.exit(3)
        self.version = release.rstrip('\n').strip(' ').strip('"')
        logging.info('release:%s' % (self.version))

    def get_release(self):
        cmd = "awk -F ':' '/fuel_version/ {print \$2}' /etc/astute.yaml"
        for node in self.nodes.values():
            # skip master
            if node.node_id == 0:
                node.release = self.version
            if (node.node_id != 0) and ( node.status == 'ready'):
                release, err, code = ssh_node(ip=node.ip,
                                              command=cmd,
                                              sshopts=self.sshopts,
                                              sshvars='',
                                              timeout=self.timeout,
                                              filename=None)
                if code != 0:
                    logging.warning("get_release: node: %s: Can't get node release" % (node.node_id))
                    node.release = self.version
                    continue
                node.release = release.strip('\n "\'')
                logging.info("get_release: node: %s, release: %s" % (node.node_id, node.release))

    def get_node_file_list(self):
        for key in self.files.keys():
            #  ###   case
            roles = []
            for node in self.nodes.values():
                node.set_files(self.dirname, key, self.files, self.version)
                # once-by-role functionality
                if self.extended and key == ckey and node.online:
                    for role in node.roles:
                        if role not in roles:
                            roles.append(role)
                            logging.info('role: %s, node: %s' %
                                         (role, node.node_id))
                            node.add_files(self.dirname, key, self.files)
                node.exclude_non_os()
            if key == ckey:
                logging.info('node: %s, os: %s, key: %s, files: %s' %
                             (node.node_id,
                              node.os_platform,
                              key,
                              node.files[key]))
        for key in [fkey, lkey]:
            if key in self.files.keys():
                for node in self.nodes.values():
                    node.get_data_from_files(key)
        for node in self.nodes.values():
            logging.debug('%s' % node.files[ckey])

    def launch_ssh(self, odir='info', timeout=15, fake=False):
        lock = flock.FLock('/tmp/timmy-cmds.lock')
        if not lock.lock():
            logging.warning('Unable to obtain lock, skipping "cmds"-part')
            return ''
        label = ckey
        threads = []
        for node in self.nodes.values():
            if (self.cluster and str(self.cluster) != str(node.cluster) and
                    node.cluster != 0):
                continue
            if node.status in self.conf.soft_filter.status and node.online:
                t = threading.Thread(target=node.exec_cmd,
                                     args=(label,
                                           self.sshvars,
                                           self.sshopts,
                                           odir,
                                           self.timeout,
                                           fake))
                threads.append(t)
                t.start()
        for t in threads:
            t.join()
        lock.unlock()

    def calculate_log_size(self, template, timeout=15):
        label = lkey
        threads = []
        for node in self.nodes.values():
            if (self.cluster and str(self.cluster) != str(node.cluster) and
                    node.cluster != 0):
                continue
            if node.status in self.conf.soft_filter.status and node.online:
                t = threading.Thread(target=node.du_logs,
                                     args=(label,
                                           self.sshopts,
                                           5,))
                threads.append(t)
                t.start()
        for t in threads:
            t.join()
        lsize = 0
        for node in self.nodes.values():
            lsize += node.logsize
        logging.info('Full log size on nodes: %s bytes' % lsize)
        fuelnode = self.nodes[self.fuelip]
        if fuelnode.log_size_from_find(template,
                                       self.sshopts,
                                       5) > 0:
            lsize += fuelnode.logsize
        logging.info('Full log size on nodes(with fuel): %s bytes' % lsize)
        self.alogsize = lsize / 1024

    def is_enough_space(self, coefficient=2.2):
        outs, errs, code = free_space(self.destdir, timeout=1)
        if code != 0:
            logging.error("Can't get free space: %s" % errs)
            return False
        fs = int(outs.rstrip('\n'))
        logging.info('logsize: %s, free space: %s Kb' % (self.alogsize, fs))
        if (self.alogsize*coefficient > fs):
            logging.error('Not enough space on device')
            return False
        else:
            return True

    def create_archive_general(self, outdir, outfile, timeout):
        cmd = "tar jcf '%s' %s" % (outfile, outdir)
        logging.info(cmd)
        outs, errs, code = ssh_node(ip='localhost',
                                    command=cmd,
                                    sshopts=self.sshopts,
                                    sshvars='',
                                    timeout=timeout,
                                    outputfile=outfile)
        if code != 0:
            logging.error("Can't create archive %s" % (errs))

    def create_archive_logs(self, template, outfile, timeout):
        fuelnode = self.nodes[self.fuelip]
        tstr = '--transform \\"flags=r;s|^|logs/fuel/|\\"'
        cmd = ("find %s -type f \( %s \) -print0 "
               "| tar --create %s --file - "
               "--null --files-from -" %
               (varlogdir, template, tstr))
        outs, errs, code = ssh_node(ip=fuelnode.ip,
                                    command=cmd,
                                    sshopts=self.sshopts,
                                    sshvars='',
                                    timeout=timeout,
                                    outputfile=outfile)
        if code != 0:
            logging.warning("stderr from tar: %s" % (errs))

    def add_logs_archive(self, directory, key, outfile, timeout):
        cmd = ("tar --append --file=%s --directory %s %s" %
               (outfile, directory, key))
        outs, errs, code = ssh_node(ip='localhost', command=cmd,
                                    sshopts=self.sshopts,
                                    sshvars='',
                                    timeout=timeout)
        if code != 2 and code != 0:
            logging.warning("stderr from tar: %s" % (errs))

    def compress_archive(self, filename, timeout):
        cmd = 'bzip2 -f %s' % filename
        outs, errs, code = launch_cmd(command=cmd,
                                      timeout=timeout)
        if code != 0:
            logging.warning("Can't compress archive %s" % (errs))

    def get_conf_files(self, odir=fkey, timeout=15):
        if fkey not in self.files:
            logging.warning("get_conf_files: %s directory does not exist" %(fkey))
            return
        lock = flock.FLock('/tmp/timmy-files.lock')
        if not lock.lock():
            logging.warning('Unable to obtain lock, skipping "files"-part')
            return ''
        label = fkey
        threads = []
        for node in self.nodes.values():
            if (self.cluster and str(self.cluster) != str(node.cluster) and
                    node.cluster != 0):
                continue
            if node.status in self.conf.soft_filter.status and node.online:
                t = threading.Thread(target=node.get_files,
                                     args=(label,
                                           self.logdir,
                                           self.sshopts,
                                           odir,
                                           self.timeout,))
                threads.append(t)
                t.start()
        for t in threads:
            t.join()
        lock.unlock()

    def get_log_files(self, odir=lkey, timeout=15):
        # lock = flock.FLock('/tmp/timmy-logs.lock')
        # if not lock.lock():
        #    logging.warning('Unable to obtain lock, skipping "logs"-part')
        #    return ''
        if lkey not in self.files:
            logging.warning("get_log_files: %s directory does not exist" %(lkey))
            return
        label = lkey
        threads = []
        for node in self.nodes.values():
            if (self.cluster and str(self.cluster) != str(node.cluster) and
                    node.cluster != 0):
                continue
            if (node.status in self.conf.soft_filter.status and
                    node.online and str(node.node_id) != '0'):
                        t = threading.Thread(target=node.get_files,
                                             args=(label,
                                                   self.logdir,
                                                   self.sshopts,
                                                   odir,
                                                   self.timeout,))
                        threads.append(t)
                        t.start()
        for t in threads:
            t.join()
        # lock.unlock()

    def print_nodes(self):
        """print nodes"""
        print('#node-id, cluster, admin-ip, mac, os, roles, online, status')
        for node in sorted(self.nodes.values(), key=lambda x: x.node_id):
            if (self.cluster and
                    (str(self.cluster) != str(node.cluster)) and
                    node.cluster != 0):
                print("#"+str(node))
            else:
                print(str(node))


def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description='need to add description')
    parser.add_argument('-a', '--dest-dir', default='/tmp/',
                        help='directory with output archive')
    parser.add_argument('-f', '--nodes',
                        help='nodes file', default='nodes.json')
    parser.add_argument('-t', '--timeout',
                        help='timeout for command', type=int, default=15)
    parser.add_argument('-l', '--log-dir',
                        help='log directory', default='./logs/')
    parser.add_argument('-o', '--ssh-vars',
                        help='ssh variables',
                        default=("OPENRC=/root/openrc "
                                 "IPTABLES_STR=\"iptables -nvL\""))
    parser.add_argument('-p', '--ssh-opts',
                        help='ssh options',
                        default=("-oConnectTimeout=2 "
                                 "-oStrictHostKeyChecking=no "
                                 "-oUserKnownHostsFile=/dev/null "
                                 "-oLogLevel=error "
                                 "-lroot -oBatchMode=yes"))
    parser.add_argument('-r', '--rq-dir',
                        help='rq directrory', default='./rq')
    parser.add_argument('-e', '--extended', default="0",
                        help='exec once by role cmdfiles')
    parser.add_argument('-c', '--cluster', help='cluster id')
    parser.add_argument('-i', '--fuel-ip',
                        help='Fuel admin ip address', default="localhost")
    parser.add_argument('-s', '--out-dir', default='info',
                        help='output directory')
    parser.add_argument('-d', '--debug',
                        help="Print lots of debugging statements",
                        action="store_const", dest="loglevel",
                        const=logging.DEBUG,
                        default=logging.WARNING,)
    parser.add_argument('-v', '--verbose',
                        help="Be verbose",
                        action="store_const", dest="loglevel",
                        const=logging.INFO,)

    args = parser.parse_args(argv[1:])
    logging.basicConfig(level=args.loglevel)
    args.extended = args.extended == "1"
    nodes = Nodes(filesd=args.rq_dir,
                  logdir=args.log_dir,
                  extended=args.extended,
                  fuelip=args.fuel_ip,
                  cluster=args.cluster,
                  sshopts=args.ssh_opts,
                  sshvars=args.ssh_vars,
                  timeout=args.timeout,
                  destdir=args.dest_dir)
    # nodes.print_nodes()
    nodes.get_node_file_list()
    nodes.calculate_log_size(conf.find['template'])
    if nodes.is_enough_space():
        nodes.get_log_files(args.out_dir)
    nodes.launch_ssh(args.out_dir)
    nodes.get_conf_files(args.out_dir)

    nodes.print_nodes()
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
