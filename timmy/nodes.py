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

import flock
import json
import os
import logging
import sys
import re
import tools

ckey = 'cmds'
fkey = 'files'
lkey = 'logs'
varlogdir = '/var/log'


class Node(object):

    override_by_id = ['ssh_opts', 'env_vars', 'log_path', 'log_filter']
    aggregate_by_role = ['log_path', 'log_filter']

    def __init__(self, node_id, mac, cluster, roles, os_platform,
                 online, status, ip, conf):
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
        self.flogs = {}
        self.mapcmds = {}
        self.logs = {}
        self.set_conf(conf)

    def override_conf(self, conf):
        for field in Node.aggregate_by_role:
            for role in self.roles:
                try:
                    getattr(self, field).append(conf.by_role[self.role][field])
                except:
                    pass
        for field in Node.override_by_id:
            try:
                setattr(self, field, conf.by_node_id[self.node_id][field])
            except:
                pass

    def set_conf(self, conf):
        self.ssh_opts = conf.ssh_opts
        self.env_vars = conf.env_vars
        self.log_path = list([conf.log_path])
        self.log_filter = list([conf.log_filter])
        self.timeout = conf.timeout
        self.override_conf(conf)

    def set_files(self, dirname, key, ds, version):
        files = []
        dfs = 'default'
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
            if dfs in ds[key] and dfs in ds[key][dfs]:
                for f in ds[key][dfs][dfs].keys():
                    files += [os.path.join(dirname, key, dfs, dfs, f)]
        self.files[key] = sorted(set(files))
        logging.debug('set_files:\nkey: %s, node: %s, file_list: %s' %
                      (key, self.node_id, self.files[key]))

    def checkos(self, filename):
        bname = str(os.path.basename(filename))
        logging.debug('check os: node: %s, filename %s' %
                      (self.node_id, filename))
        if bname[0] == '.':
            if self.os_platform in bname:
                logging.debug('os %s in filename %s' %
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
            if ('once-by-role' in ds[key] and
                    role in ds[key]['once-by-role'].keys()):
                for f in ds[key]['once-by-role'][role]:
                    self.files[key] += [os.path.join(dirname, key,
                                                     'once-by-role', role, f)]
        self.files[key] = sorted(set(self.files[key]))
        logging.debug('add files:\nnode: %s, key: %s, files:\n%s' %
                      (self.node_id, key, self.files[key]))

    def exec_cmd(self, label, odir='info', fake=False):
        sn = 'node-%s' % self.node_id
        cl = 'cluster-%s' % self.cluster
        logging.debug('%s/%s/%s/%s' % (odir, label, cl, sn))
        ddir = os.path.join(odir, label, cl, sn)
        tools.mdir(ddir)
        for f in self.files[label]:
            logging.info('node:%s(%s), exec: %s' % (self.node_id, self.ip, f))
            if not fake:
                outs, errs, code = tools.ssh_node(ip=self.ip,
                                                  filename=f,
                                                  ssh_opts=self.ssh_opts,
                                                  env_vars=self.env_vars,
                                                  timeout=self.timeout,
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
                    logging.error("exec_cmd: can't write to file %s" % dfile)
        return self

    def exec_simple_cmd(self, cmd, infile, outfile, timeout=15, fake=False):
        logging.info('node:%s(%s), exec: %s' % (self.node_id, self.ip, cmd))
        if not fake:
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              command=cmd,
                                              ssh_opts=self.ssh_opts,
                                              env_vars=self.env_vars,
                                              timeout=timeout,
                                              outputfile=outfile,
                                              inputfile=infile)
            if code != 0:
                logging.warning("node: %s, ip: %s, cmdfile: %s,"
                                " code: %s, error message: %s" %
                                (self.node_id, self.ip, cmd, code, errs))

    def du_logs(self, label, sshopts, odir='info', timeout=15):
        logging.info('node:%s(%s), filelist: %s' %
                     (self.node_id, self.ip, label))
        cmd = 'du -b %s' % self.data[label].replace('\n', ' ')
        logging.info('node: %s, logs du-cmd: %s' % (self.node_id, cmd))
        outs, errs, code = tools.ssh_node(ip=self.ip,
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

    def get_files(self, label, odir='info', timeout=15):
        logging.info('node:%s(%s), filelist: %s' %
                     (self.node_id, self.ip, label))
        sn = 'node-%s' % self.node_id
        cl = 'cluster-%s' % self.cluster
        ddir = os.path.join(odir, label, cl, sn)
        tools.mdir(ddir)
        outs, errs, code = tools.get_files_rsync(ip=self.ip,
                                                 data=self.data[label],
                                                 ssh_opts=self.ssh_opts,
                                                 dpath=ddir,
                                                 timeout=self.timeout)
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

    def logs_filter(self):
        result = {}
        for re_pair in self.log_filter:
            for f, s in self.logs.items():
                if (('include' not in re_pair or
                     re.search(re_pair['include'], f)) and
                        ('exclude' not in re_pair or
                         not re.search(re_pair['exclude'], f))):
                    result[f] = s
        self.logs = result

    def logs_populate(self, timeout=5):
        got_logs = False
        for path in self.log_path:
            cmd = ("find '%s' -type f -exec du -b {} +" % (path))
            logging.info('logs_populate: node: %s, logs du-cmd: %s' %
                         (self.node_id, cmd))
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              command=cmd,
                                              ssh_opts=self.ssh_opts,
                                              env_vars='',
                                              timeout=timeout)
            if code == 124:
                logging.error("node: %s, ip: %s, command: %s, "
                              "timeout code: %s, error message: %s" %
                              (self.node_id, self.ip, cmd, code, errs))
                break
            if len(outs):
                got_logs = True
            for line in outs.split('\n'):
                if '\t' in line:
                    size, filename = line.split('\t')
                    self.logs[filename] = int(size)
            logging.debug('logs_populate: logs: %s' % (self.logs))
        return got_logs

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

    def __init__(self, cluster, extended, conf, filename=None):
        self.dirname = conf.rqdir.rstrip('/')
        if (not os.path.exists(self.dirname)):
            logging.error("directory %s doesn't exist" % (self.dirname))
            sys.exit(1)
        dn = os.path.basename(self.dirname)
        self.files = tools.get_dir_structure(conf.rqdir)[dn]
        if (conf.fuelip is None) or (conf.fuelip == ""):
            logging.error('looks like fuelip is not set(%s)' % conf.fuelip)
            sys.exit(7)
        self.fuelip = conf.fuelip
        self.conf = conf
        self.cluster = cluster
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
            self.njdata = json.loads(self.get_nodes(conf))
        self.load_nodes(conf)
        self.get_version()

    def __str__(self):
        s = "#node-id, cluster, admin-ip, mac, os, roles, online, status\n"
        for node in sorted(self.nodes.values(), key=lambda x: x.node_id):
            if (self.cluster and (str(self.cluster) != str(node.cluster)) and
                    node.cluster != 0):
                s += "#%s\n" % str(node)
            else:
                s += "%s\n" % str(node)
        return s

    def get_nodes(self, conf):
        fuel_node_cmd = 'fuel node list --json'
        fuelnode = Node(node_id=0,
                        cluster=0,
                        mac='n/a',
                        os_platform='centos',
                        roles=['fuel'],
                        status='ready',
                        online=True,
                        ip=self.fuelip,
                        conf=conf)
        nodes_json, err, code = tools.ssh_node(ip=self.fuelip,
                                               command=fuel_node_cmd,
                                               ssh_opts=fuelnode.ssh_opts,
                                               env_vars="",
                                               timeout=fuelnode.timeout,
                                               filename=None)
        if code != 0:
            logging.error("Can't get fuel node list %s" % err)
            sys.exit(4)
        return nodes_json

    def pass_hard_filter(self, node):
        if self.conf.hard_filter:
            if (self.conf.hard_filter.status and
                    (node.status not in self.conf.hard_filter.status)):
                logging.info("hard filter by status: excluding node-%s" %
                             node.node_id)
                return False
            if (isinstance(self.conf.hard_filter.online, bool) and
                    (bool(node.online) != self.conf.hard_filter.online)):
                logging.info("hard filter by online: excluding node-%s" %
                             node.node_id)
                return False
            if (self.conf.hard_filter.node_ids and
                    (int(node.node_id) not in self.conf.hard_filter.node_ids)):
                logging.info("hard filter by ids: excluding node-%s" %
                             node.node_id)
                return False
            if self.conf.hard_filter.roles:
                ok_roles = []
                for role in node.roles:
                    if role in self.conf.hard_filter.roles:
                        ok_roles.append(role)
                if not ok_roles:
                    logging.info("hard filter by roles: excluding node-%s" %
                                 node.node_id)
                    return False
        return True

    def load_nodes(self, conf):
        node = Node(node_id=0,
                    cluster=0,
                    mac='n/a',
                    os_platform='centos',
                    roles=['fuel'],
                    status='ready',
                    online=True,
                    ip=self.fuelip,
                    conf=conf)
        self.nodes = {}
        if self.pass_hard_filter(node):
            self.nodes = {self.fuelip: node}
        for node in self.njdata:
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
            params['conf'] = conf
            nodeobj = Node(**params)

            if self.pass_hard_filter(nodeobj):
                self.nodes[node_ip] = nodeobj

    def get_version(self):
        cmd = "awk -F ':' '/release/ {print \$2}' /etc/nailgun/version.yaml"
        fuelnode = self.nodes[self.fuelip]
        release, err, code = tools.ssh_node(ip=fuelnode.ip,
                                            command=cmd,
                                            ssh_opts=fuelnode.ssh_opts,
                                            env_vars="",
                                            timeout=fuelnode.timeout,
                                            filename=None)
        if code != 0:
            logging.error("Can't get fuel version %s" % err)
            sys.exit(3)
        self.version = release.rstrip('\n').strip(' ').strip('"')
        logging.info('release:%s' % (self.version))

    def get_release(self):
        cmd = "awk -F ':' '/fuel_version/ {print \$2}' /etc/astute.yaml"
        for node in self.nodes.values():
            if node.node_id == 0:
                # skip master
                node.release = self.version
            if (node.node_id != 0) and (node.status == 'ready'):
                release, err, code = tools.ssh_node(ip=node.ip,
                                                    command=cmd,
                                                    ssh_opts=node.ssh_opts,
                                                    timeout=node.timeout)
                if code != 0:
                    logging.warning("get_release: node: %s: %s" %
                                    (node.node_id, "Can't get node release"))
                    node.release = None
                    continue
                else:
                    node.release = release.strip('\n "\'')
                logging.info("get_release: node: %s, release: %s" %
                             (node.node_id, node.release))

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
                            logging.debug('role: %s, node: %s' %
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

    def exec_filter(self, node):
        f = self.conf.soft_filter
        if f:
            result = (((not f.status) or (node.status in f.status)) and
                      ((not f.roles) or (node.role in f.roles)) and
                      ((not f.node_ids) or (node.node_id in f.node_ids)))
        else:
            result = True
        return result and (((self.cluster and node.cluster != 0 and
                             str(self.cluster) == str(node.cluster)) or not
                            self.cluster) and node.online)

    def launch_ssh(self, odir='info', timeout=15, fake=False):
        lock = flock.FLock('/tmp/timmy-cmds.lock')
        if not lock.lock():
            logging.warning('Unable to obtain lock, skipping "cmds"-part')
            return ''
        label = ckey
        run_items = []
        for key, node in self.nodes.items():
            if self.exec_filter(node):
                run_items.append(tools.RunItem(target=node.exec_cmd,
                                               args={'label': label,
                                                     'odir': odir,
                                                     'fake': fake},
                                               key=key))
        self.nodes = tools.run_batch(run_items, 100, dict_result=True)
        lock.unlock()

    def calculate_log_size(self, timeout=15):
        total_size = 0
        for node in [n for n in self.nodes.values() if self.exec_filter(n)]:
            if not node.logs_populate(5):
                logging.warning("can't get log file list from node %s" %
                                node.node_id)
            else:
                node.logs_filter()
                logging.debug('filter logs: node-%s: filtered logs: %s' %
                              (node.node_id, node.logs))
                total_size += sum(node.logs.values())
        logging.info('Full log size on nodes(with fuel): %s bytes' %
                     total_size)
        self.alogsize = total_size / 1024

    def is_enough_space(self, directory, coefficient=1.2):
        tools.mdir(directory)
        outs, errs, code = tools.free_space(directory, timeout=1)
        if code != 0:
            logging.error("Can't get free space: %s" % errs)
            return False
        try:
            fs = int(outs.rstrip('\n'))
        except:
            logging.error("is_enough_space: can't get free space\nouts: %s" %
                          outs)
            return False
        logging.info('logsize: %s Kb, free space: %s Kb' % (self.alogsize, fs))
        if (self.alogsize*coefficient > fs):
            logging.error('Not enough space on device')
            return False
        else:
            return True

    def create_archive_general(self, directory, outfile, timeout):
        cmd = "tar jcf '%s' -C %s %s" % (outfile, directory, ".")
        tools.mdir(self.conf.archives)
        logging.debug("create_archive_general: cmd: %s" % cmd)
        outs, errs, code = tools.launch_cmd(command=cmd,
                                            timeout=timeout)
        if code != 0:
            logging.error("Can't create archive %s" % (errs))

    def find_adm_interface_speed(self, defspeed):
        '''Returns interface speed through which logs will be dowloaded'''
        for node in self.nodes.values():
            if not (node.ip == 'localhost' or node.ip.startswith('127.')):
                cmd = ("%s$(/sbin/ip -o route get %s | cut -d' ' -f3)/speed" %
                       ('cat /sys/class/net/', node.ip))
                out, err, code = tools.launch_cmd(cmd, node.timeout)
                if code != 0:
                    logging.error("can't get interface speed: error: %s" % err)
                    return defspeed
                try:
                    speed = int(out)
                except:
                    speed = defspeed
                return speed

    def archive_logs(self, outdir, timeout,
                     fake=False, maxthreads=10, speed=100):
        if fake:
            logging.info('archive_logs:skip creating archives(fake:%s)' % fake)
            return
        txtfl = []
        speed = self.find_adm_interface_speed(speed)
        speed = int(speed * 0.9 / min(maxthreads, len(self.nodes)))
        pythonslowpipe = tools.slowpipe % speed
        run_items = []
        for node in [n for n in self.nodes.values() if self.exec_filter(n)]:
            node.archivelogsfile = os.path.join(outdir,
                                                'logs-node-%s.tar.gz' %
                                                str(node.node_id))
            tools.mdir(outdir)
            logslistfile = node.archivelogsfile + '.txt'
            txtfl.append(logslistfile)
            try:
                with open(logslistfile, 'w') as llf:
                    for filename in node.logs:
                        llf.write(filename+"\0")
            except:
                logging.error("create_archive_logs: Can't write to file %s" %
                              logslistfile)
                continue
            cmd = "tar --gzip --create --file - --null --files-from -"
            if not (node.ip == 'localhost' or node.ip.startswith('127.')):
                cmd = ' '.join([cmd, "| python -c '%s'" % pythonslowpipe])
            args = {'cmd': cmd,
                    'infile': logslistfile,
                    'outfile': node.archivelogsfile,
                    'timeout': timeout}
            run_items.append(tools.RunItem(target=node.exec_simple_cmd,
                                           args=args))
        tools.run_batch(run_items, maxthreads)
        for tfile in txtfl:
            try:
                os.remove(tfile)
            except:
                logging.error("archive_logs: can't delete file %s" % tfile)

    def get_conf_files(self, odir=fkey, timeout=15):
        if fkey not in self.files:
            logging.warning("get_conf_files: %s directory doesn't exist" %
                            fkey)
            return
        lock = flock.FLock('/tmp/timmy-files.lock')
        if not lock.lock():
            logging.warning('Unable to obtain lock, skipping "files"-part')
            return ''
        try:
            label = fkey
            run_items = []
            for n in [n for n in self.nodes.values() if self.exec_filter(n)]:
                run_items.append(tools.RunItem(target=n.get_files,
                                               args={'label': label,
                                                     'odir': odir}))
            tools.run_batch(run_items, 10)
        finally:
            lock.unlock()


def main(argv=None):
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
