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
from copy import deepcopy

ckey = 'cmds'
fkey = 'files'
lkey = 'logs'
varlogdir = '/var/log'


class Node(object):

    conf_appendable = ['logs','cmds','files']
    conf_keep_default = ['cmds','files']
    conf_section_prefix = 'by_'
    conf_priority_section = conf_section_prefix + 'node_id'

    def __init__(self, node_id, mac, cluster, roles, os_platform,
                 online, status, ip, conf):
        self.cluster = cluster
        self.node_id = node_id
        self.mac = mac
        self.roles = roles
        self.os_platform = os_platform
        self.online = online
        self.status = status
        self.ip = ip
        self.files = []
        self.cmds = []
        self.data = {}
        self.logsize = 0
        self.mapcmds = {}
        self.overridden = {}
        self.filtered_out = False
        self.apply_conf(conf)

    def apply_conf(self, conf):
        def __list(v):
            return v if type(v) == list else [v]

        def apply_subset(subconf, replace=False):
            for field, value in subconf.items():
                if field in Node.conf_appendable:
                    if field not in self.overridden or replace:
                        setattr(self, field, deepcopy(__list(value)))
                        self.overridden[field] = True
                    else:
                        getattr(self, field).extend(deepcopy(__list(value)))
                else:
                    setattr(self, field, deepcopy(value))

        pre = Node.conf_section_prefix
        pri_sec = Node.conf_priority_section 
        defaults = [s for s in vars(conf) if not s.startswith(pre)]
        defaults_conf = dict((attr, getattr(conf, attr)) for attr in defaults)
        override = [s for s in vars(conf) if s.startswith(pre) and
                                             s != pri_sec]
        override_conf = dict((attr, getattr(conf, attr)) for attr in override)
        pri_conf = None    
        if hasattr(conf, pri_sec):
            pri_conf = getattr(conf, pri_sec)
        # apply defaults
        apply_subset(defaults_conf, replace=True)
        # apply overrides
        for section in override:
            attr = section[len(pre):]
            subconf = getattr(conf, section)
            if hasattr(self, attr):
                if getattr(self, attr) in subconf:
                    apply_subset(subconf[getattr(self, attr)])
        # apply priority override
        if pri_conf:
            apply_subset(pri_conf, replace=True)

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

    def exec_cmd(self, odir='info', fake=False, ok_codes=[0, ]):
        sn = 'node-%s' % self.node_id
        cl = 'cluster-%s' % self.cluster
        logging.debug('%s/%s/%s/%s' % (odir, ckey, cl, sn))
        ddir = os.path.join(odir, ckey, cl, sn)
        tools.mdir(ddir)
        for c in self.cmds:
            f = os.path.join(self.rqdir,'cmds',c)
            logging.info('node:%s(%s), exec: %s' % (self.node_id, self.ip, f))
            if not fake:
                outs, errs, code = tools.ssh_node(ip=self.ip,
                                                  filename=f,
                                                  ssh_opts=self.ssh_opts,
                                                  env_vars=self.env_vars,
                                                  timeout=self.timeout)
                if code not in ok_codes:
                    logging.warning("node: %s, ip: %s, cmdfile: %s,"
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

    def exec_simple_cmd(self, cmd, infile, outfile, timeout=15,
                        fake=False, ok_codes=[0, ]):
        logging.info('node:%s(%s), exec: %s' % (self.node_id, self.ip, cmd))
        if not fake:
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              command=cmd,
                                              ssh_opts=self.ssh_opts,
                                              env_vars=self.env_vars,
                                              timeout=timeout,
                                              outputfile=outfile,
                                              inputfile=infile)
            if code not in ok_codes:
                logging.warning("node: %s, ip: %s, cmdfile: %s,"
                                " code: %s, error message: %s" %
                                (self.node_id, self.ip, cmd, code, errs))

    def get_files(self, odir='info', timeout=15):
        logging.info('node:%s(%s), filelist: %s' %
                     (self.node_id, self.ip, fkey))
        sn = 'node-%s' % self.node_id
        cl = 'cluster-%s' % self.cluster
        ddir = os.path.join(odir, fkey, cl, sn)
        tools.mdir(ddir)
        data = ''
        for f in self.files:
            fname = os.path.join(self.rqdir,'files',f)
            try:
                with open(fname, 'r') as df:
                    for line in df:
                        if not line.isspace() and line[0] != '#':
                            data += line
            except:
                logging.error('could not read file: %s' % fname)
        logging.debug('node: %s, data:\n%s' % (self.node_id, data))
        outs, errs, code = tools.get_files_rsync(ip=self.ip,
                                                 data=data,
                                                 ssh_opts=self.ssh_opts,
                                                 dpath=ddir,
                                                 timeout=self.timeout)
        if code != 0:
            logging.warning("get_files: node: %s, ip: %s, "
                            "code: %s, error message: %s" %
                            (self.node_id, self.ip, code, errs))

    def logs_populate(self, timeout=5):
        def filter_by_re(item, string):
            return (('include' not in item or
                     re.search(item['include'], string)) and
                    ('exclude' not in item or not
                     re.search(item['exclude'], string)))

        for item in self.logs:
            if 'start' in item:
                start = ' -newermt \\"$(date -d \'%s\')\\"' % item['start']
            else:
                start = ''
            cmd = ("find '%s' -type f%s -exec du -b {} +" % (item['path'],
                                                             start))
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
                item['files'] = {}
                for line in outs.split('\n'):
                    if '\t' in line:
                        size, f = line.split('\t')
                        if filter_by_re(item, f):
                            item['files'][f] = int(size)
                logging.debug('logs_populate: logs: %s' % (item['files']))
        return self

    def logs_dict(self):
        result = {}
        for item in self.logs:
            if 'files' in item:
                for f, s in item['files'].items():
                    if f in result:
                        result[f] = max(result[f], s)
                    else:
                        result[f] = s
        return result

    def __str__(self):
        if not self.filtered_out:
            my_id = self.node_id
        else:
            my_id = '#' + str(self.node_id)

        templ = '{0} {1.cluster} {1.ip} {1.mac} {1.os_platform} '
        templ += '{2} {1.online} {1.status}'
        return templ.format(my_id, self, ','.join(self.roles))


class NodeManager(object):
    """Class nodes """

    def __init__(self, cluster, extended, conf, filename=None):
        self.cluster = cluster
        self.extended = extended
        self.conf = conf
        self.rqdir = conf.rqdir.rstrip('/')
        self.import_rq(conf)
        if (not os.path.exists(self.rqdir)):
            logging.error("directory %s doesn't exist" % (self.rqdir))
            sys.exit(1)
        if (conf.fuelip is None) or (conf.fuelip == ""):
            logging.error('looks like fuelip is not set(%s)' % conf.fuelip)
            sys.exit(7)
        self.fuelip = conf.fuelip
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

    def import_rq(self, conf):
        rq = tools.load_yaml_file(conf.rqfile)
        for attr in rq:
            if 'default' in rq[attr]:
                setattr(conf, attr, rq[attr]['default'])
            pre = Node.conf_section_prefix
            override = [s for s in rq[attr] if s.startswith(pre)]
            override_conf = dict((s, rq[attr][s]) for s in override)
            for section in override:
                if not hasattr(conf, section):
                    setattr(conf, section, {})
                for k, v in override_conf[section].items():
                    if k not in getattr(conf, section):
                        getattr(conf, section)[k] = {}
                    getattr(conf, section)[k][attr] = v

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
        self.nodes = {self.fuelip: fuelnode}
        nodes_json, err, code = tools.ssh_node(ip=self.fuelip,
                                               command=fuel_node_cmd,
                                               ssh_opts=fuelnode.ssh_opts,
                                               timeout=fuelnode.timeout)
        if code != 0:
            logging.error("Can't get fuel node list %s" % err)
            sys.exit(4)
        return nodes_json

    def load_nodes(self, conf):
        for node_data in self.njdata:
            node_roles = node_data.get('roles')
            if not node_roles:
                roles = ['None']
            elif isinstance(node_roles, list):
                roles = node_roles
            else:
                roles = str(node_roles).split(', ')
            keys = "cluster mac os_platform status online ip".split()
            params = {'node_id': int(node_data['id']),
                      'roles': roles,
                      'conf': conf}
            for key in keys:
                params[key] = node_data[key]
            node = Node(**params)
            if self.filter(node, self.conf.hard_filter):
                if not self.filter(node, self.conf.soft_filter):
                    node.filtered_out = True
                self.nodes[node.ip] = node

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

    def filter(self, node, node_filter):
        f = node_filter
        return (((not f.statuses) or (node.status in f.statuses)) and
                ((not f.roles) or (node.role in f.roles)) and
                ((not f.node_ids) or (node.node_id in f.node_ids)) and
                ((not f.online) or (node.online)) and
                (((not f.clusters) or node.cluster in f.clusters) or
                 (node.cluster == 0 and f == self.conf.hard_filter))) 

    def launch_ssh(self, odir='info', timeout=15, fake=False, maxthreads=100):
        lock = flock.FLock('/tmp/timmy-cmds.lock')
        if not lock.lock():
            logging.warning('Unable to obtain lock, skipping "cmds"-part')
            return ''
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out:
                run_items.append(tools.RunItem(target=node.exec_cmd,
                                               args={'odir': odir,
                                                     'fake': fake},
                                               key=key))
        self.nodes = tools.run_batch(run_items, maxthreads, dict_result=True)
        lock.unlock()

    def calculate_log_size(self, timeout=15, maxthreads=100):
        total_size = 0
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out:
                run_items.append(tools.RunItem(target=node.logs_populate,
                                               args={'timeout': timeout},
                                               key=key))
        self.nodes = tools.run_batch(run_items, maxthreads, dict_result=True)
        for node in self.nodes.values():
            total_size += sum(node.logs_dict().values())
        logging.info('Full log size on nodes(with fuel): %s bytes' %
                     total_size)
        self.alogsize = total_size / 1024
        return self.alogsize

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
        cmd = "tar zcf '%s' -C %s %s" % (outfile, directory, ".")
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
        for node in [n for n in self.nodes.values() if not n.filtered_out]:
            if not node.logs_dict():
                logging.info(("create_archive_logs: node %s - no logs "
                             "to collect") % node.node_id)
                continue
            node.archivelogsfile = os.path.join(outdir,
                                                'logs-node-%s.tar.gz' %
                                                str(node.node_id))
            tools.mdir(outdir)
            logslistfile = node.archivelogsfile + '.txt'
            txtfl.append(logslistfile)
            try:
                with open(logslistfile, 'w') as llf:
                    for filename in node.logs_dict():
                        llf.write(filename.lstrip('/')+"\0")
            except:
                logging.error("create_archive_logs: Can't write to file %s" %
                              logslistfile)
                continue
            cmd = ("tar --gzip -C / --create --warning=no-file-changed "
                   " --file - --null --files-from -")
            if not (node.ip == 'localhost' or node.ip.startswith('127.')):
                cmd = ' '.join([cmd, "| python -c '%s'" % pythonslowpipe])
            args = {'cmd': cmd,
                    'infile': logslistfile,
                    'outfile': node.archivelogsfile,
                    'timeout': timeout,
                    'ok_codes': [0, 1]}
            run_items.append(tools.RunItem(target=node.exec_simple_cmd,
                                           args=args))
        tools.run_batch(run_items, maxthreads)
        for tfile in txtfl:
            try:
                os.remove(tfile)
            except:
                logging.error("archive_logs: can't delete file %s" % tfile)

    def get_conf_files(self, odir=fkey, timeout=15):
        lock = flock.FLock('/tmp/timmy-files.lock')
        if not lock.lock():
            logging.warning('Unable to obtain lock, skipping "files"-part')
            return ''
        run_items = []
        for n in [n for n in self.nodes.values() if not n.filtered_out]:
            run_items.append(tools.RunItem(target=n.get_files,
                                           args={'odir': odir}))
        tools.run_batch(run_items, 10)
        lock.unlock()


def main(argv=None):
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
