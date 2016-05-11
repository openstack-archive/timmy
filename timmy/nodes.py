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
from tools import w_list
from copy import deepcopy

ckey = 'cmds'
fkey = 'files'
lkey = 'logs'
varlogdir = '/var/log'


class Node(object):

    conf_appendable = ['logs', 'cmds', 'files']
    conf_keep_default = ['cmds', 'files']
    conf_once_prefix = 'once_'
    conf_match_prefix = 'by_'
    conf_default_key = '__default'
    conf_priority_section = conf_match_prefix + 'id'

    def __init__(self, id, mac, cluster, roles, os_platform,
                 online, status, ip, conf):
        self.id = id
        self.mac = mac
        self.cluster = cluster
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
        self.filtered_out = False
        self.apply_conf(conf)

    def __str__(self):
        if not self.filtered_out:
            my_id = self.id
        else:
            my_id = '#' + str(self.id)

        templ = '{0} {1.cluster} {1.ip} {1.mac} {1.os_platform} '
        templ += '{2} {1.online} {1.status}'
        return templ.format(my_id, self, ','.join(self.roles))

    def apply_conf(self, conf, clean=True):

        def apply(k, v, c_a, k_d, o, default=False):
            if k in c_a:
                if any([default,
                        k not in k_d and k not in o,
                        not hasattr(self, k)]):
                    setattr(self, k, deepcopy(w_list(v)))
                else:
                    getattr(self, k).extend(deepcopy(w_list(v)))
                if not default:
                    o[k] = True
            else:
                setattr(self, k, deepcopy(v))

        def r_apply(el, p, p_s, c_a, k_d, o, d, clean=False):
            # apply normal attributes
            for k in [k for k in el if k != p_s and not k.startswith(p)]:
                if el == conf and clean:
                    apply(k, el[k], c_a, k_d, o, default=True)
                else:
                    apply(k, el[k], c_a, k_d, o)
            # apply match attributes (by_xxx except by_id)
            for k in [k for k in el if k != p_s and k.startswith(p)]:
                attr_name = k[len(p):]
                if hasattr(self, attr_name):
                    attr = w_list(getattr(self, attr_name))
                    for v in attr:
                        if v in el[k]:
                            subconf = el[k][v]
                            if d in el:
                                d_conf = el[d]
                                for a in d_conf:
                                    apply(a, d_conf[a], c_a, k_d, o)
                            r_apply(subconf, p, p_s, c_a, k_d, o, d)
            # apply priority attributes (by_id)
            if p_s in el:
                if self.id in el[p_s]:
                    p_conf = el[p_s][self.id]
                    if d in el[p_s]:
                        d_conf = el[p_s][d]
                        for k in d_conf:
                            apply(k, d_conf[k], c_a, k_d, o)
                    for k in [k for k in p_conf if k != d]:
                        apply(k, p_conf[k], c_a, k_d, o, default=True)

        p = Node.conf_match_prefix
        p_s = Node.conf_priority_section
        c_a = Node.conf_appendable
        k_d = Node.conf_keep_default
        d = Node.conf_default_key
        overridden = {}
        if clean:
            '''clean appendable keep_default params to ensure no content
            duplication if this function gets called more than once'''
            for f in set(c_a).intersection(k_d):
                setattr(self, f, [])
        r_apply(conf, p, p_s, c_a, k_d, overridden, d, clean=clean)

    def checkos(self, filename):
        bname = str(os.path.basename(filename))
        logging.debug('check os: node: %s, filename %s' %
                      (self.id, filename))
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
                      (self.id, key, self.files[key]))

    def exec_cmd(self, odir='info', fake=False, ok_codes=[0, ]):
        sn = 'node-%s' % self.id
        cl = 'cluster-%s' % self.cluster
        logging.debug('%s/%s/%s/%s' % (odir, ckey, cl, sn))
        ddir = os.path.join(odir, ckey, cl, sn)
        tools.mdir(ddir)
        for c in self.cmds:
            for cmd in c:
                if not fake:
                    outs, errs, code = tools.ssh_node(ip=self.ip,
                                                      command=c[cmd],
                                                      ssh_opts=self.ssh_opts,
                                                      env_vars=self.env_vars,
                                                      timeout=self.timeout)
                    if code not in ok_codes:
                        logging.warning("node: %s, ip: %s, cmdfile: %s,"
                                        " code: %s, error message: %s" %
                                        (self.id, self.ip, c, code, errs))
                dfile = os.path.join(ddir, 'node-%s-%s-%s' %
                                     (self.id, self.ip, cmd))
                logging.info('outfile: %s' % dfile)
                self.mapcmds['cmd-'+cmd] = dfile
                if not fake:
                    try:
                        with open(dfile, 'w') as df:
                            df.write(outs)
                    except:
                        logging.error("exec_cmd: can't write to file %s" % dfile)
        for scr in self.scripts:
            f = os.path.join(self.rqdir, 'scripts', scr)
            logging.info('node:%s(%s), exec: %s' % (self.id, self.ip, f))
            if not fake:
                outs, errs, code = tools.ssh_node(ip=self.ip,
                                                  filename=f,
                                                  ssh_opts=self.ssh_opts,
                                                  env_vars=self.env_vars,
                                                  timeout=self.timeout)
                if code not in ok_codes:
                    logging.warning("node: %s, ip: %s, cmdfile: %s,"
                                    " code: %s, error message: %s" %
                                    (self.id, self.ip, f, code, errs))
            dfile = os.path.join(ddir, 'node-%s-%s-%s' %
                                 (self.id, self.ip, os.path.basename(f)))
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
        logging.info('node:%s(%s), exec: %s' % (self.id, self.ip, cmd))
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
                                (self.id, self.ip, cmd, code, errs))

    def get_files(self, odir='info', timeout=15):
        logging.info('node:%s(%s), filelist: %s' %
                     (self.id, self.ip, fkey))
        sn = 'node-%s' % self.id
        cl = 'cluster-%s' % self.cluster
        ddir = os.path.join(odir, fkey, cl, sn)
        tools.mdir(ddir)
        data = ''
        for f in self.files:
            fname = os.path.join(self.rqdir, 'files', f)
            try:
                with open(fname, 'r') as df:
                    for line in df:
                        if not line.isspace() and line[0] != '#':
                            data += line
            except:
                logging.error('could not read file: %s' % fname)
        logging.debug('node: %s, data:\n%s' % (self.id, data))
        outs, errs, code = tools.get_files_rsync(ip=self.ip,
                                                 data=data,
                                                 ssh_opts=self.ssh_opts,
                                                 dpath=ddir,
                                                 timeout=self.timeout)
        if code != 0:
            logging.warning("get_files: node: %s, ip: %s, "
                            "code: %s, error message: %s" %
                            (self.id, self.ip, code, errs))

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
                         (self.id, cmd))
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              command=cmd,
                                              ssh_opts=self.ssh_opts,
                                              env_vars='',
                                              timeout=timeout)
            if code == 124:
                logging.error("node: %s, ip: %s, command: %s, "
                              "timeout code: %s, error message: %s" %
                              (self.id, self.ip, cmd, code, errs))
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


class NodeManager(object):
    """Class nodes """

    def __init__(self, conf, extended=False, filename=None):
        self.conf = conf
        self.rqdir = conf['rqdir'].rstrip('/')
        self.import_rq()
        if (not os.path.exists(self.rqdir)):
            logging.error("directory %s doesn't exist" % (self.rqdir))
            sys.exit(1)
        if (conf['fuelip'] is None) or (conf['fuelip'] == ""):
            logging.error('looks like fuelip is not set(%s)' % conf['fuelip'])
            sys.exit(7)
        self.fuelip = conf['fuelip']
        logging.info('extended: %s' % extended)
        if filename is not None:
            try:
                with open(filename, 'r') as json_data:
                    self.njdata = json.load(json_data)
            except:
                logging.error("Can't load data from file %s" % filename)
                sys.exit(6)
        else:
            self.njdata = json.loads(self.get_nodes())
        self.nodes_init()
        self.get_version()
        self.nodes_get_release()
        self.nodes_reapply_conf()
        self.conf_assign_once()
        if extended:
            '''TO-DO: load smth like extended.yaml
            do additional apply_conf(clean=False) with this yaml.
            Move some stuff from rq.yaml to extended.yaml'''
            pass

    def __str__(self):
        s = "#node-id, cluster, admin-ip, mac, os, roles, online, status\n"
        return s+'\n'.join([str(n) for n in self.sorted_nodes()])

    def sorted_nodes(self):
        s = [n for n in sorted(self.nodes.values(), key=lambda x: x.id)]
        return s

    def import_rq(self):

        def sub_is_match(el, d, p, once_p):
            if type(el) is not dict:
                return False
            checks = []
            for i in el:
                checks.append(any([i == d,
                                  i.startswith(p),
                                  i.startswith(once_p)]))
            return all(checks)

        def r_sub(attr, el, k, d, p, once_p, dst):
            match_sect = False
            if type(k) is str and (k.startswith(p) or k.startswith(once_p)):
                match_sect = True
            if k not in dst and k != attr:
                dst[k] = {}
            if d in el[k]:
                if k == attr:
                    dst[k] = el[k][d]
                elif k.startswith(p) or k.startswith(once_p):
                    dst[k][d] = {attr: el[k][d]}
                else:
                    dst[k][attr] = el[k][d]
            if k == attr:
                subks = [subk for subk in el[k] if subk != d]
                for subk in subks:
                    r_sub(attr, el[k], subk, d, p, once_p, dst)
            elif match_sect or sub_is_match(el[k], d, p, once_p):
                subks = [subk for subk in el[k] if subk != d]
                for subk in subks:
                    if el[k][subk] is not None:
                        if subk not in dst[k]:
                            dst[k][subk] = {}
                        r_sub(attr, el[k], subk, d, p, once_p, dst[k])
            else:
                dst[k][attr] = el[k]

        dst = self.conf
        src = tools.load_yaml_file(self.conf['rqfile'])
        p = Node.conf_match_prefix
        once_p = Node.conf_once_prefix + p
        d = Node.conf_default_key
        for attr in src:
            r_sub(attr, src, attr, d, p, once_p, dst)

    def get_nodes(self):
        fuel_node_cmd = 'fuel node list --json'
        fuelnode = Node(id=0,
                        cluster=0,
                        mac='n/a',
                        os_platform='centos',
                        roles=['fuel'],
                        status='ready',
                        online=True,
                        ip=self.fuelip,
                        conf=self.conf)
        self.nodes = {self.fuelip: fuelnode}
        nodes_json, err, code = tools.ssh_node(ip=self.fuelip,
                                               command=fuel_node_cmd,
                                               ssh_opts=fuelnode.ssh_opts,
                                               timeout=fuelnode.timeout)
        if code != 0:
            logging.error("Can't get fuel node list %s" % err)
            sys.exit(4)
        return nodes_json

    def nodes_init(self):
        for node_data in self.njdata:
            node_roles = node_data.get('roles')
            if not node_roles:
                roles = ['None']
            elif isinstance(node_roles, list):
                roles = node_roles
            else:
                roles = str(node_roles).split(', ')
            keys = "mac os_platform status online ip".split()
            params = {'id': int(node_data['id']),
                      'cluster': int(node_data['cluster']),
                      'roles': roles,
                      'conf': self.conf}
            for key in keys:
                params[key] = node_data[key]
            node = Node(**params)
            if self.filter(node, self.conf['hard_filter']):
                if not self.filter(node, self.conf['soft_filter']):
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

    def nodes_get_release(self):
        cmd = "awk -F ':' '/fuel_version/ {print \$2}' /etc/astute.yaml"
        for node in self.nodes.values():
            if node.id == 0:
                # skip master
                node.release = self.version
            if (node.id != 0) and (node.status == 'ready'):
                release, err, code = tools.ssh_node(ip=node.ip,
                                                    command=cmd,
                                                    ssh_opts=node.ssh_opts,
                                                    timeout=node.timeout)
                if code != 0:
                    logging.warning("get_release: node: %s: %s" %
                                    (node.id, "Can't get node release"))
                    node.release = None
                    continue
                else:
                    node.release = release.strip('\n "\'')
                logging.info("get_release: node: %s, release: %s" %
                             (node.id, node.release))

    def conf_assign_once(self):
        once = Node.conf_once_prefix
        p = Node.conf_match_prefix
        once_p = once + p
        for k in [k for k in self.conf if k.startswith(once)]:
            attr_name = k[len(once_p):]
            assigned = dict((k, None) for k in self.conf[k])
            for ak in assigned:
                for node in self.nodes.values():
                    if hasattr(node, attr_name) and not assigned[ak]:
                        attr = w_list(getattr(node, attr_name))
                        for v in attr:
                            if v == ak:
                                once_conf = self.conf[k][ak]
                                node.apply_conf(once_conf, clean=False)
                                assigned[ak] = node.id
                                break
                    if assigned[ak]:
                        break

    def nodes_reapply_conf(self):
        for node in self.nodes.values():
            node.apply_conf(self.conf)

    def filter(self, node, node_filter):
        f = node_filter
        if node.id == 0 and f == self.conf['hard_filter']:
            return True
        else:
            fnames = [k for k in f if hasattr(node, k) and f[k]]
            checks = []
            for fn in fnames:
                node_v = w_list(getattr(node, fn))
                filter_v = w_list(f[fn])
                checks.append(not set(node_v).isdisjoint(filter_v))
            return all(checks)

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
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            self.nodes[key] = result[key]
        lock.unlock()

    def calculate_log_size(self, timeout=15, maxthreads=100):
        total_size = 0
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out:
                run_items.append(tools.RunItem(target=node.logs_populate,
                                               args={'timeout': timeout},
                                               key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            self.nodes[key] = result[key]
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
        tools.mdir(self.conf['archives'])
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
                             "to collect") % node.id)
                continue
            node.archivelogsfile = os.path.join(outdir,
                                                'logs-node-%s.tar.gz' %
                                                str(node.id))
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
