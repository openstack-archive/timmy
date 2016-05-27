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

import json
import os
import shutil
import logging
import sys
import re
from datetime import datetime
import tools
from tools import w_list, run_with_lock
from copy import deepcopy


class Node(object):
    ckey = 'cmds'
    skey = 'scripts'
    fkey = 'files'
    flkey = 'filelists'
    lkey = 'logs'
    pkey = 'put'
    conf_actionable = [lkey, ckey, skey, fkey, flkey, pkey]
    conf_appendable = [lkey, ckey, skey, fkey, flkey, pkey]
    conf_archive_general = [ckey, skey, fkey, flkey]
    conf_keep_default = [skey, ckey, fkey, flkey]
    conf_once_prefix = 'once_'
    conf_match_prefix = 'by_'
    conf_default_key = '__default'
    conf_priority_section = conf_match_prefix + 'id'
    print_template = '{0:<14} {1:<3} {2:<16} {3:<18} {4:<10} {5:<30}'
    print_template += ' {6:<6} {7}'

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
        self.release = None
        self.files = []
        self.filelists = []
        self.cmds = []
        self.scripts = []
        # put elements must be tuples - (src, dst)
        self.put = []
        self.data = {}
        self.logsize = 0
        self.mapcmds = {}
        self.mapscr = {}
        self.filtered_out = False
        self.outputs_timestamp = False
        self.outputs_timestamp_dir = None
        self.apply_conf(conf)

    def __str__(self):
        if not self.filtered_out:
            my_id = self.id
        else:
            my_id = str(self.id) + ' [skipped]'
        pt = self.print_template
        return pt.format(my_id, self.cluster, self.ip, self.mac,
                         self.os_platform, ','.join(self.roles),
                         str(self.online), self.status)

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

    def get_release(self):
        if self.id == 0:
            cmd = ("awk -F ':' '/release/ {print $2}' "
                   "/etc/nailgun/version.yaml")
        else:
            cmd = ("awk -F ':' '/fuel_version/ {print $2}' "
                   "/etc/astute.yaml")
        release, err, code = tools.ssh_node(ip=self.ip,
                                            command=cmd,
                                            ssh_opts=self.ssh_opts,
                                            timeout=self.timeout,
                                            prefix=self.prefix)
        if code != 0:
            logging.warning('get_release: node: %s: could not determine'
                            ' MOS release' % self.id)
        else:
            self.release = release.strip('\n "\'')
        logging.info('get_release: node: %s, MOS release: %s' %
                     (self.id, self.release))
        return self

    def exec_cmd(self, fake=False, ok_codes=None):
        sn = 'node-%s' % self.id
        cl = 'cluster-%s' % self.cluster
        logging.debug('%s/%s/%s/%s' % (self.outdir, Node.ckey, cl, sn))
        ddir = os.path.join(self.outdir, Node.ckey, cl, sn)
        if self.cmds:
            tools.mdir(ddir)
        self.cmds = sorted(self.cmds)
        for c in self.cmds:
            for cmd in c:
                dfile = os.path.join(ddir, 'node-%s-%s-%s' %
                                     (self.id, self.ip, cmd))
                if self.outputs_timestamp:
                        dfile += self.outputs_timestamp_str
                logging.info('outfile: %s' % dfile)
                self.mapcmds[cmd] = dfile
                if not fake:
                    outs, errs, code = tools.ssh_node(ip=self.ip,
                                                      command=c[cmd],
                                                      ssh_opts=self.ssh_opts,
                                                      env_vars=self.env_vars,
                                                      timeout=self.timeout,
                                                      prefix=self.prefix)
                    self.check_code(code, 'exec_cmd', c[cmd], ok_codes)
                    try:
                        with open(dfile, 'w') as df:
                            df.write(outs.encode('utf-8'))
                    except:
                        logging.error("exec_cmd: can't write to file %s" %
                                      dfile)
        if self.scripts:
            tools.mdir(ddir)
        self.scripts = sorted(self.scripts)
        for scr in self.scripts:
            f = os.path.join(self.rqdir, Node.skey, scr)
            logging.info('node:%s(%s), exec: %s' % (self.id, self.ip, f))
            dfile = os.path.join(ddir, 'node-%s-%s-%s' %
                                 (self.id, self.ip, os.path.basename(f)))
            if self.outputs_timestamp:
                    dfile += self.outputs_timestamp_str
            logging.info('outfile: %s' % dfile)
            self.mapscr[scr] = dfile
            if not fake:
                outs, errs, code = tools.ssh_node(ip=self.ip,
                                                  filename=f,
                                                  ssh_opts=self.ssh_opts,
                                                  env_vars=self.env_vars,
                                                  timeout=self.timeout,
                                                  prefix=self.prefix)
                self.check_code(code, 'exec_cmd', 'script %s' % f, ok_codes)
                try:
                    with open(dfile, 'w') as df:
                        df.write(outs.encode('utf-8'))
                except:
                    logging.error("exec_cmd: can't write to file %s" % dfile)
        return self

    def exec_simple_cmd(self, cmd, timeout=15, infile=None, outfile=None,
                        fake=False, ok_codes=None, input=None):
        logging.info('node:%s(%s), exec: %s' % (self.id, self.ip, cmd))
        if not fake:
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              command=cmd,
                                              ssh_opts=self.ssh_opts,
                                              env_vars=self.env_vars,
                                              timeout=timeout,
                                              outputfile=outfile,
                                              ok_codes=ok_codes,
                                              input=input,
                                              prefix=self.prefix)
            self.check_code(code, 'exec_simple_cmd', cmd, ok_codes)

    def get_files(self, timeout=15):
        logging.info('get_files: node: %s, IP: %s' % (self.id, self.ip))
        sn = 'node-%s' % self.id
        cl = 'cluster-%s' % self.cluster
        if self.files or self.filelists:
            ddir = os.path.join(self.outdir, Node.fkey, cl, sn)
            tools.mdir(ddir)
        if self.shell_mode:
            for f in self.files:
                outs, errs, code = tools.get_file_scp(ip=self.ip,
                                                      file=f,
                                                      ddir=ddir,
                                                      recursive=True)
                self.check_code(code, 'get_files', 'tools.get_file_scp')
        else:
            data = ''
            for f in self.filelists:
                fname = os.path.join(self.rqdir, Node.flkey, f)
                try:
                    with open(fname, 'r') as df:
                        for line in df:
                            if not line.isspace() and line[0] != '#':
                                data += line
                except:
                    logging.error('could not read file: %s' % fname)
            data += '\n'.join(self.files)
            logging.debug('node: %s, data:\n%s' % (self.id, data))
            if data:
                o, e, c = tools.get_files_rsync(ip=self.ip,
                                                data=data,
                                                ssh_opts=self.ssh_opts,
                                                dpath=ddir,
                                                timeout=self.timeout)
                self.check_code(c, 'get_files', 'tools.get_files_rsync')

    def put_files(self):
        logging.info('put_files: node: %s, IP: %s' % (self.id, self.ip))
        for f in self.put:
            outs, errs, code = tools.put_file_scp(ip=self.ip,
                                                  file=f[0],
                                                  dest=f[1],
                                                  recursive=True)

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
                                              timeout=timeout,
                                              prefix=self.prefix)
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

    def check_code(self, code, func_name, cmd, ok_codes=None):
        if code:
            if not ok_codes or code not in ok_codes:
                logging.warning("%s: got bad exit code %s,"
                                " node: %s, ip: %s, cmd: %s" %
                                (func_name, code, self.id, self.ip, cmd))

    def print_results(self, result_map):
        # result_map should be either mapcmds or mapscr
        for cmd in sorted(result_map):
            with open(result_map[cmd], 'r') as f:
                for line in f.readlines():
                    print('node-%s:\t%s' %
                          (self.id, line.rstrip('\n')))


class NodeManager(object):
    """Class nodes """

    def __init__(self, conf, extended=False, nodes_json=None):
        self.conf = conf
        if conf['outputs_timestamp'] or conf['dir_timestamp']:
            timestamp_str = datetime.now().strftime('_%F_%H-%M-%S')
            if conf['outputs_timestamp']:
                conf['outputs_timestamp_str'] = timestamp_str
            if conf['dir_timestamp']:
                conf['outdir'] += timestamp_str
                conf['archive_dir'] += timestamp_str
        if conf['clean']:
            shutil.rmtree(conf['outdir'], ignore_errors=True)
            shutil.rmtree(conf['archive_dir'], ignore_errors=True)
        if not conf['shell_mode']:
            self.rqdir = conf['rqdir']
            if (not os.path.exists(self.rqdir)):
                logging.error(('NodeManager __init__: directory %s does not'
                               'exist') % self.rqdir)
                sys.exit(1)
            if self.conf['rqfile']:
                self.import_rq()
        self.nodes = {}
        self.fuel_init()
        if nodes_json:
            try:
                with open(nodes_json, 'r') as json_data:
                    self.nodes_json = json.load(json_data)
            except:
                logging.error(('NodeManager __init__: cannot load data from'
                               ' file "%s"') % nodes_json)
                sys.exit(6)
        else:
            self.nodes_json = json.loads(self.get_nodes_json())
        self.nodes_init()
        # apply soft-filter on all nodes
        for node in self.nodes.values():
            if not self.filter(node, self.conf['soft_filter']):
                node.filtered_out = True
        if not conf['shell_mode']:
            self.nodes_get_release()
            self.nodes_reapply_conf()
            self.conf_assign_once()
            if extended:
                logging.info('NodeManager __init__: extended mode enabled')
                '''TO-DO: load smth like extended.yaml
                do additional apply_conf(clean=False) with this yaml.
                Move some stuff from rq.yaml to extended.yaml'''
                pass

    def __str__(self):
        pt = Node.print_template
        header = pt.format('node-id', 'env', 'ip/hostname', 'mac', 'os',
                           'roles', 'online', 'status') + '\n'
        nodestrings = []
        # f3flight: I only did this to not print Fuel when it is hard-filtered
        for n in self.sorted_nodes():
            if self.filter(n, self.conf['hard_filter']):
                nodestrings.append(str(n))
        return header + '\n'.join(nodestrings)

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

    def fuel_init(self):
        if not self.conf['fuelip']:
            logging.error('NodeManager fuel_init: fuelip not set')
            sys.exit(7)
        fuelnode = Node(id=0,
                        cluster=0,
                        mac='n/a',
                        os_platform='centos',
                        roles=['fuel'],
                        status='ready',
                        online=True,
                        ip=self.conf['fuelip'],
                        conf=self.conf)
        # soft-skip Fuel if it is hard-filtered
        if not self.filter(fuelnode, self.conf['hard_filter']):
            fuelnode.filtered_out = True
        self.nodes[self.conf['fuelip']] = fuelnode

    def get_nodes_json(self):
        fuelnode = self.nodes[self.conf['fuelip']]
        fuel_node_cmd = 'fuel node list --json'
        nodes_json, err, code = tools.ssh_node(ip=fuelnode.ip,
                                               command=fuel_node_cmd,
                                               ssh_opts=fuelnode.ssh_opts,
                                               timeout=fuelnode.timeout,
                                               prefix=fuelnode.prefix)
        if code != 0:
            logging.error(('NodeManager get_nodes: cannot get '
                           'fuel node list: %s') % err)
            sys.exit(4)
        return nodes_json

    def nodes_init(self):
        for node_data in self.nodes_json:
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
                self.nodes[node.ip] = node

    def nodes_get_release(self):
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out:
                run_items.append(tools.RunItem(target=node.get_release,
                                               key=key))
        result = tools.run_batch(run_items, 100, dict_result=True)
        for key in result:
            self.nodes[key] = result[key]

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
        # soft-skip Fuel node if shell mode is enabled
        if node.id == 0 and self.conf['shell_mode']:
            return False
        else:
            fnames = [k for k in f if hasattr(node, k) and f[k]]
            checks = []
            for fn in fnames:
                node_v = w_list(getattr(node, fn))
                filter_v = w_list(f[fn])
                checks.append(not set(node_v).isdisjoint(filter_v))
            return all(checks)

    @run_with_lock
    def run_commands(self, timeout=15, fake=False, maxthreads=100):
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out:
                run_items.append(tools.RunItem(target=node.exec_cmd,
                                               args={'fake': fake},
                                               key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            self.nodes[key] = result[key]

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

    def is_enough_space(self, coefficient=1.2):
        tools.mdir(self.conf['outdir'])
        outs, errs, code = tools.free_space(self.conf['outdir'], timeout=1)
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

    @run_with_lock
    def create_archive_general(self, timeout):
        outfile = os.path.join(self.conf['archive_dir'],
                               self.conf['archive_name'])
        cmd = "tar zcf '%s' -C %s %s" % (outfile, self.conf['outdir'], ".")
        tools.mdir(self.conf['archive_dir'])
        logging.debug("create_archive_general: cmd: %s" % cmd)
        outs, errs, code = tools.launch_cmd(cmd, timeout)
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

    @run_with_lock
    def get_logs(self, timeout, fake=False, maxthreads=10, speed=100):
        if fake:
            logging.info('get_logs: fake = True, skipping' % fake)
            return
        txtfl = []
        speed = self.find_adm_interface_speed(speed)
        speed = int(speed * 0.9 / min(maxthreads, len(self.nodes)))
        pythonslowpipe = tools.slowpipe % speed
        run_items = []
        for node in [n for n in self.nodes.values() if not n.filtered_out]:
            if not node.logs_dict():
                logging.info(("get_logs: node %s - no logs "
                             "to collect") % node.id)
                continue
            node.archivelogsfile = os.path.join(self.conf['archive_dir'],
                                                'logs-node-%s.tar.gz' %
                                                str(node.id))
            tools.mdir(self.conf['outdir'])
            input = ''
            for fn in node.logs_dict():
                input += '%s\0' % fn.lstrip(os.path.abspath(os.sep))
            cmd = ("tar --gzip -C %s --create --warning=no-file-changed "
                   " --file - --null --files-from -" % os.path.abspath(os.sep))
            if not (node.ip == 'localhost' or node.ip.startswith('127.')):
                cmd = ' '.join([cmd, "| python -c '%s'; exit ${PIPESTATUS}" %
                                pythonslowpipe])
            args = {'cmd': cmd,
                    'timeout': timeout,
                    'outfile': node.archivelogsfile,
                    'input': input,
                    'ok_codes': [0, 1]}
            run_items.append(tools.RunItem(target=node.exec_simple_cmd,
                                           args=args))
        tools.run_batch(run_items, maxthreads)
        for tfile in txtfl:
            try:
                os.remove(tfile)
            except:
                logging.error("get_logs: can't delete file %s" % tfile)

    @run_with_lock
    def get_files(self, timeout=15):
        run_items = []
        for n in [n for n in self.nodes.values() if not n.filtered_out]:
            run_items.append(tools.RunItem(target=n.get_files))
        tools.run_batch(run_items, 10)

    @run_with_lock
    def put_files(self):
        run_items = []
        for n in [n for n in self.nodes.values() if not n.filtered_out]:
            run_items.append(tools.RunItem(target=n.put_files))
        tools.run_batch(run_items, 10)

    def has(self, *keys):
        nodes = {}
        for k in keys:
            for n in self.nodes.values():
                if hasattr(n, k):
                    attr = getattr(n, k)
                    if attr:
                        if k not in nodes:
                            nodes[k] = []
                        nodes[k].append(n)
        return nodes


def main(argv=None):
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
