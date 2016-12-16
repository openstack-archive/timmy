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

from copy import deepcopy
from datetime import datetime, date, timedelta
from timmy import conf
from timmy.env import project_name, version
from timmy import tools
from tools import w_list, run_with_lock
import logging
import os
import re
import shutil
import sys


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
    header = ['node-id', 'env', 'ip', 'mac', 'os', 'roles', 'online',
              'accessible', 'status', 'name', 'release', 'fqdn']

    def __init__(self, ip, conf, id=None, name=None, fqdn=None, mac=None,
                 cluster=None, roles=None, os_platform=None,
                 online=True, status="ready", logger=None, network_data=None):
        self.logger = logger or logging.getLogger(project_name)
        self.id = int(id) if id is not None else None
        self.mac = mac
        self.cluster = int(cluster) if cluster is not None else None
        if type(roles) is list:
            self.roles = roles
        else:
            self.roles = roles.split(', ') if roles else []
        self.os_platform = os_platform
        self.online = online
        self.status = status
        if ip is None:
            self.logger.critical('Node: ip address must be defined')
            sys.exit(111)
        self.ip = ip
        self.network_data = network_data
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
        self.name = name
        self.fqdn = fqdn
        self.accessible = True
        self.skipped = False
        self.outputs_timestamp = False
        self.outputs_timestamp_dir = None
        self.apply_conf(conf)
        self.cluster_repr = "cluster-%s" % str(cluster)
        if self.id is not None:
            self.repr = "node-%s-%s" % (self.id, self.ip)
        else:
            self.repr = "node-%s" % self.ip

    def __str__(self):
        fields = self.print_table()
        return self.pt.format(*fields)

    def print_table(self):
        if not self.skipped:
            my_id = self.id
        else:
            my_id = '%s [skipped]' % self.id
        return [str(my_id), str(self.cluster), str(self.ip), str(self.mac),
                self.os_platform, ','.join(self.roles),
                str(self.online), str(self.accessible), str(self.status),
                str(self.name), str(self.release), str(self.fqdn)]

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

        def r_apply(el, p, c_a, k_d, o, d, clean=False):
            # apply normal attributes
            for k in [k for k in el if not k.startswith(p)]:
                if el == conf and clean:
                    apply(k, el[k], c_a, k_d, o, default=True)
                else:
                    apply(k, el[k], c_a, k_d, o)
            # apply match attributes
            for k in [k for k in el if k.startswith(p)]:
                attr_name = k[len(p):]
                if hasattr(self, attr_name):
                    attr = w_list(getattr(self, attr_name))
                    matching_keys = []
                    # negative matching ("no_")
                    for nk in [nk for nk in el[k] if nk.startswith('no_')]:
                        key = nk[4:]
                        if key not in attr:
                            matching_keys.append(nk)
                    # positive matching
                    for v in attr:
                        if v in el[k]:
                            matching_keys.append(v)
                    # apply matching keys
                    for mk in matching_keys:
                        subconf = el[k][mk]
                        if d in el:
                            d_conf = el[d]
                            for a in d_conf:
                                apply(a, d_conf[a], c_a, k_d, o)
                        r_apply(subconf, p, c_a, k_d, o, d)

        p = Node.conf_match_prefix
        c_a = Node.conf_appendable
        k_d = Node.conf_keep_default
        d = Node.conf_default_key
        overridden = {}
        if clean:
            '''clean appendable keep_default params to ensure no content
            duplication if this function gets called more than once'''
            for f in set(c_a).intersection(k_d):
                setattr(self, f, [])
        r_apply(conf, p, c_a, k_d, overridden, d, clean=clean)

    def get_os(self):
        self.logger.debug('%s: os_platform not defined, trying to determine' %
                          self.repr)
        cmd = 'which lsb_release'
        outs, errs, code = tools.ssh_node(ip=self.ip,
                                          command=cmd,
                                          ssh_opts=self.ssh_opts,
                                          env_vars=self.env_vars,
                                          timeout=self.timeout,
                                          prefix=self.prefix)
        return 'centos' if code else 'ubuntu'

    def check_access(self):
        self.logger.debug('%s: verifyng node access' %
                          self.repr)
        cmd = 'true'
        outs, errs, code = tools.ssh_node(ip=self.ip,
                                          command=cmd,
                                          ssh_opts=self.ssh_opts,
                                          env_vars=self.env_vars,
                                          timeout=self.timeout,
                                          prefix=self.prefix)
        if code == 0:
            return True
        else:
            self.logger.info('%s: not accessible' % self.repr)
            return False

    @property
    def scripts_ddir(self):
        return os.path.join(self.outdir, Node.skey, self.cluster_repr,
                            self.repr)

    def generate_mapscr(self):
        mapscr = {}
        for scr in self.scripts:
            if type(scr) is dict:
                env_vars = scr.values()[0]
                scr = scr.keys()[0]
            else:
                env_vars = self.env_vars
            if os.path.sep in scr:
                script_path = scr
            else:
                script_path = os.path.join(self.rqdir, Node.skey, scr)
            self.logger.debug('%s, exec: %s' % (self.repr, script_path))
            output_path = os.path.join(self.scripts_ddir,
                                       os.path.basename(script_path))
            if self.outputs_timestamp:
                output_path += self.outputs_timestamp_str
            self.logger.debug('outfile: %s' % output_path)
            mapscr[scr] = {'env_vars': env_vars,
                           'script_path': script_path,
                           'output_path': output_path}
        self.mapscr = mapscr

    def exec_cmd(self, fake=False, ok_codes=None):
        cl = self.cluster_repr
        self.logger.debug('%s/%s/%s/%s' %
                          (self.outdir, Node.ckey, cl, self.repr))
        if self.cmds:
            ddir = os.path.join(self.outdir, Node.ckey, cl, self.repr)
            tools.mdir(ddir)
            self.cmds = sorted(self.cmds)
        mapcmds = {}
        for c in self.cmds:
            for cmd in c:
                dfile = os.path.join(ddir, cmd)
                if self.outputs_timestamp:
                        dfile += self.outputs_timestamp_str
                self.logger.info('outfile: %s' % dfile)
                mapcmds[cmd] = dfile
                if not fake:
                    bash_cmd = "bash -c '%s'" % c[cmd]
                    outs, errs, code = tools.ssh_node(ip=self.ip,
                                                      command=bash_cmd,
                                                      ssh_opts=self.ssh_opts,
                                                      env_vars=self.env_vars,
                                                      timeout=self.timeout,
                                                      prefix=self.prefix)
                    self.check_code(code, 'exec_cmd', c[cmd], errs, ok_codes)
                    try:
                        with open(dfile, 'w') as df:
                            df.write(outs.encode('utf-8'))
                    except:
                        self.logger.error("can't write to file %s" %
                                          dfile)
        if self.scripts:
            self.generate_mapscr()
            tools.mdir(self.scripts_ddir)
        for scr, param in self.mapscr.items():
            if fake:
                continue
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              filename=param['script_path'],
                                              ssh_opts=self.ssh_opts,
                                              env_vars=param['env_vars'],
                                              timeout=self.timeout,
                                              prefix=self.prefix)
            self.check_code(code, 'exec_cmd',
                            'script %s' % param['script_path'], errs, ok_codes)
            try:
                with open(param['output_path'], 'w') as df:
                    df.write(outs.encode('utf-8'))
            except:
                self.logger.error("can't write to file %s"
                                  % param['output_path'])
        return mapcmds, self.mapscr

    def exec_simple_cmd(self, cmd, timeout=15, infile=None, outfile=None,
                        fake=False, ok_codes=None, input=None, decode=True):
        self.logger.info('%s, exec: %s' % (self.repr, cmd))
        if not fake:
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              command=cmd,
                                              ssh_opts=self.ssh_opts,
                                              env_vars=self.env_vars,
                                              timeout=timeout,
                                              outputfile=outfile,
                                              ok_codes=ok_codes,
                                              decode=decode,
                                              input=input,
                                              prefix=self.prefix)
            self.check_code(code, 'exec_simple_cmd', cmd, errs, ok_codes)

    def exec_pair(self, phase, server_node=None, fake=False):
        sn = server_node
        cl = self.cluster_repr
        if sn:
            self.logger.debug('%s: phase %s: server %s' % (self.repr, phase,
                                                           sn.repr))
        else:
            self.logger.debug('%s: phase %s' % (self.repr, phase))
        nond_msg = ('%s: network specified but network_data not set for %s')
        nonet_msg = ('%s: network %s not found in network_data of %s')
        nosrv_msg = ('%s: server_node not provided')
        noip_msg = ('%s: %s has no IP in network %s')
        for i in self.scripts_all_pairs:
            if phase not in i:
                self.logger.warning('phase %s not defined in config' % phase)
                return self.scripts_all_pairs
            if phase.startswith('client'):
                if not sn:
                    self.logger.warning(nosrv_msg % self.repr)
                    return self.scripts_all_pairs
                if 'network' in i:
                    if not sn.network_data:
                        self.logger.warning(nond_msg % (self.repr, sn.repr))
                        return self.scripts_all_pairs
                    nd = sn.network_data
                    net_dict = dict((v['name'], v) for v in nd)
                    if i['network'] not in net_dict:
                        self.logger.warning(nonet_msg % (self.repr, sn.repr))
                        return self.scripts_all_pairs
                    if 'ip' not in net_dict[i['network']]:
                        self.logger.warning(noip_msg % (self.repr, sn.repr,
                                                        i['network']))
                        return self.scripts_all_pairs
                    ip = net_dict[i['network']]['ip']
                    if '/' in ip:
                        server_ip = ip.split('/')[0]
                    else:
                        server_ip = ip
                else:
                    server_ip = sn.ip
            phase_val = i[phase]
            ddir = os.path.join(self.outdir, 'scripts_all_pairs', cl, phase,
                                self.repr)
            tools.mdir(ddir)
            if type(phase_val) is dict:
                env_vars = [phase_val.values()[0]]
                phase_val = phase_val.keys()[0]
            else:
                env_vars = self.env_vars
            if os.path.sep in phase_val:
                f = phase_val
            else:
                f = os.path.join(self.rqdir, Node.skey, phase_val)
            dfile = os.path.join(ddir, os.path.basename(f))
            if phase.startswith('client'):
                env_vars.append('SERVER_IP=%s' % server_ip)
                dname = os.path.basename(f) + '-%s' % server_ip
                dfile = os.path.join(ddir, dname)
            elif phase == 'server_stop' and 'server_output' in i:
                env_vars.append('SERVER_OUTPUT=%s' % i['server_output'])
            if fake:
                return self.scripts_all_pairs
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              filename=f,
                                              ssh_opts=self.ssh_opts,
                                              env_vars=env_vars,
                                              timeout=self.timeout,
                                              prefix=self.prefix)
            self.check_code(code, 'exec_pair, phase:%s' % phase, f, errs)
            if phase == 'server_start' and code == 0:
                i['server_output'] = outs.strip()
            open(dfile, 'a+').write(outs)
        return self.scripts_all_pairs

    def get_files(self, timeout=15):
        self.logger.info('%s: getting files' % self.repr)
        cl = self.cluster_repr
        if self.files or self.filelists:
            ddir = os.path.join(self.outdir, Node.fkey, cl, self.repr)
            tools.mdir(ddir)
        data = ''
        for f in self.filelists:
            if os.path.sep in f:
                fname = f
            else:
                fname = os.path.join(self.rqdir, Node.flkey, f)
            try:
                with open(fname, 'r') as df:
                    for line in df:
                        if not line.isspace() and line[0] != '#':
                            data += line
            except:
                self.logger.error('could not read file: %s' % fname)
        self.logger.debug('%s: data:\n%s' % (self.repr, data))
        if data:
            o, e, c = tools.get_files_rsync(ip=self.ip,
                                            data=data,
                                            ssh_opts=self.ssh_opts,
                                            rsync_opts=self.rsync_opts,
                                            dpath=ddir,
                                            timeout=self.timeout)
            self.check_code(c, 'get_files', 'tools.get_files_rsync', e)
        for f in self.files:
            outs, errs, code = tools.get_file_scp(ip=self.ip,
                                                  file=f,
                                                  ssh_opts=self.ssh_opts,
                                                  ddir=ddir,
                                                  recursive=True)
            self.check_code(code, 'get_files', 'tools.get_file_scp', errs)

    def put_files(self):
        self.logger.info('%s: putting files' % self.repr)
        for f in self.put:
            outs, errs, code = tools.put_file_scp(ip=self.ip,
                                                  file=f[0],
                                                  dest=f[1],
                                                  ssh_opts=self.ssh_opts,
                                                  recursive=True)
            self.check_code(code, 'put_files', 'tools.put_file_scp', errs)

    def log_item_manipulate(self, item):
        pass

    def logs_populate(self, timeout=5):

        def filter_by_re(item, string):
            return (('include' not in item or not item['include'] or
                     any([re.search(i, string) for i in item['include']])) and
                    ('exclude' not in item or not item['exclude'] or not
                     any([re.search(e, string) for e in item['exclude']])))

        for item in self.logs:
            self.log_item_manipulate(item)
            start_str = None
            if 'start' in item or hasattr(self, 'logs_days'):
                if hasattr(self, 'logs_days') and 'start' not in item:
                    start = self.logs_days
                else:
                    start = item['start']
                if any([type(start) is str and re.match(r'-?\d+', start),
                        type(start) is int]):
                    days = abs(int(str(start)))
                    start_str = str(date.today() - timedelta(days=days))
                else:
                    for format in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S']:
                        try:
                            if datetime.strptime(start, format):
                                start_str = start
                                break
                        except ValueError:
                            pass
                    if not start_str:
                        self.logger.warning(('incorrect value of "start"'
                                             ' parameter in "logs": "%s" -'
                                             ' ignoring...')
                                            % start)
            if start_str:
                start_param = ' -newermt "$(date -d \'%s\')"' % start_str
            else:
                start_param = ''
            cmd = ("find '%s' -type f%s -exec du -b {} +" % (item['path'],
                                                             start_param))
            self.logger.info('%s: logs du-cmd: %s' %
                             (self.repr, cmd))
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              command=cmd,
                                              ssh_opts=self.ssh_opts,
                                              env_vars=self.env_vars,
                                              timeout=timeout,
                                              prefix=self.prefix)
            if code == 124:
                self.logger.error("%s: command: %s, "
                                  "timeout code: %s, error message: %s" %
                                  (self.repr, cmd, code, errs))
                break
            if len(outs):
                item['files'] = {}
                for line in outs.split('\n'):
                    if '\t' in line:
                        size, f = line.split('\t')
                        if filter_by_re(item, f):
                            item['files'][f] = int(size)
                        else:
                            self.logger.debug('log file "%s" excluded' % f)
                self.logger.debug('logs: %s' % (item['files']))
            self.logger.info('%s: total logs size: %dMB' %
                             (self.repr,
                              sum(self.logs_dict().values())/1024/1024))
        return self.logs

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

    def check_code(self, code, func_name, cmd, err, ok_codes=None):
        if code:
            if not ok_codes or code not in ok_codes:
                self.logger.warning("%s: func: %s: "
                                    "cmd: '%s' exited %d, error: %s" %
                                    (self.repr, func_name, cmd, code, err))

    def get_results(self, result_map):
        # result_map should be either mapcmds or mapscr
        if self.id is not None:
            short_repr = "node-%s" % self.id
        else:
            short_repr = self.ip
        output = []
        for cmd in sorted(result_map):
            if type(result_map[cmd]) is dict:
                path = result_map[cmd]['output_path']
            else:
                path = result_map[cmd]
            if not os.path.exists(path):
                self.logger.warning("File %s does not exist" % path)
                continue
            with open(path, 'r') as f:
                for line in f.readlines():
                    output.append(line.rstrip('\n'))
        return short_repr, output


class NodeManager(object):
    """Class NodeManager """

    @staticmethod
    def load_conf(filename):
        config = conf.init_default_conf()
        config = conf.update_conf(config, filename)
        return config

    def __init__(self, conf, nodes_json, logger=None):
        self.base_init(conf, logger)
        self.nodes_json = tools.load_json_file(nodes_json)
        self.nodes_init(Node)
        self.post_init()

    def nodes_init_fallbacks(self):
        self.nodes_get_os()

    def base_init(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or logging.getLogger(project_name)
        if conf['outputs_timestamp'] or conf['dir_timestamp']:
            timestamp_str = datetime.now().strftime('_%F_%H-%M-%S')
            if conf['outputs_timestamp']:
                conf['outputs_timestamp_str'] = timestamp_str
            if conf['dir_timestamp']:
                conf['outdir'] += timestamp_str
                conf['archive_dir'] += timestamp_str
        if conf['clean']:
            shutil.rmtree(conf['outdir'], ignore_errors=True)
        tools.mdir(conf['outdir'])
        version_filename = '%s_version.txt' % project_name
        version_filepath = os.path.join(conf['outdir'], version_filename)
        with open(version_filepath, 'a') as f:
            now = datetime.now()
            ver_msg = 'running timmy version %s' % version
            f.write('%s: %s\n' % (now, ver_msg))
            self.logger.info(ver_msg)
        if not conf['shell_mode']:
            self.rqdir = conf['rqdir']
            if (not os.path.exists(self.rqdir)):
                self.logger.critical(('NodeManager: directory %s does not'
                                      ' exist') % self.rqdir)
                sys.exit(101)
            if self.conf['rqfile']:
                self.import_rq()
        self.nodes = {}

    def apply_soft_filter(self):
        # apply soft-filter on all nodes
        for node in self.nodes.values():
            if not self.filter(node, self.conf['soft_filter']):
                node.skipped = True

    def post_init(self):
        self.nodes_reapply_conf()
        self.apply_soft_filter()
        self.conf_assign_once()

    def __str__(self):
        def ml_column(matrix, i):
            a = [row[i] for row in matrix]
            mc = 0
            for word in a:
                lw = len(str(word))
                mc = lw if (lw > mc) else mc
            return mc + 2
        header = Node.header
        nodestrings = [header]
        for n in self.sorted_nodes():
            nodestrings.append(n.print_table())
        colwidth = []
        for i in range(len(header)):
            colwidth.append(ml_column(nodestrings, i))
        pt = ''
        for i in range(len(colwidth)):
            pt += '{%s:<%s}' % (i, str(colwidth[i]))
        nodestrings = [(pt.format(*header))]
        for n in self.sorted_nodes():
            n.pt = pt
            nodestrings.append(str(n))
        return '\n'.join(nodestrings)

    def sorted_nodes(self):
        nv = self.nodes.values()
        s = [n for n in sorted(nv, key=lambda x: (x.id, x.ip))]
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
                    if k in Node.conf_appendable:
                        dst[k] = w_list(dst[k])
                        dst[k] += w_list(el[k][d])
                    else:
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

        def merge_rq(rqfile, dst):
            file = rqfile['file']
            if os.path.sep in file:
                src = tools.load_yaml_file(file)
            else:
                f = os.path.join(self.rqdir, file)
                src = tools.load_yaml_file(f)
            if self.conf['logs_no_default'] and rqfile['default']:
                if 'logs' in src:
                    src.pop('logs')
            p = Node.conf_match_prefix
            once_p = Node.conf_once_prefix + p
            d = Node.conf_default_key
            for attr in src:
                r_sub(attr, src, attr, d, p, once_p, dst)

        dst = self.conf
        for rqfile in self.conf['rqfile']:
            merge_rq(rqfile, dst)

    def nodes_init(self, NodeClass):
        for node_data in self.nodes_json:
            params = {'conf': self.conf}
            keys = ['id', 'cluster', 'roles', 'fqdn', 'name', 'mac',
                    'os_platform', 'status', 'online', 'ip', 'network_data']
            for key in keys:
                if key in node_data:
                    params[key] = node_data[key]
            node = NodeClass(**params)
            if self.filter(node, self.conf['hard_filter']):
                self.nodes[node.ip] = node
        if self.conf['offline']:
            for node in self.nodes.values():
                node.accessible = False
        else:
            self.nodes_check_access()
            self.nodes_init_fallbacks()

    def conf_assign_once(self):
        once = Node.conf_once_prefix
        p = Node.conf_match_prefix
        once_p = once + p
        for k in [k for k in self.conf if k.startswith(once)]:
            attr_name = k[len(once_p):]
            assigned = dict((k, None) for k in self.conf[k])
            for ak in assigned:
                for node in self.selected_nodes.values():
                    if hasattr(node, attr_name) and not assigned[ak]:
                        attr = w_list(getattr(node, attr_name))
                        for v in attr:
                            if v == ak:
                                once_conf = self.conf[k][ak]
                                node.apply_conf(once_conf, clean=False)
                                assigned[ak] = node.ip
                                break
                    if assigned[ak]:
                        break

    def nodes_reapply_conf(self):
        for node in self.nodes.values():
            node.apply_conf(self.conf)

    def nodes_get_os(self, maxthreads=100):
        run_items = []
        for key, node in self.selected_nodes.items():
            if not node.os_platform:
                run_items.append(tools.RunItem(target=node.get_os, key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            if result[key]:
                self.nodes[key].os_platform = result[key]

    def nodes_check_access(self, maxthreads=100):
        self.logger.debug('checking if nodes are accessible')
        run_items = []
        for key, node in self.selected_nodes.items():
            run_items.append(tools.RunItem(target=node.check_access,
                                           key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            self.nodes[key].accessible = result[key]

    def filter(self, node, node_filter):
        f = node_filter
        if f is self.conf['soft_filter'] and not node.accessible:
            return False
        # soft-skip Fuel node for shell mode
        if (node.id == 0 and self.conf['shell_mode']):
            return False
        else:
            elems = []
            for k in f:
                if k.startswith('no_') and hasattr(node, k[3:]):
                    elems.append({'node_k': k[3:], 'k': k, 'negative': True})
                elif hasattr(node, k) and f[k]:
                    elems.append({'node_k': k, 'k': k, 'negative': False})
            checks = []
            for el in elems:
                node_v = w_list(getattr(node, el['node_k']))
                filter_v = w_list(f[el['k']])
                if el['negative']:
                    checks.append(set(node_v).isdisjoint(filter_v))
                elif node.id != 0:
                    '''Do not apply normal (positive) filters to Fuel node
                    , Fuel node will only be filtered by negative filters
                    such as no_id = [0] or no_roles = ['fuel']'''
                    checks.append(not set(node_v).isdisjoint(filter_v))
            return all(checks)

    @run_with_lock
    def run_commands(self, timeout=15, fake=False, maxthreads=100):
        run_items = []
        for key, node in self.selected_nodes.items():
            run_items.append(tools.RunItem(target=node.exec_cmd,
                                           args={'fake': fake},
                                           key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            self.nodes[key].mapcmds = result[key][0]
            self.nodes[key].mapscr = result[key][1]

    def calculate_log_size(self, timeout=15, maxthreads=100):
        total_size = 0
        run_items = []
        for key, node in self.selected_nodes.items():
            run_items.append(tools.RunItem(target=node.logs_populate,
                                           args={'timeout': timeout},
                                           key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            self.nodes[key].logs = result[key]
        for node in self.selected_nodes.values():
            total_size += sum(node.logs_dict().values())
        self.logger.info('Full log size on nodes(with fuel): %d bytes' %
                         total_size)
        self.alogsize = total_size
        return self.alogsize

    def is_enough_space(self):
        tools.mdir(self.conf['archive_dir'])
        outs, errs, code = tools.free_space(self.conf['archive_dir'],
                                            timeout=1)
        if code != 0:
            self.logger.error("Can't get free space: %s" % errs)
            return False
        try:
            fs = int(outs.rstrip('\n'))
        except:
            self.logger.error("can't get free space\nouts: %s" %
                              outs)
            return False
        coeff = self.conf['logs_size_coefficient']
        self.logger.info('logsize: %dMB * %s, free space: %dMB' %
                         (self.alogsize/1024/1024, coeff, fs/1024))
        if (self.alogsize*coeff > fs*1024):
            self.logger.error('Not enough space in "%s", logsize: %dMB * %s, '
                              'available: %dMB. Decrease logs_size_coefficient'
                              ' config parameter (--logs-coeff CLI parameter)'
                              ' or free up space.' % (self.conf['archive_dir'],
                                                      self.alogsize/1024/1024,
                                                      coeff,
                                                      fs/1024))
            return False
        else:
            return True

    @run_with_lock
    def create_archive_general(self, timeout):
        if not os.path.isdir(self.conf['outdir']):
            self.logger.warning("Nothing to do, directory %s doesn't exist" %
                                self.conf['outdir'])
            return
        outfile = os.path.join(self.conf['archive_dir'],
                               self.conf['archive_name'])
        cmd = "tar zcf '%s' -C %s %s" % (outfile, self.conf['outdir'], ".")
        tools.mdir(self.conf['archive_dir'])
        self.logger.debug("cmd: %s" % cmd)
        outs, errs, code = tools.launch_cmd(cmd, timeout)
        if code != 0:
            self.logger.error("Can't create archive %s" % (errs))

    def find_adm_interface_speed(self):
        '''Returns interface speed through which logs will be dowloaded'''
        for node in self.selected_nodes.values():
            if not (node.ip == 'localhost' or node.ip.startswith('127.')):
                cmd = ("%s$(/sbin/ip -o route get %s | cut -d' ' -f3)/speed" %
                       ('cat /sys/class/net/', node.ip))
                out, err, code = tools.launch_cmd(cmd, node.timeout)
                if code != 0:
                    self.logger.warning("can't get iface speed: err: %s" % err)
                    return self.conf['logs_speed_default']
                try:
                    speed = int(out)
                except:
                    speed = self.conf['logs_speed_default']
                return speed

    @run_with_lock
    def get_logs(self, timeout, fake=False, maxthreads=10):
        if fake:
            self.logger.info('fake = True, skipping')
            return
        if self.conf['logs_speed_limit']:
            if self.conf['logs_speed'] > 0:
                speed = self.conf['logs_speed']
            else:
                speed = self.find_adm_interface_speed()
            speed = int(speed * 0.9 / min(maxthreads, len(self.nodes)))
            py_slowpipe = tools.slowpipe % speed
            limitcmd = "| python -c '%s'; exit ${PIPESTATUS}" % py_slowpipe
        run_items = []
        for node in self.selected_nodes.values():
            if not node.logs_dict():
                self.logger.info(("%s: no logs to collect") % node.repr)
                continue
            node.archivelogsfile = os.path.join(self.conf['archive_dir'],
                                                'logs-%s.tar.gz' % node.repr)
            tools.mdir(self.conf['archive_dir'])
            input = ''
            for fn in node.logs_dict():
                input += '%s\0' % fn.lstrip(os.path.abspath(os.sep))
            cmd = ("tar --transform 's,^,%s/,' --gzip -C %s --create "
                   "--warning=no-file-changed --file - --null --files-from -" %
                   (node.repr, os.path.abspath(os.sep)))
            if self.conf['logs_speed_limit']:
                if not (node.ip == 'localhost' or node.ip.startswith('127.')):
                    cmd = ' '.join([cmd, limitcmd])
            args = {'cmd': cmd,
                    'timeout': timeout,
                    'outfile': node.archivelogsfile,
                    'input': input,
                    'ok_codes': [0, 1],
                    'decode': False}
            run_items.append(tools.RunItem(target=node.exec_simple_cmd,
                                           args=args))
        tools.run_batch(run_items, maxthreads)

    @run_with_lock
    def get_files(self, timeout=15):
        run_items = []
        for node in self.selected_nodes.values():
            run_items.append(tools.RunItem(target=node.get_files))
        tools.run_batch(run_items, 10)

    @run_with_lock
    def put_files(self):
        run_items = []
        for node in self.selected_nodes.values():
            run_items.append(tools.RunItem(target=node.put_files))
        tools.run_batch(run_items, 10)

    @run_with_lock
    def run_scripts_all_pairs(self, maxthreads, fake=False):
        nodes = self.selected_nodes.values()
        if len(nodes) < 2:
            self.logger.warning('less than 2 nodes are available, '
                                'skipping paired scripts')
            return
        run_server_start_items = []
        run_server_stop_items = []
        for n in nodes:
            start_args = {'phase': 'server_start', 'fake': fake}
            run_server_start_items.append(tools.RunItem(target=n.exec_pair,
                                                        args=start_args,
                                                        key=n.ip))
            stop_args = {'phase': 'server_stop', 'fake': fake}
            run_server_stop_items.append(tools.RunItem(target=n.exec_pair,
                                                       args=stop_args))
        result = tools.run_batch(run_server_start_items, maxthreads,
                                 dict_result=True)
        for key in result:
            self.nodes[key].scripts_all_pairs = result[key]
        one_way = self.conf['scripts_all_pairs_one_way']
        for pairset in tools.all_pairs(nodes, one_way=one_way):
            run_client_items = []
            self.logger.info(['%s->%s' % (p[0].ip, p[1].ip) for p in pairset])
            for pair in pairset:
                client = pair[0]
                server = pair[1]
                client_args = {'phase': 'client', 'server_node': server,
                               'fake': fake}
                run_client_items.append(tools.RunItem(target=client.exec_pair,
                                                      args=client_args))
            tools.run_batch(run_client_items, len(run_client_items))
        tools.run_batch(run_server_stop_items, maxthreads)

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

    @property
    def selected_nodes(self):
        return dict([(ip, n) for ip, n in self.nodes.items() if not n.skipped])


def main(argv=None):
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
