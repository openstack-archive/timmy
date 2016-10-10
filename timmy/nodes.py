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
from datetime import datetime, date, timedelta
import urllib2
import tools
from tools import w_list, run_with_lock
from copy import deepcopy

try:
    import fuelclient
    if hasattr(fuelclient, 'connect'):
        # fuel > 9.0.1 - drop support, use API and CLI instead
        FuelClient = None
    else:
        import fuelclient.client
        if type(fuelclient.client.APIClient) is fuelclient.client.Client:
            # fuel 9.0.1 and below
            from fuelclient.client import Client as FuelClient
        else:
            FuelClient = None
except:
    FuelClient = None

try:
    from fuelclient.client import logger
    logger.handlers = []
except:
    pass


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
                 online=True, status="ready", logger=None):
        self.logger = logger or logging.getLogger(__name__)
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
        self.filtered_out = False
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
        if not self.filtered_out:
            my_id = self.id
        else:
            my_id = str(self.id) + ' [skipped]'
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
            self.logger.warning('%s: could not determine'
                                ' MOS release' % self.repr)
            release = 'n/a'
        else:
            release = release.strip('\n "\'')
        self.logger.info('%s, MOS release: %s' %
                         (self.repr, release))
        return release

    def get_roles_hiera(self):
        def trim_primary(roles):
            trim_roles = [r for r in roles if not r.startswith('primary-')]
            trim_roles += [r[8:] for r in roles if r.startswith('primary-')]
            return trim_roles

        self.logger.debug('%s: roles not defined, trying hiera' % self.repr)
        cmd = 'hiera roles'
        outs, errs, code = tools.ssh_node(ip=self.ip,
                                          command=cmd,
                                          ssh_opts=self.ssh_opts,
                                          env_vars=self.env_vars,
                                          timeout=self.timeout,
                                          prefix=self.prefix)
        self.check_code(code, 'get_roles_hiera', cmd, errs, [0])
        if code == 0:
            try:
                roles = trim_primary(json.loads(outs))
            except:
                self.logger.warning("%s: failed to parse '%s' output as JSON" %
                                    (self.repr, cmd))
                return self.roles
            self.logger.debug('%s: got roles: %s' % (self.repr, roles))
            if roles is not None:
                return roles
            else:
                return self.roles
        else:
            self.logger.warning("%s: failed to load roles via hiera" %
                                self.repr)
            self.roles

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

    def get_cluster_id(self):
        self.logger.debug('%s: cluster id not defined, trying to determine' %
                          self.repr)
        astute_file = '/etc/astute.yaml'
        cmd = ("python -c 'import os,yaml; "
               "exit(1) if not os.path.exists(\"%s\") else 0; "
               "a = yaml.load(open(\"%s\").read()); "
               "print a[\"cluster\"][\"id\"]'" % (astute_file, astute_file))
        outs, errs, code = tools.ssh_node(ip=self.ip,
                                          command=cmd,
                                          ssh_opts=self.ssh_opts,
                                          env_vars=self.env_vars,
                                          timeout=self.timeout,
                                          prefix=self.prefix)
        return int(outs.rstrip('\n')) if code == 0 else None

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
            ddir = os.path.join(self.outdir, Node.skey, cl, self.repr)
            tools.mdir(ddir)
            self.scripts = sorted(self.scripts)
        mapscr = {}
        for scr in self.scripts:
            if type(scr) is dict:
                env_vars = scr.values()[0]
                scr = scr.keys()[0]
            else:
                env_vars = self.env_vars
            if os.path.sep in scr:
                f = scr
            else:
                f = os.path.join(self.rqdir, Node.skey, scr)
            self.logger.debug('%s, exec: %s' % (self.repr, f))
            dfile = os.path.join(ddir, os.path.basename(f))
            if self.outputs_timestamp:
                    dfile += self.outputs_timestamp_str
            self.logger.debug('outfile: %s' % dfile)
            mapscr[scr] = dfile
            if not fake:
                outs, errs, code = tools.ssh_node(ip=self.ip,
                                                  filename=f,
                                                  ssh_opts=self.ssh_opts,
                                                  env_vars=env_vars,
                                                  timeout=self.timeout,
                                                  prefix=self.prefix)
                self.check_code(code, 'exec_cmd', 'script %s' % f, errs,
                                ok_codes)
                try:
                    with open(dfile, 'w') as df:
                        df.write(outs.encode('utf-8'))
                except:
                    self.logger.error("can't write to file %s" % dfile)
        return mapcmds, mapscr

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

    def logs_populate(self, timeout=5, logs_excluded_nodes=[]):

        def filter_by_re(item, string):
            return (('include' not in item or not item['include'] or
                     any([re.search(i, string) for i in item['include']])) and
                    ('exclude' not in item or not item['exclude'] or not
                     any([re.search(e, string) for e in item['exclude']])))

        for item in self.logs:
            if self.logs_no_fuel_remote and 'fuel' in self.roles:
                self.logger.debug('adding Fuel remote logs to exclude list')
                if 'exclude' not in item:
                    item['exclude'] = []
                for remote_dir in self.logs_fuel_remote_dir:
                    item['exclude'].append(remote_dir)
            if 'fuel' in self.roles:
                for n in logs_excluded_nodes:
                    self.logger.debug('removing remote logs for node:%s' % n)
                    if 'exclude' not in item:
                        item['exclude'] = []
                    for remote_dir in self.logs_fuel_remote_dir:
                        ipd = os.path.join(remote_dir, n)
                        item['exclude'].append(ipd)
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
            with open(result_map[cmd], 'r') as f:
                for line in f.readlines():
                    output.append(line.rstrip('\n'))
        return short_repr, output


class NodeManager(object):
    """Class nodes """

    def __init__(self, conf, extended=False, nodes_json=None, logger=None):
        self.conf = conf
        self.logger = logger or logging.getLogger(__name__)
        if conf['outputs_timestamp'] or conf['dir_timestamp']:
            timestamp_str = datetime.now().strftime('_%F_%H-%M-%S')
            if conf['outputs_timestamp']:
                conf['outputs_timestamp_str'] = timestamp_str
            if conf['dir_timestamp']:
                conf['outdir'] += timestamp_str
                conf['archive_dir'] += timestamp_str
        if conf['clean']:
            shutil.rmtree(conf['outdir'], ignore_errors=True)
        if not conf['shell_mode']:
            self.rqdir = conf['rqdir']
            if (not os.path.exists(self.rqdir)):
                self.logger.critical(('NodeManager: directory %s does not'
                                      ' exist') % self.rqdir)
                sys.exit(101)
            if self.conf['rqfile']:
                self.import_rq()
        self.nodes = {}
        self.token = self.conf['fuel_api_token']
        self.fuel_init()
        # save os environment variables
        environ = os.environ
        self.logs_excluded_nodes = []
        if FuelClient and conf['fuelclient']:
            try:
                if self.conf['fuel_skip_proxy']:
                    os.environ['HTTPS_PROXY'] = ''
                    os.environ['HTTP_PROXY'] = ''
                    os.environ['https_proxy'] = ''
                    os.environ['http_proxy'] = ''
                self.logger.info('Setup fuelclient instance')
                self.fuelclient = FuelClient()
                if self.conf['fuel_user']:
                    self.fuelclient.username = self.conf['fuel_user']
                if self.conf['fuel_pass']:
                    self.fuelclient.password = self.conf['fuel_pass']
                if self.conf['fuel_tenant']:
                    self.fuelclient.tenant_name = self.conf['fuel_tenant']
                # self.fuelclient.debug_mode(True)
            except Exception as e:
                self.logger.info('Failed to setup fuelclient instance:%s' % e,
                                 exc_info=True)
                self.fuelclient = None
        else:
            self.logger.info('Skipping setup fuelclient instance')
            self.fuelclient = None
        if nodes_json:
            self.nodes_json = tools.load_json_file(nodes_json)
        else:
            if (not self.get_nodes_fuelclient() and
                    not self.get_nodes_api() and
                    not self.get_nodes_cli()):
                self.logger.critical('Failed to retrieve node information.')
                sys.exit(105)
        self.nodes_init()
        self.nodes_check_access()
        # get release information for all nodes
        if (not self.get_release_fuel_client() and
                not self.get_release_api() and
                not self.get_release_cli()):
            self.logger.warning('could not get Fuel and MOS versions')
        # fallbacks
        self.nodes_get_roles_hiera()
        self.nodes_get_os()
        self.nodes_get_cluster_ids()
        for node in self.nodes.values():
            # apply soft-filter on all nodes
            if not self.filter(node, self.conf['soft_filter']):
                node.filtered_out = True
                if self.conf['logs_exclude_filtered']:
                    self.logs_excluded_nodes.append(node.fqdn)
                    self.logs_excluded_nodes.append(node.ip)
        self.nodes_reapply_conf()
        self.conf_assign_once()
        os.environ = environ

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

    def fuel_init(self):
        if not self.conf['fuel_ip']:
            self.logger.critical('NodeManager: fuel_ip not set')
            sys.exit(106)
        fuelnode = Node(id=0,
                        cluster=0,
                        name='fuel',
                        fqdn='n/a',
                        mac='n/a',
                        os_platform='centos',
                        roles=['fuel'],
                        status='ready',
                        online=True,
                        ip=self.conf['fuel_ip'],
                        conf=self.conf)
        fuelnode.cluster_repr = ""
        fuelnode.repr = "fuel"
        # soft-skip Fuel if it is hard-filtered
        if not self.filter(fuelnode, self.conf['hard_filter']):
            fuelnode.filtered_out = True
        self.nodes[self.conf['fuel_ip']] = fuelnode

    def get_nodes_fuelclient(self):
        if not self.fuelclient:
            return False
        try:
            self.logger.info('using fuelclient to get nodes json')
            self.nodes_json = self.fuelclient.get_request('nodes')
            return True
        except Exception as e:
            self.logger.warning(("NodeManager: can't "
                                 "get node list from fuel client:\n%s" % (e)),
                                exc_info=True)
            return False

    def get_release_api(self):
        self.logger.info('getting release via API')
        version_json = self.get_api_request('version')
        if version_json:
            version = json.loads(version_json)
            fuel = self.nodes[self.conf['fuel_ip']]
            fuel.release = version['release']
        else:
            return False
        clusters_json = self.get_api_request('clusters')
        if clusters_json:
            clusters = json.loads(clusters_json)
            self.set_nodes_release(clusters)
            return True
        else:
            return False

    def get_release_fuel_client(self):
        if not self.fuelclient:
            return False
        self.logger.info('getting release via fuelclient')
        try:
            v = self.fuelclient.get_request('version')
            fuel_version = v['release']
            self.logger.debug('version response:%s' % v)
            clusters = self.fuelclient.get_request('clusters')
            self.logger.debug('clusters response:%s' % clusters)
        except:
            self.logger.warning(("Can't get fuel version or "
                                 "clusters information"))
            return False
        self.nodes[self.conf['fuel_ip']].release = fuel_version
        self.set_nodes_release(clusters)
        return True

    def set_nodes_release(self, clusters):
        cldict = {}
        for cluster in clusters:
            cldict[cluster['id']] = cluster
        if cldict:
            for node in self.nodes.values():
                if node.cluster:
                    node.release = cldict[node.cluster]['fuel_version']
                else:
                    # set to n/a or may be fuel_version
                    if node.id != 0:
                        node.release = 'n/a'
                self.logger.info('%s: release: %s' % (node.repr, node.release))

    def auth_token(self):
        '''Get keystone token to access Nailgun API. Requires Fuel 5+'''
        if self.token:
            return True
        self.logger.info('getting token for Nailgun')
        v2_body = ('{"auth": {"tenantName": "%s", "passwordCredentials": {'
                   '"username": "%s", "password": "%s"}}}')
        # v3 not fully implemented yet
        # v3_body = ('{ "auth": {'
        #            '  "scope": {'
        #            '    "project": {'
        #            '      "name": "%s",'
        #            '      "domain": { "id": "default" }'
        #            '    }'
        #            '  },'
        #            '  "identity": {'
        #            '    "methods": ["password"],'
        #            '    "password": {'
        #            '      "user": {'
        #            '        "name": "%s",'
        #            '        "domain": { "id": "default" },'
        #            '        "password": "%s"'
        #            '      }'
        #            '    }'
        #            '  }'
        #            '}}')
        # Sticking to v2 API for now because Fuel 9.1 has a custom
        # domain_id defined in keystone.conf which we do not know.
        args = {'user': None, 'pass': None, 'tenant': None}
        for a in args:
            if self.conf['fuel_%s' % a]:
                args[a] = self.conf['fuel_%s' % a]
            else:
                args[a] = self.conf['fuel_api_%s' % a]
        req_data = v2_body % (args['tenant'], args['user'], args['pass'])
        req = urllib2.Request("http://%s:%s/v2.0/tokens" %
                              (self.conf['fuel_ip'],
                               self.conf['fuel_api_keystone_port']), req_data,
                              {'Content-Type': 'application/json'})
        try:
            # Disabling v3 token retrieval for now
            # token = urllib2.urlopen(req).info().getheader('X-Subject-Token')
            result = urllib2.urlopen(req)
            resp_body = result.read()
            resp_json = json.loads(resp_body)
            token = resp_json['access']['token']['id']
            self.token = token
            return True
        except:
            return False

    def get_api_request(self, request):
        if self.auth_token():
            url = "http://%s:%s/api/%s" % (self.conf['fuel_ip'],
                                           self.conf['fuel_api_port'],
                                           request)
            req = urllib2.Request(url, None, {'X-Auth-Token': self.token})
            try:
                result = urllib2.urlopen(req)
                code = result.getcode()
                if code == 200:
                    return result.read()
                else:
                    self.logger.error('NodeManager: cannot get API response'
                                      ' from %s, code %s' % (url, code))
            except:
                pass

    def get_nodes_api(self):
        return False
        self.logger.info('using API to get nodes json')
        nodes_json = self.get_api_request('nodes')
        if nodes_json:
            self.nodes_json = json.loads(nodes_json)
            return True
        else:
            return False

    def get_nodes_cli(self):
        self.logger.info('using CLI to get nodes json')
        fuelnode = self.nodes[self.conf['fuel_ip']]
        o_auth = n_auth = ''
        entropy = bool(self.conf['fuel_user']) + bool(self.conf['fuel_pass'])
        if entropy == 2:
            # auth for Fuel up to 8.0
            o_auth = '--user %s --password %s' % (self.conf['fuel_user'],
                                                  self.conf['fuel_pass'])
            # Fuel 9.0+
            n_auth = 'OS_USERNAME=%s OS_PASSWORD=%s' % (self.conf['fuel_user'],
                                                        self.conf['fuel_pass'])
        elif entropy == 1:
            self.logger.warning('Must specify both fuel_user and fuel_pass')
        cmd = 'bash -c "%s fuel node --json"' % n_auth
        nodes_json, err, code = tools.ssh_node(ip=fuelnode.ip,
                                               command=cmd,
                                               ssh_opts=fuelnode.ssh_opts,
                                               timeout=fuelnode.timeout,
                                               prefix=fuelnode.prefix)
        if code != 0:
            self.logger.warning(('NodeManager: cannot get fuel node list from'
                                 ' CLI, will fallback. Error: %s') % err)
            cmd = 'bash -c "fuel %s node --json"' % o_auth
            nodes_json, err, code = tools.ssh_node(ip=fuelnode.ip,
                                                   command=cmd,
                                                   ssh_opts=fuelnode.ssh_opts,
                                                   timeout=fuelnode.timeout,
                                                   prefix=fuelnode.prefix)
            if code != 0:
                self.logger.warning(('NodeManager: cannot get '
                                     'fuel node list from CLI: %s') % err)
                self.nodes_json = None
                return False
        self.nodes_json = json.loads(nodes_json)
        return True

    def get_release_cli(self):
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out:
                run_items.append(tools.RunItem(target=node.get_release,
                                               key=key))
        result = tools.run_batch(run_items, 100, dict_result=True)
        if result:
            for key in result:
                self.nodes[key].release = result[key]
            return True
        else:
            return False

    def nodes_init(self):
        for node_data in self.nodes_json:
            params = {'conf': self.conf}
            keys = ['id', 'cluster', 'roles', 'fqdn', 'name', 'mac',
                    'os_platform', 'status', 'online', 'ip']
            for key in keys:
                if key in node_data:
                    params[key] = node_data[key]
            node = Node(**params)
            if self.filter(node, self.conf['hard_filter']):
                self.nodes[node.ip] = node

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
                                assigned[ak] = node.ip
                                break
                    if assigned[ak]:
                        break

    def nodes_reapply_conf(self):
        for node in self.nodes.values():
            node.apply_conf(self.conf)

    def nodes_get_roles_hiera(self, maxthreads=100):
        run_items = []
        for key, node in self.nodes.items():
            if all([not node.filtered_out, not node.roles,
                    node.status != 'discover']):
                run_items.append(tools.RunItem(target=node.get_roles_hiera,
                                               key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            if result[key]:
                self.nodes[key].roles = result[key]

    def nodes_get_os(self, maxthreads=100):
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out and not node.os_platform:
                run_items.append(tools.RunItem(target=node.get_os, key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            if result[key]:
                self.nodes[key].os_platform = result[key]

    def nodes_get_cluster_ids(self, maxthreads=100):
        self.logger.debug('getting cluster ids from nodes')
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out and not node.cluster:
                run_items.append(tools.RunItem(target=node.get_cluster_id,
                                               key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            if result[key] is not None:
                self.nodes[key].cluster = result[key]

    def nodes_check_access(self, maxthreads=100):
        self.logger.debug('checking if nodes are accessible')
        run_items = []
        for key, node in self.nodes.items():
            if not node.filtered_out:
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
        for key, node in self.nodes.items():
            if not node.filtered_out:
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
        for key, node in self.nodes.items():
            if not node.filtered_out:
                args = {'timeout': timeout,
                        'logs_excluded_nodes': self.logs_excluded_nodes}
                run_items.append(tools.RunItem(target=node.logs_populate,
                                               args=args,
                                               key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            self.nodes[key].logs = result[key]
        for node in self.nodes.values():
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
        for node in self.nodes.values():
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
        for node in [n for n in self.nodes.values() if not n.filtered_out]:
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
    sys.exit(main(sys.argv))
