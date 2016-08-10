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
    import fuelclient.client
    if type(fuelclient.client.APIClient) is type:
        # fuel 9.1+ (originally 10.0+)
        from fuelclient.client import APIClient as FuelClient
        FUEL_10 = True
    elif type(fuelclient.client.APIClient) is fuelclient.client.Client:
        # fuel 9.0 and below
        from fuelclient.client import Client as FuelClient
        FUEL_10 = False
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
    header = ['node-id', 'env', 'ip', 'mac', 'os',
              'roles', 'online', 'status', 'name', 'fqdn']

    def __init__(self, id, name, fqdn, mac, cluster, roles, os_platform,
                 online, status, ip, conf, logger=None):
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
        self.name = name
        self.fqdn = fqdn
        self.filtered_out = False
        self.outputs_timestamp = False
        self.outputs_timestamp_dir = None
        self.apply_conf(conf)
        self.logger = logger or logging.getLogger(__name__)

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
                str(self.online), str(self.status),
                str(self.name), str(self.fqdn)]

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
            self.logger.warning('node: %s: could not determine'
                                ' MOS release' % self.id)
            release = 'n/a'
        else:
            release = release.strip('\n "\'')
        self.logger.info('node: %s, MOS release: %s' %
                         (self.id, release))
        return release

    def exec_cmd(self, fake=False, ok_codes=None):
        sn = 'node-%s' % self.id
        cl = 'cluster-%s' % self.cluster
        self.logger.debug('%s/%s/%s/%s' % (self.outdir, Node.ckey, cl, sn))
        ddir = os.path.join(self.outdir, Node.ckey, cl, sn)
        if self.cmds:
            tools.mdir(ddir)
        self.cmds = sorted(self.cmds)
        mapcmds = {}
        for c in self.cmds:
            for cmd in c:
                dfile = os.path.join(ddir, 'node-%s-%s-%s' %
                                     (self.id, self.ip, cmd))
                if self.outputs_timestamp:
                        dfile += self.outputs_timestamp_str
                self.logger.info('outfile: %s' % dfile)
                mapcmds[cmd] = dfile
                if not fake:
                    outs, errs, code = tools.ssh_node(ip=self.ip,
                                                      command=c[cmd],
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
            tools.mdir(ddir)
        scripts = sorted(self.scripts)
        mapscr = {}
        for scr in scripts:
            if type(scr) is dict:
                env_vars = scr.values()[0]
                scr = scr.keys()[0]
            else:
                env_vars = self.env_vars
            if os.path.sep in scr:
                f = scr
            else:
                f = os.path.join(self.rqdir, Node.skey, scr)
            self.logger.debug('node:%s(%s), exec: %s' % (self.id, self.ip, f))
            dfile = os.path.join(ddir, 'node-%s-%s-%s' %
                                 (self.id, self.ip, os.path.basename(f)))
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
        self.logger.info('node:%s(%s), exec: %s' % (self.id, self.ip, cmd))
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
        self.logger.info('node: %s, IP: %s' % (self.id, self.ip))
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
                self.check_code(code, 'get_files', 'tools.get_file_scp', errs)
        else:
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
            data += '\n'.join(self.files)
            self.logger.debug('node: %s, data:\n%s' % (self.id, data))
            if data:
                o, e, c = tools.get_files_rsync(ip=self.ip,
                                                data=data,
                                                ssh_opts=self.ssh_opts,
                                                dpath=ddir,
                                                timeout=self.timeout)
                self.check_code(c, 'get_files', 'tools.get_files_rsync', e)

    def put_files(self):
        self.logger.info('node: %s, IP: %s' % (self.id, self.ip))
        for f in self.put:
            outs, errs, code = tools.put_file_scp(ip=self.ip,
                                                  file=f[0],
                                                  dest=f[1],
                                                  recursive=True)
            self.check_code(code, 'put_files', 'tools.put_file_scp', errs)

    def logs_populate(self, timeout=5):

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
                item['exclude'].append(self.logs_fuel_remote_dir)
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
            self.logger.info('node: %s, logs du-cmd: %s' %
                             (self.id, cmd))
            outs, errs, code = tools.ssh_node(ip=self.ip,
                                              command=cmd,
                                              ssh_opts=self.ssh_opts,
                                              env_vars='',
                                              timeout=timeout,
                                              prefix=self.prefix)
            if code == 124:
                self.logger.error("node: %s, ip: %s, command: %s, "
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
                        else:
                            self.logger.debug('log file "%s" excluded' % f)
                self.logger.debug('logs: %s' % (item['files']))
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
                self.logger.warning("id: %s, fqdn: %s, ip: %s, func: %s, "
                                    "cmd: '%s' exited %d, error: %s" %
                                    (self.id, self.fqdn, self.ip,
                                     func_name, cmd, code, err))

    def print_results(self, result_map):
        # result_map should be either mapcmds or mapscr
        for cmd in sorted(result_map):
            with open(result_map[cmd], 'r') as f:
                for line in f.readlines():
                    print('node-%s:\t%s' %
                          (self.id, line.rstrip('\n')))


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
            shutil.rmtree(conf['archive_dir'], ignore_errors=True)
        if not conf['shell_mode']:
            self.rqdir = conf['rqdir']
            if (not os.path.exists(self.rqdir)):
                self.logger.critical(('NodeManager: directory %s does not'
                                      ' exist') % self.rqdir)
                sys.exit(1)
            if self.conf['rqfile']:
                self.import_rq()
        self.nodes = {}
        self.token = None
        self.fuel_init()
        # save os environment variables
        environ = os.environ
        if FuelClient and conf['fuelclient']:
            try:
                if self.conf['fuel_skip_proxy']:
                    os.environ['HTTPS_PROXY'] = ''
                    os.environ['HTTP_PROXY'] = ''
                    os.environ['https_proxy'] = ''
                    os.environ['http_proxy'] = ''
                self.logger.info('Setup fuelclient instance')
                if FUEL_10:
                    self.fuelclient = FuelClient(
                        host=self.conf['fuel_ip'],
                        port=self.conf['fuel_port'],
                        os_username=self.conf['fuel_user'],
                        os_password=self.conf['fuel_pass'],
                        os_tenant_name=self.conf['fuel_tenant'])
                else:
                    self.fuelclient = FuelClient()
                    self.fuelclient.username = self.conf['fuel_user']
                    self.fuelclient.password = self.conf['fuel_pass']
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
                sys.exit(4)
        self.nodes_init()
        # apply soft-filter on all nodes
        for node in self.nodes.values():
            if not self.filter(node, self.conf['soft_filter']):
                node.filtered_out = True
        if (not self.get_release_fuel_client() and
                not self.get_release_api() and
                not self.get_release_cli()):
            self.logger.warning('could not get Fuel and MOS versions')
        else:
            self.nodes_reapply_conf()
            self.conf_assign_once()
        os.environ = environ

    def __str__(self):
        def ml_column(matrix, i):
            a = [row[i] for row in matrix]
            mc = 0
            for word in a:
                lw = len(word)
                mc = lw if (lw > mc) else mc
            return mc + 2
        header = Node.header
        nodestrings = [header]
        for n in self.sorted_nodes():
            if self.filter(n, self.conf['hard_filter']):
                nodestrings.append(n.print_table())
        colwidth = []
        for i in range(len(header)):
            colwidth.append(ml_column(nodestrings, i))
        pt = ''
        for i in range(len(colwidth)):
            pt += '{%s:<%s}' % (i, str(colwidth[i]))
        nodestrings = [(pt.format(*header))]
        for n in self.sorted_nodes():
            if self.filter(n, self.conf['hard_filter']):
                n.pt = pt
                nodestrings.append(str(n))
        return '\n'.join(nodestrings)

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
            sys.exit(7)
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
                self.logger.info('node: %s - release: %s' % (node.id,
                                                             node.release))

    def auth_token(self):
        '''Get keystone token to access Nailgun API. Requires Fuel 7.0+'''
        if self.token:
            return True
        req_data = ('{ "auth": {'
                    '  "scope": {'
                    '    "project": {'
                    '      "name": "%s",'
                    '      "domain": { "id": "default" }'
                    '    }'
                    '  },'
                    '  "identity": {'
                    '    "methods": ["password"],'
                    '    "password": {'
                    '      "user": {'
                    '        "name": "%s",'
                    '        "domain": { "id": "default" },'
                    '        "password": "%s"'
                    '      }'
                    '    }'
                    '  }'
                    '}}' % (self.conf['fuel_tenant'],
                            self.conf['fuel_user'],
                            self.conf['fuel_pass']))
        req = urllib2.Request("http://%s:%s/v3/auth/tokens" %
                              (self.conf['fuel_ip'],
                               self.conf['fuel_keystone_port']), req_data,
                              {'Content-Type': 'application/json'})
        try:
            token = urllib2.urlopen(req).info().getheader('X-Subject-Token')
            self.token = token
            return True
        except:
            return False

    def get_api_request(self, request):
        if self.auth_token():
            url = "http://%s:%s/api/%s" % (self.conf['fuel_ip'],
                                           self.conf['fuel_port'],
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
        fuel_node_cmd = ('fuel node list --json --user %s --password %s' %
                         (self.conf['fuel_user'],
                          self.conf['fuel_pass']))
        nodes_json, err, code = tools.ssh_node(ip=fuelnode.ip,
                                               command=fuel_node_cmd,
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
        for key in result:
            self.nodes[key].release = result[key]

    def nodes_init(self):
        for node_data in self.nodes_json:
            node_roles = node_data.get('roles')
            if not node_roles:
                roles = ['None']
            elif isinstance(node_roles, list):
                roles = node_roles
            else:
                roles = str(node_roles).split(', ')
            keys = "fqdn name mac os_platform status online ip".split()
            cl = int(node_data['cluster']) if node_data['cluster'] else None
            params = {'id': int(node_data['id']),
                      # please do NOT convert cluster id to int type
                      # because None can be valid
                      'cluster': cl,
                      'roles': roles,
                      'conf': self.conf}
            for key in keys:
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
                                assigned[ak] = node.id
                                break
                    if assigned[ak]:
                        break

    def nodes_reapply_conf(self):
        for node in self.nodes.values():
            node.apply_conf(self.conf)

    def filter(self, node, node_filter):
        f = node_filter
        # soft-skip Fuel node for shell mode
        if node.id == 0 and self.conf['shell_mode']:
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
                run_items.append(tools.RunItem(target=node.logs_populate,
                                               args={'timeout': timeout},
                                               key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            self.nodes[key].logs = result[key]
        for node in self.nodes.values():
            total_size += sum(node.logs_dict().values())
        self.logger.info('Full log size on nodes(with fuel): %s bytes' %
                         total_size)
        self.alogsize = total_size / 1024
        return self.alogsize

    def is_enough_space(self):
        tools.mdir(self.conf['outdir'])
        outs, errs, code = tools.free_space(self.conf['outdir'], timeout=1)
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
        self.logger.info('logsize: %s Kb * %s, free space: %s Kb' %
                         (self.alogsize, coeff, fs))
        if (self.alogsize*coeff > fs):
            self.logger.error('Not enough space in "%s", logsize: %s Kb * %s, '
                              'available: %s Kb. Decrease logs_size_coefficien'
                              't config parameter (--logs-coeff CLI parameter)'
                              ' or free up space.' % (self.conf['outdir'],
                                                      self.alogsize, coeff,
                                                      fs))
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
                self.logger.info(("node %s - no logs "
                                  "to collect") % node.id)
                continue
            node.archivelogsfile = os.path.join(self.conf['archive_dir'],
                                                'logs-node-%s.tar.gz' %
                                                str(node.id))
            tools.mdir(self.conf['archive_dir'])
            input = ''
            for fn in node.logs_dict():
                input += '%s\0' % fn.lstrip(os.path.abspath(os.sep))
            cmd = ("tar --gzip -C %s --create --warning=no-file-changed "
                   " --file - --null --files-from -" % os.path.abspath(os.sep))
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
