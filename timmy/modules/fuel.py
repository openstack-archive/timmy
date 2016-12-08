#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#    Copyright 2016 Mirantis, Inc.
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


import json
import os
import sys
import urllib2
from timmy import tools
from timmy import conf
from timmy.nodes import NodeManager as BaseNodeManager
from timmy.nodes import Node as BaseNode

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


def add_args(parser):
    parser.add_argument('--fuel-ip', help='fuel ip address')
    parser.add_argument('--fuel-user', help='fuel username')
    parser.add_argument('--fuel-pass', help='fuel password')
    parser.add_argument('--fuel-token', help='fuel auth token')
    parser.add_argument('--fuel-logs-no-remote', action='store_true',
                        help='Do not collect remote logs from Fuel.')
    parser.add_argument('--fuel-proxy',
                        help='use os system proxy variables for fuelclient',
                        action='store_true')
    parser.add_argument('-j', '--nodes-json',
                        help=('Path to a json file retrieved via'
                              ' "fuel node --json". Useful to speed up'
                              ' initialization, skips "fuel node" call.'))
    return parser


def check_args(args, conf):
    if args.fuel_ip:
        conf['fuel_ip'] = args.fuel_ip
    if args.fuel_user:
        conf['fuel_user'] = args.fuel_user
    if args.fuel_pass:
        conf['fuel_pass'] = args.fuel_pass
    if args.fuel_proxy:
        conf['fuel_skip_proxy'] = False
    if args.fuel_token:
        conf['fuel_api_token'] = args.fuel_token
        conf['fuelclient'] = False
    if args.fuel_logs_no_remote:
        conf['fuel_logs_no_remote'] = True


def add_conf(conf):
    conf['fuel_ip'] = '127.0.0.1'
    conf['fuel_api_user'] = 'admin'
    conf['fuel_api_pass'] = 'admin'
    conf['fuel_api_token'] = None
    conf['fuel_api_tenant'] = 'admin'
    conf['fuel_api_port'] = '8000'
    conf['fuel_api_keystone_port'] = '5000'
    # The three parameters below are used to override FuelClient, API, CLI auth
    conf['fuel_user'] = None
    conf['fuel_pass'] = None
    conf['fuel_tenant'] = None

    conf['fuelclient'] = True  # use fuelclient library by default
    conf['fuel_skip_proxy'] = True
    conf['fuel_logs_remote_dir'] = ['/var/log/docker-logs/remote',
                                    '/var/log/remote']
    conf['fuel_logs_no_remote'] = False  # do not collect /var/log/remote
    '''Do not collect from /var/log/remote/<node>
    if node is in the array of nodes filtered out by soft filter'''
    conf['fuel_logs_exclude_filtered'] = True
    return conf


class Node(BaseNode):
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

    def get_cluster_id(self):
        self.logger.debug('%s: cluster id not defined, trying to determine' %
                          self.repr)
        astute_file = '/etc/astute.yaml'
        cmd = ("python -c 'import yaml; a = yaml.load(open(\"%s\")"
               ".read()); print a[\"cluster\"][\"id\"]'" % astute_file)
        outs, errs, code = tools.ssh_node(ip=self.ip,
                                          command=cmd,
                                          ssh_opts=self.ssh_opts,
                                          env_vars=self.env_vars,
                                          timeout=self.timeout,
                                          prefix=self.prefix)
        return int(outs.rstrip('\n')) if code == 0 else None

    def log_item_manipulate(self, item):
        if self.fuel_logs_no_remote and 'fuel' in self.roles:
            self.logger.debug('adding Fuel remote logs to exclude list')
            if 'exclude' not in item:
                item['exclude'] = []
            for remote_dir in self.fuel_logs_remote_dir:
                item['exclude'].append(remote_dir)
        if 'fuel' in self.roles:
            for n in self.logs_excluded_nodes:
                self.logger.debug('removing remote logs for node:%s' % n)
                if 'exclude' not in item:
                    item['exclude'] = []
                for remote_dir in self.fuel_logs_remote_dir:
                    ipd = os.path.join(remote_dir, n)
                    item['exclude'].append(ipd)


class NodeManager(BaseNodeManager):
    @staticmethod
    def load_conf(filename):
        config = conf.init_default_conf()
        config = add_conf(config)
        config = conf.update_conf(config, filename)
        return config

    def __init__(self, conf, nodes_json=None, logger=None):
        self.base_init(conf, logger)
        self.token = self.conf['fuel_api_token']
        fuelnode = self.fuel_init()
        self.logs_excluded_nodes = []
        if FuelClient and conf['fuelclient']:
            # save os environment variables
            environ = os.environ
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
            os.environ = environ
        else:
            self.logger.info('Skipping setup fuelclient instance')
            self.fuelclient = None
        if nodes_json:
            self.nodes_json = tools.load_json_file(nodes_json)
        else:
            if (not self.get_nodes_fuelclient() and
                    not self.get_nodes_api() and
                    not self.get_nodes_cli()):
                sys.exit(105)
        self.nodes_init(Node)
        # get release information for all nodes
        if fuelnode.accessible:
            self.get_release()
        self.post_init()
        fuelnode.logs_excluded_nodes = self.logs_excluded_nodes

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
            fuelnode.skipped = True
        self.nodes[self.conf['fuel_ip']] = fuelnode
        return fuelnode

    def apply_soft_filter(self):
        # apply soft-filter on all nodes
        for node in self.nodes.values():
            if not self.filter(node, self.conf['soft_filter']):
                node.skipped = True
                if self.conf['fuel_logs_exclude_filtered']:
                    if node.fqdn:
                        self.logs_excluded_nodes.append(node.fqdn)
                    self.logs_excluded_nodes.append(node.ip)

    def get_release(self):
        if (not self.get_release_fuel_client() and
                not self.get_release_api() and
                not self.get_release_cli()):
            self.logger.warning('could not get Fuel and MOS versions')

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
        for key, node in self.selected_nodes.items():
            run_items.append(tools.RunItem(target=node.get_release,
                                           key=key))
        result = tools.run_batch(run_items, 100, dict_result=True)
        if result:
            for key in result:
                self.nodes[key].release = result[key]
            return True
        else:
            return False

    def nodes_init_fallbacks(self):
        self.nodes_get_roles_hiera()
        self.nodes_get_os()
        self.nodes_get_cluster_ids()

    def nodes_get_roles_hiera(self, maxthreads=100):
        run_items = []
        for key, node in self.selected_nodes.items():
            if node.status != 'discover' and not node.roles:
                run_items.append(tools.RunItem(target=node.get_roles_hiera,
                                               key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            if result[key]:
                self.nodes[key].roles = result[key]

    def nodes_get_cluster_ids(self, maxthreads=100):
        self.logger.debug('getting cluster ids from nodes')
        run_items = []
        for key, node in self.selected_nodes.items():
            if not node.cluster:
                run_items.append(tools.RunItem(target=node.get_cluster_id,
                                               key=key))
        result = tools.run_batch(run_items, maxthreads, dict_result=True)
        for key in result:
            if result[key] is not None:
                self.nodes[key].cluster = result[key]

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
