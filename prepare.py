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
Prepare module
"""

import os
import sys
import json
import glob
import argparse
import os.path


class Node(object):
    """Init node"""
    def __init__(self, node_id, cluster, mac, os_platform,
                 roles, status, online, ip):
        self.node_id = node_id
        self.cluster = cluster
        self.mac = mac
        self.roles = roles
        self.rolelist = roles.split(',')
        self.rfiles = []
        self.os_platform = os_platform
        self.sfiles = []
        self.online = online
        self.status = status
        self.ip = ip

    def __str__(self):
        if self.status == 'ready' and self.online:
            my_id = self.node_id
        else:
            my_id = '#' + self.node_id

        templ = '{0} {1.cluster} {1.ip} {1.mac} {1.os_platform} '
        templ += '{1.roles} {1.online} {1.status}'
        return templ.format(my_id, self)


class Nodes(object):
    """Class nodes """

    def __init__(self, filename, rolesd, sfdir, template, extended,
                 version, fuelip, cluster):
        self.cdir = rolesd
        self.template = template
        self.version = version
        self.sfdir = sfdir
        self.fuelip = fuelip

        self.extended = extended

        with open(filename, 'r') as json_data:
            data = json.load(json_data)
            node = Node(node_id='0',
                        cluster='0',
                        mac='n/a',
                        os_platform='centos',
                        roles='fuel',
                        status='ready',
                        online=True,
                        ip=self.fuelip)

            self.nodes = {self.fuelip: node}

            for node in data:

                node_roles = node.get('roles')
                if node_roles is not None:
                    is_cluster_empty = cluster == "" or cluster is None
                    if is_cluster_empty or cluster == node['cluster']:

                        if isinstance(node_roles, list):
                            roles = ', '.join(map(str, node_roles))
                            roles = roles.replace(' ', '')
                        else:
                            roles = str(node_roles).replace(' ', '')

                        node_ip = str(node['ip'])

                        keys = "cluster mac os_platform status online".split()
                        params = {'node_id': str(node['id']),
                                  'roles': roles,
                                  'ip': node_ip}
                        for key in keys:
                            #  params[key] = str(node[key])
                            params[key] = node[key]
                        #  params['online'] = node['online']

                        self.nodes[node_ip] = Node(**params)

    def printnodes(self):
        """print nodes"""

        print('#node-id, cluster, admin-ip, mac, os, roles, online, status')

        for node in sorted(self.nodes.values(), key=lambda x: x.node_id):
            print(str(node))

    def files_by_role(self):
        """create file by role"""

        for node in self.nodes.values():
            for role in node.rolelist:
                directory = os.path.join(self.cdir, 'by-role', role, '*')
                node.rfiles += glob.glob(directory)

                directory = os.path.join(self.cdir, 'by-role', role,
                                         '.*-' + node.os_platform)
                node.rfiles += glob.glob(directory)

    def files_default(self):
        """files_default"""

        for node in self.nodes.values():
            directory = os.path.join(self.cdir, 'default', 'default', '*')
            node.rfiles += glob.glob(directory)
            directory = os.path.join(self.cdir, 'default', 'default',
                                     '.*-' + node.os_platform)
            node.rfiles += glob.glob(directory)

    def files_once_by_role(self):
        """files once by role"""
        directory = os.path.join(self.cdir, 'once-by-role', '*')
        roles = glob.glob(directory)
        for role in roles:
            rfile = os.path.basename(role)
            for node in self.nodes.values():
                if rfile in node.rolelist:
                    ddir = os.path.join(role, '*')
                    node.rfiles += glob.glob(ddir)
                    ddir = os.path.join(role, '.*-' + node.os_platform)
                    node.rfiles += glob.glob(ddir)
                    break

    def files_by_os(self):
        """files by os"""
        for node in self.nodes.values():
            directory = os.path.join(self.cdir, 'by-os', node.os_platform, '*')
            node.rfiles += glob.glob(directory)

    def files_by_release(self):
        """files by release"""
        directory = os.path.join(self.cdir, 'release-' + self.version, '*')
        roles = glob.glob(directory)
        for role in roles:
            rfile = os.path.basename(role)
            for node in self.nodes.values():
                if rfile in node.rolelist:
                    ddir = os.path.join(role, '*')
                    node.rfiles += glob.glob(ddir)
                    ddir = os.path.join(role, '.*-' + node.os_platform)
                    node.rfiles += glob.glob(ddir)

    def dump_rfiles(self):
        """dump role files"""
        self.files_by_role()
        self.files_default()
        self.files_by_os()
        self.files_by_release()

        if self.extended:
            self.files_once_by_role()

        for ip, node in self.nodes.items():
            oipf = open(self.template + ip + '-cmds.txt', 'w')
            oipf.write("#" + str(node.node_id + '\n'))
            oipf.write("#roles: " + str(node.roles) + '\n')
            for rfile in sorted(set(node.rfiles)):
                oipf.write(str(rfile)+'\n')
            oipf.close()

    def static_files_by_role(self):
        """method to get static files. Static files by role"""
        for node in self.nodes.values():
            for role in node.rolelist:
                directory = os.path.join(self.sfdir, 'by-role', role, '*')
                node.sfiles += glob.glob(directory)
                directory = os.path.join(self.sfdir, 'by-role', role,
                                         '.*-' + node.os_platform)
                node.sfiles += glob.glob(directory)

    def static_files_default(self):
        """static files default"""
        for node in self.nodes.values():
            directory = os.path.join(self.sfdir, 'default', 'default', '*')
            node.sfiles += glob.glob(directory)
            directory = os.path.join(self.sfdir, 'default', 'default',
                                     '.*-' + node.os_platform)
            node.sfiles += glob.glob(directory)

    def static_files_by_os(self):
        """static files by OS"""
        for node in self.nodes.values():
            directory = os.path.join(self.sfdir, 'by-os',
                                     node.os_platform, '*')
            node.sfiles += glob.glob(directory)

    def static_files_by_release(self):
        """static files by release"""
        directory = os.path.join(self.sfdir, 'release-' + self.version, '*')
        roles = glob.glob(directory)
        for role in roles:
            rfile = os.path.basename(role)
            for node in self.nodes.values():
                if rfile in node.rolelist:
                    ddir = os.path.join(role, '*')
                    node.sfiles += glob.glob(dd)
                    ddir = os.path.join(role, '.*-' + node.os_platform)
                    node.sfiles += glob.glob(ddir)

    def static_dump_rfiles(self):
        """static dump role files"""
        self.static_files_by_role()
        self.static_files_default()
        self.static_files_by_os()
        self.static_files_by_release()

        for ip, node in self.nodes.items():
            fname = self.template + ip + '-files.txt'

            file_lines = ["#{0}".format(node.node_id)]
            file_lines.append("#roles: {0}".format(node.roles))
            file_lines.extend(sorted(set(node.sfiles)))

            with open(fname, 'w') as oipf:
                oipf.write("\n".join(file_lines) + "\n")


def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description='get cluster id')
    parser.add_argument('-f', '--nodes', required=True,
                        help='nodes file', default='./logs/nodes.json')
    parser.add_argument('-v', '--fuel-version', required=True,
                        help='fuel version')
    parser.add_argument('-t', '--template',
                        help='template of cmdfiles', default='./logs/ip-')
    parser.add_argument('-r', '--rolesd',
                        help='directory of cmdfiles', default='./cmd')
    parser.add_argument('-s', '--req-files',
                        help='directory of requested files',
                        default='./req-files')
    parser.add_argument('-e', '--extended', default="0",
                        help='exec once by role cmdfiles')
    parser.add_argument('-c', '--cluster', help='cluster id')
    parser.add_argument('-i', '--admin-ip',
                        help='fuel admin ip address', default="localhost")

    args = parser.parse_args(argv[1:])
    args.extended = args.extended == "1"

    fnodes = Nodes(filename=args.nodes,
                   rolesd=args.rolesd,
                   sfdir=args.req_files,
                   template=args.template,
                   extended=str(args.extended),
                   version=args.fuel_version,
                   fuelip=args.admin_ip,
                   cluster=args.cluster)

    fnodes.printnodes()
    fnodes.files_by_role()
    fnodes.dump_rfiles()
    fnodes.static_dump_rfiles()
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))
