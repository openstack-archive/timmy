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

"""Prepare module
Prepare module
"""

import json
import argparse
import sys
import glob
import os

r = "\t"


class node():
    """Init node"""
    def __init__ (self, id, cluster, mac, os, roles, status, online ):
        self.id = id
        self.cluster = cluster
        self.mac = mac
        self.roles = roles
        self.rolelist = roles.split(',')
        self.rfiles = []
        self.os = os
        self.sfiles = []
        self.online = online
        self.status = status


class nodes():
    """Class nodes """
    def __init__ (self, filename, rolesd, sfdir, template, extended, version, fuelip ):
        self.cdir = rolesd
        self.template = template
        self.version = version
        self.sfdir = sfdir
        self.fuelip = fuelip
        if extended == "1":
            self.ex = True
        else:
            self.ex = False
        with open(filename,'r') as json_data:
            data = json.load(json_data)
            self.n = {self.fuelip: node('fuel', '0', 'n/a', 'centos', 'fuel', 'ready', True )}
            for i in data:
                if 'roles' in i.keys():
                    if (( args.cluster == "" ) or ( args.cluster == None )) or ( str(args.cluster) == str(i['cluster']) ):
                        if isinstance(i['roles'], list):
                            roles = ', '.join([str(x) for x in i['roles']]).replace(' ', '')
                        else:
                            roles = str(i['roles']).replace(' ', '')
                        self.n[str(i['ip'])] = node(str(i['id']), str(i['cluster']), str(i['mac']), str(i['os_platform']), roles, i['status'], i['online'])

    def printnodes (self):
        """print nodes"""
        print('#node-id, cluster, admin-ip, mac, os, roles, online, status')
        for i in self.n:
            id = self.n[i].id
            if ( self.n[i].status != u'ready' ) or ( self.n[i].online != True ):
                id = '#%s' %(self.n[i].id)
            print('%s %s %s %s %s %s %s %s' %(id, self.n[i].cluster, i, self.n[i].mac, self.n[i].os, str(self.n[i].roles), self.n[i].online, self.n[i].status))

    def files_by_role (self):
        """create file by role"""
        for ip in self.n:
            for role in self.n[ip].rolelist:
                d = self.cdir + '/by-role/' + role + '/*'
                rl = glob.glob(d)
                d = self.cdir + '/by-role/' + role + '/.*-' + self.n[ip].os
                rl += glob.glob(d)
                self.n[ip].rfiles += rl

    def files_default (self):
       """files_default""" 
       for ip in self.n:
            d = self.cdir + '/default/default/*'
            rl = glob.glob(d)
            d = self.cdir + '/default/default/.*-' + self.n[ip].os
            rl += glob.glob(d)
            self.n[ip].rfiles += rl

    def files_once_by_role (self):
        """files once by role"""
        d = self.cdir + '/once-by-role'
        roles = glob.glob(d + '/*')
        for role in roles:
            r = os.path.basename(role)
            for ip in self.n:
                if r in self.n[ip].rolelist:
                    dd = role + '/*'
                    rl = glob.glob(dd)
                    dd = role + '/.*-' + self.n[ip].os
                    rl += glob.glob(dd)
                    self.n[ip].rfiles += rl
                    break

    def files_by_os (self):
        """files by os"""
        for ip in self.n:
            d = self.cdir + '/by-os/' + self.n[ip].os + '/*'
            rl = glob.glob(d)
            self.n[ip].rfiles += rl

    def files_by_release (self):
        """files by release"""
        d = self.cdir + '/release-' + self.version + '/'
        roles = glob.glob(d + '/*')
        for role in roles:
            r = os.path.basename(role)
            for ip in self.n:
                if r in self.n[ip].rolelist:
                    dd = role + '/*'
                    rl = glob.glob(dd)
                    dd = role + '/.*-' + self.n[ip].os
                    rl += glob.glob(dd)
                    self.n[ip].rfiles += rl

    def dump_rfiles (self):
        """dump role files"""
        self.files_by_role()
        self.files_default()
        self.files_by_os()
        self.files_by_release()
        if self.ex:
            self.files_once_by_role()
        for ip in self.n:
            oipf = open(self.template + ip + '-cmds.txt', 'w')
            oipf.write("#" + str(self.n[ip].id + '\n'))
            oipf.write("#roles: " + str(self.n[ip].roles) + '\n' )
            for rfile in set(self.n[ip].rfiles):
                oipf.write(str(rfile)+'\n')
            oipf.close()

    def static_files_by_role (self):
        """ methods to get static files. Static files by role"""
        for ip in self.n:
            for role in self.n[ip].rolelist:
                d = self.sfdir + '/by-role/' + role + '/*'
                rl = glob.glob(d)
                d = self.sfdir + '/by-role/' + role + '/.*-' + self.n[ip].os
                rl += glob.glob(d)
                self.n[ip].sfiles += rl

    def static_files_default (self):
        """static files default"""
        for ip in self.n:
            d = self.sfdir + '/default/default/*'
            rl = glob.glob(d)
            d = self.sfdir + '/default/default/.*-' + self.n[ip].os
            rl += glob.glob(d)
            self.n[ip].sfiles += rl

    def static_files_by_os (self):
        """static files by OS"""
        for ip in self.n:
            d = self.sfdir + '/by-os/' + self.n[ip].os + '/*'
            rl = glob.glob(d)
            self.n[ip].sfiles += rl

    def static_files_by_release (self):
        """static files by release"""
        d = self.sfdir + '/release-' + self.version + '/'
        roles = glob.glob(d + '/*')
        for role in roles:
            r = os.path.basename(role)
            for ip in self.n:
                if r in self.n[ip].rolelist:
                    dd = role + '/*'
                    rl = glob.glob(dd)
                    dd = role + '/.*-' + self.n[ip].os
                    rl += glob.glob(dd)
                    self.n[ip].sfiles += rl

    def static_dump_rfiles (self):
        """static dump role files"""
        self.static_files_by_role()
        self.static_files_default()
        self.static_files_by_os()
        self.static_files_by_release()
        for ip in self.n:
            oipf = open(self.template + ip + '-files.txt', 'w')
            oipf.write("#" + str(self.n[ip].id + '\n'))
            oipf.write("#roles: " + str(self.n[ip].roles) + '\n' )
            for sfile in set(self.n[ip].sfiles):
                oipf.write(str(sfile)+'\n')
            oipf.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='get cluster id')
    parser.add_argument( '-f', '--nodes', required=True, help='nodes file', default = './logs/nodes.json' )
    parser.add_argument( '-v', '--fuel-version', required=True, help='fuel version' )
    parser.add_argument( '-t', '--template', required=False, help='template of cmdfiles', default = './logs/ip-')
    parser.add_argument( '-r', '--rolesd', required=False, help='directory of cmdfiles', default = './cmd')
    parser.add_argument( '-s', '--req-files', required=False, help='directory of requested files', default = './req-files')
    parser.add_argument( '-e', '--extended', required=False, help='exec once by role cmdfiles', default = 0)
    parser.add_argument( '-c', '--cluster', required=False, help='cluster id')
    parser.add_argument( '-i', '--admin-ip', required=False, help='fuel admin ip address', default="localhost")
    args = parser.parse_args()

    fnodes = nodes(filename = args.nodes, rolesd = args.rolesd, template = args.template, extended = str(args.extended), version=args.fuel_version, sfdir = args.req_files, fuelip=args.admin_ip)
    fnodes.printnodes()
    fnodes.files_by_role()
    fnodes.dump_rfiles()
    fnodes.static_dump_rfiles()
