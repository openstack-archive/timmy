=============
Specification
=============

Mirantis OpenStack Ansible-like tool for parallel node operations: two-way data transfer, log collection, remote command execution


* The tool is based on https://etherpad.openstack.org/p/openstack-diagnostics
* Should work fine in the following environments that have been tested: 4.x, 5.x, 6.x, 7.0, 8.0, 9.0
* Operates non-destructively.
* Can be launched on any host within admin network, provided the fuel node IP is specified and access to Fuel and other nodes is possible  via ssh from the local system.
* Parallel launch - only on the nodes that are 'online'. Some filters for nodes are also available.
* Commands (from ./cmds directory) are separated according to roles (detected automatically) by the symlinks. Thus, the command list may depend on release, roles and OS. In addition, there can be some commands that run everywhere. There are also commands that are executed only on one node according to its role, using the first node of this type they encounter.
* Modular: possible to create a special package that contains only certain required commands.
* Collects log files from the nodes using filters
* Some archives are created - general.tar.bz2 and logs-*
* Checks are implemented to prevent filesystem overfilling due to log collection, appropriate error shown.
* Can be imported into other python scripts (ex. https://github.com/f3flight/timmy-customtest) and used as a transport and structure to access node parameters known to Fuel, run commands on nodes, collect outputs, etc. with ease.
