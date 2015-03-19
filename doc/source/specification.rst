=======
Specification
=======

* This tool is based on https://etherpad.openstack.org/p/openstack-diagnostics
* Should work fine on the following environments that were tested: 4.x, 5.x, 6.0
* Operates non-destructively. Completely safe.
* Can be launched not only on the master node, if the master node's IP is specified.
* Parallel launch, only on the nodes that are 'online'.
* Commands (from ./cmds directory) are separated by roles (detected automatically) by the symlinks. So the command list may depend on release, roles and OS, there also can be commands that run everywhere. Also there are commands that are executed *only on one node* by its *role*, first encountered.
* Human-readable format output of 'fuel node list' (check ./info/nodes.txt :) )
* Modular: possible to create a special package that contains only some required commands.
* 2 archives are being created - *min* and *all* - only outputs and outputs+files respectively.
