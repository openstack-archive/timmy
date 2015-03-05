=================
Configuration
=================

Timmy is usually ready to be used as is, however, it can be slightly tweaked according to your needs.

The following useful variables are available in **env.sh** configuration file:

* **cluster** - specific cluster to inspect, commented out by default so all clusters are used
* **extended** - extended run, considers role-specific commands
* **sshopts** - parameters for SSH
* **env_timeout** - SSH command timeout
* **sshvars** - variables for commands executed on the nodes. *OPENRC* variable contains path to the file that should be sourced
* **stemplate** - prefix for naming the snapshots
