==========
Exit Codes
==========

* `2` - SIGINT (Keyboard Interrupt) caught.
* `100` - not enough free space for logs. Decrease logs coefficient via CLI or config or free up space.
* `101` - **rqdir** configuration parameter points to a non-existing directory.
* `102` - could not load YAML file - I/O Error.
* `103` - could not load YAML file - Value Error, see log for details.
* `104` - could not load YAML file - Parser Error - incorrectly formatted YAML.
* `105` - could not retrieve information about nodes by any available means.
* `106` - **fuel_ip** configuration parameter not defined.
* `107` - could not load JSON file - I/O Error.
* `108` - could not load JSON file - Value Error, see log for details.
* `109` - subprocess (one of the node execution processes) exited with a Python exception.
* `110` - unable to create a directory.
* `111` - ip address must be defined for Node instance.
* `112` - one of the two parameters **fuel_user** or **fuel_pass** specified without the other.
* `113` - unhandled Python exception occured in main process.
