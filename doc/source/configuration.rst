=====================
General configuration
=====================

All default configuration values are defined in ``timmy/conf.py``. Timmy works with these values if no configuration file is provided.
If a configuration file is provided via ``-c | --config`` option, it overlays the default configuration.
An example of a configuration file is ``config.yaml``.

Some of the parameters available in configuration file:

* **ssh_opts** parameters to send to ssh command directly (recommended to leave at default), such as connection timeout, etc. See ``timmy/conf.py`` to review defaults.
* **env_vars** environment variables to pass to the commands and scripts - you can use this to expand variables in commands or scripts
* **fuel_ip** the IP address of the master node in the environment
* **fuel_user** username to use for accessing Nailgun API
* **fuel_pass** password to access Nailgun API
* **rqdir** the path of *rqdir*, the directory containing scripts to execute and filelists to pass to rsync
* **out_dir** directory to store output data
* **archive_dir** directory to put resulting archives into
* **timeout** timeout for SSH commands and scripts in seconds

===================
Configuring actions
===================

Actions can be configured in a separate yaml file (by default ``rq.yaml`` is used) and / or defind in the main config file or passed via command line options ``-P``, ``-C``, ``-S``, ``-G``.

The following actions are available for definition:

* **put** - a list of tuples / 2-element lists: [source, destination]. Passed to ``scp`` like so ``scp source <node-ip>:destination``. Wildcards supported for source.
* **cmds** - a list of dicts: {'command-name':'command-string'}. Example: {'command-1': 'uptime'}. Command string is a bash string. Commands are executed in a sorted order of their names.
* **scripts** - a list of elements, each of which can be a string or a dict:
    * string - represents a script filename located on a local system. If filename does not contain a path separator, the script is expected ot be located inside ``rqdir/scripts``. Otherwise the provided path is used to access the script. Example: ``'./my-test-script.sh'``
    * dict - use this option if you need to pass variables to your script. Script parameters are not supported, but instead you can use env variables. A dict should only contain one key which is the script filename (read above), and the value is a Bash space-separated variable assignment string. Example: ``'./my-test-script.sh': 'var1=123 var2="HELLO WORLD"'``
    * **LIMITATION**: if you use a script with the same name more than once for a given node, the collected output will only contain the last execution's result.
    * **INFO**: Scripts are not copied to the destination system - script code is passed as stdin to `bash -s` executed via ssh or locally. Therefore passing parameters to scripts is not supported (unlike cmds where you can write any Bash string). You can use variables in your scripts instead. Scripts are executed in the following order: all scripts without variables, sorted by their full filename, then all scripts with variables, also sorted by full filename. Therefore if the order matters, it's better to put all scripts into the same folder and name them according to the order in which you want them executed on the same node, and mind that scripts with variables are executed after all scripts without variables. If you need to mix scripts with variables and without and maintain order, just use dict structure for all scripts, and set `null` as the value for those which do not need variables.
* **files** - a list of filenames to collect. passed to ``scp``. Supports wildcards.
* **filelists** - a list of filelist filenames located on a local system. Filelist is a text file containing files and directories to collect, passed to rsync. Does not support wildcards. If filename does not contain path separator, the filelist is expected to be located inside ``rqdir/filelists``. Otherwise the provided path is used to read the filelist.
* **logs**
    * **path** - base path to scan for logs
    * **include** - regexp string to match log files against for inclusion (if not set = include all)
    * **exclude** - regexp string to match log files against. Excludes matched files from collection.
    * **start** - date or datetime string to collect only files modified on or after the specified time. Format - ``YYYY-MM-DD`` or ``YYYY-MM-DD HH:MM:SS`` or ``-N`` where N = number of days from now (number should be negative, meaning last N days).

===============
Filtering nodes
===============

* **soft_filter** - use to skip any operations on non-matching nodes
* **hard_filter** - same as above but also removes non-matching nodes from NodeManager.nodes dict - useful when using timmy as a module

Nodes can be filtered by the following parameters defined inside **soft_filter** and/or **hard_filter**:
 * **roles** - the list of roles, ex. **['controller','compute']**
 * **online** - enabled by default to skip non-accessible nodes
 * **status** - the list of statuses. Default: **['ready', 'discover']**
 * **ids** - the list of ids, ex. **[0,5,6]**
 * any other attribute of Node object which is a simple type (int, float, str, etc.) or a list containing simple types

Lists match **any**, meaning that if any element of the filter list matches node value (if value is a list - any element in it), node passes.

Negative filters are possible by pretending filter parameter with **no_**, example: **no_id = [0]** will filter out Fuel.

Negative lists also match **any** - if any match / collision found, node is skipped.

You can combine any number of positive and negative filters as long as their names differ (since this is a dict).

You can use both positive and negative parameters to match the same node parameter (though it does not make much sense):
**roles = ['controller', 'compute']**
**no_roles = ['compute']**
This will skip computes and run only on controllers. Like stated above, does not make much sense :)

=============================
Parameter-based configuration
=============================

It is possible to define special **by_<parameter-name>** dicts in config to (re)define node parameters based on other parameters. For example:

::

  by_roles:
    controller:
      cmds: {'check-uptime': 'uptime'}

In this example for any controller node, cmds setting will be reset to the value above. For nodes without controller role, default (none) values will be used.

It is also possible to define a special **once_by_<parameter-name>** which works similarly, but will only result in attributes being assigned to single (first in the list) matching node. Example:

::

  once_by_roles:
    controller:
      cmds: {'check-uptime': 'uptime'}

Such configuration will result in `uptime` being executed on only one node with controller role, not on every controller.

=============
rqfile format
=============

``rqfile`` format is a bit different from config. The basic difference:

**config:**

::

  scripts: [a ,b, c]
  by_roles:
    compute:
      scripts: [d, e, f]

**rqfile:**

::

  scripts:
    __default: [a, b, c]
    by_roles:
      compute: [d, e, f]

The **config** and **rqfile** definitions presented above are equivalent. It is possible to define config in a config file using the **config** format, or in an **rqfile** using **rqfile** format, linking to the **rqfile** in config with ``rqfile`` setting. It is also possible to define part here and part there. Mixing identical parameters in both places is not recommended - results may be unpredictable (such scenario was not thoroughly tested). In general **rqfile** is good for fewer settings with more parameter-based variations (``by_``), and main config for more different settings with less such variations.

===============================
Configuration application order
===============================

Configuration is assembled and applied in a specific order:

1. default configuration is initialized. See ``timmy/conf.py`` for details.
2. command line parameters, if defined, are used to modify the configuration.
3. **rqfile**, if defined (default - ``rq.yaml``), is converted and injected into the configuration. At this stage the configuration is in its final form.
4. for every node, configuration is applied, except ``once_by_`` directives:
    1. first the top-level attributes are set
    2. then ``by_<attribute-name>`` parameters except ``by_id`` are iterated to override or append(accumulate) the attributes
    3. then ``by_id`` is iterated to override any matching attributes, redefining what was set before
5. finally ``once_by_`<attribute-name>`` parameters are applied - only for one matching node for any set of matching values. This is useful for example if you want a specific file or command from only a single node matching a specific role, like running ``nova list`` only on one controller.

Once you are done with the configuration, you might want to familiarize yourself with :doc:`Usage </usage>`.
