=====
Usage
=====

**NOTICE:** Even though Timmy uses nice and ionice to limit impact on the cloud, you should still expect 1 core utilization both locally (where Timmy is launched) and on each node where commands are executed or logs collected. Additionally, if logs are collected, local disk (log destination directory) may get utilized significantly.

**WARNING** If modifying the ``outdir`` config parameter, please first read the related warning on `configuration </configuration>` page.

The easiest way to launch Timmy would be running the ``timmy.py`` script / ``timmy`` command:
* Timmy will perform all actions defined in the ``default.yaml`` rq-file. The file is located in ``timmy_data/rq`` folder in Python installation directory. Specifically:
    * run diagnostic scripts on all nodes, including Fuel server
    * collect configuration files for all nodes
* Timmy will **NOT** collect log files when executed this way.


Basically, ``timmy.py`` is a simple wrapper that launches ``cli.py``.
* Current page does not reference all available CLI options. Full :doc:`reference </cli>` for command line interface.
* You may also want to create a custom :doc:`configuration </configuration>` for Timmy, depending on your use case.

Basic parameters:

* ``--only-logs`` only collect logs (skip files, filelists, commands and scripts)
* ``-l``, ``--logs`` also collect logs (logs are not collected by default due to their size)
* ``-e``, ``--env`` filter by environment ID
* ``-R``, ``--role`` filter by role
* ``-c``, ``--config`` use custom configuration file to overwrite defaults. See ``timmy_data/config/example.yaml`` as an example
* ``-j``, ``--nodes-json`` use json file instead of polling Fuel (to generate json file use ``fuel node --json``) - speeds up initialization
* ``-o``, ``--dest-file`` the name/path for output archive, default is ``general.tar.gz`` and put into ``/tmp/timmy/archives``. A folder will be created if it does not exist. It's not recommended to use ``/var/log`` as destination because subsequent runs with log collection may cause Timmy to collect it's own previously created files or even update them while reading from them. The general idea is that a destination directory should contain enough space to hold all collected data and should not be in collection paths.
* ``-v``, ``--verbose`` verbose(INFO) logging. Use ``-vv`` to enable DEBUG logging.

==========
Shell Mode
==========

**Shell Mode** is activated whenever any of the following parameters are used via CLI: ``-C``, ``-S``, ``-P``, ``-G``.

A mode of execution which makes the following changes:

* rqfile (``timmy_data/rq/default.yaml`` by default) is skipped
* Fuel node is skipped. If for some reason you need to run specific scripts/actions via Timmy on Fuel and on other nodes at the same time, create an rqfile instead (see :doc:`configuration </configuration>` for details, see ``timmy_data/rq/neutron.yaml`` as an example), coupled with ``--rqfile`` option or a custom config file to override default rqfile.
* outputs of commands (specified with ``-C`` options) and scripts (specified with ``-S``) are printed on screen
* any actions (cmds, scripts, files, filelists, put, **except** logs) and Parameter Based configuration defined in config are ignored.

The following parameters ("actions") are available via CLI:

* ``-C <command>`` - Bash command (string) to execute on nodes. Using multiple ``-C`` statements will produce the same result as using one with several commands separated by ``;`` (traditional Shell syntax), but for each ``-C`` statement a new SSH connection is established.
* ``-S <script>`` - name of the Bash script file to execute on nodes (if you do not have a path separator in the filename, you need to put the file into ``scripts`` folder inside a path specified by ``rqdir`` config parameter, defaults to ``rq``. If a path separator is present, the given filename will be used directly as provided)
* ``-P <file/path> <dest>`` - upload local data to nodes (wildcards supported). You must specify 2 values for each ``-P`` switch.
* ``-G <file/path>`` - download (collect) data from nodes

====
Logs
====

It's possible to specify custom log collection when using CLI:
* ``-L <base-path> <include-regex> <exclude-regex>``, ``--get-logs`` - specify a base path, include regex and exclude regex to collect logs. This option can be specified more than once, in this case log lists will be united. This option **does not** disable default log collection defined in ``timmy_data/rq/default.yaml``.
* ``--logs-no-default``  - use this option of you **only** need logs specified via ``-L``.

===============
Execution order
===============

Specified actions are executed for all applicable nodes, always in the following order:
1. put
2. commands
3. scripts
4. get, filelists
5. logs

========
Examples
========

* ``timmy`` - run according to the default configuration and default actions. Default actions are defined in ``timmy_data/rq/default.yaml``. Logs are not collected.
* ``timmy -l`` - run default actions and also collect logs. Such execution is similar to Fuel's "diagnostic snapshot" action, but will finish faster and collect less logs. There is a default log collection period based on file modification time, only files modified within the last 30 days are collected.
* ``timmy -l --days 3`` - same as above but only collect log files updated within the last 3 days.
* ``timmy --only-logs`` - only collect logs, no actions (files, filelists, commands, scripts, put, get) performed.
* ``timmy -C 'uptime; free -m'`` - check uptime and memory on all nodes
* ``timmy -G /etc/nova/nova.conf`` - get ``nova.conf`` from all nodes
* ``timmy -R controller -P package.deb '' -C 'dpkg -i package.deb' -C 'rm package.deb' -C 'dpkg -l | grep [p]ackage'`` - push a package to all nodes, install it, remove the file and check that it is installed. Commands are executed in the order in which they are provided.
* ``timmy -с myconf.yaml`` - use a custom config file and run the program according to it. Custom config can specify any actions, log setup, and other settings. See configuration doc for more details.

===============================
Using custom configuration file
===============================

If you want to perform a set of actions on the nodes without writing a long command line (or if you want to use the options only available in config), you may want to set up config file instead. An example config structure would be:

::

  rqdir: './pacemaker-debug' # a folder which should contain any filelists and/or scripts if they are defined later, should contain folders 'filelists' and/or 'scripts' 
  rqfile: null # explicitly undefine rqfile to skip default filelists and scripts
  hard_filter:
    roles: # only execute on Fuel and controllers
      - fuel
      - controller 
  cmds: # some commands to run on all nodes (after filtering). cmds syntax is {name: value, ...}. cmds are executed in alphabetical order.
    01-my-first-command: 'uptime'
    02-disk-check: 'df -h'
    and-also-ram: 'free -m'
  logs:
    path: '/var/log' # base path to search for logs
    exclude: # a list of exclude regexes
      - '.*' # exclude all logs by default - does not make much sense - just an example. If the intention is to not collect all logs then this 'logs' section can be removed altogether, just ensure that either rqfile is custom or 'null', or '--logs-no-default' is set via CLI / 'logs_no_default: True' set in config.
  logs_days: 5 # collect only log files updated within the last 5 days
  # an example of parameter-based configuration is below:
  by_roles:
    controller:
      scripts: # I use script here to not overwrite the cmds we have already defined for all nodes 
        - pacemaker-debug.sh # the name of the file inside 'scripts' folder inside 'rqdir' path, which will be executed (by default) on all nodes
      files:
        - '/etc/coros*' # get all files from /etc/coros* wildcard path
    fuel:
      logs:
        path: '/var/log/remote'
        include: # include regexp - non-matching log files will be excluded.
          - 'crmd|lrmd|corosync|pacemaker'

Then you would run ``timmy -l -c my-config.yaml`` to execute Timmy with such config.

Instead of putting all structure in a config file you can move actions (cmds, files, filelists, scripts, logs) to an rqfile, and specify ``rqfile`` path in config (although in this example the config-way is more compact). ``rqfile`` structure is a bit different:

::

  cmds: # top-level elements are node parameters, __default will be assigned to all nodes
    __default:
      - 01-my-first-command: 'uptime'
      - 02-disk-check: 'df -h'
      - and-also-ram: 'free -m'
  scripts:
    by_roles: # all non "__default" keys should match, "by_<parameter>"
      controller: 
        - pacemaker-debug.sh
  files:
    by_roles:
      controller:
        - '/etc/coros*'
  logs:
    by_roles:
      fuel:
        path: '/var/log/remote'
        include:
          - 'crmd|lrmd|corosync|pacemaker'
    __default: # again, this default section is useless, just serving as an example here.
      path: '/var/log'
      exclude:
        - '.*'

Then the config should look like this:

::

  rqdir: './pacemaker-debug'
  rqfile:
    - file: './pacemaker-rq.yaml'
  hard_filter:
    roles:
      - fuel
      - controller

And you run ``timmy -l -c my-config.yaml``.

Back to :doc:`Index </index>`.
