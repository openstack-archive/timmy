=====
Usage
=====

The easiest way to launch timmy would be running the ``timmy.py`` script.
However, you need to :doc:`configure </configuration>` it first.

Basically, the ``timmy.py`` is a simple wrapper that launches ``cli.py``.
Full :doc:`reference </cli>` for command line interface

Basic parameters:

* ``--only-logs`` only collect logs (skip files, filelists, commands and scripts)
* ``-l``, ``--logs`` also collect logs (logs are not collected by default due to their size)
* ``-C <command>`` enables ``shell mode``\*, Bash command (string) to execute on nodes. Using multiple ``-C`` statements will give the same result as using one with several commands separated by ``;`` (traditional Shell syntax), but for each ``-C`` statement a new SSH connection is established
* ``-S <script>`` enables ``shell mode``, name of the Bash script file (you need to put it into ``scripts`` folder inside a path specified by ``rqdir`` config parameter, defaults to ``rq``) to execute on nodes
* ``-P <file/path> <dest>`` enables ``shell mode``, upload local data to nodes (wildcards supported). You must specify 2 values for each ``-P`` switch.
* ``-G <file/path>`` enables ``shell mode``, download (collect) data from nodes
* ``-e``, ``--env`` filter by environment ID
* ``-R``, ``--role`` filter by role
* ``--config`` use custom configuration file to overwrite defaults. See ``config.yaml`` as an example
* ``-j``, ``--nodes-json`` use json file instead of polling Fuel (to generate json file use ``fuel node --json``) - speeds up initialization
* ``-o``, ``--dest-file`` the name/path for output archive, default is ``general.tar.gz`` and put into ``/tmp/timmy/archives``.
* ``-v``, ``--verbose`` verbose(INFO) logging
* ``-d``, ``--debug`` debug(DEBUG) logging

Shell mode - rqfile (``rq.yaml`` by default) is skipped, Fuel node is skipped, outputs of commands (specified with ``-C`` options) and scripts (specified with ``-S``) are printed on screen.

========
Examples
========

* ``timmy -C 'uptime; free -m'`` - check uptime and memory on all nodes
* ``timmy -G /etc/nova/nova.conf`` - get nova.conf from all nodes
* ``timmy -R controller -P package.deb '' -C 'dpkg -i package.deb' -C 'rm package.deb' -C 'dpkg -l | grep [p]ackage'`` - push a package to all nodes, install it, remove the file and check that it is installed
* ``timmy -с myconf.yaml`` - use a custom config file and run according to it

===============================
Using custom configuration file
===============================

If you want to do a set of actions on the nodes and you do not want to write a long command line (or you want to use options only available in config), you may want to set up config file instead. An example config structure would be:

::

  rqdir: './pacemaker-debug' # a folder which should contain any filelists and/or scripts if they are defined later, should contain folders 'filelists' and/or 'scripts' 
  rqfile: None # explicitly undefine rqfile to skip default filelists and scripts
  hard_filter:
    roles: # only execute on Fuel and controllers
      - fuel
      - controller 
  cmds: # some commands to run on all nodes (after filtering). cmds syntax is {name: value, ...}. cmds are executed in alphabetical order of names.
    01-my-first-command: 'uptime'
    02-disk-check: 'df -h'
    and-also-ram: 'free -m'
  logs:
    exclude: '.*' # exclude all logs by default
  by_roles:
    controller:
      scripts: # I use script here to not overwrite cmds we have already defined for all nodes earlier
        - pacemaker-debug.sh # the name of the file inside 'scripts' folder inside 'rqdir' path, which will be executed (by default) on all nodes
      files:
        - '/etc/coros*' # get all files from /etc/coros* wildcard path
    fuel:
      logs:
        include: 'crmd|lrmd|corosync|pacemaker' # only get logs which names match (re.search is used) this regexp

Then you would run ``timmy -l -c my-config.yaml`` to execute timmy with such config.

Instead of setting all structure in a config file you can move actions (cmds, files, filelists, scripts, logs) to an rqfile, and specify ``rqfile`` path in config (although with this example the config-way is more compact). ``rqfile`` structure is a bit different:

::

  cmds: # top-level elements are node parameters, __default will be assigned to all nodes
    __default:
      - 01-my-first-command: 'uptime'
      - 02-disk-check: 'df -h'
      - and-also-ram: 'free -m'
  scripts:
    by_roles: # all non "__default" keys should be matches, "by_<parameter>"
      controller: 
        - pacemaker-debug.sh
  files:
    by_roles:
      controller:
        - '/etc/coros*'
  logs:
    by_roles:
      fuel:
        include: 'crmd|lrmd|corosync|pacemaker'
    __default:
        exclude: '.*'

Then the config should look like:

::

  rqdir: './pacemaker-debug'
  rqfile: './pacemaker-rq.yaml'
  hard_filter:
    roles:
      - fuel
      - controller

And you run ``timmy -l -c my-config.yaml``.

Back to :doc:`Index </index>`.
