=====
Usage
=====

The easiest way to launch timmy would be running the ``launch.sh`` script.
However, you need to :doc:`configure </configuration>` it first.

Basically, the ``launch.sh`` is a simple wrapper that launches ``cmds.py`` and ``getlogs.py``.
The first script launches commands on remote hosts and records outputs, and the second one gathers some logs.

The ``cmds.py`` script accepts the following parameters:

* ``--config`` the configuration file location, default is *config.yaml*
* ``-o``, ``--dest-file`` the location for output archives, default is */tmp*
* ``-e``, ``--extended`` execute commands once by roles
* ``-c``, ``--cluster`` ability to provide the cluster ID
* ``-d``, ``--debug`` debugging mode, return more debugging info
* ``-v``, ``--verbose`` verbose mode

The ``getlogs.py`` script accepts the following parameters:

* ``-a``, ``--dest-file`` the location for output archives, default is */tmp*
* ``-l``, ``--log-dir`` directory for storing logs, default is *./logs/*
* ``-c``, ``--cluster`` ability to provide the cluster ID
* ``-d``, ``--debug`` debugging mode, return more debugging info
* ``-v``, ``--verbose`` verbose mode

Back to :doc:`Index </index>`.
