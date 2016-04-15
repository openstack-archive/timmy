=====
Usage
=====

The easiest way to launch timmy would be running the ``timmy.py`` script.
However, you need to :doc:`configure </configuration>` it first.

Basically, the ``timmy.py`` is a simple wrapper that launches ``cli.py``.

The script accepts the following parameters:

* ``--config`` the configuration file location, default is *config.yaml*
* ``-o``, ``--dest-file`` the location for output archives, default is */tmp/archives/general.tar.bz2*
* ``-e``, ``--extended`` execute commands once by roles
* ``-c``, ``--cluster`` ability to provide the cluster ID
* ``-d``, ``--debug`` debugging mode, return more debugging info
* ``-v``, ``--verbose`` verbose mode
* ``--only-logs`` collect only logs from nodes (without commands)
* ``-l``, ``--logs`` collect log files from nodes

Back to :doc:`Index </index>`.
