=====
Usage
=====

The easiest way to launch timmy would be running the ``timmy.py`` script.
However, you need to :doc:`configure </configuration>` it first.

Basically, the ``timmy.py`` is a simple wrapper that launches ``cli.py``.

Basic parameters:

* ``--only-logs`` collect only logs (skip files, filelists, commands and scripts)
* ``-l``, ``--logs`` also collect logs (logs are not collected by default due to their size)
* ``-C <command>`` enables ``shell mode``\*, Bash command (string) to execute on nodes
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

Back to :doc:`Index </index>`.
