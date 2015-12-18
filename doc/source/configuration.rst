=============
Configuration
=============

There is default configuration file ``config.yaml``, which is used by the scripts by default.
If you wish to keep several configuration files, that is possible - just copy it and explicitly provide the name of it once you launch a script (``--config`` option) (not yet implemented in ``getlogs.py``).

Here is the description of available parameters in configuration file:

* **ssh** parameters of *SSH*

 * **opts** parameters to send to ssh command directly (recommended to leave at default)
 * **vars** environment variables to set for SSH

* **fuelip** the IP address of the master node in the environment
* **rqdir** the path of *rqdir*, the directory containing info about commands to execute and logs to gather
* **logdir** the path of directory for storing logs
* **out-dir** directory to store output data
* **timeout** timeout for SSH commands in seconds
* **find** parameters of *find*

 * **template** template of parameters to pass to *find* when searching for logs

Once you are done with the configuration, you might want to familiarize yourself with :doc:`Usage </usage>`.
