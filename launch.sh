rm -rf info
time (./cmds.py -e 1 -d -v 2>&1 | tee cmds.log; ./getlogs.py -d -v 2>&1 | tee getlogs.log)
