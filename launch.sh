export LC_ALL=C
export LANG=C
export TERM=xterm

rm -rf info
time (./cmds.py -e 1 -d -v 2>&1 | tee cmds.log; ./getlogs.py -d -v 2>&1 | tee getlogs.log)
