#! /usr/bin/env python2
# -*- coding: utf-8 -*-

#    The MIT License (MIT)
#    Copyright (c) 2009 Max Polk
#    Permission is hereby granted, free of charge, to any person
#    obtaining a copy of this software and associated documentation files
#    (the "Software"), to deal in the Software without restriction,
#    including without limitation the rights to use, copy, modify, merge,
#    publish, distribute, sublicense, and/or sell copies of the Software,
#    and to permit persons to whom the Software is furnished to do so,
#    subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be
#    included in all copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
#    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
#    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
#    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import os
import errno
import fcntl


class FLock:
    '''
    Ensures application is running only once, by using a lock file.

    Ensure call to lock works.  Then call unlock at program exit.

    You cannot read or write to the lock file, but for some reason you can
    remove it.  Once removed, it is still in a locked state somehow.  Another
    application attempting to lock against the file will fail, even though
    the directory listing does not show the file.  Mysterious, but we are glad
    the lock integrity is upheld in such a case.

    Instance variables:
        lockfile  -- Full path to lock file
        lockfd    -- File descriptor of lock file exclusively locked
    '''
    def __init__(self, lockfile):
        self.lockfile = lockfile
        self.lockfd = None

    def lock(self):
        '''
        Creates and holds on to the lock file with exclusive access.
        Returns True if lock successful, False if it is not, and raises
        an exception upon operating system errors encountered creating the
        lock file.
        '''
        try:
            #
            # Create or else open and trucate lock file, in read-write mode.
            #
            # A crashed app might not delete the lock file, so the
            # os.O_CREAT | os.O_EXCL combination that guarantees
            # atomic create isn't useful here.  That is, we don't want to
            # fail locking just because the file exists.
            #
            # Could use os.O_EXLOCK, but that doesn't exist yet in my Python
            #
            self.lockfd = os.open(self.lockfile,
                                  os.O_TRUNC | os.O_CREAT | os.O_RDWR)

            # Acquire exclusive lock on the file,
            # but don't block waiting for it
            fcntl.flock(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            # Writing to file is pointless, nobody can see it
            os.write(self.lockfd, "lockfile")

            return True
        except (OSError, IOError), e:
            # Lock cannot be acquired is okay,
            # everything else reraise exception
            if e.errno in (errno.EACCES, errno.EAGAIN):
                return False
            else:
                raise

    def unlock(self):
        try:
            # FIRST unlink file, then close it.  This way, we avoid file
            # existence in an unlocked state
            os.unlink(self.lockfile)
            # Just in case, let's not leak file descriptors
            os.close(self.lockfd)
        except (OSError, IOError):
            # Ignore error destroying lock file.  See class doc about how
            # lockfile can be erased and everything still works normally.
            pass


# Test main routine
if __name__ == '__main__':
    import time
    applock = FLock('./cmds.lock')
    if (applock.lock()):
        # Hint: try running 2nd program instance while this instance sleeps
        print("Obtained lock, sleeping 10 seconds")
        time.sleep(10)
        print("Unlocking")
        applock.unlock()
    else:
        print("Unable to obtain lock, exiting")
