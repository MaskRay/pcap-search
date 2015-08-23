#!/usr/bin/env python2
import os
import tempfile
import sys
import subprocess
import multiprocessing
import struct
import psutil
import hashlib

APFILE=sys.argv[1]
SERVICE=sys.argv[2]
PORT=int(sys.argv[3])

def loconn(loc):
    ret = os.popen("./offset2stream.py %s %d locconn /dev/null /dev/stdout" % (APFILE, loc)).read().strip()
    if not ret:
        return None
    else:
        return int(ret.split()[1])

def gen_replay(loc):
    fd, fname = tempfile.mkstemp(".py")
    os.close(fd)
    os.system("./offset2stream.py %s %d pythondiff /dev/null %s" % (APFILE, loc, fname))
    return fname

_fd, TMPSCRIPTNAME = tempfile.mkstemp(".sh")
os.close(_fd)
os.chmod(TMPSCRIPTNAME, 0755)
fff = open(TMPSCRIPTNAME, "w")
if os.getenv("ARCH") == "mips":
    fff.write("#!/bin/bash\ncd %s;LD_PRELOAD=/tmp/qemu.so qemu-mipsel -U LD_PRELOAD -L /mnt/rootfs-mips -strace %s 2>&1" % (os.path.dirname(SERVICE), SERVICE))
else:
    fff.write("#!/bin/bash\ncd %s;LD_PRELOAD=/tmp/qemu.so qemu-x86_64 -U LD_PRELOAD -strace %s 2>&1" % (os.path.dirname(SERVICE), SERVICE))
fff.close()


existed = set()

mng = multiprocessing.Manager()
existed = mng.dict()
lock = mng.Lock()

def process(loc):
    pocfname = gen_replay(loc)
    fffpoc = open(pocfname, "rb")
    poccode = fffpoc.read()
    fffpoc.close()
    codehash = hashlib.sha1(poccode).hexdigest()
    lock.acquire()
    if codehash in existed:
        lock.release()
        os.unlink(pocfname)
        return loc, -2
    existed[codehash] = 1
    lock.release()
    checker_popen = os.popen("python2 %s 127.0.0.1 %d 2>&1 r" % (pocfname, PORT))
    checker_data = checker_popen.read()
    checker_popen.close()
    os.unlink(pocfname)
    if "FARKFARKFARK" in checker_data:
        return loc, loc
    else:
        return loc, -1

socatproc = subprocess.Popen("socat tcp-listen:%d,fork,reuseaddr exec:%s,su=nobody >/dev/null 2>/dev/null" % (PORT, TMPSCRIPTNAME), shell=True)


curloc = 0
fsize = os.stat(APFILE).st_size
fff = open(APFILE, "rb")
fff.seek(-4, 2)
ttt = struct.unpack('I', fff.read(4))[0]
fff.close()
fsize = fsize - (ttt + 1) * 4

def tasks():
    global curloc
    while curloc < fsize:
        nextloc = loconn(curloc)
        if nextloc != None:
            yield curloc
            curloc = nextloc
        else:
            curloc = curloc + 1

pool = multiprocessing.Pool(100)

ret = pool.imap(process, tasks())

for i in ret:
    if i[1] > 0:
        print i[1]

#socatproc.kill()
#socatproc.send_signal(9)
def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()

kill(socatproc.pid)
os.unlink(TMPSCRIPTNAME)
