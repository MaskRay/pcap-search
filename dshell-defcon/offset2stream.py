#!/usr/bin/env python2

import re
import sys
import struct
import socket
import time

ff = open(sys.argv[1], 'rb')
offset = int(sys.argv[2])

ff.seek(-4, 2)
total_conns = struct.unpack('I', ff.read(4))[0]
ff.seek(-4 * (1 + total_conns), 2)
len_conns = list(struct.unpack('I' * total_conns, ff.read(4 * total_conns)))

_out_file = sys.stdout

def out_end_str(*args):
    if _out_file != sys.stdout:
        _out_file.close()
out_end_repr = out_end_hex = out_end_str

def out_begin_hex(*args):
    global _out_file
    _out_file = open(sys.argv[5], 'wb')
    print >>_out_file, 'Time: ', time.ctime(args[1])
out_begin_str = out_begin_repr = out_begin_hex


def out_pcap(*args):
    pass
out_end_pcap = out_pcap


def out_repr(srcip, srcport, destip, dstport, data, direction):
    print >>_out_file, socket.inet_ntoa(struct.pack('I', srcip)) + ':' + str(srcport),
    print >>_out_file, ' --> ',
    print >>_out_file, socket.inet_ntoa(struct.pack('I', destip)) + ':' + str(dstport),
    print >>_out_file, '(%d bytes)' % len(data)
    print >>_out_file, repr(data)
    print >>_out_file, "--------------------------------------------"


def out_hex(srcip, srcport, destip, dstport, data, direction):
    print >>_out_file, socket.inet_ntoa(struct.pack('I', srcip)) + ':' + str(srcport),
    print >>_out_file, ' --> ',
    print >>_out_file, socket.inet_ntoa(struct.pack('I', destip)) + ':' + str(dstport),
    print >>_out_file, '(%d bytes)' % len(data)
    enc_data = data.encode('hex')
    print >>_out_file, ' '.join([enc_data[j:j+2] for j in xrange(0, len(enc_data), 2)])
    print >>_out_file, "--------------------------------------------"


def out_str(srcip, srcport, destip, dstport, data, direction):
    print >>_out_file, socket.inet_ntoa(struct.pack('I', srcip)) + ':' + str(srcport),
    print >>_out_file, ' --> ',
    print >>_out_file, socket.inet_ntoa(struct.pack('I', destip)) + ':' + str(dstport),
    print >>_out_file, '(%d bytes)' % len(data)
    print >>_out_file, str(data)
    print >>_out_file, "--------------------------------------------"


def out_begin_python(*args):
    global _out_file
    _out_file = open(sys.argv[5], 'wb')
    print >>_out_file, '#!/usr/bin/env python2'
    print >>_out_file, '#-*- coding:utf-8 -*-'
    print >>_out_file, 'try: from termcolor import colored'
    print >>_out_file, 'except:'
    print >>_out_file, '    def colored(text, color=None, on_color=None, attrs=None):'
    print >>_out_file, '        return text'
    print >>_out_file, 'peers = [{}, {}]'
    print >>_out_file, 'seq = []'
    print >>_out_file, 'idx = 0'


def out_end_python():
    print >>_out_file, "colors = ['cyan', 'yellow']"
    print >>_out_file, 'for s, o in seq: print colored(repr(peers[s][o]), colors[s])'
    if _out_file != sys.stdout:
        _out_file.close()

def out_python(srcip, srcport, destip, dstport, data, direction):
    _idir = {'sc': 0, 'cs': 1}
    idir = _idir[direction]
    print >>_out_file, "idx += 1"
    print >>_out_file, "peers[%d][idx] = %s" % (idir, repr(data))
    print >>_out_file, "seq.append((%d, idx))" % (idir)


def out_begin_pcap(_pkts):
    import dpkt
    import pcap
    pkts = list(_pkts)
    reader = pcap.pcap(sys.argv[4])
    writer = dpkt.pcap.Writer(open(sys.argv[5], 'wb'))
    cnt = 0
    while True:
        try:
            i = reader.next()
            cnt += 1
            if cnt in pkts:
                writer.writepkt(str(i[1]), i[0])
                pkts.remove(cnt)
            if len(pkts) == 0:
                break
        except StopIteration:
            break
    assert(pkts == [])
    writer.close()




out = eval('out_' + sys.argv[3])
out_begin = eval('out_begin_' + sys.argv[3])
out_end = eval('out_end_' + sys.argv[3])

current_offset = 0
found = False
for i in len_conns:
    if current_offset <= offset < current_offset + i:
        found = True
        ff.seek(current_offset, 0)
        len_pkt, cliip, servip, cliport, servport, timestamp = struct.unpack('IIIHHI', ff.read(20))
        cnt_pkt = struct.unpack('I', ff.read(4))[0]
        pkts_id = struct.unpack('I' * cnt_pkt, ff.read(4 * cnt_pkt))
        out_begin(pkts_id, timestamp)
        for i in xrange(len_pkt):
            direction = ff.read(1)
            len_data = struct.unpack('I', ff.read(4))[0]
            data = ff.read(len_data)
            if direction == 'c':
                out(cliip, cliport, servip, servport, data, 'cs')
            else:
                out(servip, servport, cliip, cliport, data, 'sc')
        out_end()
        break
    current_offset += i

ff.close()

if not found:
    sys.exit(5)
