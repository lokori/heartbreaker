import struct
import re
import os #environ
import subprocess
import sys
import time
from lxml import etree
from cStringIO import StringIO

class Packet:
    def __init__(self, payload):
        self.time=0,0
        self.linktype=1
        self.data=payload
        
class Pcap:
    def __init__(self):
        self.offset=0
        self.probe=""
        self.packets=[]
    
    def rdpcap(self,filename):
        print "Opening "+filename
        self.filename = filename
        pcapfile = open(filename)
        magic = pcapfile.read(4)
        if len(magic) < 4:
            return
        if struct.unpack("<I",magic) == (0xa1b2c3d4L,):
            endian = "<"
        elif struct.unpack(">I",magic) == (0xa1b2c3d4L,):
            endian = ">"
        else:
            return
        hdr = pcapfile.read(20)
        if len(hdr)<20:
            return 
        vermaj,vermin,tz,sig,snaplen,\
                                       self.linktype = \
                                       struct.unpack(endian+"HHIIII",hdr)
        while 1:
            hdr = pcapfile.read(16)
            if len(hdr) < 16:
                break
            sec,usec,caplen,olen = struct.unpack(endian+"IIII", hdr )

            if self.offset != 0:
                #hmm, where is this scaling in sequencer import? -jke
                print "time change", self.probe, sec, usec , "->", 

                t = sec + (usec*10**(-6))
                t += (self.offset*10**(-6))
                sec = int(t)
                usec = int(((t-int(t))*10**6)+0.5)
                print sec, usec

            if caplen > 65536:
                break
            data=pcapfile.read(caplen)
            if(len(data) < caplen):
                break
            else:
                p = Packet(data)
                p.time = (sec,usec)
                p.linktype = self.linktype
                p.network = self.probe
                self.packets.append(p)
        pcapfile.close()

class TShark:
    pdmltshark={}

    def __init__(self):
        self.tshark_path = '/usr/local/bin/tshark'


    def packetxmlparse(self, r, w, packet):
        print 1
        w.write(struct.pack("IIII", packet.time[0], packet.time[1], len(packet.data), len(packet.data)))
        w.write(packet.data)
        w.flush()
        lines=""
        while True:
            line = r.readline()
            if not line.startswith("<pdml"):
                lines+=line
            if line == "</packet>\n":
                break
        return lines
    
    def analysepsml(self, packet):
        if not self.psmltshark.has_key(packet.linktype):
            self.spawnpsml(packet.linktype)
        r,w = self.psmltshark[packet.linktype]

        lines  = self.packetxmlparse(r,w, packet)
        tree = etree.fromstring(lines)
        return ["","","","","",""]



    def analysepdml(self, packet, fields):
        if not self.pdmltshark.has_key(packet.linktype):
            self.spawnpdml(packet.linktype)
        r,w = self.pdmltshark[packet.linktype]
        lines  = self.packetxmlparse(r,w, packet)
        tree = etree.fromstring(lines)
        fields=tree.xpath('/packet/proto/field')
        for f in fields:
            print "name: %s, pos: %s, size: %s, val: %s" % (f.get('name'),f.get('pos'),f.get('size'),f.get('value'))
        return fields

    def spawnpsml(self, linktype):
        pass
#        self.psmltshark[linktype] = popen2.popen2(self.tshark_path +"  -tad -Tpsml -n -l -i - ")
#        r,w = self.psmltshark[linktype]
#        w.write(struct.pack("IHHIIII",
#                            0xa1b2c3d4L,
#                            2, 4, 0, 0, 1500, linktype))
#        w.flush()
#        return self.psmltshark[linktype]

    def spawnpdml(self, linktype):
        p = subprocess.Popen(["strace","-tt","-o","foo.trace",self.tshark_path,"-Tpdml","-n","-l","-i-"], bufsize=0,stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=False)
        self.pdmltshark[linktype]=(p.stdout,p.stdin)
        r,w = self.pdmltshark[linktype]
        w.write(struct.pack("IHHIIII",
                            0xa1b2c3d4L,
                            2, 4, 0, 0, 1500, linktype))
        w.flush()
        return self.pdmltshark[linktype]


    def close(self):
        for tshark in self.psmltshark.values():
            tshark[1].close()

        for tshark in self.pdmltshark.values():
            tshark[1].close()

t = TShark()

pcap=Pcap()
pcap.rdpcap(sys.argv[1])

for p in pcap.packets:    
    t.analysepdml(p,{})


