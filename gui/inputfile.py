import struct
import subprocess
import sys
import time
import json, base64
import os
import tempfile
import atexit
import shutil

try:
    from scapy.all import rdpcap, TCP, UDP, Raw
    scapy_installed = True
except:
    scapy_installed = False
    print "Scapy not installed, no pcap support!"

try:
    from scapy.all import SCTPChunkData
    scapy_sctp = True
except:
    scapy_sctp = False
    print "Scapy snapshot required for SCTP support in pcap files"

def open_input(filename, config=None):
    if filename is None:
        exit("No input given, exiting")
    if filename.endswith('.json'):
        return Json(filename, config)
    elif filename.endswith('.pcap'):
        return Pcap(filename, config)
    else:
        return RawFile(filename, config)

def which(program):
        def is_exe(fpath):
            return os.path.exists(fpath) and os.access(fpath, os.X_OK)

        fpath, fname = os.path.split(program)
        if fpath:
            if is_exe(program):
                return program
        else:
            for path in ['.']+os.environ["PATH"].split(os.pathsep):
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return exe_file
        return None

class Fuzzer:
    def __init__(self, samples, fuzz_dir=None):
        self.radamsa=which("radamsa")
        if self.radamsa is None:
            sys.exit("No radamsa in . or $PATH, exiting")

        self.samples=[]
        self.fuzzed_samples=[]

        self.radamsa_tmpdir=tempfile.mkdtemp()+"/"
        atexit.register(self.sample_cleanup)

        if fuzz_dir is None:
            fuzz_dir=tempfile.mkdtemp()+"/"
            atexit.register(self.fuzzed_cleanup)

        if not os.path.isdir(fuzz_dir):
            os.makedirs(fuzz_dir)

        self.fuzz_dir = fuzz_dir

        for i, s in enumerate(samples):
            filename = os.path.join(self.fuzz_dir, '%06d' % i)
            f=open(filename, 'w')
            f.write(s)
            f.close()
            self.samples.append(filename)

    def eof(self):
        return False

    def sample_cleanup(self):
        # Be paranoid, / ending up in this variable would be very bad...
        if self.radamsa_tmpdir.startswith('/tmp'):
            shutil.rmtree(self.radamsa_tmpdir)

    def fuzzed_cleanup(self):
        # Be paranoid, / ending up in this variable would be very bad...
        if self.fuzz_dir.startswith('/tmp'):
            shutil.rmtree(self.fuzz_dir)

    def get_fuzzed(self):
        data=""
        while len(data) == 0:
                if len(self.fuzzed_samples) == 0:
                    self.gen_fuzz(self.samples, 10)
                filename = os.path.join(self.fuzz_dir, self.fuzzed_samples.pop())
                f=open(filename)
                data=f.read()
                f.close()
        return data

    def __iter__(self):
        return self

    def next(self):
        return self.get_fuzzed()

    def gen_fuzz(self, samples, n):
        subprocess.call([self.radamsa,"-n","%d" % n,"-o", os.path.join(self.fuzz_dir, "fuzz-%n")]+samples)
        self.fuzzed_samples = os.listdir(self.fuzz_dir)

    
class InputFile:
    def __init__(self, filename, config=None):
        self.radamsa=which("radamsa")
        self.packets=[]
        self.uniquesamples=set()
        self.index = 0
        self.params = {'ppid':0} 
        if config:
            self.start = config.starttime
            self.stop = config.stoptime
            self.loop = config.loop
            self.last = config.last
            # Hack to prevent fuzzer from getting infinite samples from input
            if config.fuzz:
                self.loop = False
        else:
            self.start = 0
            self.stop = float('inf')
            self.loop = False
            self.last = 0
        self.read_file(filename)
        if self.last > 0:
            self.packets = self.packets[-self.last:]
            self.uniquesamples = set(self.packets)
        print "Found %d unique samples from %d inputs" % (len(self.uniquesamples),len(self.packets))

    def __getitem__(self, item):
        return self.packets[item]
    
    def __iter__(self):
        return self

    def eof(self):
        if len(self.packets) == 0 or self.loop == False and self.index >= len(self.packets):
            return True
        else:
            return False

    def next(self):
        if self.eof():
            raise StopIteration
        if self.loop and self.index >= len(self.packets):
            self.index=0
        self.index = self.index + 1
        return self[self.index-1]

class Json(InputFile):
    def read_file(self, filename):
        f=open(filename)
        print "Opening JSON file %s " % filename
        self.params['ppid']=0
        for l in f.readlines():
            try:
                m=json.loads(l)
            except:
                continue
            msg=base64.b64decode(m['msg'])
            ts=float(m.get('timestamp',0))
            if ts >= self.start and ts <= self.stop:
                self.packets.append(msg)
                self.uniquesamples.add(msg)
            if m.get('ppid',0) and self.params['ppid'] != m['ppid']:
                self.params['ppid']=m.get('ppid',0)
            f.close()
# Not used currently so don't print
#        if self.params['ppid'] != 0:
#            print "Using PPID %d" %  self.params['ppid']

class RawFile(InputFile):
    def read_file(self, filename):
        if os.path.isdir(filename):
            filenames=os.listdir(filename)
            for i, name in enumerate(filenames):
                try:
                    numname=float(name)
                    if numname < start or numname > stop:
                        filenames.pop(i)
                except:
                    pass
            files=filter(os.path.isfile,map(lambda x: os.path.join(filename, x),os.listdir(filename)))
        else:
            files=[filename,]
        for fn in files:
            print "Opening raw sample file %s" % fn
            f = open(fn)
            data = f.read()
            self.packets.append(data)
            self.uniquesamples.add(data)
            f.close()
        
class Pcap(InputFile):
    def read_file(self, filename):
        if not scapy_installed:
            exit("Could not read pcap due to missing scapy")
        self.params['ppid']=0
        print "Opening pcap file %s" % filename
        packets=rdpcap(filename)
        for p in packets:
            if scapy_sctp and SCTPChunkData in p:
                msg=p.data
            elif (TCP in p and Raw in p) or UDP in p or (Ethernet in p and Raw in p):
                msg = p.load
            if p.time >= self.start and p.time <= self.stop:
                self.packets.append(msg)
                self.uniquesamples.add(msg)
            ppid=getattr(p,'proto_id',0)
            if self.params['ppid'] != ppid:
                self.params['ppid'] = ppid
# This is not used so don't print
#        if self.params['ppid'] != 0:
#            print "Using PPID %d" %  self.params['ppid']
