import datetime, struct, sys, os, time, json, base64, subprocess, asyncore
import socket
from inputfile import *
import errno
import re
import ssl
from certutil import CertGen

socket.IPPROTO_SCTP=132

try:
    import sctp
except:
    try:
        from pysctp import sctp
    except:
        print "No pysctp found"


def gettime():
        ts=datetime.datetime.now()
        tstext=ts.strftime("%Y%m%d%H%M%S")
        tstext+=".%.6d" % ts.microsecond
        return tstext
            
class Logger(asyncore.file_dispatcher):
    def __init__(self, f):
        asyncore.file_dispatcher.__init__(self,f)
        self.buffer=""

    def readable(self):
        return False

    def writable(self):
        return len(self.buffer) > 0

    def handle_write(self):
        written=self.send(self.buffer)
        self.buffer=self.buffer[written:]
        
logger = Logger(sys.stdout)

Timeout = object()
    
#        tstext=gettime()
#        self.datadir="data/%s-%s-%s" % (tstext,self.clientName,self.serverName)
#        print "Logging to %s" % self.datadir
        

# Have to be global, ClientEndpoints get created for every instance
case_count = 0
start_timestamp = gettime()

class Endpoint(asyncore.dispatcher):        
        def __init__(self, sock, config = None):
            asyncore.dispatcher.__init__(self, sock)
            self.connected = True
            self.other = None
            self.logger = None
            self.timeout = None
            self.send_hook = None
            self.buffer=[]
            self.rcvbuf=[]
            self.max_count = getattr(config,'count',0)

            logpath = getattr(config,'logfile',None)
            if logpath:
                logpath=re.sub("TIMESTAMP",start_timestamp,logpath)
                self.logfile = open(logpath, "a")
            else:
                self.logfile = None

        def meet(self, other):
            self.other = other
            other.other = self
        
        def log(self, msg):
            if self.logfile:
                self.logfile.write(msg)
                return

            while len(msg) > 0:
                try:
                    written=logger.write(msg)
                    msg=msg[written:]
                except OSError, (e, strerror): 
                    if e == errno.EAGAIN:
                        continue
                    else:
                        raise OSError, (e, strerror) 

        def send_data(self, payload, **params):
            if self.send_hook is not None:
                payload=self.send_hook(payload)
            logdata=params
            logdata['msg']=base64.b64encode(payload)
            logdata['timestamp']=gettime()
            if not params.get('nolog', None):
                self.log(json.dumps(logdata)+"\n")
            self.buffer.append((payload,params))
            asyncore.loop(count=1)
            global case_count
            case_count+=1
            if case_count == self.max_count:
                exit('%d cases reached, exiting' % case_count)

 	def log_data(self, payload):
	    logdata={'msg':base64.b64encode(payload),'timestamp':gettime()}
    	    self.log(json.dumps(logdata)+"\n")


        def handle_error(self):
            print >>sys.stderr, "Endpoint error:", sys.exc_info()
            self.handle_close()

        def receive(self, t):
            ts2=ts=time.time()
            while ts2-ts < t and len(self.rcvbuf) == 0:
                asyncore.loop(timeout=t,count=1)
                ts2=time.time()

            if len(self.rcvbuf) == 0:
                return Timeout
            else:
                return self.rcvbuf.pop()

        def handle_read(self,data, params={}):
            if len(data) > 0:
                if self.other:
                    self.other.send_data(data)
                self.rcvbuf.append(data)

        def writable(self):
            return len(self.buffer) > 0

        def handle_close(self):
            self.connected = False
            while self.writable():
                self.handle_write()
            if not self.other:
                self.close()
                return
            print >>sys.stderr, "Endpoint closed"
            while self.other.writable():
                self.other.handle_write()
            self.other.close()
            self.close()
            self.other = None
            
class TcpEndpoint(Endpoint):

        def handle_read(self):
            data = self.recv(65536)
            Endpoint.handle_read(self,data)
                        
        def handle_write(self):
            if len(self.buffer) == 0:
                print "Empty buffer while writing?"
                return
            payload,params=self.buffer.pop(0)
            sent = self.send(payload)
            if sent < len(payload):
                payload=payload[sent:]
                # sent > 0 added to prevent deadlock, assume if we can't send anything, client isn't listening?
                # XXX investigate further!
                if sent > 0 and len(payload) > 0:
                    self.buffer.insert(0,(payload,params))

class UdpEndpoint(Endpoint):
        def __init__(self, sock, config = None):
            Endpoint.__init__(self, sock, config)
            self.dst = None

        def handle_read(self):
            data, addr = self.recvfrom(2048)
            if self.dst != addr:
                print "UDP client is now: ",addr
                self.dst = addr
            Endpoint.handle_read(self,data, {'fromaddr':addr})
            
        def handle_write(self):
            if self.dst:
                self.sendto(self.buffer.pop(0)[0],self.dst)
            else:
                self.buffer.pop(0)
                print "No victim, dropping packet"
                        
class SctpEndpoint(Endpoint):
        def handle_read(self):
            fromaddr, flags,msg,notif = self.sctp_recv(65536)
            params={'fromaddr':fromaddr,'flags':flags,'ppid':socket.ntohl(notif.ppid)}
            Endpoint.handle_read(self,msg,params)

        def handle_write(self):
            while len(self.buffer) > 0:
                payload, params = self.buffer.pop(0)
                sndrcvinfo = sctp.sndrcvinfo()
                sndrcvinfo.ppid = socket.htonl(params.get('ppid',0))
                fromaddr,flags,msg,notif="",128,payload[:1460],sndrcvinfo
                sent = self.sctp_send(msg,ppid=sndrcvinfo.ppid,flags=notif.flags)

def create_bound_socket(protocol, sockparams, reuse=True):
        domain=sockparams[0]
        bindaddr=(sockparams[1],sockparams[2])
        if protocol == socket.IPPROTO_SCTP:            
            sock=sctp.sctpsocket_tcp(domain)
        elif protocol == socket.IPPROTO_TCP:
            sock=socket.socket(domain)
        elif protocol == socket.IPPROTO_UDP:
            sock=socket.socket(domain,  socket.SOCK_DGRAM, protocol)
        if reuse:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        sock.bind(bindaddr)

        return sock

class NetworkDispatcher(asyncore.dispatcher):
    def __init__(self,config):
        asyncore.dispatcher.__init__(self)
        self.proto = config.proto_num
        self.config = config
        self.ssl = config.ssl

        if self.proto == socket.IPPROTO_TCP:
            self.NetworkEndpoint = TcpEndpoint
        elif self.proto == socket.IPPROTO_UDP:
            self.NetworkEndpoint = UdpEndpoint
        elif self.proto == socket.IPPROTO_SCTP:
            self.NetworkEndpoint = SctpEndpoint

    def handle_connection(self):
        print "Connection fully established"

    def prepare_sock(self, sock, server=None):
        if self.proto == socket.IPPROTO_SCTP:
            sock.events.clear()
            sock.events.data_io = 1
        if self.ssl:
            if server:
                key=CertGen().get_key(server)
                try:
#                sock=ssl.wrap_socket(sock,keyfile=key,certfile=crt,ssl_version=ssl.PROTOCOL_TLSv1)
                    sock=ssl.wrap_socket(sock,keyfile=key,certfile=key,ssl_version=ssl.PROTOCOL_SSLv23,server_side=True)
                except ssl.SSLError, e:
                    print e
            else:
                try:
                    sock=ssl.wrap_socket(sock,ssl_version=ssl.PROTOCOL_SSLv23,ciphers="ALL")
                except ssl.SSLError, e:
                    print e
        return sock

class Client(NetworkDispatcher):
    def __init__(self, config):
        if config.connect_address[2] == 0:
            exit("Destination undefined, exiting!")

        NetworkDispatcher.__init__(self,config)

        self.server = None
        self.server_sock = create_bound_socket(config.proto_num, config.bind_address,True)
        self.server_sock=self.prepare_sock(self.server_sock)
        self.dst=config.connect_address[1:]
        print "Connecting to "+str(self.dst)+" from "+str(config.bind_address)
        if self.proto != socket.IPPROTO_UDP:
            self.server_sock.connect(self.dst)

        self.server = self.NetworkEndpoint(self.server_sock,config=self.config)
        self.server.dst = self.dst
        self.handle_connection()

class Server(NetworkDispatcher):
    def __init__(self, config):
        if config.listen_address[2] == 0:
            exit("Listen port not defined, exiting!")
        NetworkDispatcher.__init__(self,config)

        sock=create_bound_socket(self.proto, config.listen_address)
        self.set_socket(sock)
        self.client = None

        if self.proto != socket.IPPROTO_UDP:
            self.listen(5)
            print "Listening on %s:%d" % (config.listen_address[1:3])

    def wait_for_connection(self):
      while self.client is None or self.client.connected is False:
          asyncore.loop(count=1)

    def handle_accept(self):
        if self.proto == socket.IPPROTO_UDP:
            return
        pair = self.accept()
        if pair is None:
            pass
        else:
            client_sock, addr = pair
            client_sock=self.prepare_sock(client_sock,"localhost")
            self.client = self.NetworkEndpoint(client_sock, config=self.config)
 
            self.handle_connection()
            
class MITMServer(NetworkDispatcher):
    def __init__(self, config):
        if config.listen_address[2] == 0:
            exit("Listen port not defined, exiting!")
        NetworkDispatcher.__init__(self, config)

        self.dst = config.connect_address

        self.bindaddr = config.bind_address

        sock=create_bound_socket(self.proto,config.listen_address)
        self.set_socket(sock)

        self.listen(5)
        print "Listening on %s, forwarding to %s from %s" % (config.listen_address, self.dst, self.bindaddr)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            pass
        else:
            client_sock, addr = pair
            domain, srv_host, srv_port = self.dst
            if srv_port == 0:
                dst=client_sock.getsockopt(socket.SOL_IP, 80, 16)
                srv_port, srv_ip = struct.unpack("!2xH4s8x", dst)
                srv_host = socket.inet_ntoa(srv_ip)

            client_sock = self.prepare_sock(client_sock, srv_host)
            print 'Incoming connection from %s' % repr(addr)
            print 'Outgoing connection to %s:%d' %(srv_host, srv_port)

            server_sock = create_bound_socket(self.proto,self.bindaddr,True)

            server_sock=self.prepare_sock(server_sock)
            self.prepare_sock(server_sock)

            try:
                server_sock.connect((srv_host, srv_port))
            except Exception,e:
                print "Connection failed"
                client_sock.close()
                server_sock.close()
                return
            self.client=self.NetworkEndpoint(client_sock, config=self.config)
            self.server=self.NetworkEndpoint(server_sock, config=self.config)
            self.server.meet(self.client)
            self.handle_connection()


