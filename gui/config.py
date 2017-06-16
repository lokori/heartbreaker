import sys
import ConfigParser
from optparse import OptionParser
import datetime

import socket
socket.IPPROTO_SCTP=132

def addrparse(addr_str):
  if addr_str is None:
    domain=socket.AF_INET
    addr,port = "0.0.0.0",0
  elif addr_str.count(':') == 0:
    # Port only given
    domain=socket.AF_INET
    addr,port="0.0.0.0",addr_str
  elif  addr_str.count(':') == 1:
    # IPv4 address and port
    domain=socket.AF_INET
    addr,port=addr_str.rsplit(':')
  else:
    domain=socket.AF_INET6
    addr,port=addr_str.rsplit(':',1)
  try:
    socket.inet_pton(domain,addr)
  except:
    sys.exit("Invalid address %s" % addr)
  try:
    port = int(port)
  except:
    sys.exit("Invalid port '%s'" % port)

  return domain, addr, port

config = {}

class BaseOptionParser(OptionParser):
  def __init__(self,filename=None):
    OptionParser.__init__(self)
    cp=ConfigParser.ConfigParser()
    configs = ['default.cfg']
    if filename:
      configs.append(filename)

    for c in configs:
      print "Reading configuration from %s" % c

    read=set(cp.read(configs))

    for c in set(configs)-read:
      print "Configuration file %s not found, continuing" % c

    if cp.has_section("config"):
      for option in cp.options("config"):
        config[option] = cp.get("config",option)

    def cf_option(short, long, *rest, **kw):
      try:
        cf_val = cp.get("config", long.lstrip('-'))
      except ConfigParser.NoOptionError:
        pass
      else:
        kw['default'] = cf_val

      self.add_option(short, long, *rest, **kw)

    cf_option("-p", "--protocol", help="Protocol family (sctp, tcp, udp)",metavar="PROTO")
    cf_option("-i","--input", help="Use FILE as input (pcap or json)",metavar="FILE")  
    cf_option("-o", "--output-directory", help="Write output to DIR", metavar="DIR", dest="out_dir")
    cf_option("-L", "--logfile", help="Log to FILE", metavar="FILE", dest="logfile")
    cf_option("","--count", help="Stop after COUNT cases sent", metavar="COUNT", dest="count",default=0,type='int')

    cf_option("-f","--starttime", help="Sample start timestamp (default 0)", dest="starttime", metavar="STARTTIME", default='0')
    cf_option("-t","--stoptime", help="Sample stop timestamp (default inf)", dest="stoptime", metavar="STOPTIME", default='inf')
    cf_option("","--ppid", help="Use SCTP PPID", metavar="PPID", dest="ppid",default=0)
    if self.bind:
      cf_option("-b","--bind", help="Bind to address & port HOST:PORT for outgoing connections (client & mitm) ", metavar="BINDADDR",default=config.get('bind_address'), dest="bind_address")
    if self.connect:
      cf_option("-c","--connect",help="Connect to address & port HOST:PORT  (client & mitm) ",metavar="CONNECTADDR",default=config.get('connect_address',None),dest="connect_address")
    if self.listen:
      cf_option("-l","--listen",help="Listen on address & port HOST:PORT (server & mitm) ",metavar="LISTENADDR",default=config.get('listen_address',None),dest="listen_address")
    cf_option("", "--fuzz", action="store_true",help="Fuzz (enabled by default)",dest="fuzz",default=True)
    cf_option("","--ssl", action="store_true",help="Use SSL for sockets",dest="ssl", default=False)

    def repeat_callback(option, opt_str, value, parser):
      parser.values.fuzz = False
      parser.values.input = parser.values.logfile
      parser.values.logfile = '/dev/null'

    cf_option("-r", "--repeat", action="callback",help="Repeat old test cases (disable fuzzing and logging unless enabled)",callback=repeat_callback)
    cf_option("", "--loop", action="store_true",help="Loop forever",dest="loop", default = False)
    cf_option("", "--last", help="Use last LASTNUM samples",dest="last", metavar="LASTNUM",type="int",default=0)
    options, args = self.parse_args()
    for k in filter(lambda x: not x.startswith("_"),dir(options)):
      setattr(self,k, getattr(options,k,None))

  def config(self):
    return self.parse_args()[0]

  def parse_args(self):
    (options, args) = OptionParser.parse_args(self)
    try:
      options.proto_num = socket.getprotobyname(options.protocol)
    except socket.error:
      exit("Unsupported protocol " + options.protocol)

    for f in ('bind_address','listen_address','connect_address'):
      setattr(options,f,addrparse(getattr(options,f,None)))

    for f in ('starttime','stoptime'):
      val=getattr(options,f,None)
      try:
        setattr(options,f,float(val))
        continue
      except ValueError:
        pass
      try:
        ts=datetime.datetime.now()
        t=datetime.datetime.strptime(val,'%H:%M:%S')
        ts=ts.replace(hour=t.hour,minute=t.minute,second=t.second)
        setattr(options,f,float(ts.strftime("%Y%m%d%H%M%S")))
      except ValueError:
        exit("Invalid time %s" % val)
      
    return options, args

class ClientConfig(BaseOptionParser):
  bind = True
  connect = True
  listen = False

class ServerConfig(BaseOptionParser):
  bind = True
  connect = False
  listen = True

class MITMConfig(BaseOptionParser):
  bind = True
  connect = True
  listen = True

if __name__ == "__main__":
  print MITMConfig()


