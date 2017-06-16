from scapy.all import *
import sys
import json
import base64

# Very naive implementation, doesn't try reassembly etc.

packets=rdpcap(sys.argv[1])

for p in packets:
  if TCP in p and Raw in p:
    t={}
    if IP in p:
      layer=IP
    elif IPv6 in p:
      layer=IPv6
    else:
      continue
    
    t['fromaddr'] = [p[layer].src, p[TCP].sport]
    t['toaddr'] = [p[layer].dst, p[TCP].dport]
    t['msg'] = base64.b64encode(p[TCP].load)
    print json.dumps(t)
    
    
    


