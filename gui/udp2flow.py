from scapy.all import *
import sys
import json
import base64

packets=rdpcap(sys.argv[1])

for p in packets:
  if UDP in p:
    if IP in p:
      layer=IP
    elif IPv6 in p:
      layer=IPv6
    else:
      continue
    t={}
    t['fromaddr'] = [p[layer].src, p[UDP].sport]
    t['toaddr'] = [p[layer].dst, p[UDP].dport]
    t['msg'] = base64.b64encode(p[UDP].load)
    print json.dumps(t)
    
    
    


