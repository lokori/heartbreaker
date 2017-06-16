from scapy.all import *
import sys
import json
import base64

packets=rdpcap(sys.argv[1])

for p in packets:
  if SCTPChunkData in p:
    if IP in p:
      layer=IP
    elif IPv6 in p:
      layer=IPv6
    else:
      continue
    t={}
    t['tsn']=p[SCTPChunkData].tsn
    t['cumtsn'] = 0 # Scapy doesn't report?
    t['stream'] = p[SCTPChunkData].stream_id
    t['fromaddr'] = [p[layer].src, p[SCTP].sport]
    t['toaddr'] = [p[layer].dst, p[SCTP].dport]
    t['assoc_id'] = 0 # ???
    t['ssn'] = p[SCTPChunkData].stream_seq
    t['timetolive'] = 0 
    t['context'] = 0
    t['flags'] = 0
    t['ppid'] = p[SCTPChunkData].proto_id
    t['msg'] = base64.b64encode(p[SCTPChunkData].data)
    print json.dumps(t)
    
    
    


