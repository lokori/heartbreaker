from network import *
#from config import *
#from datetime import datetime

from binascii import *
def watchLog(msg,s_r_v,resending=False,trunca=True):
	lenght = len(msg)
	msg=b2a_qp(msg)
	trunc = ''
	if trunca:
		if lenght > 180:
			trunc = ' (Truncated, Additional '+str(lenght-180)+' characters not shown)'
	if s_r_v == 'r':
		s_r_v = 'RECEIVED <-- '
	elif s_r_v == 'a':
		if resending:
			s_r_v = '*RE*SENT ANOMALY --> '
		else:
			s_r_v = 'SENT ANOMALY --> '
	elif s_r_v == 'w':
		s_r_v = 'WARNING: '
	elif s_r_v == 'f':
		s_r_v = 'FAIL: '
	elif s_r_v == 'v':
		s_r_v = 'SENT VALID --> '
	elif s_r_v == 'rsa':
		s_r_v = 'RE-SENT ANOMALY --> '
	else:
		s_r_v = 'LOG: '

	with open('watch.log','a') as wl:
		#logline=str(datetime.now().time())+' '+s_r_v
		logline=gettime()+' '+s_r_v
		wl.writelines(logline)
		
		if trunca:
			wl.write(' '.join(msg[0:180].split()))
			wl.write(trunc+'0a'.decode('hex'))
		else:
			wl.write('\n'+msg+'\n')

	# Keep the watch.log in fixed size, it is not the actual log anyway
	with open('watch.log','rb+') as wl:
		if os.path.getsize('watch.log') > 20080:
			#fh = open(the_file, 'rb+')
			wl.seek(-20080, 2)
			data = wl.read()
			wl.seek(0) # rewind
			wl.write(data)
			wl.truncate()
