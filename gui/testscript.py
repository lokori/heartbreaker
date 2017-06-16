#!/usr/bin/python
from network import *
from config import *
from watchlog import *
from binascii import *
import signal

global terminate_s
terminate_s = False
def receive_signal(signum, stack):
    global terminate_s
    terminate_s=True

signal.signal(signal.SIGTERM, receive_signal)

config =ClientConfig()

f = open_input(config.input, config)
if config.fuzz:
    f=Fuzzer(f, config.out_dir)

ufuzz_b =''

ufuzz_a =''


resending = False

while True:
    if terminate_s:
        quit()
    
    
    try:
        myself=Client(config)
    except:
        watchLog('Cannot make connection to target...','f')
        time.sleep(0.5)
	continue

    # Get a new test case or resending case
    case=f.next()
    # Remove the last newline from the end, if any
    if not resending:
        if case[-1:] == '0a'.decode('hex'):
            case = case[:-1]
        case.rstrip('0a'.decode('hex'))
    watchLog(ufuzz_b+case+ufuzz_a,'a',resending,True)
    myself.server.send_data(ufuzz_b+case+ufuzz_a)

    reply=myself.server.receive(0.5)
    if reply is Timeout:
        watchLog('No response for fuzzed message','w')
        if os.path.isfile('.target_resp'):
            os.remove('.target_resp')
    else:
        watchLog(reply,'r',False,True)
        with open('.target_resp','w') as af:
            pass
    
    
    myself.server.close()

    time.sleep(0.5)
