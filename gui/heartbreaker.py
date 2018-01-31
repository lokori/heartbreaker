#!/usr/bin/python

import os, fcntl
import subprocess
import signal
import re

from tkFileDialog import askopenfilename, askdirectory
import socket
import tkMessageBox
from config import *
import time
from animatedGif import AnimatedGif
from datetime import datetime
from widgets import *
from string import Template

config = MITMConfig('heartbreaker.cfg')
if os.path.isfile('.target_resp'):
    os.remove('.target_resp')
if os.path.isfile('.target_fail'):
    os.remove('.target_fail')


class BuilderFrame(tk.Frame):
	def __init__(self, parent):
		tk.Frame.__init__(self, parent)	
		ttk.Separator(self, orient=HORIZONTAL).grid(row=0,columnspan=5,sticky=EW, pady=15)
		Label(self, text="Connections: ").grid(row=0,column=0) 

		self.target = LabeledTextFrame(self,"Target IP: ",20,1,0)
		self.target.textfield.var.set(config.connect_address[1])
		self.targetport = LabeledTextFrame(self,"Target Port: ",5,1,1)
		self.targetport.textfield.var.set(config.connect_address[2])
		self.target.textfield.bind("<FocusIn>",self.clearSelection) # Why it gets selected and focused?

		self.bind = LabeledTextFrame(self,"Bind IP: ",20,2,0)
		#self.bind.textfield.var.set(config.bind_address[1])
		self.bindport = LabeledTextFrame(self,"Bind Port: ",5,2,1)
		#self.bindport.textfield.var.set(config.bind_address[2])

		self.listen = LabeledTextFrame(self,"Listen IP: ",20,3,0)
		self.listen.textfield.var.set(config.listen_address[1])
		self.listenport = LabeledTextFrame(self,"Listen Port: ",5,3,1)
		self.listenport.textfield.var.set(config.listen_address[2])
		#values = ("tcp", "udp", "sctp")
		#self.protocol = LabeledComboBoxFrame(self,values,"Protocol: ",1,3)
		self.protocol = Labeled3RadioButtonFrame(self,"Protocol:", "TCP","UDP","SCTP", self.protocolDependencies,1,3)

		self.protocol.var.set('TCP')

		self.reconnect = CheckButton(self,"Reconnect After each Test Case",None,2,4)
		#self.reconnect.var.set(True)

		#self.valid = CheckButton(self, "Valid case instrumentation", None,21,3)

		self.direction = Labeled3RadioButtonFrame(self,"Test Direction (Act As):", "Client", "Server","MITM Server",self.directionDependencies,1,2) 
		self.direction.var.set('Client')
		self.directionDependencies()

		self.ssl = CheckButton(self,"Use TLS/SSL",None,1,4)
		self.ppid = ActivatedInputFrame(self,"SCTP PPID=",4,3)

		self.timeout = LabeledTextFrame(self,"Timeout in receiving: ",4,3,4)
		self.timeout.textfield.var.set('0.5')

		##
		## Directories and files
		##
		ttk.Separator(self, orient=HORIZONTAL).grid(row=7,columnspan=5,sticky=EW, pady=15)
		Label(self, text="Directories And Files:").grid(row=7,column=0)

		self.script = ActivatedInputFrame(self,"Custom Script: ",8,1)  
		self.script.buttonfield.config(state='enabled', command=self.customDependencies)
		self.script.textfield.config(width=40)
		self.script.grid(columnspan=3)
		self.fbutton = PressButton(self,"Select Custom script",lambda i=self.script: self.selectFile(i),8,0)

		self.sampledir = LabeledTextFrame(self,"Samples Directory: ",40,9,1)
		self.dbutton = PressButton(self,"Select Samples Dir",lambda i=self.sampledir: self.selectDirectory(i),9,0)
		self.sampledir.textfield.var.set(config.input)
		self.sampledir.textfield.config(state='enabled')

		#self.logdir = LabeledTextFrame(self,"Log File (from default.cfg): ",40,10,1)
		#self.logbutton = PressButton(self,"Select Log File",lambda i=self.logdir: self.selectDirectory(i),10,0)
		#self.logdir.textfield.var.set(config.logfile)
		#self.logdir.textfield.config(state='disabled')

		#self.inputfile = LabeledTextFrame(self,"Input File:  ",40,11,1)
		#self.inputbutton = PressButton(self,"Select Input File",lambda i=self.inputfile: self.selectFile(i),11,0)
		#self.inputfile.textfield.config(state='disabled')

		self.inputfile = ActivatedInputFrame(self,"Use File input: ",11,1)  
		self.inputfile.buttonfield.config(state='enabled')
		self.inputfile.textfield.config(width=40)
		self.inputfile.grid(columnspan=3)
		self.inputbutton = PressButton(self,"Select Input File",lambda i=self.inputfile: self.selectFile(i),11,0)



		self.unfuzzedbefore = LabeledTextFrame(self,"Fixed part before fuzz:  ",40,12,1)
		self.unfuzzedbeforebutton = PressButton(self,"Select",lambda i=self.unfuzzedbefore: self.selectFile(i),12,0)

		self.unfuzzedafter = LabeledTextFrame(self,"Fixed part after fuzz:  ",40,13,1)
		self.unfuzzedafterbutton = PressButton(self,"Select",lambda i=self.unfuzzedafter: self.selectFile(i),13,0)

		self.validcase = ActivatedInputFrame(self,"Valid Case Insrumentation: ",14,1)
		self.validcase.buttonfield.config(state='enabled')#, command=self.customDependencies)
		self.validcase.textfield.config(width=40)
		self.validcase.grid(columnspan=3)
		#self.validcase = LabeledTextFrame(self,"Valid Case:  ",40,14,1)

		self.validcasebutton = PressButton(self,"Select valid case",lambda i=self.validcase: self.selectFile(i),14,0)

		ttk.Separator(self, orient=HORIZONTAL).grid(row=17,columnspan=5,sticky=EW, pady=15)
		Label(self, text="Run Control:").grid(row=17,column=0) 

		self.cbutton = PressButton(self,"Play",self.executeCommand,25,2)
		self.killkenny = PressButton(self,"Stop",self.killProc,25,1)
		self.heartbleed = PressButton(self,"Test For Heartbleed",self.testForHeartbleed,25,3)

		self.repeat = CheckButton(self, "Rerun (No fuzzing)", self.repeatDependencies,20,0)
		self.last = ActivatedInputFrame(self,"Last=",21,0)
		#self.nofuzz = CheckButton(self, "Do not Fuzz input", None,21,0)
		self.loop = CheckButton(self, "Loop", None,21,2)
		self.loop.config(state='disabled')
		self.count = ActivatedInputFrame(self,"Count=",20,2)
		self.count.buttonfield.config(state='enabled')
		self.fromtime = ActivatedInputFrame(self,"From: ",20,1)
		self.fromtime.textfield.config(width=21)
		self.totime = ActivatedInputFrame(self,"To: ",21,1)
		self.totime.textfield.config(width=21)
		self.sleeptime = LabeledTextFrame(self,"Sleep between test cases: ",4,20,3)
		self.sleeptime.textfield.var.set('0.5')
		ttk.Separator(self, orient=HORIZONTAL).grid(row=22,columnspan=5,sticky=EW, pady=15)
		Label(self, text="Script Execution:").grid(row=23,column=0) 
		Label(self, text="Target Status:").grid(row=23,column=4) 

		self.playerRage = AnimatedGif('gif/rage.gif')
		self.playerIdle = AnimatedGif('gif/rage00.gif')
		self.playerBleed = AnimatedGif('gif/bleed.gif')
		self.label1 = Label(self)
		self.label1.grid(row=25, column = 0)
		#self.updateDisplay()
		self.label1.config(image = self.playerRage.currentFrame())

		self.playerTarget = AnimatedGif('gif/target.gif')
		self.playerFail = AnimatedGif('gif/break.gif')
		self.label2 = Label(self)
		self.label2.grid(row=25, column = 4)
		#self.updateDisplay()
		self.label2.config(image = self.playerTarget.currentFrame())
		self.executed = LabeledTextFrame(self,"Executed Command: ",100,30,0)
		self.executed.grid(columnspan=5)

		self.updateDisplay()


	def clearSelection(self,event):
		self.target.textfield.select_clear()


	def updateDisplay(self):
		global proc
		try:
			pid=proc.pid
			try:
				os.kill(int(pid), 0)
				self.label1.config(image=self.playerRage.nextFrame())
				if os.path.isfile('.target_resp'):
					self.label2.config(image = self.playerTarget.nextFrame())
				elif os.path.isfile('.target_fail'): 
					self.label2.config(image = self.playerFail.currentFrame())
				proc.poll()
			except:
				self.label1.config(image = self.playerIdle.currentFrame())
				self.killProc(self)
				self.label2.config(image = self.playerTarget.currentFrame())
				os.remove('.target_resp')
				if os.path.isfile('.target_fail'): 
					self.label2.config(image = self.playerFail.currentFrame())
		except:
			self.label1.config(image = self.playerIdle.currentFrame())
			self.label2.config(image = self.playerTarget.currentFrame())
			if os.path.isfile('.target_fail'): 
				self.label2.config(image = self.playerFail.currentFrame())
		line = os.popen('tail -n 1 watch.log').read()

		if line == "[+] Server is vulnerable!\n":
			self.label2.config(image = self.playerBleed.currentFrame())

		self.after(400,self.updateDisplay)

	def customDependencies(self):
		if self.script.buttonfield.var.get():
			self.script.textfield.config(state='enabled')
			self.validcase.buttonfield.config(state='disabled') #correct this
			self.validcase.textfield.config(state='disabled')
			self.reconnect.config(state='disabled')
			#self.direction.button1.config(state='disabled')
			#self.direction.button2.config(state='disabled')
			#self.direction.button3.config(state='disabled')
			#self.bind.textfield.config(state='enabled')
			#self.listen.textfield.config(state='enabled')
			#self.target.textfield.config(state='enabled')
			#self.bindport.textfield.config(state='enabled')
			#self.listenport.textfield.config(state='enabled')
			#self.targetport.textfield.config(state='enabled')
			self.timeout.textfield.config(state='disabled')
			self.unfuzzedbefore.textfield.config(state='disabled')
			self.unfuzzedafter.textfield.config(state='disabled')
			self.sleeptime.textfield.config(state='disabled')
		else:
			self.script.textfield.config(state='disabled')
			self.validcase.buttonfield.config(state='enabled')
			self.validcase.textfield.config(state='enabled')
			self.reconnect.config(state='enabled')
			#self.direction.button1.config(state='active')
			#self.direction.button2.config(state='active')	
			#self.direction.button3.config(state='active')
			#self.directionDependencies()
			self.timeout.textfield.config(state='enabled')
			self.unfuzzedbefore.textfield.config(state='enabled')
			self.unfuzzedafter.textfield.config(state='enabled')
			self.sleeptime.textfield.config(state='enabled')

	def repeatDependencies(self):
		if self.repeat.var.get():
			self.last.buttonfield.config(state='enabled')
			self.last.textfield.config(state='disabled')
			self.last.buttonfield.var.set(False)
			self.fromtime.buttonfield.config(state='enabled')
			self.fromtime.textfield.config(state='disabled')
			self.fromtime.buttonfield.var.set(False)
			self.totime.buttonfield.config(state='enabled')
			self.totime.textfield.config(state='disabled')
			self.totime.buttonfield.var.set(False)
			self.count.buttonfield.config(state='disabled')
			self.count.textfield.config(state='disabled')
			self.count.buttonfield.var.set(False)
			self.loop.config(state='enabled')
			self.loop.var.set(False)
		else:
			self.last.buttonfield.config(state='disabled')
			self.last.textfield.config(state='disabled')
			self.last.buttonfield.var.set(False)
			self.fromtime.buttonfield.config(state='disabled')
			self.fromtime.textfield.config(state='disabled')
			self.fromtime.buttonfield.var.set(False)
			self.totime.buttonfield.config(state='disabled')
			self.totime.textfield.config(state='disabled')
			self.totime.buttonfield.var.set(False)
			self.count.buttonfield.config(state='enabled')
			self.count.textfield.config(state='disabled')
			self.count.buttonfield.var.set(False)
			self.loop.config(state='disabled')
			self.loop.var.set(False)

	def protocolDependencies(self):
		protocol = self.protocol.var.get()
		# TBD, UDP Server uses bind IP, no listen IP, poor patch below
		pass

	def directionDependencies(self):
		if self.direction.var.get() == "Client" or self.protocol.var.get() == "UDP":
			self.bind.textfield.config(state='enabled')
			self.listen.textfield.config(state='disabled')
			self.target.textfield.config(state='enabled')
			self.bindport.textfield.config(state='enabled')
			self.listenport.textfield.config(state='disabled')
			self.targetport.textfield.config(state='enabled')
			self.reconnect.var.set(True)
			#self.validcase.buttonfield.config(state='enabled')
		else:
			if self.direction.var.get() == "Server":
				self.bind.textfield.config(state='disabled')
				self.listen.textfield.config(state='enabled')
				self.target.textfield.config(state='disabled')
				self.bindport.textfield.config(state='disabled')
				self.listenport.textfield.config(state='enabled')
				self.targetport.textfield.config(state='disabled')
				self.reconnect.var.set(False)
			else:
				self.bind.textfield.config(state='enabled')
				self.listen.textfield.config(state='enabled')
				self.target.textfield.config(state='enabled')
				self.bindport.textfield.config(state='enabled')
				self.listenport.textfield.config(state='enabled')
				self.targetport.textfield.config(state='enabled')
				self.validcase.buttonfield.config(state='disabled')

	def checkIPaddr(self,addr):
		try:
			socket.inet_pton(socket.AF_INET,addr)
			return True
		except socket.error:
			tkMessageBox.showwarning("Error","Invalid Target IP Address\n(%s)" % addr)
			return False

        def writeMITMscript(self, gen_params):
            port = self.bindport.textfield.get()
            addr = self.bind.textfield.get()
            
            if not self.checkIPaddr(addr):
                return
            
            addr = addr+":"+port
            cmd.extend(["-b",addr])
            
            port = self.targetport.textfield.get()
            addr = self.target.textfield.get()
            if not self.checkIPaddr(addr):
                return
                
            addr = addr+":"+port
            cmd.extend(["-c",addr])
                    
                    
            str="\
#!/usr/bin/python\n\
from network import *\n\
from config import *\n\
from watchlog import *\n\
from subprocess import Popen, PIPE, STDOUT\n\
\n\
config = MITMConfig()\n\
\n\
class FuzzMitm(MITMServer):\n\
  def fuzz(self, data):\n\
    watchLog(data,'r',False,"+gen_params['trunca']+")\n\
    fuzzed = data\n\
    while fuzzed == data:\n\
      p = Popen('radamsa', stdout=PIPE, stdin=PIPE, stderr=STDOUT)\n\
      fuzzed=p.communicate(input=data)[0]\n\
    data = fuzzed\n\
    watchLog(data,'a',False,"+gen_params['trunca']+")\n\
    return data\n\
\n\
  def handle_connection(self):\n\
    self.client.send_hook=self.fuzz\n\
\n\
server=FuzzMitm(config)\n\
asyncore.loop()\n"
            return str

        def writeNonMITM(self, gen_params):
            str="\
#!/usr/bin/python\n\
from network import *\n\
from config import *\n\
from watchlog import *\n\
from binascii import *\n\
import signal\n\
\n\
global terminate_s\n\
terminate_s = False\n\
def receive_signal(signum, stack):\n\
    global terminate_s\n\
    terminate_s=True\n\
"+gen_params['quit_if_server']+"\n\
signal.signal(signal.SIGTERM, receive_signal)\n\
\n\
config ="+gen_params['Me']+"Config()\n\
\n\
f = open_input(config.input, config)\n\
if config.fuzz:\n\
    f=Fuzzer(f, config.out_dir)\n\
\n\
"+gen_params['ufuzzb']+"\n\
"+gen_params['ufuzza']+"\n\
"+gen_params['valid_msg']+"\n\
"+gen_params['resending']+"\n\
"+gen_params['if_connect']+"\n\
while True:\n\
    if terminate_s:\n\
        quit()\n\
    "+gen_params['valid_case']+"\n\
    "+gen_params['if_reconnect']+"\n\
    # Get a new test case or resending case\n\
    case=f.next()\n\
    # Remove the last newline from the end, if any\n\
    if not resending:\n\
        if case[-1:] == '0a'.decode('hex'):\n\
            case = case[:-1]\n\
        case.rstrip('0a'.decode('hex'))\n\
    "+gen_params['wait_for_connection_or_send']+"\n\
    reply=myself."+gen_params['peer']+".receive("+gen_params['timeout']+")\n\
    if reply is Timeout:\n\
        watchLog('No response for fuzzed message','w')\n\
        if os.path.isfile('.target_resp'):\n\
            os.remove('.target_resp')\n\
    else:\n\
        watchLog(reply,'r',False,"+gen_params['trunca']+")\n\
        with open('.target_resp','w') as af:\n\
            pass\n\
    "+gen_params['server_send']+"\n\
    "+gen_params['if_reclose']+"\n\
    time.sleep("+gen_params['sleeptime']+")\n\
    "
                    
            return str
        
        # non mitm attack
        # dict keys: server_send, if_reclose, wait_for_connection_or_send, peer, timeout, trunca
        #            quit_if_server, Me, ufuzza, ufuzzb, valid_smg, resending, if_connect, valid_case, sleeptime
        def writeTestscript(self, outputfile):
            fname = 'template_script.pytempl'
            with open(fname, 'r') as myfile:
                template=myfile.read()
            str = template.substitute(d)
            f.write(str)
            f.close()

        def executeCommand(self):
            global proc
            global notrunc
            if self.script.buttonfield.var.get():
                testscript = self.script.textfield.var.get()
            else:
                testscript = "testscript.py"
		
            gen_params = dict()
            gen_params['resending'] = ""
            # check addresses
            cmd = ['python',testscript]
            
            # Truncate messages in WatchLog or not
            if notrunc.var.get():
                gen_params['trunca'] = 'False'
            else:
                gen_params['trunca'] = 'True'

            if self.repeat.var.get():
                gen_params['resending']="resending = True"
                cmd.append("-r")
                if self.fromtime.buttonfield.var.get():
                    cmd.extend(["-f",self.fromtime.textfield.var.get()])
                    if self.totime.buttonfield.var.get():
                        cmd.extend(["-t",self.totime.textfield.var.get()])
			if self.last.buttonfield.var.get():
                            cmd.extend(["--last", self.last.textfield.var.get()])
			if self.inputfile.buttonfield.var.get():
			#if self.inputfile.textfield.cget('state')== 'enabled':
                            input_dir_file = self.inputfile.textfield.var.get()
                            cmd.extend(["-i",input_dir_file])
            else:
                if not self.inputfile.buttonfield.var.get(): #self.sampledir.textfield.cget('state')== 'enabled':
                    input_dir_file = self.sampledir.textfield.var.get()
                else:
                    input_dir_file = self.inputfile.textfield.var.get()
                    cmd.extend(["-i",input_dir_file])
                    gen_params['resending']="resending = False"

            if self.loop.var.get():
                cmd.append("--loop")

            if self.ssl.var.get():
                cmd.append("--ssl")

            if self.count.buttonfield.var.get():
                cmd.extend(["--count", self.count.textfield.var.get()])

		#log_file = self.logdir.textfield.var.get()
		#cmd.extend(["-L",log_file])

		##
		##  Direction: Client, Server, (MITM)
		##
            protocol = self.protocol.var.get()
            direction = self.direction.var.get()

            # In case of UDP, use Client even if it a server 
            if direction == "Client" or (protocol == 'UDP'):
                gen_params['peer']="server"
                me="client"
                gen_params['Me']="Client"
                if direction == "Client":
                    gen_params['wait_for_connection_or_send']=\
"watchLog(ufuzz_b+case+ufuzz_a,'a',resending,"+gen_params['trunca']+")\n\
    myself."+gen_params['peer']+".send_data(ufuzz_b+case+ufuzz_a)\n"
                    gen_params['server_send'] =""
                    gen_params['quit_if_server']=""
                else: # UDP Server:
                    gen_params['wait_for_connection_or_send']=""
                    gen_params['server_send']="    watchLog(ufuzz_b+case+ufuzz_a,'a',resending,"+gen_params['trunca']+")\n\
        myself."+gen_params['peer']+".send_data(ufuzz_b+case+ufuzz_a)\n"
                    gen_params['quit_if_server']="    quit()"
                    port = self.targetport.textfield.get()
                    addr = self.target.textfield.get()
                    if not self.checkIPaddr(addr):
                        return
                    addr = addr+":"+port
                    cmd.extend(["-c",addr])

                    if self.bind.textfield.get() =="":
                        pass
                    else:
                        port = self.bindport.textfield.get()
                        addr = self.bind.textfield.get()
                        if not self.checkIPaddr(addr):
                            return
                            addr = addr+":"+port
                            cmd.extend(["-b",addr])

            else:
                gen_params['peer']="client"
                me="server"
                gen_params['Me']="Server"
                gen_params['wait_for_connection_or_send']="myself.wait_for_connection()"
                gen_params['server_send']="    watchLog(ufuzz_b+case+ufuzz_a,'a',resending,"+trunca+")\n\
        myself."+peer+".send_data(ufuzz_b+case+ufuzz_a)\n\
    myself.client.close()\n" 
                gen_params['quit_if_server'] = "    quit()"
                port = self.listenport.textfield.get()
                addr = self.listen.textfield.get()
                if not self.checkIPaddr(addr):
                    return
                    addr = addr+":"+port
                    cmd.extend(["-l",addr])

##
## Fixed Part
## todo:check if file exists!!

            if self.unfuzzedbefore.textfield.get() == "" or self.repeat.var.get():	
                gen_params['ufuzzb'] = "ufuzz_b =''\n"
            else:
                gen_params['ufuzzb'] = "\n\
ufuzz_b = str(RawFile('"+self.unfuzzedbefore.textfield.get()+"')[0])\n\
if ufuzz_b[-1:] == '0a'.decode('hex'):\n\
    ufuzz_b = ufuzz_b[:-1]\n\
ufuzz_b.rstrip('0a'.decode('hex'))\n"

            if self.unfuzzedafter.textfield.get() == "" or self.repeat.var.get():
                gen_params['ufuzza'] = "ufuzz_a =''\n"
            else:	
                gen_params['ufuzza'] = "\n\
ufuzz_a = str(RawFile('"+self.unfuzzedafter.textfield.get()+"')[0])\n\
if ufuzz_a[-1:] == '0a'.decode('hex'):\n\
    ufuzz_a = ufuzz_a[:-1]\n\
ufuzz_a.rstrip('0a'.decode('hex'))\n"





            gen_params['timeout']=self.timeout.textfield.var.get()
            gen_params['sleeptime']=self.sleeptime.textfield.var.get()	

##
## 
##
            if self.validcase.buttonfield.var.get():
                gen_params['if_continue'] = "with open('.target_fail','w') as af:\n\
            pass\n\
        quit()\n"
            else:
                gen_params['if_continue'] = "continue"
##
## Reconnect after each test case
##
            if self.reconnect.var.get():
                gen_params['if_reconnect'] ="\n\
    try:\n\
        myself="+gen_params['Me']+"(config)\n\
    except:\n\
        watchLog('Cannot make connection to target...','f')\n\
        time.sleep("+gen_params['sleeptime']+")\n\
	"+gen_params['if_continue']+"\n"
                gen_params['if_connect'] = ""
                gen_params['if_reclose'] = "\n\
    myself."+gen_params['peer']+".close()\n"
                gen_params['if_close'] = ""
            else:
                gen_params['if_reconnect'] = ""
                gen_params['if_connect'] ="# (Re)Connect to target\n\
try:\n\
    myself="+gen_params['Me']+"(config)\n\
except:\n\
    watchLog('Cannot make connection to target, quitting..','f')\n\
    quit()\n" 
                gen_params['if_reclose'] = ""
                gen_params['if_close'] ="\n\
    myself."+gen_params['peer']+".close()\n"

##
## Valid case instrumentation, only for clients
##
            if self.validcase.buttonfield.var.get() and self.direction.var.get()=="Client" and self.validcase.textfield.get():
                gen_params['valid_msg'] = "valid_msg = RawFile('"+self.validcase.textfield.get()+"')"
                gen_params['valid_case']="\n\
    "+gen_params['if_reconnect']+"\n\
    myself."+gen_params['peer']+".send_data(valid_msg[0],nolog=True)\n\
    watchLog(valid_msg[0],'v')\n\
    response=myself."+gen_params['peer']+".receive("+gen_params['timeout']+")\n\
    if response is Timeout:\n\
        watchLog('No response for Valid message, Quitting..','f')\n\
        with open('.target_fail','w') as af:\n\
            pass\n\
        quit()\n\
    else:\n\
        watchLog(response,'r',False,"+gen_params['trunca']+")\n\
    "+gen_params['if_reclose']+"\n\
    time.sleep("+gen_params['sleeptime']+")\n"
            else:
                gen_params['valid_case']=''
                gen_params['valid_msg']=''


      
            f = open("testscript.py","w")
            # may be needed
            #msg = msg.encode('utf-8')
            #data = msg + case

            if direction == "MITM Server":
               str = self.writeMITMScript(gen_params)
            else:
               str = self.writeNonMITM(gen_params)

            f.write(str)
            f.close()

		
            if protocol == 'UDP':
                cmd.extend(["-p","udp"])
            elif protocol == 'SCTP':
                cmd.extend(["-p","sctp"])
            else:
                cmd.extend(["-p","tcp"])

            executed = " ".join(cmd)  
            self.executed.textfield.var.set(executed)

            self.killProc()
            proc = subprocess.Popen(cmd)


	def testForHeartbleed(self):
		port = self.targetport.textfield.get()
		addr = self.target.textfield.get()
		#tbd: hangs if port not open for ssl,fix
		with open("watch.log","w") as f:
			subprocess.Popen(['python', 'hb-test.py', '-p', port, addr], stdout=f)
		self.executed.textfield.var.set(" ".join(['python', 'hb-test.py', '-p', port, addr]))

	def killProc(self):
		global proc
		try:
			proc.terminate()
			#os.killpg(proc.pid, signal.SIGKILL)
			#print "after terminate: ", proc.pid
		except:
			pass  
		try:
			proc.poll()
		except:
			pass
			#os.killpg(proc.pid, signal.SIGTERM)
		try:    
			del proc
		except:
			pass
		if os.path.isfile('.target_fail'):
			os.remove('.target_fail')
		if os.path.isfile('.target_resp'):
			os.remove('.target_resp')

	def selectFile(self,widget):	
		if widget==self.inputfile:
			self.sampledir.textfield.config(state='disabled')
			self.inputfile.textfield.config(state='enabled')
		filename = StringVar()
		filename = askopenfilename()
		if filename:
			widget.textfield.delete(0,END)
			widget.textfield.insert(0,filename)
			if len(filename) > 40:
				widget.textfield.config(width = len(filename))

	def selectDirectory(self,widget):
		if widget == self.sampledir:
			self.sampledir.textfield.config(state='enabled')
			self.inputfile.textfield.config(state='disabled')
		dirname = StringVar()
		dirname = askdirectory()
		if dirname:
			widget.textfield.delete(0,END)
			widget.textfield.insert(0,dirname)
			if len(dirname) > 40:
				widget.textfield.config(width = len(dirname))

class WatchLog(tk.Frame):      
	def __init__(self, parent,file):
		tk.Frame.__init__(self, parent)
		global notrunc
		self.parent = parent
		self.watchlog = file
		with open(self.watchlog,"w") as f:
			#f.write("Test satrted at" + str(datetime.now().time()))
			pass
		self.eins = StringVar()
		self.data1 = TextExtension(self, textvariable=self.eins)
		self.data1.grid(row=0,column=0, sticky = EW+NS,columnspan=3)
		self.data1.rowconfigure(0,weight=1)
		self.data1.columnconfigure(0,weight=1)

		self.update = CheckButton(self, "Update realtime", None,1,0)
		self.update.rowconfigure(0,weight=0)
		self.update.columnconfigure(0,weight=0)
		self.update.grid(sticky=W, pady=0, padx=10)
		self.update.var.set(True)

		notrunc = CheckButton(self, "Do not truncate", None,1,1)
		notrunc.rowconfigure(0,weight=0)
		notrunc.columnconfigure(0,weight=0)
		notrunc.grid(sticky=W, pady=0, padx=10)
		notrunc.var.set(False)

		self.killkenny = PressButton(self,"Clear",self.clearWatch,1,2)
		self.get_text(self.eins,self.watchlog)

	def clearWatch(self):
		with open(self.watchlog,"w") as f:
			#f.write("Test satrted at" + str(datetime.now().time()))
			pass
		self.data1.Clear()

	def get_text(self,val,name):
	# try to open the file and set the value of val to its contents 
		try:
			if self.update.var.get():
				with open(name,"r") as f:
					val.set(f.read())
				self.data1.Text.see(tk.END)
				self.data1.highlight_pattern("RECEIVED.*$", "blue",regexp=True)
				self.data1.highlight_pattern("SENT VALID.*$", "green",regexp=True)
				self.data1.highlight_pattern("FAIL.*$", "red",regexp=True)
				self.data1.highlight_pattern("SENT ANOMALY.*$", "brown",regexp=True)
				self.data1.highlight_pattern("WARNING.*$", "orange",regexp=True)
				self.data1.highlight_pattern("=[0-9A-Z]{2}", "binary", regexp=True)
				self.data1.highlight_pattern("(Trun.*shown)", "black", regexp=True)
		except IOError as e:
			print e
		else:
			pass
			# schedule the function to be run again after 1000 milliseconds  
		self.after(1000,lambda:self.get_text(val,name))		
		# optimize , add auto update stop, update when idle, textfield lenght?
		#if self.update.var.get(): 
		#	self.data1.Text.see(tk.END)

		#self.after(1000,self.get_text(val,name))

class MyNotebook(ttk.Notebook):
	def __init__(self,parent):
		ttk.Notebook.__init__(self,parent)

		self.builderFrame=BuilderFrame(self)
		for i in range (0,9):
			self.builderFrame.rowconfigure(i, weight=1)
		for i in range (0,3):
			self.builderFrame.columnconfigure(i, weight=1)

		self.watchLog=WatchLog(self,'watch.log')
		self.watchLog.rowconfigure(0, weight=1)
		self.watchLog.columnconfigure(0, weight=1)

		self.add(self.builderFrame, text='Builder')
		self.add(self.watchLog, text='Watch Log')



class MainApplication(tk.Frame):
	def __init__(self, parent):
		tk.Frame.__init__(self, parent)
		self.notebook = MyNotebook(self)
		self.notebook.grid(row=0, column=0,sticky=W+E+N+S)
		self.notebook.rowconfigure(0, weight=1)
		self.notebook.columnconfigure(0, weight=1)
		#self.notebook.builderFrame.config(raisecommand = self.clearSelection())
		self.rowconfigure(0, weight=1)
		self.columnconfigure(0, weight=1)
	def quit(self):
		sys.exit()

def ask_quit():
	global proc
	if tkMessageBox.askokcancel("Quit", "You want to leave me? *sniff*"):
		try:
			proc.terminate()
		except:
			pass
		sys.exit()
		#root.destroy()

#-----------------------------------------
def main():
	root = tk.Tk()
	root.title('Heartbreaker v0.00')
	root.rowconfigure(0, weight=1)
	root.columnconfigure(0, weight=1)
	mainApp = MainApplication(root).grid(sticky=W+E+N+S)
	root.protocol("WM_DELETE_WINDOW", ask_quit)
	root.mainloop()
#-----------------------------------------
if __name__ == '__main__':
	main()
