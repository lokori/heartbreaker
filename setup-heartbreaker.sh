#!/bin/sh

# Install Heartbreaker GUI, run this in the virtual machine as root
python get-pip.py # -- pip
pip install scapy  # - scapy
yum -y install tkinter # -- TKInter 

pip install pyttk  # - ttk
yum -y install python-imaging # pip install pil does not work
yum -y install python-imaging-tk # pip install does not work
cp extlib/radamsa /usr/bin

echo "GO BREAK THINGS!"

