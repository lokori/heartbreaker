#!/bin/sh
# Installation script option "BT5" for BackTrack5
# Already installed:
# Python 2.6.5
# scapy 2.0.1 

# Basic installation, SCTP not supported


cp ./src/*.py /usr/lib/python2.7/
cp ./extlib/radamsa /usr/bin/

# Adding SCTP support
apt-get install libsctp-dev


# Python 2.6 / 2.7 need a kernel patch for SCTP

cd extlib
tar -xvf pysctp-0.5-py2.6-kernelkludge.tar.gz
cd pysctp-0.5-py2.6-kernelkludge
python setup.py build
python setup.py install
cd ../../


# For GUI animations
apt-get install python-imaging-tk

# Adding SCTP and IPv6 support to scapy (update to 2.2.0).
# Needed for example if SCTP pcap file is used as input for swizzfuzz
#if [ "$1" == "BT5" ]
#then
#cd extlib
#unzip scapy-latest.zip
#cd scapy-2.2.0
#chmod +x setup.py
#./setup.py install --user
#cd ../../
#fi




