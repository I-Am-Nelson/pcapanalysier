#!/usr/bin/python3

from scapy.all import *
from scapy.layers import http

packets = rdpcap('cap.pcap')

for packet in packets:
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            print(str(packet.getlayer(DNS).qd.qname , "UTF-8"))
