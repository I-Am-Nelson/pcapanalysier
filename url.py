#!/usr/bin/python3

from scapy.all import *
from scapy.layers import http

packets = rdpcap('cap.pcap')

for packet in packets:
    if not packet.haslayer('HTTPRequest'):
        continue
    ip_layer = packet.getlayer('IP').fields
    path = packet.getlayer('HTTPRequest').Path
    domain = packet.getlayer('HTTPRequest').Host


    print("-> "+ str(domain,"UTF-8")+str(path,"UTF-8"))
    # print('\n{0[src]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer,http_layer))