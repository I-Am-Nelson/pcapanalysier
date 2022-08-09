#!/usr/bin/python3
from scapy.all import *
ips = set()
pcap = PcapReader("cap.pcap")
for p in pcap:
    if IP in p:
        ips.add(p[IP].src  +" -------> "+p[IP].dst)
print("Source IP    -------> Destination IP")
for i in ips:
    print(i)

        