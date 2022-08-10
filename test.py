import sys
from scapy.all import *
from scapy.layers.http import *
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
packets = rdpcap('cap.pcap')
print(len(packets))

for packet in packets:
    if not packet.haslayer('HTTPRequest'):
        continue
    ip_layer = packet.getlayer('IP').fields
    http_layer= packet.getlayer('HTTPRequest').fields
    path = packet.getlayer('HTTPRequest').Path
    domain = packet.getlayer('HTTPRequest').Host
    method = packet.getlayer('HTTPRequest').Method
    
    for packet in packets:
        if (HTTP in packet) and (HTTPResponse in packet):
            status = packet[HTTPResponse].Status_Code
            ip_source = packet[IP].src            
            print("->",ip_source,"just requested",str(method,"UTF-8"),str(domain,"UTF-8")+str(path,"UTF-8"),"==>",str(status,"UTF-8"))

