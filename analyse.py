#!/usr/bin/python3
import sys
from scapy.all import *
from scapy.layers.http import *
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff


def analyse(*argv):
    for arg in argv:
        if (len(argv))==0 or sys.argv[1]=="-h":
            print("""
                  This is pcap file analyser please pass the first argument in pcap file
                  
                  ip      -  it show the IPs in pcap file
                  status  -  it show the status code in pcap file
                  url     -  it show the requested url in pcap file
                  domain  -  it show the Host in response
                  all     -  it show all details in pcap file
                  """)
            sys.exit()
        file_cap = sys.argv[1]
        packets = rdpcap(file_cap)
        if sys.argv[2]=="ip":
            ips = set()
            for p in packets:
                if IP in p:
                    ips.add(p[IP].src  +" -------> "+p[IP].dst)

            print("Source IP    -------> Destination IP")
            for i in ips:
                print(i)

        elif sys.argv[2]=="status":
            for packet in packets:
                if HTTP in packet:
                    if HTTPResponse in packet:
                        status = packet[HTTPResponse].Status_Code
                        print(str(status,"UTF-8"))

        elif sys.argv[2]=="url":
            for packet in packets:
                if not packet.haslayer('HTTPRequest'):
                    continue
                ip_layer = packet.getlayer('IP').fields
                path = packet.getlayer('HTTPRequest').Path
                domain = packet.getlayer('HTTPRequest').Host
                print("-> "+ str(domain,"UTF-8")+str(path,"UTF-8"))
    
        elif sys.argv[2]=="domain":
            for packet in packets:
                if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                    print(str(packet.getlayer(DNS).qd.qname , "UTF-8"))
        
        elif sys.argv[2]=="all":
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

try:
    analyse(sys.argv)
except:
    print("""Error: please provide the pcap file , 
          usage: ./analyse.py file_name opions""")