from scapy.all import *
from scapy.layers.http import *

packets = rdpcap("cap.pcap")
for packet in packets:
    if HTTP in packet:
        if HTTPResponse in packet:
            status = packet[HTTPResponse].Status_Code
            print(status)

