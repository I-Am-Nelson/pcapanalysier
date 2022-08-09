from scapy.all import *
ip = set((p[IP].src, p[IP].dst) for p in PcapReader('cap.pcap') if IP in p)
for i in ip:
    print(i)