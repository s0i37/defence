#!/usr/bin/python3
from scapy.all import *
from netaddr import IPNetwork
from time import sleep
from sys import argv
from os import system

IPS_WITH_PTR = IPNetwork("176.34.0.0/24")
targets = []
dns_servers = []
conf.verb = 0

alerts = []
def alert(ip):
	if ip in alerts:
		return
	print("[!] sniffer detected %s" % ip)
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null")
	system("zenity --warning --title='sniffer detected' --text='sniffer detected: %s' &" % ip)
	#system("echo 'sniffer detected' | festival --tts --language english")
	alerts.append(ip)

n = 1
def get_source():
	global n
	while True:
		ip = str(IPS_WITH_PTR[n])
		if not dns_no_recurse(ip):
			return ip
		n += 1

def dns_no_recurse(ip):
	def rev(ip):
		ip = ip.split(".")
		ip.reverse()
		return ".".join(ip)
	for dns_server in dns_servers:
		try:
			answer = sr1(IP(dst=dns_server)/UDP(dport=53)/DNS(rd=0, qd=DNSQR(qname=rev(ip)+".in-addr.arpa", qtype='PTR')))
			if answer[DNS].ancount > 0:
				return True
		except:
			print(f"[-] {dns_server} has no answer")

def probe(src, dst):
	send(IP(src=src, dst=dst)/ICMP())

with open(argv[1]) as f:
	for line in f:
		targets.append( line.split("\n")[0] )

with open(argv[2]) as f:
	for line in f:
		dns_servers.append( line.split("\n")[0] )

src = get_source()
while True:
	for dst in targets:
		probe(src, dst)
		sleep(1)
		if dns_no_recurse(src):
			alert(dst)
			src = get_source()
	sleep(60)
