#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from os import system
from sys import argv


MAX_PORTS_ALLOWED = 2
clients = {}

alerts = []
def alert(src_ip):
	if src_ip in alerts:
		return
	print("[!] port scanning %s" % src_ip)
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='port scanning detected' --text='port scanning detected' &")
	#system("echo 'port scanning detected' | festival --tts --language english")
	alerts.append(src_ip)

def parse(p):
	if IP in p and TCP in p:
		src_ip = p[IP].src
		src_port = p[TCP].sport
		dst_port = p[TCP].dport
		print("[+] %s:%d -> %s:%d" % (src_ip, src_port, ip, dst_port))
		if not src_ip in clients:
			clients[src_ip] = set()
		clients[src_ip].add(dst_port)
		if len(clients[src_ip]) > MAX_PORTS_ALLOWED:
			alert(src_ip)

conf.iface = argv[1]
ip = conf.iface.ip
sniff(iface=conf.iface, prn=parse, filter='tcp[tcpflags] == tcp-syn and dst host %s'%ip, store=0)
