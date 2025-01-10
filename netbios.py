#!/usr/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * # scapy==2.4.5
from threading import Thread
from random import random
from string import ascii_uppercase
from time import sleep
from sys import argv
from os import system


conf.iface = argv[1]
broadcast = conf.route.get_if_bcast(conf.iface)
conf.verb = 0

def nbns_responses(p):
	global name, ip
	if NBNSQueryResponse in p:
		if bytes(p[NBNSQueryResponse][0].RR_NAME).decode() == name:
			ip = str(p[NBNSQueryResponse][0].NB_ADDRESS)

alerts = []
def alert(ip):
	if ip in alerts:
		return
	print("[!] NetBIOS spoofing detected %s" % ip)
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='NetBIOS spoofing detected' --text='NetBIOS spoofing: %s' &" % ip)
	#system("echo 'NetBIOS spoofing detected' | festival --tts --language english")
	alerts.append(ip)

def rand(length):
	return "WIN-L" + "".join(map(lambda x:ascii_uppercase[ int(random()*len(ascii_uppercase)) ], range(length)))

def nbns_query(name):
	send(IP(dst=broadcast)/UDP(sport=RandShort())/NBNSQueryRequest(NAME_TRN_ID=RandShort(), FLAGS=0x0110, QUESTION_NAME=name, QUESTION_TYPE='NB'))

names = {}
while True:
	thr = Thread(target=lambda:sniff(timeout=5, prn=nbns_responses))
	thr.start()
	ip = ''
	name = rand(10)
	nbns_query(name)
	thr.join()
	if ip:
		if not names.get(ip):
			print("[*] {name} = {ip}".format(name=name, ip=ip))
			names[ip] = name
		elif names[ip] != name:
			print("[!] {name} = {ip}".format(name=name, ip=ip))
			alert(ip)
	sleep(3)
