#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from mac_vendor_lookup import MacLookup # pip3 install mac-vendor-lookup
from random import choice
from string import ascii_letters
from time import sleep
from sys import argv
from os import system


iface = argv[1]
conf.verb = 0
oui = MacLookup()

alerts = []
def alert(ap, essid, signal):
	if ap in alerts:
		return

	print(f'[!] KARMA detected: {ap} "{essid}" {signal}dBm [{oui.lookup(ap)}]')
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null")
	system("zenity --warning --title='KARMA detected' --text='KARMA detected' &")
	#system("echo 'KARMA detected' | festival --tts --language english")
	alerts.append(ap)
	
def probe_request(essid):
	source = "00:11:22:33:44:55"
	target = "ff:ff:ff:ff:ff:ff"
	radio = RadioTap()
	probe = Dot11(subtype=4, addr1=target, addr2=source, addr3=target, SC=0x3060)/\
	 Dot11ProbeReq()/\
	 Dot11Elt(ID='SSID', info=essid)/\
	 Dot11Elt(ID='Rates', info=b'\x8c\x12\x98\x24\xb0\x48\x60\x6c')/\
	 Dot11Elt(ID='DSset', info=int(36).to_bytes(1,'big'))
	return srp1(radio/probe, iface=iface, timeout=0.1)

def rand(size):
	return "".join(list(map(lambda _:random.choice(ascii_letters), range(size))))

while True:
	essid = rand(10)
	probe_resp = probe_request(essid)
	if probe_resp:
		signal = int(probe_resp[RadioTap].dBm_AntSignal) if hasattr(probe_resp[RadioTap], "dBm_AntSignal") else 0
		ap = probe_resp[Dot11].addr2
		print(f'[*] {ap} "{essid}" {signal}dBm')
		alert(ap, essid, signal)
	sleep(1)
