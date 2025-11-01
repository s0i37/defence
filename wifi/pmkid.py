#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from time import sleep
from sys import argv
from os import system


iface = argv[1]
conf.verb = 0

alerts = []
def alert(client, bssid, essid):
	global aps, clients
	if client in alerts and essid in alerts:
		return
	print(f'[!] PMKID gathering detected: {client} {clients.get(client,{}).get("signal","-")}dBm to {essid}')
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='PMKID gathering detected' --text='PMKID gathering detected' &")
	#system("echo 'PMKID gathering detected' | festival --tts --language english")
	alerts.append(client)
	alerts.append(essid)
	system(f"prevent/m1.py {iface} {bssid} '{essid}' {client}")

aps = {}
clients = {}
def parse_raw_80211(p):
	signal = int(p[RadioTap].dBm_AntSignal or 0) if hasattr(p[RadioTap], "dBm_AntSignal") else 0
	freq = p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else 0
	if Dot11Beacon in p: # Beacon
		ap = p[Dot11].addr2
		essid = str(p[Dot11Elt].info, "utf-8")
		if not ap in aps:
			aps[ap] = {"essid": essid, "m1":set(), "m2": set()}
	elif Dot11AssoReq in p: # Association req
		print("assoc %s -> %s" % (p[Dot11].addr2, p[Dot11].addr3))
		clients[p[Dot11].addr2] = {"signal": signal}
	elif EAPOL in p and p[Dot11].addr3 in aps:
		ap = p[Dot11].addr3
		if p[Dot11].addr2 == ap:
			aps[ap]["m1"].add(p[Dot11].addr1)
			print('M1 %s <- %s' % (p[Dot11].addr1, ap))
		elif p[Dot11].addr1 == ap:
			aps[ap]["m2"].add(p[Dot11].addr2)
			print('M2 %s -> %s' % (p[Dot11].addr1, ap))

def analyze():
	while True:
		for ap in aps.copy():
			for client in aps[ap]["m1"] - aps[ap]["m2"]:
				alert(client, ap, aps[ap]["essid"])
		sleep(1)

Thread(target=analyze, args=()).start()
sniff(iface=iface, prn=parse_raw_80211, store=0)
