#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from datetime import datetime, timedelta
from time import sleep
from sys import argv
from os import system


iface = argv[1]
conf.verb = 0
MAX_PASSWORD_ATTEMPTS = 3
MAX_APS_ATTEMPTS = 2

alerts = []
def alert(client, ap, reason):
	global aps, clients
	if client in alerts and ap in alerts:
		return
	
	print(f'[!] WPA bruteforce detected - {reason}: {client} {clients[client]["signal"]}dBm -> "{aps[ap]["essid"]}"')
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null")
	system("zenity --warning --title='WPA bruteforce detected' --text='WPA bruteforce detected' &")
	#system("echo 'WPA bruteforce detected' | festival --tts --language english")
	alerts.append(client)
	alerts.append(ap)
	system(f"prevent/deauth.py {iface} {ap} {client}")

aps = {}
clients = {}
def parse_raw_80211(p):
	signal = int(p[RadioTap].dBm_AntSignal or 0) if hasattr(p[RadioTap], "dBm_AntSignal") else 0
	freq = p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else 0
	if Dot11Beacon in p: # Beacon
		ap = p[Dot11].addr2
		essid = str(p[Dot11Elt].info, "utf-8")
		if not ap in aps:
			aps[ap] = {"essid": essid}
	elif EAPOL in p and p[Dot11].addr3 in aps:
		ap = p[Dot11].addr3
		if p[Dot11].addr2 == ap:
			client = p[Dot11].addr1
			try: clients[client]
			except: clients[client] = {"signal": 0, "aps":{}}
			try: clients[client]["aps"][ap]
			except: clients[client]["aps"][ap] = {"m2":set(), "m3":0}
			if bytes(p[EAPOL].payload)[77:77+16] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': # AMIC, EAPOL M1
				pass
			else: # EAPOL M3
				clients[client]["aps"][ap]["m3"] += 1
				print(f'[*] WPA PSK auth success {client} {signal}dBm <- "{aps[ap]["essid"]}"')
			clients[client]["signal"] = signal
		elif p[Dot11].addr1 == ap: # EAPOL M2
			client = p[Dot11].addr2
			try: clients[client]
			except: clients[client] = {"signal": 0, "aps":{}}
			try: clients[client]["aps"][ap]
			except: clients[client]["aps"][ap] = {"m2":set(), "m3":0}
			snonce = bytes(p[EAPOL].payload)[13:13+32]
			clients[client]["aps"][ap]["m2"].add(snonce)
			clients[client]["signal"] = signal
			print(f'[*] WPA PSK auth attempt {client} {signal}dBm -> "{aps[ap]["essid"]}" (attempts/success: {len(clients[client]["aps"][ap]["m2"])}/{clients[client]["aps"][ap]["m3"]})')

def analyze():
	while True:
		for client in clients:
			for ap in clients[client]["aps"]:
				if len(clients[client]["aps"][ap]["m2"]) > MAX_PASSWORD_ATTEMPTS and clients[client]["aps"][ap]["m3"] == 0:
					alert(client, ap, f'in depth {len(clients[client]["aps"][ap]["m2"])} attempts') # in depth
			if len(clients[client]["aps"]) > MAX_APS_ATTEMPTS:
				alert(client, ap, f'in width {len(clients[client]["aps"])} aps') # in width
		sleep(1)

Thread(target=analyze, args=()).start()
sniff(iface=iface, prn=parse_raw_80211, store=0)
