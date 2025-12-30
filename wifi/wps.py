#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from datetime import datetime
from time import sleep
from sys import stdout, argv
from os import system


iface = argv[1]
conf.verb = 0
MAX_PIN_ATTEMPTS = 3
MAX_APS_ATTEMPTS = 2
debug = 0

alerts = []
def alert(client, ap, reason):
	global aps, clients
	if client in alerts and ap in alerts:
		return
	
	print(f'[!] WPS bruteforce detected - {reason}: {client} {clients[client]["signal"]}dBm -> "{aps[ap]["essid"]}"')
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='WPS bruteforce detected' --text='WPS bruteforce detected' &")
	#system("echo 'WPS bruteforce detected' | festival --tts --language english")
	alerts.append(client)
	alerts.append(ap)
	system(f"prevent/deauth.py {iface} {ap} {client}")

aps = {}
clients = {}
e_nonce = None; r_nonce = None; dh_peer_public_key = None; dh_own_public_key = None; enrollee_mac = None; r_hash1 = None; r_hash2 = None
def parse_raw_80211(p):
	global e_nonce, r_nonce, dh_peer_public_key, dh_own_public_key, enrollee_mac, r_hash1, r_hash2
	signal = int(p[RadioTap].dBm_AntSignal or 0) if hasattr(p[RadioTap], "dBm_AntSignal") else 0
	freq = p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else 0
	ap = None; client = None; d = None
	if Dot11Beacon in p: # Beacon
		ap = p[Dot11].addr2
		essid = str(p[Dot11Elt].info, "utf-8")
		if not ap in aps:
			aps[ap] = {"essid": essid}
	elif EAP in p and p[EAP].type == 254: # WPS
		ap = p[Dot11].addr3
		e_hash1 = None
		r_hash1 = None
		success1 = False
		success2 = False
		ok = False
		fail = False
		lock = False
		offset = p[EAP].load.find(b"\x10\x22\x00\x01")
		message_type = p[EAP].load[offset+4]
		message_types = {0x04: "M1", 0x05: "M2", 0x07: "M3", 0x08: "M4", 0x09: "M5", 0x0a: "M6", 0x0b: "M7", 0x0c: "M8", 0x0e: "WSC_NACK"}
		if message_type in message_types.keys():
			if message_type in [0x04, 0x07, 0x09, 0x0b]:
				client = p[Dot11].addr1
				d = "->"
			elif message_type in [0x05, 0x08, 0x0a, 0x0c]:
				client = p[Dot11].addr2
				d = "<-"
			elif message_type == 0x0e:
				if p[EAP].code == 1:
					client = p[Dot11].addr1
					d = "->"
				elif p[EAP].code == 2:
					client = p[Dot11].addr2
					d = "<-"

			if d:
				if debug >= 1: print(f"WPS {message_types.get(message_type)} {ap} {d} {client}")

			if message_types[message_type] == "M1":
				offset = p[EAP].load.find(b"\x10\x1a") + 4
				e_nonce = p[EAP].load[offset:offset+16]
				if debug >= 2: print(f" e_nonce: {e_nonce.hex()}")
				offset = p[EAP].load.find(b"\x10\x20\x00\x06") + 4
				enrollee_mac = p[EAP].load[offset:offset+6]
				if debug >= 2: print(f" enrollee_mac: {enrollee_mac.hex()}")
				offset = p[EAP].load.find(b"\x10\x32\x00\xc0") + 4
				dh_peer_public_key = p[EAP].load[offset:offset+192] # PK_E
				if debug >= 2: print(f" dh_peer_public_key: {dh_peer_public_key.hex()}")
			if message_types[message_type] == "M2":
				offset = p[EAP].load.find(b"\x10\x32\x00\xc0") + 4
				dh_own_public_key = p[EAP].load[offset:offset+192] # PK_R
				if debug >= 2: print(f" dh_own_public_key: {dh_own_public_key.hex()}")
				offset = p[EAP].load.find(b"\x10\x39\x00\x10") + 4
				r_nonce = p[EAP].load[offset:offset+16]
				if debug >= 2: print(f" r_nonce: {r_nonce.hex()}")
			if message_types[message_type] == "M3":
				offset = p[EAP].load.find(b"\x10\x14\x00\x20") + 4
				e_hash1 = p[EAP].payload.load[offset:offset+32]
				if debug >= 2: print(f" e_hash1: {e_hash1.hex()}")
				offset = p[EAP].load.find(b"\x10\x15\x00\x20") + 4
				e_hash2 = p[EAP].payload.load[offset:offset+32]
				if debug >= 2: print(f" e_hash2: {e_hash2.hex()}")
			if message_types[message_type] == "M4":
				offset = p[EAP].load.find(b"\x10\x3d\x00\x20") + 4
				r_hash1 = p[EAP].payload.load[offset:offset+32]
				if debug >= 2: print(f" r_hash1: {r_hash1.hex()}")
				offset = p[EAP].load.find(b"\x10\x3e\x00\x20") + 4
				r_hash2 = p[EAP].payload.load[offset:offset+32]
				if debug >= 2: print(f" r_hash2: {r_hash2.hex()}")
			if message_types[message_type] == "M5":
				success1 = True
			if message_types[message_type] == "M7":
				success2 = True
			if message_types[message_type] == "WSC_NACK":
				if d == "->":
					if p[EAP].load.find(b"\x10\x05\x00\x08") != -1:
						ok = True
					elif p[EAP].load.find(b"\x00\x02\x00\x12") != -1:
						fail = True
					elif p[EAP].load.find(b"\x00\x02\x00\x0f") != -1:
						lock = True
		
		if ap and client:
			try: aps[ap]
			except: aps[ap] = {"essid": ""}
			try: clients[client]
			except: clients[client] = {"signal": 0, "aps":{}}
			try: clients[client]["aps"][ap]
			except: clients[client]["aps"][ap] = {"e_hashes":set(), "r_hashes": set(), "fails": 0, "success_half": 0, "success_full": 0}
			clients[client]["signal"] = signal
			if e_hash1:
				clients[client]["aps"][ap]["e_hashes"].add(e_hash1)
			if r_hash1:
				clients[client]["aps"][ap]["r_hashes"].add(r_hash1)
				print(f'[*] WPS PIN attempt {client} {signal}dBm -> "{aps[ap]["essid"]}" (attempts/success: {len(clients[client]["aps"][ap]["r_hashes"])}/{clients[client]["aps"][ap]["success_full"]})')
			if success1:
				clients[client]["aps"][ap]["success_half"] += 1
				print(f'[*] WPS PIN half success {client} {signal}dBm <- "{aps[ap]["essid"]}"')
			if success2:
				clients[client]["aps"][ap]["success_full"] += 1
				print(f'[*] WPS PIN full success {client} {signal}dBm <- "{aps[ap]["essid"]}"')
			if fail:
				clients[client]["aps"][ap]["fails"] += 1
				print(f'[*] WPS PIN fail {client} {signal}dBm <- "{aps[ap]["essid"]}"')
			if lock:
				print(f'[*] WPS PIN lock {client} {signal}dBm <- "{aps[ap]["essid"]}"')

def analyze():
	while True:
		for client in clients:
			for ap in clients[client]["aps"]:
				if len(clients[client]["aps"][ap]["r_hashes"]) > MAX_PIN_ATTEMPTS and clients[client]["aps"][ap]["success_full"] == 0:
					alert(client, ap, f'WPS PIN bruteforce in depth - {len(clients[client]["aps"][ap]["r_hashes"])} attempts')
			if len(clients[client]["aps"]) > MAX_APS_ATTEMPTS:
				alert(client, ap, f'WPS PIN bruteforce in width {len(clients[client]["aps"])} aps')
		sleep(1)

Thread(target=analyze, args=()).start()
sniff(iface=iface, prn=parse_raw_80211, store=0)
