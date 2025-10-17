#!/usr/bin/python3
from scapy.all import *
from sys import argv
from os import system


iface = argv[1]
conf.verb = 0

alerts = []
def alert(src, dst, signal, essid):
	if src in alerts and dst in alerts:
		return

	print(f'[!] WPA handshake deauth detected: "{essid}" {src} <-x-> {dst} {signal}dBm')
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='PMKID gathering detected' --text='WPA handshake deauth detected' &")
	#system("echo 'WPA handshake deauth detected' | festival --tts --language english")
	alerts.append(src)
	alerts.append(dst)
	system(f"prevent/m2.py {iface} {src} '{essid}' {dst}")

aps = {}
deauths = {}
def parse_raw_80211(p):
	signal = int(p[RadioTap].dBm_AntSignal or 0) if hasattr(p[RadioTap], "dBm_AntSignal") else 0
	freq = p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else 0
	if Dot11Beacon in p: # Beacon
		ap = p[Dot11].addr2
		essid = str(p[Dot11Elt].info, "utf-8")
		if not ap in aps:
			aps[ap] = {"essid": essid}
	if Dot11Deauth in p:
		ap = p[Dot11].addr3
		src = p[Dot11].addr2
		dst = p[Dot11].addr1
		if ap == src:
			print(f"[*] deauth {src} -> {dst}")
		elif ap == dst:
			print(f"[*] deauth {dst} <- {src}")
		deauths[src] = dst
		if deauths.get(dst) == src or dst.lower() == "ff:ff:ff:ff:ff:ff":
			alert(src, dst, signal, aps.get(ap,{}).get("essid"))

sniff(iface=iface, prn=parse_raw_80211, store=0)
