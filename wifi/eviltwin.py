#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from mac_vendor_lookup import MacLookup # pip3 install mac-vendor-lookup
from datetime import datetime, timedelta
from time import sleep
from sys import argv
from os import system


iface = argv[1]
conf.verb = 0
oui = MacLookup()

alerts = []
def alert(ap):
	global aps
	if ap in alerts:
		return
	try: vendor = oui.lookup(ap)
	except: vendor = ""
	print(f'[!] EvilTwin AP detected: "{aps[ap]["essid"]}" {aps[ap]["freq"]}MHz {aps[ap]["signal"]}dBm (uptime: {aps[ap]["uptime"]}) [{vendor}]')
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='EvilTwin AP detected' --text='EvilTwin AP detected' &")
	#system("echo 'EvilTwin AP detected' | festival --tts --language english")
	alerts.append(ap)
	system(f"prevent/deauth.py {iface} {ap} ff:ff:ff:ff:ff:ff")

def get_uptime(timestamp):
	delta = timedelta(microseconds=timestamp)
	upTime = str(delta).split('.')[0]
	#upSince = str(datetime.now() - delta).split('.')[0]
	return upTime

aps = {}
ENC_CAP = int(Dot11Beacon(cap='privacy').cap)
ENC_FIELD = int(Dot11(FCfield='protected').FCfield)
def parse_raw_80211(p):
	signal = int(p[RadioTap].dBm_AntSignal or 0) if hasattr(p[RadioTap], "dBm_AntSignal") else 0
	freq = p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else 0
	if Dot11Beacon in p: # Beacon
		ap = p[Dot11].addr2
		essid = str(p[Dot11Elt].info, "utf-8")
		enc = "WPA" if ENC_CAP & int(p[Dot11Beacon].cap) else "OPN"
		if Dot11EltDSSSet in p:
			channel = p[Dot11EltDSSSet].channel
		if not ap in aps:
			aps[ap] = {"essid": essid, "enc": enc, "freq": freq, "channel": channel, "uptime": get_uptime(p[Dot11Beacon].timestamp), "signal": signal}
			try: vendor = oui.lookup(ap)
			except: vendor = ""
			print(f'[*] {ap} "{essid}" {enc} {freq}MHz {channel} {signal}dBm (uptime: {aps[ap]["uptime"]}) [{vendor}]')
		if aps[ap]["freq"] != freq and aps[ap]["signal"] < signal:
			aps[ap]["signal"] = signal
			aps[ap]["freq"] = freq
			aps[ap]["channel"] = channel

def analyze():
	while True:
		wpa = set([])
		for ap in aps.copy():
			if aps[ap]["enc"] == "WPA":
				wpa.add(aps[ap]["essid"])
		for ap in aps.copy():
			if aps[ap]["enc"] == "OPN":
				if aps[ap]["essid"] in wpa:
					alert(ap)
		sleep(1)

Thread(target=analyze, args=()).start()
sniff(iface=iface, prn=parse_raw_80211, store=0)
