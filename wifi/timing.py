#!/usr/bin/python3
from scapy.all import *
from os import system
from sys import argv


iface = argv[1]
conf.verb = 0

alerts = []
def alert(flow, stage, delta):
	if flow in alerts:
		return
	print(f'[!] Raw packets generation detected: {flow} {stage} {delta}')
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='Raw packets generation detected' --text='Raw packets generation detected' &")
	#system("echo 'Raw packets generation detected' | festival --tts --language english")
	alerts.append(flow)

stages = ["probe_req", "probe_res", "auth_req", "auth_res", "assoc_req", "assoc_res"]
connections = {}
def parse_raw_80211(p):
	global connections
	signal = int(p[RadioTap].dBm_AntSignal or 0) if hasattr(p[RadioTap], "dBm_AntSignal") else 0
	freq = p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else 0
	ap = p[Dot11].addr3
	if Dot11ProbeReq in p:
		sta = p[Dot11].addr2
		stage = "probe_req"
		direction = "->"
	elif Dot11ProbeResp in p:
		sta = p[Dot11].addr1
		stage = "probe_res"
		direction = "<-"
	elif Dot11Auth in p:
		if p[Dot11].addr1 == ap:
			sta = p[Dot11].addr2
			stage = "auth_req"
			direction = "->"
		elif p[Dot11].addr2 == ap:
			sta = p[Dot11].addr1
			stage = "auth_res"
			direction = "<-"
	elif Dot11AssoReq in p:
		sta = p[Dot11].addr2
		stage = "assoc_req"
		direction = "->"
	elif Dot11AssoResp in p:
		sta = p[Dot11].addr1
		stage = "assoc_res"
		direction = "<-"
	else:
		return

	flow = f"{sta} %s {ap}"
	if not flow in connections:
		connections[flow] = {}
	if not stage in connections[flow]:
		_flow = flow.replace(ap, "ff:ff:ff:ff:ff:ff") if stages.index(stage) == 1 else flow
		if stages.index(stage) > 0 and connections.get(_flow) and connections[_flow].get( stages[stages.index(stage)-1] ):
			connections[flow][stage] = p.time
			delta = p.time - connections[_flow][stages[stages.index(stage)-1]]
			if delta > 1:
				delta = 0 # noise
			print(f"[*] {flow%direction} {stage} {freq}MHz {signal}dBm +{delta}")
			if 'assoc_req' in stage and delta > 0.01: # sta timing
				alert(flow%direction, stage, delta)
			elif 'res' in stage: # ap timing
				pass
			del( connections[_flow][stages[stages.index(stage)-1]] )
		else:
			connections[flow] = {stage: p.time}
			print(f"[*] {flow%direction} {stage} {freq}MHz {signal}dBm")

sniff(iface=iface, lfilter=lambda p: p.haslayer(Dot11), prn=parse_raw_80211, store=0)
