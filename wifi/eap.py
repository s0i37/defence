#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from mac_vendor_lookup import MacLookup # pip3 install mac-vendor-lookup
from datetime import datetime, timedelta
from time import sleep
from random import random
from sys import argv
from os import system


iface = argv[1]
conf.iface = iface
conf.verb = 0
oui = MacLookup()

alerts = []
def alert(ap):
	global aps
	if ap in alerts:
		return
	try: vendor = oui.lookup(ap)
	except: vendor = ""
	print(f'[!] EAPhammer detected: "{ap} {aps[ap]["essid"]}" {aps[ap]["signal"]}dBm {aps[ap]["freq"]}MHz (uptime: {aps[ap]["uptime"]}) [{vendor}]')
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='EAPhammer detected' --text='EAPhammer detected' &")
	#system("echo 'EAPhammer detected' | festival --tts --language english")
	alerts.append(ap)
	system(f"prevent/gtc.sh wlan1 {ap}")

def get_uptime(timestamp):
	delta = timedelta(microseconds=timestamp)
	upTime = str(delta).split('.')[0]
	#upSince = str(datetime.now() - delta).split('.')[0]
	return upTime

aps = {}
beacons = set()
def parse_raw_80211(p):
	global beacons
	signal = int(p[RadioTap].dBm_AntSignal or 0) if hasattr(p[RadioTap], "dBm_AntSignal") else 0
	freq = p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else 0
	if Dot11Beacon in p: # Beacon
		ap = p[Dot11].addr2
		essid = str(p[Dot11Elt].info, "utf-8")
		beacons.add(ap)
		if not ap in aps:
			if "privacy" in p[Dot11Beacon].cap:
				layer = p[Dot11Elt].payload
				while True:
					if not layer:
						break
					if layer.ID == 0x30:
						if layer.info[17] == 1:
							enc = "EAP"
						else:
							enc = "WPA"
						break
					layer = layer.payload
			else:
				enc = "OPN"
			aps[ap] = {"essid": essid, "enc": enc, "signal": signal, "freq": freq, "uptime": get_uptime(p[Dot11Beacon].timestamp)}
			if enc == "EAP":
				try: vendor = oui.lookup(ap)
				except: vendor = ""
				print(f'[*] WPA Enterprise detected {ap} "{essid}" {signal}dBm {freq}MHz (uptime: {aps[ap]["uptime"]}) [{vendor}]')
	elif 0 and Dot11ProbeResp in p: # hidden, karma
		if p[Dot11].subtype == 5:
			ap = p[Dot11].addr2
			essid = str(p[Dot11Elt].info, "utf-8")
			aps[ap] = {"essid": essid, "enc": "EAP", "signal": signal, "freq": freq, "uptime": 0}

is_assoc = False
is_ident = False
eap_type = None
def connect(ap, essid):
	global is_assoc, is_ident, eap_type
	is_assoc = False
	is_ident = False
	eap_type = None

	def get_random_mac(l=6):
		return ':'.join(list(map(lambda x:"%02x"%int(random()*0xff),range(l))))
	source = "00:11:22:33:44:55"# + get_random_mac(5)
	
	#print(f" > auth req {ap}")
	authorization_request = RadioTap()/Dot11(proto=0, FCfield=0, subtype=11, addr2=source, addr3=ap, addr1=ap, SC=0, type=0)\
		/ Dot11Auth(status=0, seqnum=1, algo=0)
	if not srp1(authorization_request, verbose=0, timeout=1.0):
		return
	#print(f" > auth resp {ap}")

	def get_assoc_resp():
		def handle(p):
			global is_assoc, is_ident
			seen_receiver = p[Dot11].addr1
			seen_sender = p[Dot11].addr2
			seen_bssid = p[Dot11].addr3

			if ap.lower() == seen_bssid.lower() and \
			  ap.lower() == seen_sender.lower() and \
			  source.lower() == seen_receiver.lower():
				if Dot11AssoResp in p:
					#print(f" < assoc resp {ap}")
					is_assoc = True
				elif EAP in p and p[EAP].code == 1:
					#print(f" < ident req {ap}")
					is_ident = True
		sniff(iface=iface, lfilter=lambda p: p.haslayer(Dot11AssoResp) or p.haslayer(EAP), stop_filter=handle, timeout=1.0, store=0)
	#print(f" > assoc req {ap}")
	association_request = RadioTap()/Dot11(proto=0, FCfield=0, subtype=0, addr2=source, addr3=ap, addr1=ap, SC=0, type=0)\
		/ Dot11AssoReq(listen_interval=1, cap=0x3114)\
		/ Dot11Elt(ID=0, len=len(essid), info=essid)\
		/ Dot11Elt(ID=1, len=8, info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')\
		/ Dot11Elt(ID=48, len=0x14, info=b'\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x00\x00')\
		/ Dot11Elt(ID=50, len=4, info=b'\x30\x48\x60\x6c')\
		/ Dot11Elt(ID=59, len=0x14, info=b'\x51\x51\x53\x54\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82')\
		/ Dot11Elt(ID=221, len=8, info=b'\x8c\xfd\xf0\x01\x01\x02\x01\x00')
	Thread(target=get_assoc_resp).start()
	sendp(association_request, verbose=0)
	wait = 1.0
	while not is_ident and wait > 0:
		sleep(0.001)
		wait -= 0.001
	if not is_ident:
		return

	eap_type = 0
	def get_eap_type():
		def handle(p):
			global eap_type
			seen_receiver = p[Dot11].addr1
			seen_sender = p[Dot11].addr2
			seen_bssid = p[Dot11].addr3

			if ap.lower() == seen_bssid.lower() and \
			  ap.lower() == seen_sender.lower() and \
			  source.lower() == seen_receiver.lower():
				if EAP in p:
					eap_type = p[EAP].type
					#print(f" > eap req {ap} type={eap_type}")

		sniff(iface=iface, lfilter=lambda p: p.haslayer(EAP_PEAP), stop_filter=handle, timeout=5, store=0)
	#print(f" > ident resp {ap}")
	eap_identity_response = RadioTap()/Dot11(proto=0, FCfield=1, subtype=8, addr2=source, addr3=ap, addr1=ap, SC=0, type=2, ID=55808)\
		/ Dot11QoS(TID=6, TXOP=0, EOSP=0) \
		/ LLC(dsap=0xaa, ssap=0xaa, ctrl=0x3)\
		/ SNAP(OUI=0, code=0x888e)\
		/ EAPOL(version=1, type=0, len=9)\
		/ EAP(code=2, id=103, type=1, identity=b'user')
	Thread(target=get_eap_type).start()
	sendp(eap_identity_response, verbose=0, count=10)
	wait = 1.0
	while not eap_type and wait > 0:
		sleep(0.001)
		wait -= 0.001
	#print(f" > done {ap}")
	return eap_type

checked = []
def analyze():
	global checked, beacons
	while True:
		for ap in aps.copy():
			if not ap in checked and aps[ap]["enc"] == "EAP" and ap in beacons:
				eap_type = connect(ap, aps[ap]["essid"])
				if eap_type != None:
					checked.append(ap)
					if eap_type == 25: # CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
						alert(ap)
		beacons = set()
		sleep(1)

Thread(target=analyze, args=()).start()
sniff(iface=iface, prn=parse_raw_80211, store=0)
