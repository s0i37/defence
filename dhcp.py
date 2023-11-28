#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from time import sleep
from sys import argv
from os import system

conf.iface = argv[1]
conf.verb = 0

def parse(p):
	global dhcp_servers
	if DHCP in p:
		for option in p[DHCP].options:
			if 'message-type' in option and 2 in option:
				dhcp_servers.add(p[IP].src)
	elif DHCP6_Advertise in p:
		dhcp_servers.add(p[IPv6].src)
		try:
			domains = ','.join(p[DHCP6OptDNSDomains].dnsdomains)
			print(domains)
		except:
			pass

alerts = []
def alert(new_dhcp_servers):
	if not new_dhcp_servers - set(alerts):
		return
	dhcp_servers = ", ".join(map(str, new_dhcp_servers))
	print("[!] DHCP roque: " + dhcp_servers)
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='DHCP roque server' --text='DHCP roque: %s' &" % dhcp_servers)
	#system("echo 'DHCP roque server detected' | festival --tts --language english &")
	alerts.extend(new_dhcp_servers)

def dhcp_discover():
	dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=Ether().src, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67,sport=68)/BOOTP(op=1, chaddr=Ether().src, xid=RandInt())/DHCP(options=[('message-type','discover'), ('hostname','localhost'), ('param_req_list',[1,3,6]), ('end')])
	sendp(dhcp_discover)
	dhcp_discover6 = Ether(dst="33:33:00:01:00:02", src=Ether().src)/IPv6(dst="ff02::1:2")/UDP(sport=546, dport=547)/DHCP6_Solicit(trid=RandInt())/DHCP6OptClientId(duid=DUID_LLT(lladdr=Ether().src,timeval=int(time.time())))/DHCP6OptIA_NA(iaid=0xf)/DHCP6OptRapidCommit()/DHCP6OptElapsedTime()/DHCP6OptOptReq(reqopts=[23,24])
	sendp(dhcp_discover6)

dhcp_servers_legal = set()
while True:
	dhcp_servers = set()
	thr = Thread(target=lambda:sniff(timeout=5, prn=parse))
	thr.start()
	dhcp_discover()
	thr.join()
	if not dhcp_servers_legal:
		dhcp_servers_legal = dhcp_servers.copy() or set([""])
		print("[*] DHCP legal: " + ", ".join(map(str,dhcp_servers_legal)))
	if dhcp_servers - dhcp_servers_legal:
		alert(dhcp_servers - dhcp_servers_legal)
	sleep(10)
