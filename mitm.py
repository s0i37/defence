#!/usr/bin/python3
from scapy.all import *
from time import sleep
from sys import argv
from os import system


targets = []
conf.verb = 0
TIMEOUT = 1

alerts = []
def alert(ip, distance_old, distance_new):
	if ip in alerts:
		return
	traceroute = probe_traceroute(ip)
	print("[!] MiTM detected %s: change distance: %s -> %s (%s)" % (ip, str(distance_old), str(distance_new), traceroute))
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='MiTM detected' --text='MiTM detected: victim %s' &" % ip)
	#system("echo 'MiTM detected' | festival --tts --language english")
	alerts.append(ip)

def probe_ttl(ip):
	answer = sr1(IP(dst=ip)/ICMP(), timeout=TIMEOUT)
	if answer:
		return answer[IP].ttl

def probe_traceroute(ip):
	trace = []
	for hop in traceroute(ip, l4=ICMP(), timeout=TIMEOUT):
		req,res = hop
		trace.append(res[IP].src)
	return "->".join(trace)

with open(argv[1]) as f:
	for line in f:
		targets.append( line.split("\n")[0] )

distances = {}
while True:
	for target in targets:
		distance = probe_ttl(target)
		#distance = probe_traceroute(target)
		if distance:
			if not distances.get(target):
				distances[target] = distance
			if distances[target] != distance:
				alert(target, distances[target], distance)
		sleep(1)
	sleep(30)
