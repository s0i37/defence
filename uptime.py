#!/usr/bin/python3
from scapy.all import *
from geolite2 import geolite2 #pip3 install maxminddb-geolite2
from ipwhois import IPWhois #pip3 install ipwhois
import scapy_p0f #pip3 install scapy-p0f
from netaddr import IPNetwork
import datetime
import time
from sys import argv


iface = argv[1]
filter = argv[2] if len(argv) > 2 else ""
addr = get_if_addr(iface)

grey_A = IPNetwork("10.0.0.0/8")
grey_B = IPNetwork("172.16.0.0/12")
grey_C = IPNetwork("192.168.0.0/16")
def is_grey(ip):
	return ip in grey_A or ip in grey_B or ip in grey_C

geoip = geolite2.reader()
geoip_cache = {}
def geoip_lookup(ip):
	if ip in geoip_cache:
		return geoip_cache[ip]
	LANG = 'ru'
	country = ""; city = ""
	result = geoip.get(ip)
	if result:
		country = result['country']['names'][LANG] if 'country' in result else ''
		city = result['city']['names'].get(LANG) if 'city' in result else ''
		geoip_cache[ip] = {"country": country or "", "city": city or ""}
	return {"country": country or "", "city": city or ""}

whois_cache = {}
def whois_lookup(ip):
	if ip in whois_cache:
		return whois_cache[ip]
	result = IPWhois(ip).lookup_whois()
	netname = result['nets'][0]['name']
	descr = result['nets'][0]['description']
	whois_cache[ip] = {"netname": netname, "descr": descr}
	return {"netname": netname, "descr": descr}

def p0f(packet):
	os = ""; ver = ""
	try:
		(_,_,os,ver),_,_ = scapy_p0f.p0f(packet)
	except:
		pass
	if not os and IP in packet:
		if packet[IP].ttl <= 64:
			os = "Linux"
		elif 64 < packet[IP].ttl <= 128:
			os = "Windows"
		elif 128 < packet[IP].ttl <= 255:
			os = "Cisco"
	return os, ver

uptimes = {}
def parse(packet):
	global uptimes
	if IP in packet and packet[IP].dst == addr and TCP in packet:
		#print(packet[IP].src, packet[TCP].options)
		for option in packet[TCP].options:
			if option[0] == 'Timestamp':
				boot_timestamp = option[1][0] / 1000 #HZ
				boot_time = datetime.datetime.utcfromtimestamp(time.time() - boot_timestamp).strftime('%Y-%m-%d %H:%M')
				ip = packet[IP].src
				if not ip in uptimes: uptimes[ip] = []
				if not boot_time in uptimes[ip]:
					os,ver = p0f(packet)
					if not is_grey(ip):
						geoip = geoip_lookup(ip)
						whois = whois_lookup(ip)
					else:
						geoip = {"country": "", "city": "",}
						whois = {"netname": "intranet", "descr": ""}
					print("{os} {country} {city} {netname} {src}: {uptime}".format(
							os=f"{os}{ver}",
							country=geoip["country"],
							city=geoip["city"],
							netname=whois["netname"],
							src=ip,
							uptime=boot_time
						))
					uptimes[ip].append(boot_time)
				break

sniff(iface=iface, prn=parse, filter=filter, store=0)
