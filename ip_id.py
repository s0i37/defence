#!/usr/bin/python3
from scapy.all import *
from geolite2 import geolite2 #pip3 install maxminddb-geolite2
from ipwhois import IPWhois #pip3 install ipwhois
import scapy_p0f #pip3 install scapy-p0f
from netaddr import IPNetwork
from sys import argv


iface = argv[1]
filter = argv[2] if len(argv) > 2 else ""
conf.iface = iface
conf.verb = 0
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

delta_ids = {}
def get_delta_id(packet):
	delta = 0
	src_ip = packet[IP].src
	if delta_ids.get(src_ip):
		delta = abs(packet[IP].id - delta_ids[src_ip])
	delta_ids[src_ip] = packet[IP].id
	return delta

def analyze(packet):
	distance = None; delta_ttl = None; os = None
	try:
		if IP in packet:
			if packet[IP].dst == addr: # incoming
				ip = packet[IP].src
				delta_id = get_delta_id(packet)
				src_port = packet[IP].payload.sport if TCP in packet or UDP in packet else 0
				dst_port = packet[IP].payload.dport if TCP in packet or UDP in packet else 0
				proto = packet[IP].payload.name
				os,ver = p0f(packet)
				if not is_grey(ip):
					geoip = geoip_lookup(ip)
					whois = whois_lookup(ip)
				else:
					geoip = {"country": "", "city": "",}
					whois = {"netname": "intranet", "descr": ""}
				print("{os} {country} {city} {netname} {src_ip}:{src_port} -> {proto} :{dst_port} +{delta}".format(
					delta=delta_id,
					src_ip=ip,
					src_port=src_port,
					proto=proto,
					dst_port=dst_port,
					os=f"{os}{ver}",
					country=geoip["country"],
					city=geoip["city"],
					netname=whois["netname"]
				))
	except Exception as e:
		print(str(e))
		pass

sniff(iface=iface, prn=analyze, filter=filter, store=0)
