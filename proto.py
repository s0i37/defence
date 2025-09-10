#!/usr/bin/python3
import socket
import struct
import difflib
from geolite2 import geolite2 #pip3 install maxminddb-geolite2
from ipwhois import IPWhois #pip3 install ipwhois
from netaddr import IPNetwork
from sys import argv


port = argv[1]
proto = argv[2]

grey_A = IPNetwork("10.0.0.0/8")
grey_B = IPNetwork("172.16.0.0/12")
grey_C = IPNetwork("192.168.0.0/16")
def is_grey(ip):
	return ip in grey_A or ip in grey_B or ip in grey_C

geoip_cache = {}
def geoip_lookup(ip):
	global geoip_cache
	if ip in geoip_cache:
		return geoip_cache[ip]
	geoip = geolite2.reader()
	LANG = 'ru'
	result = geoip.get(ip)
	if result:
		country = result['country']['names'][LANG] if 'country' in result else ''
		city = result['city']['names'].get(LANG) if 'city' in result else ''
		geoip_cache[ip] = {"country": country or "", "city": city or ""}
	else:
		geoip_cache[ip] = {"country": "", "city": ""}
	geolite2.close()
	return geoip_cache[ip]

whois_cache = {}
def whois_lookup(ip):
	global whois_cache
	if ip in whois_cache:
		return whois_cache[ip]
	result = IPWhois(ip).lookup_whois()
	netname = result['nets'][0]['name']
	descr = result['nets'][0]['description']
	whois_cache[ip] = {"netname": netname, "descr": descr}
	return whois_cache[ip]

def get_nmap_probe(buf):
	best_match = 0
	probename = None
	for probe in probes:
		matcher = difflib.SequenceMatcher(a=probes[probe], b=buf)
		match = matcher.find_longest_match(0, len(matcher.a), 0, len(matcher.b))
		if match.size/len(buf) > best_match:
			best_match = match.size/len(buf)
			probename = probe
			#matcher.a[match.a:match.a+match.size]
	return probename,best_match

def get_strings(bytes):
	out = ''
	for byte in bytes:
		if 0x20 <= byte <= 0x7f:
			out += chr(byte)
		else:
			out += "."
	return out

def get_original_dst(sock):
	try:
		sockaddr_in = sock.getsockopt(socket.SOL_IP, 80, 16)
		(proto, port, a,b,c,d) = struct.unpack("!HHBBBB", sockaddr_in[:8])
		dst_ip = "%d.%d.%d.%d" % (a,b,c,d)
		dst_port = port
		return (dst_ip, dst_port)
	except:
		pass

probes = {}
with open("/usr/share/nmap/nmap-service-probes") as f:
	#https://github.com/boy-hack/nmap-parser
	for line in f.readlines():
		line = line.strip()
		if line.startswith("Probe "):
			protocol = line[6:9]
			if protocol not in ["TCP", "UDP"]:
				continue
			probename_start = 10
			probename_end = line.index(" ", probename_start)
			if probename_end - probename_start <= 0:
				continue
			probename = line[probename_start:probename_end]
			probestring_start = line.index("q|", probename_end) + 1
			probestring = line[probestring_start:].strip("|")
			probes[probename] = probestring.encode().decode('unicode-escape').encode()

def analyze(ip, port, dst, packet):
	MAX = 50
	if not (is_grey(ip) or ip == "127.0.0.1"):
		geoip = geoip_lookup(ip)
		whois = whois_lookup(ip)
	else:
		geoip = {"country": "", "city": "",}
		whois = {"netname": "localhost" if ip == "127.0.0.1" else "intranet", "descr": ""}
	probe,match = get_nmap_probe(packet)
	print("{country} {city} {netname} {src_ip}:{src_port} -> :{dst_port} [{probe},{match}%] {buf}".format(
		country=geoip["country"],
		city=geoip["city"],
		netname=whois["netname"],
		src_ip=ip,
		src_port=port,
		dst_ip=dst[0],
		dst_port=dst[1],
		probe=probe,
		match=int(round(match,2)*100),
		buf=get_strings(packet)[:MAX]
	))

if proto.upper() == 'TCP':
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("0.0.0.0", int(port)))
	s.listen(10)
	while True:
		c,info = s.accept()
		dst = get_original_dst(c) or ("0.0.0.0",port)
		try:
			buf = c.recv(1024)
			analyze(info[0], info[1], dst, buf)
		except Exception as e:
			pass
		c.close()
elif proto.upper() == 'UDP':
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(("0.0.0.0", int(port)))
	while True:
		try:
			buf,info = s.recvfrom(1024)
			analyze(info[0], info[1], ["",port], buf)
		except:
			pass
s.close()
