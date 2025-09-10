#!/usr/bin/python3
import socket
import struct
import rstr #pip3 install rstr
import random
from sys import argv


port = argv[1]
proto = argv[2]

def get_random_match():
	return random.choice(matches)

def get_match_by_port(port):
	return matches[port%len(matches)]

def get_original_dst(sock):
	try:
		sockaddr_in = sock.getsockopt(socket.SOL_IP, 80, 16)
		(proto, port, a,b,c,d) = struct.unpack("!HHBBBB", sockaddr_in[:8])
		dst_ip = "%d.%d.%d.%d" % (a,b,c,d)
		dst_port = port
		return (dst_ip, dst_port)
	except:
		pass

matches = []
with open("/usr/share/nmap/nmap-service-probes") as f:
	#https://github.com/boy-hack/nmap-parser
	for line in f.readlines():
		line = line.strip()
		if line.startswith("match "):
			matchtext = line[len("match "):]
			index = matchtext.index(" m")
			m = matchtext[index + 2]
			name = matchtext[:index]
			matchtext = matchtext[len(name):].strip()
			regx_start = 2
			regx_end = matchtext.index(m, regx_start)
			regx = matchtext[regx_start:regx_end]
			try:
				matches.append( rstr.xeger(regx) )
			except Exception as e:
				pass

if proto.upper() == 'TCP':
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("0.0.0.0", int(port)))
	s.listen(10)
	while True:
		c,info = s.accept()
		_,port = get_original_dst(c) or ("",0)
		try:
			if port:
				c.send(get_match_by_port(port).encode())
			else:
				c.send(get_random_match().encode())
		except:
			pass
		c.close()
elif proto.upper() == 'UDP':
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(("0.0.0.0", int(port)))
	while True:
		try:
			buf,client = s.recvfrom(1024)
			s.sendto(get_random_match().encode(), client)
		except:
			pass
s.close()
