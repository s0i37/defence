#!/usr/bin/python3
import socket
import struct
import difflib
from sys import argv


port = argv[1]
proto = argv[2]

def get_nmap_probe(buf):
	best_match = 0
	probename = None
	for probe in probes:
		matcher = difflib.SequenceMatcher(a=probes[probe], b=buf)
		match = matcher.find_longest_match(0, len(matcher.a), 0, len(matcher.b))
		if match.size > best_match:
			best_match = match.size
			probename = probe
			#matcher.a[match.a:match.a+match.size]
	return probename

def get_strings(bytes):
	out = ''
	for byte in bytes:
		if 0x20 <= byte <= 0x7f:
			out += chr(byte)
		else:
			out += "."
	return out

def get_original_dst(sock):
	sockaddr_in = sock.getsockopt(socket.SOL_IP, 80, 16)
	(proto, port, a,b,c,d) = struct.unpack("!HHBBBB", sockaddr_in[:8])
	dst_ip = "%d.%d.%d.%d" % (a,b,c,d)
	dst_port = port
	return (dst_ip, dst_port)

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

MAX = 100
if proto.upper() == 'TCP':
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("0.0.0.0", int(port)))
	s.listen(10)
	while True:
		c,info = s.accept()
		dst = get_original_dst(c)
		try:
			buf = c.recv(1024)
			print("{src_ip}:{src_port} -> {dst_ip}:{dst_port} [{probe}] {buf}".format(
				src_ip=info[0],
				src_port=info[1],
				dst_ip=dst[0],
				dst_port=dst[1],
				probe=get_nmap_probe(buf),
				buf=get_strings(buf)[:MAX]
			))
		except:
			pass
		c.close()
elif proto.upper() == 'UDP':
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(("0.0.0.0", int(port)))
	while True:
		try:
			buf,info = s.recvfrom(1024)
			print(info[0], get_nmap_probe(buf), get_strings(buf)[:MAX])
		except:
			pass
s.close()
