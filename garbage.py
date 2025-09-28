#!/usr/bin/python3
import socket
import random
from time import sleep
from threading import Thread
from sys import argv


port = argv[1]
proto = argv[2]

def serve(sock):
	#SIZE=1024
	SIZE=1
	SLOW=1
	#SLOW=0
	print("[+] garbage started")
	data = "\x0e"*SIZE
	#data = "".join(map(lambda x:random.choice("\x01\x02\x03\x04\x05\x06\x08\x0a\x0b\x0e\x0f\x10\x11"), range(SIZE)))
	while True:
		try:
			sock.send(data.encode())
		except:
			break
		sleep(random.random()*SLOW)
	sock.close()
	print("[-] garbage closed")

if proto.upper() == 'TCP':
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("0.0.0.0", int(port)))
	s.listen(10)
	while True:
		c,info = s.accept()
		Thread(target=serve, args=(c,)).start()
elif proto.upper() == 'UDP':
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(("0.0.0.0", int(port)))
	while True:
		try:
			buf,client = s.recvfrom(1024)
			Thread(target=serve, args=(client,)).start()
		except:
			pass
s.close()
