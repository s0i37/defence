#!/usr/bin/python3
from scapy.all import *
import hmac,hashlib,binascii
import random,string
from sys import argv

iface = argv[1]
ap = argv[2]
essid = argv[3]
sta = argv[4]
conf.verb = 0
COUNT = 20
WORDLIST = "/usr/share/wordlists/rockyou.txt"
words = open(WORDLIST).readlines(100000)

def get_password_brutable(min_len):
	attempts = 10
	while attempts:
		word = random.choice(words).strip().lower()
		if not "'" in word and min_len <= len(word):
			return word
		attempts -= 1

def get_password_unbrutable(len):
	return "".join(map(lambda _:random.choice(string.printable[:95]), range(len)))

def beacon(ap, essid, count):
	WPA = 'ESS+privacy'
	RATE_1B = b"\x82"
	RATE_2B = b"\x84"
	RATE_5_5B = b"\x8b"
	RATE_11B = b"\x96"
	CHANNEL = 1
	beacon = RadioTap()/Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap)/\
		Dot11Beacon(cap=WPA)/\
		Dot11Elt(ID='SSID',info=essid, len=len(essid))/\
		Dot11Elt(ID='Rates', info=RATE_1B+RATE_2B+RATE_5_5B+RATE_11B)/\
		Dot11Elt(ID='ERPinfo', info=b"\x04")/\
		Dot11Elt(ID='DSset', info=int(CHANNEL).to_bytes(1,'big'))/\
		Dot11Elt(ID=48, len=20, info=b'\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00')
	sendp(beacon, iface=iface, inter=0.01, count=count, verbose=False)

anonce = None
def m1(ap, sta, count):
	global anonce
	def get_rand(n):
		o = b''
		for _ in range(n):
			o += int(random.random()*255).to_bytes(1, 'big')
		return o

	anonce = get_rand(32)
	eapol_data_4 = bytearray(95)
	eapol_data_4[0:1] = b"\x02" # Key Description_type
	eapol_data_4[1:3] = b"\x00\x8a" # Key Information
	eapol_data_4[3:5] = b"\x00\x10" # Key Length
	eapol_data_4[5:13] = b"\x00\x00\x00\x00\x00\x00\x00\x01" # Replay Counter
	eapol_data_4[13:45] = anonce
	eapol_data_4[45:61] = b"\x00"*16 # Key IV
	eapol_data_4[61:69] = b"\x00"*8 # WPA Key RSC
	eapol_data_4[69:77] = b"\x00"*8 # WPA Key Id
	eapol_data_4[77:93] = b"\x00"*16 # WPA Key Mic
	eapol_data_4[93:95] = b"\x00"*2 # WPA Key Data Length
	m1 = RadioTap() / Dot11(proto=0, FCfield=2, addr1=sta, addr2=ap, addr3=ap, subtype=8, SC=0, type=2, ID=55808) \
		/ Dot11QoS(TID=6, TXOP=0, EOSP=0) \
		/ LLC(dsap=0xaa, ssap=0xaa, ctrl=0x3) \
		/ SNAP(OUI=0, code=0x888e) \
		/ EAPOL(version=1, type=3, len=95) / bytes(eapol_data_4)
	sendp(m1, iface=iface, count=count, inter=0.01, verbose=False)

def m2(ap, sta, count):
	global anonce
	def assemble_EAP_Expanded(self, l):
	    ret = ''
	    for i in range(len(l)):
	        if l[i][0] & 0xFF00 == 0xFF00:
	            ret += (l[i][1])
	        else:
	            ret += pack('!H', l[i][0]) + pack('!H', len(l[i][1])) + l[i][1]
	    return ret


	def PRF_512(key,A,B):
	    return b''.join(hmac.new(key,A+chr(0).encode()+B+chr(i).encode(),hashlib.sha1).digest() for i in range(4))[:64]

	def get_rand(n):
	    o = b''
	    for _ in range(n):
	        o += int(random.random()*255).to_bytes(1, 'big')
	    return o

	def b(mac):
	    o = b''
	    for m in mac.split(':'):
	        o += int(m, 16).to_bytes(1, 'big')
	    return o

	password = get_password_brutable(8)
	#password = get_password_unbrutable(8)
	print(f"[*] send {password}")
	pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), essid.encode(), 4096, 32)
	snonce = get_rand(32)
	ptk = PRF_512(pmk, b"Pairwise key expansion", min(b(ap),b(sta))+max(b(ap),b(sta))+min(anonce,snonce)+max(anonce,snonce))
	kck = ptk[0:16]

	rsn_cap = b"\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00" # !!!!!!!
	eapol_data_4 = bytearray(117)
	eapol_data_4[0:1] = b"\x02" # Key Description Type: EAPOL RSN Key
	eapol_data_4[1:1+2] = b"\x01\x0a" # Key Information: 0x010a
	eapol_data_4[3:3+2] = b"\x00\x00" # Key Length: 0
	eapol_data_4[5:5+8] = b"\x00\x00\x00\x00\x00\x00\x00\x01" # Replay Counter: 1
	eapol_data_4[13:13+32] = snonce # WPA Key Nonce
	eapol_data_4[45:45+16] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # WPA Key IV
	eapol_data_4[61:61+8] = b"\x00\x00\x00\x00\x00\x00\x00\x00" # WPA Key RSC
	eapol_data_4[69:69+8] = b"\x00\x00\x00\x00\x00\x00\x00\x00" # WPA Key ID
	eapol_data_4[77:77+16] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # WPA Key MIC
	eapol_data_4[93:93+2] = b"\x00\x16" # WPA Key Data Length: 22
	eapol_data_4[95:95+26] = bytes(rsn_cap) # WPA Key Data Length

	mic = hmac.new(kck, b"\x01\x03\x00\x75" + bytes(eapol_data_4[:77]) + bytes.fromhex("00000000000000000000000000000000") + bytes(eapol_data_4[93:]), hashlib.sha1).digest()[0:16]
	eapol_data_4[77:77+16] = mic

	m2 = RadioTap() / Dot11(proto=0, FCfield=1, addr1=ap, addr2=sta, addr3=ap, subtype=8, SC=0, type=2, ID=55808) \
		/ Dot11QoS(TID=6, TXOP=0, EOSP=0) \
		/ LLC(dsap=0xaa, ssap=0xaa, ctrl=0x3) \
		/ SNAP(OUI=0, code=0x888e) \
		/ EAPOL(version=1, type=3, len=117) / bytes(eapol_data_4)
	sendp(m2, iface=iface, count=count, inter=0.01, verbose=False)


for _ in range(COUNT):
	beacon(ap, essid, 5)
	m1(ap, sta, 5)
	m2(ap, sta, 10)
