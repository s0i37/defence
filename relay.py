#!/usr/bin/python3
from scapy.all import *
from os import system
from sys import argv


conf.iface = argv[1]
filter = argv[2] if len(argv) > 2 else ""
load_layer("ntlm")
load_layer("http")
sessions = {}

alerts = []
def alert(flow):
	if flow in alerts:
		return
	print("[!] NTLM-relay attack detected: %s" % flow)
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='NTLM-relay attack detected' --text='NTLM-relay attack detected' &")
	#system("echo 'NTLM-relay attack detected' | festival --tts --language english")
	alerts.append(flow)

def parse(p):
	if SMB_Header in p or SMB2_Header in p:
		if SMB2_Session_Setup_Response in p or SMBSession_Setup_AndX_Response_Extended_Security in p:
			flow = f"{p[IP].dst} -smb-> {p[IP].src}"
			try:
				if SMBSession_Setup_AndX_Response_Extended_Security in p:
					if NTLM_CHALLENGE in p.SecurityBlob:
						ntlm = p.SecurityBlob
					else:
						ntlm = p.SecurityBlob.token.responseToken.value
				elif SMB2_Session_Setup_Response in p:
					if NTLM_CHALLENGE in p.Buffer[0][1]:
						ntlm = p.Buffer[0][1]
					else:
						ntlm = p.Buffer[0][1].token.responseToken.value
				challenge = ntlm.ServerChallenge
				print(f"[*] NTLM {flow} challenge={challenge.hex()}")
				if challenge in ['aaaaaaaaaaaaaaaa']:
					return
				if challenge in sessions and sessions[challenge] != flow:
					alert(f"{p[IP].dst} -smb-> {sessions[challenge]}")
				else:
					sessions[challenge] = flow
			except Exception as e:
				pass
	elif HTTP in p:
		if HTTPResponse in p:
			try:
				auth,nego = p[HTTPResponse].WWW_Authenticate.split()
				if auth == b'NTLM':
					flow = f"{p[IP].dst} -http-> {p[IP].src}"
					challenge = base64.decodebytes(nego)[24:32]
					print(f"[*] NTLM {flow} challenge={challenge.hex()}")
					if challenge in ['aaaaaaaaaaaaaaaa']:
						return
					if challenge in sessions and sessions[challenge] != flow:
						alert(f"{p[IP].dst} -http-> {sessions[challenge]}")
					else:
						sessions[challenge] = flow
			except Exception as e:
				pass
	elif LDAP in p:
		if LDAP_BindResponse in p.protocolOp:
			try:
				flow = f"{p[IP].dst} -ldap-> {p[IP].src}"
				challenge = bytes(p.protocolOp.matchedDN)[27:27+8]
				print(f"[*] NTLM {flow} challenge={challenge.hex()}")
				if challenge in ['aaaaaaaaaaaaaaaa']:
					return
				if challenge in sessions and sessions[challenge] != flow:
					alert(f"{p[IP].dst} -ldap-> {sessions[challenge]}")
				else:
					sessions[challenge] = flow
			except Exception as e:
				pass

sniff(iface=conf.iface, filter=filter, prn=parse, store=0)
