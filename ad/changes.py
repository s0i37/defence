#!/usr/bin/python3
# -*- coding: utf-8 -*-
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3 import Server, Connection, SUBTREE, BASE, ALL, ALL_ATTRIBUTES
from time import sleep
from datetime import datetime
from getpass import getpass
from os import system
from sys import argv
from re import match
from colorama import Fore

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.sid import SID
from winacl.dtyp.ace import ADS_ACCESS_MASK


dc = argv[1]
userdom = argv[2] # "user@company.org"
ATTACKS = { # notifications
	"SPN attack": {"attr": "^serviceprincipalname$", "dn": ".*"},
	"RBCD attack" : {"attr": "^msds-allowedtoactonbehalfofotheridentity$", "dn": ".*"},
	"ShadowCredentials attack" : {"attr": "^msds-keycredentiallink$", "dn": ".*"},
	"membership changed": {"attr": "^member$", "dn": ".*admin.*"},
	"GPO attack": {"attr": "^gpcfilesyspath$", "dn": ".*"},
	"user object abuse": {"attr": "^scriptpath$", "dn": ".*"},
	"ACL attack": {"attr": ".*generic_all.*", "dn": ".*"},
	"ADCS attack authorities": {"attr": ".*", "dn": ".*CN=Certification Authorities,.*"},
	"ADCS attack templates": {"attr": ".*", "dn": ".*CN=Certificate Templates,.*"}
}

server = Server(dc, get_info=ALL)
Connection(server, auto_bind=True)
root = server.info.naming_contexts[0] #[1]
server_time = server.info.other.get('currentTime')[0]
print("{root} {server_time}".format(root=root, server_time=server_time))
conn = Connection(server, user=userdom, password=argv[3] if len(argv) > 3 else getpass("password: "))
conn.bind()

alerts = []
def alert(dn, attr, value, message):
	if (dn,attr) in alerts:
		return
	print("[!] Danger changes detected: %s: %s=%s (%s)" % (dn, attr, value, message))
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")                                                                  
	system("zenity --warning --title='Danger changes detected' --text='%s: %s=%s (%s)' &" % (dn, attr, value, message))                                                                       
	#system("echo 'Danger changes detected' | festival --tts --language english")
	alerts.append((dn,attr))

cache_sid = {}
def resolve_sid(sid):
	global cache_sid
	if not sid in cache_sid:
		cache_sid[sid] = None
		for dn in objects:
			if objects[dn].get("objectSid") == [sid]:
				name = objects[dn]["sAMAccountName"]
				cache_sid[sid] = name
				break
	return cache_sid.get(sid)

def parse_acl(nTSecurityDescriptor):
	acl = SECURITY_DESCRIPTOR.from_bytes(nTSecurityDescriptor)
	acl_canonical = {"owner": [acl.Owner.to_sddl() if acl.Owner else ""], "dacl":[]}
	for ace in acl.Dacl.aces if acl.Dacl else []:
		ace_canonical = {}
		ace_canonical["who"] = SID.wellknown_sid_lookup(ace.Sid.to_sddl()) or resolve_sid(ace.Sid.to_sddl()) or ace.Sid.to_sddl()
		ace_canonical["type"] = str(ace).split("\n")[0].strip()
		for line in str(ace).split("\n")[1:]:
			if line.strip():
				field = line.split(":")[0].lower()
				value = line.split(":")[1].strip()
				ace_canonical[field] = value
		acl_canonical["dacl"].append(ace_canonical)
	return acl_canonical

def snapshot():
	#conn.search(root, '(objectClass=*)', SUBTREE, attributes=ALL_ATTRIBUTES) # only attributes
	conn.search(root, '(objectClass=*)', SUBTREE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05)) # with ACL
	#conn.search(root, '(|(objectClass=pKICertificateTemplate)(objectClass=certificationAuthority))', SUBTREE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05)) # with ACL
	#conn.search(root, '(objectClass=user)', SUBTREE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05))
	for result in conn.entries:
		dn = result.entry_dn
		objects[dn] = result.entry_attributes_as_dict
	for dn in objects: # because of resolve_sid()
		if 'nTSecurityDescriptor' in objects[dn]:
			objects[dn]['nTSecurityDescriptor'] = parse_acl(objects[dn]['nTSecurityDescriptor'][0])

def get_attrs(dn):
	#conn.search(dn, '(objectClass=*)', BASE, attributes=ALL_ATTRIBUTES) # only attributes
	conn.search(dn, '(objectClass=*)', BASE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05)) # with ACL
	attrs = conn.entries[0].entry_attributes_as_dict
	if attrs.get('nTSecurityDescriptor'):
		attrs['nTSecurityDescriptor'] = parse_acl(attrs['nTSecurityDescriptor'][0])
	return attrs

def print_diff(dn):
	if not dn in objects:
		return
	def diff(attrs_before, attrs_after):
		for attr in attrs_before:
			if not attr in attrs_after:
				print(f"{Fore.RED}delete %s: %s{Fore.RESET}" % (attr, str(attrs_before[attr])))
			else:
				if type(attrs_before[attr]) == dict:
					diff(attrs_before[attr], attrs_after[attr])
				else:
					for value in attrs_before[attr]:
						if not value in attrs_after[attr]:
							print(f"{Fore.RED}delete %s: %s{Fore.RESET}" % (attr, value))
		for attr in attrs_after:
			if not attr in attrs_before:
				print(f"{Fore.GREEN}new %s: %s{Fore.RESET}" % (attr, str(attrs_after[attr])))
				for attack in ATTACKS:
					if (match(ATTACKS[attack]["attr"], attr.lower()) or match(ATTACKS[attack]["attr"], str(attrs_after[attr]).lower())) and match(ATTACKS[attack]["dn"], dn.lower()):
						alert(dn, attr, attrs_after[attr], attack)
			else:
				if type(attrs_after[attr]) == dict:
					diff(attrs_before[attr], attrs_after[attr])
				else:
					for value in attrs_after[attr]:
						if not value in attrs_before[attr]:
							print(f"{Fore.GREEN}added %s: %s{Fore.RESET}" % (attr, value))
							for attack in ATTACKS:
								if (match(ATTACKS[attack]["attr"], attr.lower()) or match(ATTACKS[attack]["attr"], str(value).lower())) and match(ATTACKS[attack]["dn"], dn.lower()):
									alert(dn, attr, value, attack)
	attrs = get_attrs(dn)
	diff(objects[dn], attrs)
	objects[dn] = attrs

objects = {}
snapshot()
print("[*] %d objects" % len(objects))
now = datetime.strptime(server_time, '%Y%m%d%H%M%S.0Z').timestamp() or datetime.utcnow().timestamp()
first_time = True
while True:
	conn.search(root, f'(whenChanged>={datetime.utcfromtimestamp(now).strftime("%Y%m%d%H%M%S.0Z")})', SUBTREE, attributes=["distinguishedName", "whenChanged", "whenCreated"])
	lasts = [now]
	for result in conn.entries:
		dn = result.entry_dn
		changed = result['whenChanged'].value
		created = result['whenCreated'].value
		time = changed.strftime("%d.%m.%Y %H:%M:%S")
		if changed == created:
			if not first_time:
				print(f'[{time}] "{dn}" created')
				objects[dn] = get_attrs(dn)
			lasts.append(created.timestamp())
		else:
			if not first_time:
				print(f'[{time}] "{dn}" changed')
				print_diff(dn)
			lasts.append(changed.timestamp())
	now = max(lasts) + 1
	sleep(1)
	first_time = False
