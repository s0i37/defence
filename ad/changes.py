#!/usr/bin/python3
# -*- coding: utf-8 -*-
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3 import Server, Connection, SUBTREE, BASE, ALL, ALL_ATTRIBUTES, NTLM, GSSAPI,SASL
import pickle
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
ATTACKS = { # notifications
	"SPN attack": {"attr": "^serviceprincipalname$", "val": ".*", "dn": ".*"},
	"RBCD attack" : {"attr": "^msds-allowedtoactonbehalfofotheridentity$", "val": ".*", "dn": ".*"},
	"ShadowCredentials attack" : {"attr": "^msds-keycredentiallink$", "val": ".*", "dn": ".*"},
	"membership changed": {"attr": "^member$", "val": ".*", "dn": ".*admin.*"},
	"GPO attack": {"attr": "^gpcfilesyspath$", "val": ".*", "dn": ".*"},
	"user object abuse": {"attr": "^scriptpath$", "val": ".*", "dn": ".*"},
	"ACL attack": {"attr": ".*generic_all.*", "val": ".*", "dn": ".*"},
	"sAMAccountName spoofing": {"attr": "^samaccountname$", "val": r"^(.*dc.*(?!\$).)$", "dn": ".*"},
	"dNSHostName spoofing": {"attr": "^dnshostname$", "val": ".*dc.*", "dn": ".*"},
	"ADCS attack templates ESC4": {"attr": "^(msPKI-Certificate-Name-Flag|msPKI-Enrollment-Flag|msPKI-RA-Signature)$", "val": ".*", "dn": ".*CN=Certificate Templates,.*"},
	"kerberos-relay attack": {"attr": "TODO", "val": ".*1UWhR.*", "dn": ".*"}
}
INTERVAL = 1

server = Server(dc, get_info=ALL)
#server = Server(dc, port=636, use_ssl=True, get_info=ALL)
Connection(server, auto_bind=True)
server_time = server.info.other.get('currentTime')[0]
if len(argv) < 4:
	print(server_time)
	print("\n".join(server.info.naming_contexts))
	exit()
else:
	root = argv[3]
userdom = argv[2] # "company\\user"
#conn = Connection(server, user=userdom, password=getpass("password: "))
conn = Connection(server, user=userdom, password=getpass("password: "), authentication=NTLM)
#conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI)
conn.bind()

alerts = []
def alert(dn, attr, value, message):
	if (dn,attr) in alerts:
		return
	print("[!] Danger changes detected: %s: %s=%s (%s)" % (dn, attr, value, message))
	#system("telegram '{message}'".format(message="Danger changes detected %s: %s=%s (%s)" % (dn, attr, value, message)))
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

def snapshot_create():
	global objects
	#results = conn.extend.standard.paged_search(search_base=root, search_filter='(objectClass=*)', search_scope=SUBTREE, attributes=ALL_ATTRIBUTES, paged_size=1000) # only attributes
	results = conn.extend.standard.paged_search(search_base=root, search_filter='(objectClass=*)', search_scope=SUBTREE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05), paged_size=1000) # with ACL
	#conn.search(root, '(objectClass=*)', SUBTREE, attributes=ALL_ATTRIBUTES) # only attributes
	#conn.search(root, '(objectClass=*)', SUBTREE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05)) # with ACL
	#conn.search(root, '(|(objectClass=pKICertificateTemplate)(objectClass=certificationAuthority))', SUBTREE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05)) # with ACL
	#for result in conn.entries:
	for result in results:
		if result.get('type') == 'searchResRef':
			continue
		#dn = result.entry_dn
		#objects[dn] = result.entry_attributes_as_dict
		dn = result["dn"]
		objects[dn] = result["raw_attributes"]
	for dn in objects: # because of resolve_sid()
		if 'nTSecurityDescriptor' in objects[dn]:
			objects[dn]['nTSecurityDescriptor'] = parse_acl(objects[dn]['nTSecurityDescriptor'][0])
	open("objects.dat", "wb").write(pickle.dumps([objects,cache_sid]))

def snapshot_restore():
	global objects, cache_sid
	try:
		objects, cache_sid = pickle.loads(open("objects.dat", "rb").read())
		return True
	except:
		return False

def get_attrs(dn):
	#conn.search(dn, '(objectClass=*)', BASE, attributes=ALL_ATTRIBUTES) # only attributes
	#conn.search(dn, '(objectClass=*)', BASE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05)) # with ACL
	results = conn.extend.standard.paged_search(search_base=dn, search_filter='(objectClass=*)', search_scope=BASE, attributes=ALL_ATTRIBUTES, controls=security_descriptor_control(sdflags=0x05), paged_size=1000) # with ACL
	result = next(results)
	#attrs = conn.entries[0].entry_attributes_as_dict
	attrs = result["raw_attributes"]
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
				for value in attrs_after[attr]:
					print(f"{Fore.GREEN}new %s: %s{Fore.RESET}" % (attr, value))
					for attack in ATTACKS:
						if match(ATTACKS[attack]["attr"].lower(), attr.lower()) and match(ATTACKS[attack]["val"].lower(), str(value).lower()) and match(ATTACKS[attack]["dn"].lower(), dn.lower()):
							alert(dn, attr, str(value), attack)
			else:
				if type(attrs_after[attr]) == dict:
					diff(attrs_before[attr], attrs_after[attr])
				else:
					for value in attrs_after[attr]:
						if not value in attrs_before[attr]:
							print(f"{Fore.GREEN}added %s: %s{Fore.RESET}" % (attr, value))
							for attack in ATTACKS:
								if match(ATTACKS[attack]["attr"].lower(), attr.lower()) and match(ATTACKS[attack]["val"].lower(), str(value).lower()) and match(ATTACKS[attack]["dn"].lower(), dn.lower()):
									if attack == "SPN attack" and str(value).split("/")[1].lower() == attrs_after.get("dNSHostName","").lower():
										continue
									alert(dn, attr, str(value), attack)
	attrs = get_attrs(dn)
	diff(objects[dn], attrs)
	objects[dn] = attrs

objects = {}
snapshot_restore() or snapshot_create()
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
	sleep(INTERVAL)
	first_time = False
