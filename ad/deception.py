#!/usr/bin/python3
# -*- coding: utf-8 -*- 
from ldap3 import Server, Connection, SUBTREE, ALL, NTLM, GSSAPI,SASL
from time import sleep
from datetime import datetime
from getpass import getpass
from os import system
from sys import argv
from colorama import Fore

dc = argv[1]
INTERVAL = 60

server = Server(dc, get_info=ALL)
#server = Server(dc, port=636, use_ssl=True, get_info=ALL)
Connection(server, auto_bind=True)
if len(argv) < 5:
	print("\n".join(server.info.naming_contexts))
	exit()
else:
	root = argv[3]
userdom = argv[2] # "company\\user"
watch = argv[4] # someuser
#conn = Connection(server, user=userdom, password=getpass("password: "))
conn = Connection(server, user=userdom, password=getpass("password: "), authentication=NTLM)
#conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI)
conn.bind()

def alert(user, action):
	print("[!] Event detected: %s %s" % (user,action))
	#system("telegram '{message}' &".format(message="Event detected: "+user+" "+action))
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='Event detected' --text='%s %s' &" % (user,action))
	#system("echo 'Auth event detected' | festival --tts --language english")

events = {"auth_failure_count": None, "failures_time": None, "lockout_time": None, "success_time": None}
while True:
	conn.search(root, '(sAMAccountName={user})'.format(user=watch), SUBTREE, attributes=["sAMAccountName", "badPasswordTime", "lastLogon", "badPwdCount", "lockoutTime"])
	for result in conn.entries:
		dn = result.entry_dn
		user = result['sAMAccountName'].value
		auth_failure_count = int(result['badPwdCount'].value)
		failures_time = result['badPasswordTime'].value.timestamp() if result['badPasswordTime'] else None
		lockout_time = result['lockoutTime'].value.timestamp() if result['lockoutTime'] else None
		success_time = result['lastLogon'].value.timestamp() if result['lastLogon'] else None
		if events["auth_failure_count"] != None and events["auth_failure_count"] != auth_failure_count:
			alert(user, "auth fail")
		elif events["failures_time"] != None and events["failures_time"] != failures_time:
			alert(user, "auth fail")
		elif events["lockout_time"] != None and events["lockout_time"] != lockout_time:
			alert(user, "locked")
		elif events["success_time"] != None and events["success_time"] != success_time:
			alert(user, "auth success")
		events["auth_failure_count"] = auth_failure_count
		events["failures_time"] = failures_time
		events["lockout_time"] = lockout_time
		events["success_time"] = success_time
	sleep(INTERVAL)

# echo $[(`date +"%s" -d '2020-12-31 06:00:00'` + 11644473600) * 10000000]
# (&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(&(lastLogon<=132538500000000000)(badPasswordTime<=132538500000000000)))
