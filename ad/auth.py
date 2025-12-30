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
USERS = { # notifications
	'auth': ['honeypot_user'],
	'fail': ['guest', 'security', 'audit', 'testuser', 'test1'],
	'lock': ['administrator', 'guest', 'security', 'audit', 'testuser', 'test1']
}
BLACKLIST = ('incident',)
MAX_LOCKS = 50
MAX_FAILS = 100
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
#conn.start_tls()
conn.bind()

alerts = []
def alert(user, action):
	if user in alerts:
		return
	print("[!] Auth event detected: %s %s" % (user,action))
	#system("telegram '{message}' &".format(message="Auth event detected: "+user+" "+action))
	#system("email admin@company.org '{message}' &".format(message="Auth event detected: "+user+" "+action))
	#system("sms PHONENUMBER '{message}' &".format(message="Auth event detected: "+user+" "+action))
	system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	system("zenity --warning --title='Auth event detected' --text='%s %s' &" % (user,action))
	#system("echo 'Auth event detected' | festival --tts --language english")
	alerts.append(user)

failures_time = {}
success_time = {}
fails = set()
locks = set()
timestamp = (int(datetime.strptime(server_time, "%Y%m%d%H%M%S.0Z").timestamp() if server_time else datetime.utcnow().timestamp()) + 11644473600) * 10000000
while True:
	conn.search(root, '(&(objectCategory=person)(objectClass=user)(|(badPasswordTime>={timestamp})(lastLogon>={timestamp})))'.format(timestamp=timestamp), SUBTREE, attributes=["sAMAccountName", "badPasswordTime", "lastLogon", "badPwdCount", "lockoutTime"])
	lasts = [timestamp]
	for result in conn.entries:
		dn = result.entry_dn
		if result['sAMAccountName']:
			user = result['sAMAccountName'].value
			if user.lower() in BLACKLIST:
				continue
			auth_failure_count = ""
			if result['badPwdCount']:
				auth_failure_count = int(result['badPwdCount'].value)
			if result['badPasswordTime']:
				if user in failures_time and failures_time[user] < result['badPasswordTime'].value.timestamp():
					print('[{now}]{red} "{user}" auth failure ({auth_failure_count}){reset}'.format(now=datetime.now().strftime("%d.%m.%Y %H:%M:%S"), badPasswordTime=result["badPasswordTime"].value.strftime("%d.%m.%Y %H:%M:%S"), red=Fore.RED, user=user, auth_failure_count=auth_failure_count, reset=Fore.RESET))
					if user.lower() in USERS['fail']:
						alert(user, 'failure')
					lasts.append((result['badPasswordTime'].value.timestamp() + 11644473600) * 10000000)
					if result['lockoutTime'].value and result['lockoutTime'].value.timestamp() == result['badPasswordTime'].value.timestamp():
						print('[{now}]{red} "{user}" locked{reset}'.format(now=datetime.now().strftime("%d.%m.%Y %H:%M:%S"), red=Fore.LIGHTRED_EX, user=user, reset=Fore.RESET))
						if user.lower() in USERS['lock']:
							alert(user, 'locked')
						locks.add(user)
					fails.add(user)
				failures_time[user] = result['badPasswordTime'].value.timestamp()
			if result['lastLogon']:
				if user in success_time and success_time[user] < result['lastLogon'].value.timestamp():
					print('[{now}]{green} "{user}" auth success{reset}'.format(now=datetime.now().strftime("%d.%m.%Y %H:%M:%S"), lastLogon=result["lastLogon"].value.strftime("%d.%m.%Y %H:%M:%S"), green=Fore.GREEN, user=user, reset=Fore.RESET))
					lasts.append((result['lastLogon'].value.timestamp() + 11644473600) * 10000000)
					if user.lower() in USERS['auth']:
						alert(user, 'auth')
				if user in locks: locks.remove(user)
				if user in fails: fails.remove(user)
				success_time[user] = result['lastLogon'].value.timestamp()
	if len(locks) > MAX_LOCKS:
		alert("mass locks users", str(len(locks)))
	if len(fails) > MAX_FAILS:
		alert("mass fails users", str(len(fails)))
	timestamp = int(max(lasts) + 1)
	sleep(INTERVAL)
