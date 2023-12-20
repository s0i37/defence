#!/usr/bin/python3
import subprocess
import os


MAX_AUTH_ATTEMPTS = 2
clients = {}

alerts = []
def alert(ip):
	if ip in alerts:
		return
	print("[!] ssh bruteforcing %s" % ip)
	os.system("mplayer /home/soier/.music/sounds/StarCraft/usunaleskanal.wav >/dev/null 2>/dev/null &")
	os.system("zenity --warning --title='ssh bruteforcing detected' --text='ssh bruteforcing detected' &")
	#os.system("echo 'ssh bruteforcing detected' | festival --tts --language english")
	alerts.append(ip)

os.chdir("ssh-honeypot/")
ssh = subprocess.Popen("./bin/ssh-honeypot -r ssh-honeypot.rsa -p 22", shell=True, stdout=subprocess.PIPE)
ssh.stdout.readline()
while True:
	line = ssh.stdout.readline().decode().split("\n")[0]
	if line.strip() and line.split(" ")[5][0] in ["1","2"]:
		ip = line.split(" ")[5]
		user = line.split(" ")[6]
		password = " ".join(line.split(" ")[7:])
		print('[+] auth {ip} "{user}" "{password}"'.format(ip=ip, user=user, password=password))
		if not ip in clients:
			clients[ip] = set()
		clients[ip].add((user,password))
		if len(clients[ip]) > MAX_AUTH_ATTEMPTS:
			alert(ip)
