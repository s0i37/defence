#!/usr/bin/python3
from datetime import datetime
import matplotlib.pyplot as plt


HOURS = 24
auth_success = {}
auth_fail = {}
auth_lock = {}
while True:
	try:
		line = input()
	except:
		break
	try:
		date,time,user,*result = line.strip().split()
	except:
		continue
	date = date.split("[")[1]
	time = time.split("]")[0]
	hour = time.split(":")[0]
	result = " ".join(result)
	try: datetime.strptime(date, '%d.%m.%Y')
	except:	continue
	if result.find("success") != -1:
		try: auth_success[date+"-"+hour] += 1
		except: auth_success[date+"-"+hour] = 1
	elif result.find("fail") != -1:
		try: auth_fail[date+"-"+hour] += 1
		except: auth_fail[date+"-"+hour] = 1
	elif result.find("lock") != -1:
		try: auth_lock[date+"-"+hour] += 1
		except: auth_lock[date+"-"+hour] = 1

plt.plot(sorted(auth_success, key=lambda k:datetime.strptime(k, '%d.%m.%Y-%H').timestamp()), list(map(lambda d: auth_success[d], sorted(auth_success, key=lambda k:datetime.strptime(k, '%d.%m.%Y-%H').timestamp()))), label="success")
plt.plot(sorted(auth_fail, key=lambda k:datetime.strptime(k, '%d.%m.%Y-%H').timestamp()), list(map(lambda d: auth_fail[d], sorted(auth_fail, key=lambda k:datetime.strptime(k, '%d.%m.%Y-%H').timestamp()))), label="fail")
plt.plot(sorted(auth_lock, key=lambda k:datetime.strptime(k, '%d.%m.%Y-%H').timestamp()), list(map(lambda d: auth_lock[d], sorted(auth_lock, key=lambda k:datetime.strptime(k, '%d.%m.%Y-%H').timestamp()))), label="lock")
ax = plt.gca(); ax.set_xticks(ax.get_xticks()[::HOURS])
plt.legend()
plt.show()
