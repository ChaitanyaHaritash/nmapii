#!/usr/share/env python 
#Simple NMAP automated script Coded by !NDi G3@r / Chaitanya. which saves time learning and setting nmap commands.
#lol its basically meant for ppl like me :V lazy stiing on desk for hours 
#feel free making changes. Its an open source project :) 

#Installation ----
#1 Do git clone 
#2 Install NSE script for option 4 (scan for CVE-2015-1635) into /usr/share/nmap/scripts and update nmap db
#3 run nmapii.py

import os
import time

os.system('clear')
banner = '''
 /$$   /$$ /$$      /$$  /$$$$$$  /$$$$$$$        /$$ /$$
| $$$ | $$| $$$    /$$$ /$$__  $$| $$__  $$      |__/|__/
| $$$$| $$| $$$$  /$$$$| $$  \ $$| $$  \ $$       /$$ /$$
| $$ $$ $$| $$ $$/$$ $$| $$$$$$$$| $$$$$$$/      | $$| $$
| $$  $$$$| $$  $$$| $$| $$__  $$| $$____/       | $$| $$
| $$\  $$$| $$\  $ | $$| $$  | $$| $$            | $$| $$
| $$ \  $$| $$ \/  | $$| $$  | $$| $$            | $$| $$
|__/  \__/|__/     |__/|__/  |__/|__/            |__/|__/
                                                         
                    SCRIPT Coded By !NDi G3@r / Chaitanya


[1] Normal Intense Scan
[2] Scan for heartbleed vuln
[3] Simple port Scan & OS detect
[4] check if target is vulneravle to CVE-2015-1635
'''
print banner 
os.system ("sleep 2") 

class scan:
	def PortScan(self):
		
		if option == "1":
			scanner = os.system("nmap -T4 -A -v "+str(target))
			print scanner
		elif option == "2":
			scanner2 = os.system("sudo nmap -p 443 --script ssl-heartbleed"+str(target))
			print scanner2
		elif option == "3":
		    scanner3 = os.system('nmap -sS -O ' +str(target)+'/24')
		    print scanner3 
		elif option == "4":
			scanner4 = os.system("sudo nmap -sV -Pn -p 80 --script ms15-034.nse "+str(target))   	

			

if __name__ == "__main__":
	
	option = raw_input('Your 0pti0n > ')
	target = str(raw_input('Define your t4rg3t > '))
	print ""
	print "[+] Scanning Started according to option '%s'"%option
	
			
	scan().PortScan()


