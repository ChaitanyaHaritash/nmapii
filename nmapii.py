#!/usr/share/env python 

#Simple NMAP automated script Coded by !NDi G3@r / Chaitanya. which saves time , learning and setting up nmap commands. 
#Special thanks to VirKid and r00t-3xp10it:)
#lol its basically meant for ppl like me :V lazy stiing on desk for hours 
#feel free making changes. Its an open source project :) 

#Installation ----
#1 Do git clone 
#2 sudo bash ../path/nmapii/utils/install.sh
#3 sudo python nmapii.py

import os,sys
import time
from termcolor import colored, cprint
from packages import help
from packages import scans
from packages import about
os.system('clear')
time.sleep(1) 
banner = colored ('''		
 /$$   /$$ /$$      /$$  /$$$$$$  /$$$$$$$       /$$ /$$  
| $$$ | $$| $$$    /$$$ /$$__  $$| $$__  $$     |__/|__/
| $$$$| $$| $$$$  /$$$$| $$  \ $$| $$  \ $$      /$$ /$$
| $$ $$ $$| $$ $$/$$ $$| $$$$$$$$| $$$$$$$/     | $$| $$ 
| $$  $$$$| $$  $$$| $$| $$__  $$| $$____/  --- | $$| $$ 
| $$\  $$$| $$\  $ | $$| $$  | $$| $$           | $$| $$ 
| $$ \  $$| $$ \/  | $$| $$  | $$| $$  Ver 1.0  | $$| $$ 
|__/  \__/|__/     |__/|__/  |__/|__/           |__/|__/ 
                                                        ''' , 'cyan')
name = colored ('''         SCRIPT Coded By !NDi G3@r / Chaitanya ''' , 'cyan')
usage = colored ('''          [+] Usage ? hit "help" for help [+]''' , 'cyan')
quitting = colored ("[+] Exitting ....... :) ", 'yellow' , attrs=['bold'])

print banner
print name
print ""
print usage
print ""
class rugged:
	def __init__(self,):
		print ""
	def Nmap(self):

		if option == "1":
			scanner1 = os.system("sudo nmap -T4 -A -v -oN /home/.nmapii-logs/basic/intense --script ip-geolocation-geoplugin.nse "+str(target))
			print scanner1
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "2":
			scanner2 = os.system("sudo nmap -p 443 -oN /home/.nmapii-logs/SSL/heartbleed --script ssl-heartbleed.nse,ip-geolocation-geoplugin.nse "+str(target))
			print scanner2
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])		
		elif option == "3":
		    scanner3 = os.system('sudo nmap -sS -O -oN /home/.nmapii-logs/basic/port_os ' +str(target)+'/24')
		    print scanner3
		    print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])		    
		elif option == "4":
			scanner4 = os.system('sudo nmap -sS -Pn -p 80,443 -oN /home/.nmapii-logs/CVE-MS/ms16_034 --script ms15-034.nse,ip-geolocation-geoplugin.nse --script-args "uri=/welcome.png" '+str(target))   	
			print scanner4
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "5":
		    scanner5 = os.system('sudo nmap -p 443 -oN /home/.nmapii-logs/CVE-MS/cve_2014_2126 --script http-vuln-cve2014-2126.nse,ip-geolocation-geoplugin.nse '+str(target))
		    print scanner5
		    print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])		    
		elif option == "6":
		    scanner6 = os.system('sudo nmap -sV -oN /home/.nmapii-logs/CVE-MS/ms12_020 --script=rdp-ms12-020.nse,ip-geolocation-geoplugin.nse -p 3389 '+str(target))
		    print scanner6
		    print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])		    
		elif option == "7":
		    scanner7 = os.system('sudo nmap -p 443 -oN /home/.nmapii-logs/CVE-MS/cve_2014_2126 --script http-vuln-cve2014-2126.nse,ip-geolocation-geoplugin.nse '+str(target))
		    print scanner7
		    print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])		    
		elif option == "8":
		    scanner8 = os.system('sudo nmap -oN /home/.nmapii-logs/CVE-MS/cve_2012_1182 --script=samba-vuln-cve-2012-1182.nse,ip-geolocation-geoplugin.nse  -p 139 '+str(target))
		    print scanner8
		    print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])		    
		elif option == "9":
			scanner9 = os.system('sudo nmap -oN /home/.nmapii-logs/CVE-MS/ms08_067 --script smb-vuln-ms08-067.nse,ip-geolocation-geoplugin.nse -p 137,445 '+str(target))
			print scanner9
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "10":
			scanner10 = os.system('sudo nmap -sS -Pn -p 6660-7000 -oN /home/.nmapii-logs/IRC/irc --script irc-info.nse,ip-geolocation-geoplugin.nse '+str(target))
			print scanner10
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "11":
			scanner11 = os.system('sudo nmap -oN /home/.nmapii-logs/MSF/msf ' +str(target)+ ' --script metasploit-info --script-args.nse,ip-geolocation-geoplugin.nse username=root,password=root')	
			print scanner11
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "12":
			scanner12 = os.system('sudo nmap -sS -Pn -p 3306 -oN /home/.nmapii-logs/MYSQL/mysql --script mysql-info.nse,ip-geolocation-geoplugin.nse '+str(target))
			print scanner12
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "13":	     	
			scanner13 = os.system('sudo nmap -p 445 -oN /home/.nmapii-logs/MS-SQL/ms-sql --script ms-sql-info.nse,ip-geolocation-geoplugin.nse '+str(target))
			print scanner13
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "14":
			scanner14 = os.system('sudo nmap -sU -sS -oN /home/.nmapii-logs/SMB/smb --script smb-os-discovery.nse,ip-geolocation-geoplugin.nse -p 137-139 '+str(target))
			print scanner14
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])
		elif option == "15":
			scanner15 = os.system('sudo nmap -p 5900,5901,5902 -oN /home/.nmapii-logs/VNC/vnc --script vnc-info.nse,ip-geolocation-geoplugin.nse '+str(target))		
			print scanner15
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])
		elif option == "16":
			scanner16 = os.system('sudo nmap -sn -oN /home/.nmapii-logs/basic/devices_up '+str(target)+'/24')
			print scanner16
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])
		elif option == "17":
			scanner17 = os.system('sudo nmap -sV -Pn -p 80 -oN /home/.nmapii-logs/other_vulns/phpipam --open --reason --script phpipam.nse,file-checker.nse --script-args read=true,ip-geolocation-geoplugin.nse '+str(target))
			print scanner17
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])
		elif option == "18":
			scanner18 = os.system('sudo nmap -T4 -sS -Pn -oN /home/.nmapii-logs/TELNET/telnet --append-output -O --script dns-brute.nse,ip-geolocation-geoplugin.nse -p 23 '+str(target))	
			print scanner18
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "19":
			scanner19 = os.system('sudo nmap -T4 -sS -Pn -O -oN /home/.nmapii-logs/FTP/ftp --script ftp-anon.nse,ftp-brute.nse,dns-brute.nse,ip-geolocation-geoplugin.nse -p 21 '+str(target))
			print scanner19
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])			
		elif option == "20":
			scanner20 = os.system('sudo nmap -T4 -sS -Pn -O -oN /home/.nmapii-logs/SSH/ssh --script ssh-hostkey.nse,ssh2-enum-algos.nse,dns-brute.nse,ip-geolocation-geoplugin.nse -p 22 '+str(target))
			print scanner20
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])
		elif option == "21":
			args = str(raw_input('Define file-type you wanted to scan > '))
			scanner21 = os.system('sudo nmap -sS -Pn -p 80 -oN /home/.nmapii-logs/other_vulns/file-checker --script file-checker.nse,dns-brute.nse,ip-geolocation-geoplugin.nse  --script-args "file=/'+str(args)+',read=true"  '+str(target))
			print scanner21
			print colored ('[+] Scan Has Been Completed , scan logs saved in /home/.nmapii-logs/ [+]' , 'green' , attrs=['bold'])
if __name__ == "__main__":
	options=[str(i) for i in range(22)]
	options.append('help')
	options.append('about')
	options.append('scans')
	options.append('quit')
	options.append('reset_logs')
	options.append('clear')

	while  1:
		print ""
		option=raw_input('Nmapii > ') 
		if option in options:

			if option=="help":
				x=help.nmaphelp()
				x.helpus()
			elif option == "scans":
				x=scans.scanhelp()
				x.scanlist()
			elif option == "about":
				x=about.thisme()
				x.itsme()
			elif option == "quit":
				os.system('clear')
				print banner
				print quitting
				time.sleep(3)
				os.system('clear') 
				sys.exit(0)
			elif option == "clear":
				os.system('clear')
				print banner
				print name
				print ""
				print usage
				print ""
			elif option == "reset_logs":
				os.chdir('utils')
				os.system('sudo bash reset_logs.sh')
			else:
				

				print ""
				target = str(raw_input('Define your t4rg3t > '))
				print ""
				print "[+] Option => '%s'"%option
				print ""
				print "[+] Target => '%s'"%target
				print ""
				print colored ("[+] Your Scan will start in couple of seconds [+]" , 'green' , attrs=['bold'])

				time.sleep(2)
				rugged().Nmap()

		else : 
				print ""
				print colored ("[-] Nigga, '%s' is not an 0ption Check 'help'" , 'red' , attrs=['bold'])%option
				print ""
				continue 	
		
	print ""
	target = str(raw_input('Define your t4rg3t >'))
	print ""
	print "[+] Option => '%s'"%option
	print ""
	print "[+] Target => '%s'"%target
	print ""
	print "[+] Scan will start in couple of seconds [+]"

	time.sleep(2)
	rugged().Nmap()
	option=""


				


