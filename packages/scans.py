#!/usr/bin/env python
import os
from termcolor import colored, cprint
#os.system('clear')
class scanhelp:
	def __init__(self):
		pass
		print ""
		print "        ::: Types Of Scans :::"
		print ""
	def scanlist(self):
			dumb = '''
[1]  Normal Intense Scan.
[2]  Scan For Heartbleed vuln. 
[3]  Simple Port Scan & OS detect.
[4]  Check CVE-2015-1635 (check for RCE Vulnerability (MS15-034) in Microsoft Windows System). 
[5]  Check CVE-2014-2126 (Cisco ASA ASDM Privilege Escalation Vuln.)
[6]  Check CVE-2012-0152 (MS-020 RDP Vulnerability)
[7]  Check CVE-2014-2127 (Cisco ASA ASDM Privilege Escalation Vuln)
[8]  Check CVE-2012-1182 (Samba 3.6.3 Heap OverFlow Vuln.)
[9]  Check CVE-2008-4250 (SMB RCE on target (MS08-067))
[10] IRC Scan (Gathers Info from an IRC server).
[11] MSF Scan (Gathers Info about Metasploit rpc service. IT requires a valid login pair, Default - root:root).
[12] MYSQL Scan (Gathers Info about MYSQL running on target box).
[13] MS-SQL Scan (Gathers Info about MS-SQL running on target box [windows]).
[14] SMB OS Discovery (Gathers Info About host running SMB and OS).
[15] VNC Scan (Queries a VNC Server for its protocol version and supported security types).
[16] Live hosts on an network.
[17] phpipam 1.5 (multiple vulnerabilities)  
[18] TelNet Scan (Grabs Info about target TelNet)
[19] FTP Scan (Grabs Info about target FTP)
[20] SSH Scan (Grabs Info about target SSH)
[21] File Checker (check/read contents of the selected file/path in target webserver.)

			
				  '''
			print dumb
			 
