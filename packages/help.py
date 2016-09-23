#!/usr/bin/env python
import os
from termcolor import colored, cprint
#from packages import banner
#os.system('clear')
class nmaphelp:
	def __init__(self):
		pass
		print ""
		print "        ::: Help Menu :::"
	def helpus(self):
			mad = '''
[help]			- List all help options
[scans] 		- List all types of scan you can begin with'
[about] 		- About Creator and tool
[reset_logs]		- Reset all logs of old scans in directory /home/.nmapii-logs/
[clear] 		- Clear Screen
[quit]  		- Quit :)
			
				  '''
			print mad 
