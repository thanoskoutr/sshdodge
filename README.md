SSHDODGE
========
Original tool used to test weakness of some ssh passwords, thanks to a dictionary attack (bypassing fail2ban protection). Tool has been extended to test the weakness of other services (ssh, ftp, http) behind fail2ban and can be used to brute-force usernames as well as passwords.

A timeout flag has been added to continue to the next attempt if a process is stuck and a wait flag has been added to give some time to the Tor service to restart.

Copyright (C) 2017  Neetx

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

### CONTACTS:
[Neetx](mailto:neetx@protonmail.com)

---

Tool developed to demonstrate the weakness of some ssh passwords.
It bypasses fail to ban protection changing ip with tor reload function, after some attempts defined in input by user.
Use these tool with consciousness.

Usage:
```
usage: sshdodge.py [-h] [-b BRUTEFORCE] [-c CREDENTIAL] [-i IP] [-p PORT]
                   [-a ATTEMPTS] [-w WAIT] [-o TIMEOUT] [-s SERVICE] [-t]
                   wordlist

positional arguments:
  wordlist              Wordlist for dictionary attack

optional arguments:
  -h, --help            show this help message and exit
  -b BRUTEFORCE, --bruteforce BRUTEFORCE
                        The bruteforce attack type (user, pass)
  -c CREDENTIAL, --credential CREDENTIAL
                        Constant credential (user, pass) value depending on
                        the bruteforce attack type
  -i IP, --ip IP        Destination ip address or hostname
  -p PORT, --port PORT  Destination port
  -a ATTEMPTS, --attempts ATTEMPTS
                        Number of attempts before identity change
  -w WAIT, --wait WAIT  Waiting time after Tor service restart (in seconds)
  -o TIMEOUT, --timeout TIMEOUT
                        Timeout for each attempt (in seconds)
  -s SERVICE, --service SERVICE
                        The targeted service: ssh, ftp, http
  -t, --test            Use the to test dependences
```

Example:
```bash
sudo ./sshdodge.py wordlist.txt -i 127.0.0.1 -p 22 -a 3 -b pass -c root
```

DEPENDENCES: You need to install on your system:
* tor
* sshpass
* ftp
* curl
* proxychains

SYSTEM USED:
* Debian 9.2

##### COLLABORATIONS:

* [davenull](mailto:dave-null@riseup.net)
* [neb](nebulasit@riseup.net)<br/>[website](https://www.freenixsecurity.net)
* [giuseongit](giuseppe.pagano.p@gmail.com)<br/>[website](https://github.com/giuseongit)
