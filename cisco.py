import serial
from time import sleep
import sys
import os
try:
        from colorama import Fore
        from colorama import init
except:
        os.system("pip3 install colorama")
        os.system("pip install colorama")
try:
        from serial import *
except:
        os.system("pip3 install pyserial")
        os.system("pip install pyserial")
        os.system("pip3 install serial")
        os.system("pip install serial")

#allows colors to be used in powershell
init()

#color variables
RED = Fore.RED
BLUE = Fore.BLUE
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RESET = Fore.RESET

# Open the serial port. The settings are set to Cisco default.
comport = input("COM Port to use? \n")
port = ("COM"+comport)
serial_port = serial.Serial(port, 9600)

# Make sure there is not any lingering input - input in this case being data waiting to be received
serial_port.flushInput()

print(YELLOW+"You are connected through COM Port "+serial_port.name+" "+RESET)
username = input("Username: \n")
password = input("Password: \n")
IP = input("SSH IP Address, MGMT IP, with subnet mask (ex: 172.16.1.1 255.255.255.0): \n")
net = input("Network MGMT IP for dhcp pool (ex 172.16.1.0 255.255.255.0): \n")
default = input("Default Router IP for MGMT (ex 172.16.1.1): \n")
user = ("username "+username+" priv 15 secret "+password+"\n")
ssh = ("ip add "+IP+"\n")

cisco = input("Is this a switch or router (s/r): \n")
bytes_to_read = serial_port.inWaiting()

if (cisco == "s"):
        serial_port.write("\n".encode())
        serial_port.write("en \n".encode())
        serial_port.write("conf t \n".encode())
        serial_port.write("ip domain-name test.com \n".encode())
        print(GREEN+"Creating User and Password on device"+RESET)
        serial_port.write(user.encode())
        serial_port.write("lin vty 0 15\n".encode())
        serial_port.write("transport input ssh\n".encode())
        serial_port.write("transport output ssh\n".encode())
        serial_port.write("login local\n".encode())
        serial_port.write("int vlan 1\n".encode())
        serial_port.write("no ip add \n".encode())
        serial_port.write("shut \n".encode())
        serial_port.write("int vlan 99\n".encode())
        print(GREEN+"Creating SSH on VLAN 99 with IP and Subnet of "+IP+""+RESET)
        serial_port.write(ssh.encode())
        serial_port.write("no shut\n".encode())
        serial_port.write("vlan 99 \n".encode())
        serial_port.write("no shut\n".encode())
        serial_port.write("ip routing \n".encode())
        serial_port.write("router eigrp 1 \n".encode())
        serial_port.write("network 172.16.1.0 255.255.255.0 \n".encode())
        serial_port.write("crypto key zeroize rsa \n".encode())
        while bytes_to_read < serial_port.inWaiting():
                bytes_to_read = serial_port.inWaiting()
                sleep(1)
        serial_port.write("yes\n".encode())
        serial_port.write("crypto key generate rsa \n".encode())
        serial_port.write("1024 \n".encode())
        while bytes_to_read < serial_port.inWaiting():
                bytes_to_read = serial_port.inWaiting()
                sleep(1)
        serial_port.write("\n\n\n".encode())
        switch = input("Is this a 48, 24, 10 or 8 port switch (ex: 48):\n")
        interface = input("What type of interface (ex g1/0/): \n")
        swp = ("int "+interface+switch+"\n\n\n")
        serial_port.write(swp.encode())
        serial_port.write("switchport mode access\n".encode())
        serial_port.write("switchport access vlan 99\n".encode())
        serial_port.write("ip dhcp pool MGMT \n".encode())
        network = ("network "+net+"\n")
        serial_port.write(network.encode())
        dr = ("default-router "+default+"\n")
        serial_port.write(dr.encode())
        if (switch == "48"):
                print(GREEN+"1 - 40 are going to be access and voice vlans, 41 - 47 are trunk ports allowing all vlans"+RESET)
                access = input("Access VLAN (ex 30): \n")
                voice = input("Voice VLAN (ex 40): \n")
                voicevlan = ("switchport voice vlan "+voice+"\n")
                accessvlan = ("switchport access vlan "+access+"\n")
                intrange = ("int range "+interface+"1 - 40 \n")
                serial_port.write(intrange.encode())
                serial_port.write("switchport mode access \n".encode())
                serial_port.write(accessvlan.encode())
                serial_port.write(voicevlan.encode())
        if (switch == "24"):
                print(GREEN+"1 - 20 are going to be access and voice vlans, 21 - 23 are trunk ports allowing all vlans"+RESET)
                access = input("Access VLAN (ex 30): \n")
                voice = input("Voice VLAN (ex 40): \n")
                voicevlan = ("switchport voice vlan "+voice+"\n")
                accessvlan = ("switchport access vlan "+access+"\n")
                intrange = ("int range "+interface+"1 - 20 \n")
                serial_port.write(intrange.encode())
                serial_port.write("switchport mode access \n".encode())
                serial_port.write(accessvlan.encode())
                serial_port.write(voicevlan.encode())
        if (switch == "10"):
                print(GREEN+"1 - 8 are going to be access and voice vlans, 9 are trunk ports allowing all vlans"+RESET)
                access = input("Access VLAN (ex 30): \n")
                voice = input("Voice VLAN (ex 40): \n")
                voicevlan = ("switchport voice vlan "+voice+"\n")
                accessvlan = ("switchport access vlan "+access+"\n")
                intrange = ("int range "+interface+"1 - 8 \n")
                serial_port.write(intrange.encode())
                serial_port.write("switchport mode access \n".encode())
                serial_port.write(accessvlan.encode())
                serial_port.write(voicevlan.encode())
        if (switch == "8"):
                

        print(RED+"Please connect laptop to switch on port "+switch+" this is for SSH \n"+RESET)
        connect = input("Please press enter to continue")


bytes_to_read = serial_port.inWaiting()

# Give the line a small amount of time to receive data
sleep(.5)

# 9600 baud is not very fast so if you call serial_port.inWaiting() without sleeping at all it will likely just say
# 0 bytes. This loop sleeps 1 second each iteration and updates bytes_to_read. If serial_port.inWaiting() returns a
# higher value than what is in bytes_to_read we know that more data is still coming in. I noticed just by doing a ?
# command it had to iterate through the loop twice before all the data arrived.
while bytes_to_read < serial_port.inWaiting():
    bytes_to_read = serial_port.inWaiting()
    sleep(1)

# This line reads the amount of data specified by bytes_to_read in. The .decode converts it from a type of "bytes" to a
# string type, which we can then properly print.
data = serial_port.read(bytes_to_read).decode()
print(data)
