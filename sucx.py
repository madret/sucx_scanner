import argparse
from scapy.all import *
import socket
import threading
from queue import Queue
from time import time
from scapy.all import *
from scapy.layers.inet import ICMP, TCP, UDP, IP
import re

#This program is a port scanner, that has the following scan options: tcp SYN / UDP / tcp Connect / XMAS == SUCX.
#Then it gives the user the option to put in an End port (starting from port 1).

### Example usage ### 
#Enter Target IP:
#Starting from Port 1, type in the end Port (max = 65535): 
#Enter the Scan-type (SYN = s / UDP = u / CON = c / XMAS = x):

socket.setdefaulttimeout(0.6)
starttime = time.time()
print_lock = threading.Lock()
q = Queue()
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

print("_ " * 40)
print("""                                                                                                                                          
                 _     _     _____ _    _  _______   __              
                (_)   | |   / ____| |  | |/ ____\ \ / /              
   ___ _____   ___  __| |  | (___ | |  | | |     \ V /   _ __  _   _ 
  / __/ _ \ \ / / |/ _` |   \___ \| |  | | |      > <   | '_ \| | | |
 | (_| (_) \ V /| | (_| |   ____) | |__| | |____ / . \ _| |_) | |_| |
  \___\___/ \_/ |_|\__,_|  |_____/ \____/ \_____/_/ \_(_) .__/ \__, |
                                                       | |     __/ |
                                                       |_|    |___/                                                                                                                                                                                                                                                                                                                                                                  
""")
print("_ " * 40)

#print definition of port number + state (open/closed etc.)
def print_ports(port, state):
	print("%s | %s" % (port, state))

# SYN
def syn_scan(target, ports):
	print("Syn scan on, %s with ports %s" % (target, ports))
	sport = RandShort()
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
		if pkt != None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:
					None
				elif pkt[TCP].flags == 18:
					print_ports(port, "Open")
				else:
					print_ports(port, "TCP packet response / filtered")
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP response / filtered")
			else:
				print_ports(port, "Unknown response")
				print(pkt.summary())
		else:
			print_ports(port, "Unanswered")

# UDP
def udp_scan(target, ports):
	print("Udp scan on, %s with ports %s" % (target, ports))
	for port in ports:
		pkt = sr1(IP(dst=target)/UDP(sport=port, dport=port), timeout=2, verbose=0)
		if pkt == None:
			print_ports(port, "Open / filtered")
		else:
			if pkt.haslayer(ICMP):
				None
			elif pkt.haslayer(UDP):
				print_ports(port, "Open / filtered")
			else:
				print_ports(port, "Unknown")
				print(pkt.summary())

# XMAS
def xmas_scan(target, ports):
	print("Xmas scan on, %s with ports %s" %(target, ports))
	sport = RandShort()
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="FPU"), timeout=1, verbose=0)
		if pkt != None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:
					None
				else:
					print_ports(port, "TCP flag %s" % pkt[TCP].flag)
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP response / filtered")
			else:
				print_ports(port, "Unknown response")
				print(pkt.summary())
		else:
			print_ports(port, "Open / filtered")

#CONNECT
def con_scan(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection = s.connect((host, port))

        with print_lock:
            print('{} | Open'.format(port))

            connection.close()
    except:
        pass

def thread(h):
    while True:
        ports_to_scan = q.get()
        con_scan(h, ports_to_scan)
        q.task_done()

def main():
    print(" - " * 20)
    host = socket.gethostbyname(target)
    starttime = time.time()
#Threading is set to 200 (it can be changed obviously)
    for i in range(200):
        t = threading.Thread(target=thread, args=(host,))
        t.daemon = True

        t.start()

    for ports in range(int(port2), int(port3)):
        q.put(ports)

    q.join()

# Argument setup
parser = argparse.ArgumentParser("Scapy / Socket portscanner")
parser.add_argument("-t", "--target", help="Specify target IP", required=False)
parser.add_argument("-p", "--ports", type=int, nargs="+")
parser.add_argument("-s", "--scantype", help="Scan type, syn/udp/con/xmas", required=False)
args = parser.parse_args()

# User input: Target
target = input("Enter target IP: ")

#User input validation: IP & End port --> target must be a valid IPv4 address AND portnumber is integer with a maximum of 65535.
if(re.search(regex, target)):
	port1 = input("Starting from Port 1, type in the end Port (max = 65535): ")
	try:
		port1 = int(port1)
	except ValueError:
		quit("Must be integers from 2 - 65535!")
	if port1 >= 2 and port1 <= 65535:
		port2 = 1
		port3 = port1 + 1
		ports = range(port2,port3)
	else:
		quit("Port number must be from 2 - 65535.")
else:
	quit("Target has to be a Valid IPv4 address.")

#User input: Scan type
scantype = input("Enter the Scan-type (SYN = s / UDP = u / CON = c / XMAS = x): ")

# User port range
if args.ports:
	ports = args.ports
else:
	# Port range logic. Start counting from port 1 instead of 0.
	port1 = port1
	port2 = 1
	port3 = port3
	ports = range(port2,port3)

# SUCX:
if scantype == "syn" or scantype == "s" or scantype == "S":
	syn_scan(target, ports)
elif scantype == "udp" or scantype == "u" or scantype == "U":
	udp_scan(target, ports)
elif scantype == "con" or scantype == "c" or scantype == "C":
	main()
elif scantype == "xmas" or scantype == "x" or scantype == "X":
	xmas_scan(target, ports)
else:
	print(" - " * 20)
	print("Scan type not supported, Usage: (SYN = s / UDP = u / CON = c / XMAS = x)")

#Get totalrun output + target IP
totalrun = float("%0.2f" % (time.time() - starttime))
print(" - " * 20)
print("SUCX scanner completed in {} seconds!".format(totalrun))
print('Scanned IP address: ', target)
print(" - " * 20)
