#!/usr/bin/python3

import socket
import sys
import os
from struct import *

def listen():
	s1 = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
	s1.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
	while 1:
		data, addr = s1.recvfrom(1508)
		print ("Packet from %r: %r" % (addr,data))

HOST = socket.gethostbyname('alesca.it')
PORT = 80	
ADDR = (HOST, PORT)
ttl = 1
try:
	send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error as msg: 
	print('send socket no created. Errror code:' + str(msg))
	sys.exit()

try:
	listen_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_ICMP)
except socket.error as msg: 
	print('listen socket no created. Errror code:' + str(msg))
	sys.exit()

listen_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
listen_socket.settimeout(10)

while 1:	
	send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
	p = pack('hhl', 1, 2, 3)
	b = send_socket.sendto(p, ADDR)
	print ("bytes sent:", b)
	try:
		data, addr = listen_socket.recvfrom(1508)
	except socket.timeout:
		print("timeout at hop", ttl, '\n')
		continue
	if (addr == HOST):
		print("Arrived!\n")
		break
	print("hop:", ttl, addr)
	ttl += 1



"""try:
	s.connect((HOST, PORT))
except socket.timeout as e:
	print('timeout1', e)
except socket.error as e:
	print ('se1:', e)
else:
	s.sendall(b'GET / \n\n')
	try:
		data = s.recv(1024)
	except socket.timeout as e:
		print('timeout2', e)
	except socket.error as e:
		print ('se2:', e)
	else:
		print('Received', repr(data))
	

HOST = socket.gethostbyname('www.google.it')
PORT = 33434
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg: 
	print('socket no created. Errror code:' + str(msg))
	sys.exit()

s.bind((HOST, 0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
p = pack('hhl', 1, 2, 3)
s.sendto(p, (HOST, PORT))
data = s.recvfrom(1024)
print('received: ', repr(data))

# the public network interface
HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive a package
print(s.recvfrom(65565))

# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)"""
