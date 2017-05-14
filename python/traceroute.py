#!/usr/bin/python3

import socket
import sys
import os
from struct import *

def listen():
  s1 = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
  #s1.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
  while 1:
    data, addr = s1.recvfrom(1508)
    print ("Packet from %r: %r" % (addr,data))

HOST = socket.gethostbyname('google.it')
PORT = 33434
ADDR = (HOST, PORT)
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error as msg: 
	print('socket no created. Errror code:' + str(msg))
	sys.exit()

#s.settimeout(3)	
s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
p = pack('hhl', 1, 2, 3)
b = s.sendto(p, ADDR)
listen()


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
