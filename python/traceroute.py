#!/usr/bin/python3

import socket
import sys
import os
from struct import *
from collections import namedtuple

ip4_header = namedtuple('ip4_header', 'version_ihl tos length ident flags ttl proto checksum source destination')
icmp_header = namedtuple('icmp_header', 'type code checksum rest')
ip4_header_format  = ('!BBHHHBBH4s4s')
icmp_header_format = ('!5IBBHI')

def listen():

	HOST = socket.gethostbyname('google.it')
	PORT = 80	
	ADDR = (HOST, PORT)
	ttl = 1
	timeout = 0
	try:
		dgram_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error as msg: 
		print('send socket no created. Errror code:' + str(msg))
		sys.exit()

	try:
		listen_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_ICMP)
	except socket.error as msg: 
		print('listen socket no created. Errror code:' + str(msg))
		sys.exit()

	listen_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
	listen_socket.settimeout(3)

	while ttl < 100:	

		if (timeout >= 3):
			ttl += 1
			timeout = 0		
		
		dgram_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
		
		p = pack('!bbb', 1, 2, 3)
		b = dgram_socket.sendto(p, ADDR)
		try:
			data, addr = listen_socket.recvfrom(1508)
		except socket.timeout:
			print("timeout at hop", ttl, '\n')
			timeout += 1		
			continue
		if (addr == HOST):
			print("Arrived!\n")
			
			break
		print("hop:", ttl, addr, "size:", sys.getsizeof(data), data)
		break
		ttl += 1
	
"""
example data of 105 byte size
b'E\xc04\x00\xea\x8e\x00\x00@\x01{d\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xa5i\x00\x00\x00\x00E\x00,\x00\x81O\x00\x00\x01\x11\x882\n\x00\x00\x02\xd8:\xce\x03\xe5\xee\x00P\x00\x18c?\x01\x00\x02\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'
"""
def unpack_icmp_packet(buffer):
	#ip_header_format = "!bbhII4s4s"
	#ip_header_format = "!IIIIIbbhlh3s"
	ip4_h = ip4_header._make(unpack_from(ip4_header_format, buffer))
	version = (ip4_h.version_ihl & 0xF0) >> 4
	ihl = (ip4_h.version_ihl & 0x0F)
	if (version != 4 and ihl != 5):
		print("not my packet")
		return
	icmp_h = icmp_header._make(unpack_from(icmp_header_format, buffer)[5:])
	print(icmp_h.type)
	print(icmp_h.code)



test_packet = b'E\xc04\x00\xea\x8e\x00\x00@\x01{d\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xa5i\x00\x00\x00\x00E\x00,\x00\x81O\x00\x00\x01\x11\x882\n\x00\x00\x02\xd8:\xce\x03\xe5\xee\x00P\x00\x18c?\x01\x00\x02\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'
test_packet2 = b"E\xc0'\x00\xac\xfa\x00\x00@\x01\xb9\x05\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xa5<\x00\x00\x00\x00E\x00\x1f\x00'P\x00\x00\x01\x11\xe2^\n\x00\x00\x02\xd8:\xcd\xe3\xd7x\x00P\x00\x0bs\xed\x01\x02\x03"
#version_ihl, dscp_ecn, total_length, _, _, source_ip, dest_ip = unpack_packet(test_packet)
#iph = ip4_header._make(unpack_packet(test_packet))

#print(iph.version_ihl)
#print((iph.version_ihl & 240) >> 4)
#listen()
#print(total_length)
unpack_icmp_packet(test_packet2)
