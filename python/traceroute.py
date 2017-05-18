#!/usr/bin/python3

import socket
import sys
import os
from struct import *
from collections import namedtuple

ip4_header = namedtuple('ip4_header', 'version_ihl tos length ident flags ttl proto checksum source destination')
icmp_header = namedtuple('icmp_header', 'type code checksum rest')
icmp_hl = 2
packet_header_format = namedtuple('packet_header_format', 'format length')
ip4_header_format  = packet_header_format._make(('!BBHHHBBH4s4s', 10))
icmp_header_format = packet_header_format._make((ip4_header_format.format + 'BBHI', ip4_header_format.length + 4))

pid = os.getpid()


def listen():

	HOST = socket.gethostbyname('google.it')
	PORT = 80	
	ADDR = (HOST, PORT)
	ttl = 1
	timeout = 0

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
	listen_socket.settimeout(3)

	while ttl < 100:	

		if (timeout >= 3):
			ttl += 1
			timeout = 0		
		
		send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
		
		p = pack('!I', pid)

		b = send_socket.sendto(p, ADDR)
		try:
			data, addr = listen_socket.recvfrom(1508)
		except socket.timeout:
			print("timeout at hop", ttl, '\n')
			timeout += 1		
			continue
		if (addr == HOST):
			print("Arrived!\n")
			
			break
		#print("hop:", ttl, addr, "size:", sys.getsizeof(data), data)
		return data
		break
		ttl += 1
	
"""
example data of 105 byte size
b'E\xc04\x00\xea\x8e\x00\x00@\x01{d\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xa5i\x00\x00\x00\x00E\x00,\x00\x81O\x00\x00\x01\x11\x882\n\x00\x00\x02\xd8:\xce\x03\xe5\xee\x00P\x00\x18c?\x01\x00\x02\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'
"""
def dissect_icmp_packet(buffer):
	ip4_h = ip4_header._make(unpack_from(icmp_header_format.format, buffer)[0:ip4_header_format.length])
	version = (ip4_h.version_ihl & 0xF0) >> 4
	ihl = (ip4_h.version_ihl & 0x0F)
	#TODO: better handling of error
	if (version != 4 or ihl != 5 or ip4_h.proto != 1):
		print("can't handle this ip4 packet")
		return
	icmp_h = icmp_header._make(unpack_from(icmp_header_format.format, buffer)[ip4_header_format.length:])
	if (icmp_h.type != 11 or icmp_h.code != 0):
		print("can't handle this icmp packet")
		return
	icmp_data = buffer[((ihl * 4) + (icmp_hl * 4)):]
	return (icmp_h, icmp_data)
	



test_packet = b'E\xc04\x00\xea\x8e\x00\x00@\x01{d\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xa5i\x00\x00\x00\x00E\x00,\x00\x81O\x00\x00\x01\x11\x882\n\x00\x00\x02\xd8:\xce\x03\xe5\xee\x00P\x00\x18c?\x01\x00\x02\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'
test_packet2 = b"E\xc0'\x00\xac\xfa\x00\x00@\x01\xb9\x05\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xa5<\x00\x00\x00\x00E\x00\x1f\x00'P\x00\x00\x01\x11\xe2^\n\x00\x00\x02\xd8:\xcd\xe3\xd7x\x00P\x00\x0bs\xed\x01\x02\x03"
test_packet3 = b"E\xc0'\x00\x92\t\x00\x00@\x01\xd3\xf6\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xc2:\x00\x00\x00\x00E\x00\x1f\x00%\x01\x00\x00\x01\x11\xc7\xaf\n\x00\x00\x02\xac\xd9\x16C\xc4#\x00P\x00\x0bjD\x01\x02\x03"
test_packet4 = b'E\xc00\x00^\xf0\x00\x00@\x01\x07\x07\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xad\xc5\x00\x00\x00\x00E\x00(\x00\xa4\xd9\x00\x00\x01\x11\\L\n\x00\x00\x02\xd8:\xd6c\xd2\xf9\x00P\x00\x14s\xd6\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03'

#version_ihl, dscp_ecn, total_length, _, _, source_ip, dest_ip = unpack_packet(test_packet)
#iph = ip4_header._make(unpack_packet(test_packet))

#print(iph.version_ihl)
#print((iph.version_ihl & 240) >> 4)
#listen()
#print(total_length)
test_packet = listen()
#print(test_packet)
icmp_data = dissect_icmp_packet(test_packet)[1]
ip4_h = ip4_header._make(unpack_from(ip4_header_format.format, icmp_data))
ihl = (ip4_h.version_ihl & 0x0F)


original_buffer = icmp_data[(5*4):]
#the original datagrams also contains a 8 byte header!!!!!
original_data = unpack_from("!III", original_buffer)
assert original_data[2] == pid
#print(pack('!BBB',1,2,3))