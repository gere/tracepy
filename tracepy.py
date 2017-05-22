#!/usr/bin/python3

import socket
import sys
import os
import argparse
from struct import *
from time import sleep
from collections import namedtuple

"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
ip4_header = namedtuple('ip4_header', 
						'version_ihl tos length ident flags ttl proto checksum source destination')


"""
	0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               rest of the message / unused                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
icmp_header = namedtuple('icmp_header', 'type code checksum rest')


"""
 0      7 8     15 16    23 24    31  
 +--------+--------+--------+--------+ 
 |     Source      |   Destination   | 
 |      Port       |      Port       | 
 +--------+--------+--------+--------+ 
 |                 |                 | 
 |     Length      |    Checksum     | 
 +--------+--------+--------+--------+ 
 """
udp_header = namedtuple('udp_header', 'source_port dest_port length checksum')



"""
 struct format for packet headers 
Python formats
Format	C Type			Python type			Standard size	
x		pad byte		no value	 	 
c		char			bytes of length 1		1	 
b		signed char		integer					1
B		unsigned char	integer					1	
?		_Bool			bool					1
h		short			integer					2	
H		unsigned short	integer					2	
i		int				integer					4
I		unsigned int	integer					4	
l		long			integer					4	
L		unsigned long	integer					4	
q		long long		integer					8	
Q		unsigned long long	integer				8	
n		ssize_t			integer	 	
N		size_t			integer		 	
e		(7)				float					2	
f		float			float					4	
d		double			float					8	
s		char[]			bytes	 	 
p		char[]			bytes	 	 
P		void *			integer	 		
"""
ip4_header_format  = '!BBHHHBBH4s4s'
icmp_header_format = '!BBHI'	
udp_header_format = '!HHHH'

""" command line arguments parser """
parser = argparse.ArgumentParser(
	description='A simple Python implemantation of traceroute')
parser.add_argument('host', type=str, nargs=1,
					help='The route to reach the host')


def makeHeader(type, format, buffer):
	return type._make(unpack_from(format, buffer))


def dissect_icmp_packet(buffer):
	ip4_h = makeHeader(ip4_header, ip4_header_format, buffer)	
	version = (ip4_h.version_ihl & 0xF0) >> 4
	ihl = (ip4_h.version_ihl & 0x0F)
	#TODO: better handling of error
	if (version != 4 or ihl != 5 or ip4_h.proto != 1):
		print("can't handle this ip4 packet")
		return	

	ip4_h_size = calcsize(ip4_header_format) # always 20 bytes since packet with ihl > 5 are discarded
	icmp_h = makeHeader(icmp_header, icmp_header_format, buffer[ip4_h_size:])
	
	if (icmp_h.type != 11 or icmp_h.code != 0):
		print("can't handle this icmp packet")
		return
	
	icmp_h_size = calcsize(icmp_header_format) # 8 bytes. That's a constants	
	icmp_data = buffer[(ip4_h_size + icmp_h_size):]

	return (icmp_h, icmp_data)


def probe(send_socket, address, packet, ttl):
	send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)	
	b = send_socket.sendto(packet, address)
	port_number = send_socket.getsockname()[1]	
	return port_number


def start(host):	
	HOST = socket.gethostbyname(host)
	PORT = 80	
	ADDR = (HOST, PORT)
	ttl = 1
	timeout = 0
	pid = os.getpid()
	probe_packet = pack('!h', pid)	

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
	
	""" send first """
	port_number = probe(send_socket, ADDR, probe_packet, ttl)
	while (True):
		if (ttl > 100):
			break
		if (timeout >= 3):
			ttl += 1
			timeout = 0
		
		try:
			data, addr = listen_socket.recvfrom(1508)
		except socket.timeout:
			print("timeout at hop", ttl, '\n')
			timeout += 1		
			continue

		icmp_h, icmp_data = dissect_icmp_packet(data)
		original_buffer = icmp_data[(5*4):]		
		original_ip4_h = makeHeader(ip4_header, ip4_header_format, icmp_data)
		original_udp_h = makeHeader(udp_header, udp_header_format, original_buffer)		
	
		if(original_udp_h.source_port == port_number):
			print(ttl, addr[0])
			ttl += 1
			""" send again """
			port_number = probe(send_socket, ADDR, probe_packet, ttl)
		else:
			#TODO: add 
			continue


""" some test packet to use when adding tests """
test_packet  = (b'E\xc04\x00\xea\x8e\x00\x00@\x01{d\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xa5i\x00\x00'
			    b'\x00\x00E\x00,\x00\x81O\x00\x00\x01\x11\x882\n\x00\x00\x02\xd8:\xce\x03\xe5\xee\x00'
			    b'P\x00\x18c?\x01\x00\x02\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00')
test_packet2 = (b"E\xc0'\x00\xac\xfa\x00\x00@\x01\xb9\x05\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xa5<"
				b"\x00\x00\x00\x00E\x00\x1f\x00'P\x00\x00\x01\x11\xe2^\n\x00\x00\x02\xd8:\xcd\xe3\xd7"
				b"x\x00P\x00\x0bs\xed\x01\x02\x03")
test_packet3 = (b"E\xc0'\x00\x92\t\x00\x00@\x01\xd3\xf6\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xc2:"
				b"\x00\x00\x00\x00E\x00\x1f\x00%\x01\x00\x00\x01\x11\xc7\xaf\n\x00\x00\x02\xac\xd9"
				b"\x16C\xc4#\x00P\x00\x0bjD\x01\x02\x03")
test_packet4 = (b'E\xc00\x00^\xf0\x00\x00@\x01\x07\x07\n\x00\x00\x01\n\x00\x00\x02\x0b\x00\xad'
				b'\xc5\x00\x00\x00\x00E\x00(\x00\xa4\xd9\x00\x00\x01\x11\\L\n\x00\x00\x02\xd8:'
				b'\xd6c\xd2\xf9\x00P\x00\x14s\xd6\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03')


if __name__ == '__main__':
	args = parser.parse_args()
	try:
		start(args.host[0])
	except KeyboardInterrupt:
		print()
		sys.exit(0)