# Sentence

## Category: pwn

## Objectives


- Format string bug
  - Libc leak
  - Stack leak
  - Pie leak (optional)

There is a more optimized solution in the official writeups, but I uploaded my working exploit for this challenge which was
crafted during the competition.

The extra step I did was to overwrite the return address with `_start` address to re run the program. This was not necessary for the actual solution.

You only needed a libc and a stack address which was leakd with one run.

The rest of the exploitation was easy you just needed to overwrite the return address with one gadget.
  
