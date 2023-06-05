# Dante's notebook

## Category: pwn

## Objectives


- format string bug. (leaks)
- Buffer overflow

There was a format (fmt) vulnerability in the date command, through which I was able to leak a libc address and the stack cookie. In the same buffer (date), by adding a null byte, we were able to bypass the date check and length validation. 
We could write up to 96 bytes in the buffer, where the buffer overflow (bof) occurs, facilitating the completion of our exploit. 
The process involved overwriting the return address with a one-gadget.
