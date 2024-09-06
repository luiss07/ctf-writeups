from pwn import *
from unicorn import *
from unicorn.arm_const import *

CONNECTON_TYPE = 'remote' # 'remote' or 'local'

if CONNECTON_TYPE == 'remote':
    p = remote('94.237.58.173', 43455)
elif CONNECTON_TYPE == 'local':
    p = process('./execute')
else: 
    print("pwn not needed")

# memory address where emulation starts
ADDRESS    = 0x10000

def caluculate_r0(hex_code):

    ARM_CODE = bytes.fromhex(hex_code)
    #print(f"ARM_CODE: {ARM_CODE}")
    # Initialize emulator in ARM mode
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, ARM_CODE)

    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))

    #print(">>> Emulation done. Below is the CPU context")

    r0 = mu.reg_read(UC_ARM_REG_R0)
    return r0

for i in range(0,50):
    p.recvuntil(b'/50:')
    hex_code = p.recvline().decode().strip()
    r0 = caluculate_r0(hex_code)
    print(f">>> Level {i} -> r0 = 0x{r0}")
    p.sendline(str(r0))

print(p.recvall().decode())
