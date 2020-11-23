#!/usr/bin/env python3

"""
    Unicorn script used to decompress Canon MG6450 printer firmwares
"""
from unicorn import *
from unicorn.arm_const import *

def hook_code(mu, address, size, user_data):
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    if address == 0x04220384:
        R1 = mu.reg_read(UC_ARM_REG_R1)
        R2 = mu.reg_read(UC_ARM_REG_R2)
        print('%x / %x' % (R1, R2))

BASE = 0x0
STACK_ADDR = 0xFFFFFFFF
STACK_SIZE = 2 * 1024 * 1024 # 2 MB stack size
FW_PATH = 'firmware/176BV3020AN_decrypted-fixed.bin'
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM|UC_MODE_THUMB)

with open(FW_PATH, 'rb') as f:
    fw_data = f.read()

# Map stack
mu.mem_map(STACK_ADDR + 1 - STACK_SIZE, STACK_SIZE)

# Map firmware at 0x4000000
mu.mem_map(0x4000000, 16*1024*1024) # 16MB
mu.mem_write(0x4000000, fw_data)

# 0xE8009B20 dereferenced by 0x00220BC2
# 0xE8009B0A is written by read_dword_array (0x220480)
# 0xE8006000 - 0xe8106000
mu.mem_map(0xE8006000, 0x100000) # 1MB

# 0x18EDBC48 dereferenced by 0x00220270
mu.mem_map(0x18EDBC48 & (~(0x1000-1)) , 0x100000) # 1MB

"""
char *call_small_decrypt_routine()
{
  return small_decompress_routine((char *)&compr_dict, (_BYTE *)0x1DF9DE00, 0x108A780);
}
"""
# 0x1DF9DE00: address of decompression buffer of size 0x108A780
mu.mem_map(0x1DF9DE00 & (~(0x1000-1)) , (0x108A780 & (~(0x1000-1))) + 0x2000) # more than 16MB

mu.hook_add(UC_HOOK_CODE, hook_code)

mu.reg_write(UC_ARM_REG_SP, STACK_ADDR & (~(0x1000-1)))

decompression_routine_call = 0x04220058
decompression_routine_after_call = decompression_routine_call + 4

mu.emu_start(decompression_routine_call, decompression_routine_after_call)

with open('output_memory2.bin', 'wb') as f:
    memory = mu.mem_read(0x1DF9DE00, 0x108A780)
    f.write(memory)
