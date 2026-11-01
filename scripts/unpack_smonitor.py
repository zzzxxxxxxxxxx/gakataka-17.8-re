#!/usr/bin/env python3
# 从原始 packed Smonitor.exe 解包出内存镜像（Unicorn 仿真，已验证与真实解包结果 100% 一致）。
# 用法: python unpack_smonitor.py <packed.exe> <out_image.bin>
import struct, sys
from unicorn import *
from unicorn.x86_const import *
BASE=0x400000; IMGSIZE=0x200000
TEB=0x30000000; STACK=0x20000000; STACKSZ=0x100000; SCRATCH=0x22000000
def w32(uc,a,v): uc.mem_write(a, struct.pack('<I', v & 0xffffffff))
def main():
    if len(sys.argv)!=3:
        print('usage: unpack_smonitor.py <packed.exe> <out_image.bin>'); return 1
    packed=open(sys.argv[1],'rb').read()
    uc=Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(BASE, IMGSIZE); uc.mem_map(STACK, STACKSZ); uc.mem_map(TEB, 0x10000)
    uc.mem_map(SCRATCH, 0x100000); uc.mem_map(0, 0x10000)
    # 原始文件布局: headers 0x0, .rdata file 0x400->0x460000, .rsrc file 0x600->0x468000,
    # .text1 file 0x1200->0x47c000 (0x4ae00), 尾部 .reloc file 0x4c000->0x4c7000
    uc.mem_write(BASE, packed[0:0x400])
    uc.mem_write(0x460000, packed[0x400:0x600])
    uc.mem_write(0x468000, packed[0x600:0x1200])
    uc.mem_write(0x47c000, packed[0x1200:0x1200+0x4ae00])
    uc.mem_write(0x4c7000, packed[0x4c000:0x4c200])
    w32(uc,TEB,0xFFFFFFFF); w32(uc,TEB+4,STACK+STACKSZ); w32(uc,TEB+8,STACK)
    w32(uc,TEB+0x18,TEB); w32(uc,TEB+0x30,TEB+0x1000); w32(uc,TEB+0x1008,BASE)
    sp=STACK+STACKSZ-0x1000; w32(uc,sp,0)
    uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp)
    uc.reg_write(UC_X86_REG_FS_BASE,TEB)
    for r in (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI):
        uc.reg_write(r,0)
    # entry point 0x4AE041（来自 PE AddressOfEntryPoint）
    try:
        uc.emu_start(0x4AE041, 0xFFFFFFF0, count=60000000)
    except UcError as e:
        print('emulation stopped:', e)
    img=uc.mem_read(BASE, IMGSIZE)
    open(sys.argv[2],'wb').write(img)
    print('wrote', sys.argv[2], len(img), 'bytes; eip=%#x' % uc.reg_read(UC_X86_REG_EIP))
    return 0
if __name__=='__main__':
    sys.exit(main())