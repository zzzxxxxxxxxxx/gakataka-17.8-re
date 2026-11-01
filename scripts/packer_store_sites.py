from capstone import Cs, CS_ARCH_X86, CS_MODE_32
packed=open('analysis/tmp/Smonitor-packed.exe','rb').read()
md=Cs(CS_ARCH_X86, CS_MODE_32)
def dump(va, n=30):
    off=0x1200+(va-0x47c000)
    print('==== %#x' % va)
    for ins in md.disasm(packed[off:off+300], va):
        print('%#08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
        n-=1
        if n<=0: break
for va in (0x4c31c8, 0x4c31d2, 0x4aeaf0, 0x4aeaf4):
    dump(va, 20)
