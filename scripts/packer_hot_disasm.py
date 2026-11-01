from capstone import Cs, CS_ARCH_X86, CS_MODE_32
stage=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
packed=open('analysis/tmp/Smonitor-packed.exe','rb').read()
md=Cs(CS_ARCH_X86, CS_MODE_32)
def dump(va, n=30, src='stage'):
    data = stage if src=='stage' else packed
    off = va-BASE if src=='stage' else 0x1200+(va-0x47c000)
    print('==== %s %#x' % (src, va))
    for ins in md.disasm(data[off:off+200], va):
        print('%#08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
        n-=1
        if n<=0: break
for va in (0x4B0BD7, 0x47C43C, 0x4C4A3A, 0x4ADB71):
    dump(va, 24)
