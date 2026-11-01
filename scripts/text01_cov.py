import struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000); CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
entries=set()
for i in range(CODE[0]-BASE, CODE[1]-BASE-5):
    if IMG[i] in (0xE8,0xE9):
        rel=struct.unpack('<i', IMG[i+1:i+5])[0]; t=BASE+i+5+rel
        if in_txt(t): entries.add(t)
for a in [0x47a71c,0x4795cc,0x479800,0x4731c9,0x47a85b,0x47404e,0x47b4d1]: entries.add(a)
decoded={}
queue=list(sorted(entries)); seen=set()
while queue:
    start=queue.pop(0)
    if start in seen: continue
    seen.add(start); a=start
    while True:
        if in_txt(a) and a in decoded: break
        if not in_txt(a): break
        b=IMG[a-BASE:a-BASE+16]
        if len(b)<5: break
        try: ins=next(md.disasm(b,a))
        except StopIteration: break
        decoded[a]=(ins.size,ins.mnemonic,ins.op_str); a+=ins.size
        if ins.mnemonic in ('ret','retf','iret'): break
        if ins.mnemonic=='jmp':
            if ins.op_str.startswith('0x'):
                try:
                    t=int(ins.op_str,16)
                    if in_txt(t) and t not in decoded: queue.append(t)
                except: pass
            break
        if ins.mnemonic.startswith('j') and ins.mnemonic!='jmp':
            if ins.op_str.startswith('0x'):
                try:
                    t=int(ins.op_str,16)
                    if in_txt(t) and t not in decoded: queue.append(t)
                except: pass
        if ins.mnemonic=='call' and ins.op_str.startswith('0x'):
            try:
                t=int(ins.op_str,16)
                if in_txt(t) and t not in decoded: queue.append(t)
            except: pass
b0=sum(sz for a,(sz,m,o) in decoded.items() if T0[0]<=a<T0[1])
b1=sum(sz for a,(sz,m,o) in decoded.items() if T1[0]<=a<T1[1])
print('decoded insns',len(decoded))
print('text0 bytes covered %d / %d = %.2f%%' % (b0, T0[1]-T0[0], 100.0*b0/(T0[1]-T0[0])))
print('text1 bytes covered %d / %d = %.2f%%' % (b1, T1[1]-T1[0], 100.0*b1/(T1[1]-T1[0])))
print('total covered %d / %d = %.2f%%' % (b0+b1, (T0[1]-T0[0])+(T1[1]-T1[0]), 100.0*(b0+b1)/((T0[1]-T0[0])+(T1[1]-T1[0]))))
