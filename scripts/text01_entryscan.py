import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000); CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
# 立即数候选
cands=set()
for i in range(0,len(IMG)-4):
    v=struct.unpack('<I', IMG[i:i+4])[0]
    if in_txt(v): cands.add(v)
print('dword candidates (all offsets)', len(cands))
def traverse(entries):
    dec={}; queue=list(sorted(entries)); seen=set()
    while queue:
        st=queue.pop(0)
        if st in seen: continue
        seen.add(st); a=st
        while True:
            if in_txt(a) and a in dec: break
            if not in_txt(a): break
            b=IMG[a-BASE:a-BASE+16]
            if len(b)<5: break
            try: ins=next(md.disasm(b,a))
            except StopIteration: break
            dec[a]=ins.size; a+=ins.size
            if ins.mnemonic in ('ret','retf','iret'): break
            if ins.mnemonic=='jmp':
                if ins.op_str.startswith('0x'):
                    try:
                        t=int(ins.op_str,16)
                        if in_txt(t) and t not in dec: queue.append(t)
                    except: pass
                break
            if ins.mnemonic.startswith('j') and ins.mnemonic!='jmp':
                if ins.op_str.startswith('0x'):
                    try:
                        t=int(ins.op_str,16)
                        if in_txt(t) and t not in dec: queue.append(t)
                    except: pass
            if ins.mnemonic=='call' and ins.op_str.startswith('0x'):
                try:
                    t=int(ins.op_str,16)
                    if in_txt(t) and t not in dec: queue.append(t)
                except: pass
    return dec
base=set()
for i in range(CODE[0]-BASE, CODE[1]-BASE-5):
    if IMG[i] in (0xE8,0xE9):
        rel=struct.unpack('<i', IMG[i+1:i+5])[0]; t=BASE+i+5+rel
        if in_txt(t): base.add(t)
base |= {0x47a71c,0x4795cc,0x479800,0x4731c9,0x47a85b,0x47404e,0x47b4d1}
def stat(d):
    b0=sum(sz for a,sz in d.items() if T0[0]<=a<T0[1]); b1=sum(sz for a,sz in d.items() if T1[0]<=a<T1[1])
    return len(d),b0,100.0*b0/(T0[1]-T0[0]),b1,100.0*b1/(T1[1]-T1[0])
s0=stat(traverse(base)); print('base: insns=%d text0=%.2f%% text1=%.2f%%' % (s0[0],s0[2],s0[4]))
s1=stat(traverse(base|cands)); print('with immediates: insns=%d text0=%.2f%% text1=%.2f%%' % (s1[0],s1[2],s1[4]))
