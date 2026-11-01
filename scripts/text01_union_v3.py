import struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000); CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
d=json.load(open('analysis/tmp/rizin_aflj.json'))
def traverse(entries, dec=None):
    if dec is None: dec={}
    queue=list(sorted(entries)); seen=set()
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
trusted=traverse(base)
# rizin 线性
rz={}
for f in d:
    o=f['offset']
    if not in_txt(o): continue
    sz=f.get('realsz') or f.get('size') or 0
    end=min(o+sz,(T1[1] if o>=T1[0] else T0[1]))
    a=o
    while a<end:
        b=IMG[a-BASE:a-BASE+16]
        try: ins=next(md.disasm(b,a))
        except StopIteration: break
        rz[a]=ins.size; a+=ins.size
trusted.update(rz)
# 已知指令内部地址集合
inside=set()
for a,sz in trusted.items():
    for k in range(1,sz): inside.add(a+k)
cands=set()
for i in range(0,len(IMG)-4):
    v=struct.unpack('<I', IMG[i:i+4])[0]
    for t in (v, v+BASE, v-BASE, v^0x40000000):
        if in_txt(t): cands.add(t)
cands={c for c in cands if c not in inside}
print('candidates after inside-filter', len(cands))
extra=traverse(cands, dict(trusted))
def cov(dec):
    b0=set(); b1=set()
    for a,sz in dec.items():
        for k in range(sz):
            (b0 if T0[0]<=a<T0[1] else b1).add(a+k)
    return len(b0),len(b1)
c=cov(extra)
print('final insns', len(extra), 'text0 %.2f%% text1 %.2f%%' % (100.0*c[0]/(T0[1]-T0[0]), 100.0*c[1]/(T1[1]-T1[0])))
addrs=sorted(extra)
lines=['# Smonitor .text0/.text1 指令清单（可信入口：CODE 引用 + 已知 handler + 过滤后的指针候选 + rizin 函数）','',
 'image base 0x%x; text0 0x%x-0x%x; text1 0x%x-0x%x; 指令数 %d; text0 %.2f%%; text1 %.2f%%'%(BASE,T0[0],T0[1],T1[0],T1[1],len(addrs),100.0*c[0]/(T0[1]-T0[0]),100.0*c[1]/(T1[1]-T1[0])),'']
for a in addrs:
    b=IMG[a-BASE:a-BASE+16]
    try: ins=next(md.disasm(b,a))
    except StopIteration: continue
    lines.append('0x%08x  %-8s %s'%(a,ins.mnemonic,ins.op_str))
open('analysis/SMONITOR-TEXT01-INSN-FULL.txt','w').write('\n'.join(lines))
json.dump({hex(k):v for k,v in extra.items()}, open('analysis/tmp/text01_union_v3.json','w'))
print('wrote listing', len(lines), 'lines')
