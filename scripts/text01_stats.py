import struct, json, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read()
BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
entries=set()
for i in range(CODE[0]-BASE, CODE[1]-BASE-5):
    if IMG[i] in (0xE8,0xE9):
        rel=struct.unpack('<i', IMG[i+1:i+5])[0]
        t=BASE+i+5+rel
        if in_txt(t): entries.add(t)
KNOWN={0x47a71c:'U0_entry',0x4795cc:'U1_entry',0x479800:'V1_entry',0x4731c9:'V0_entry',0x47a85b:'X_entry',0x47404e:'X_layer',0x47b4d1:'VM_dispatch',0x47ac56:'U0_body',0x478f52:'X_tail',0x475cea:'X_chain'}
for a in KNOWN: entries.add(a)
decoded={}; blocks={}; starts=set()
queue=list(sorted(entries)); seen=set()
while queue:
    start=queue.pop(0)
    if start in seen: continue
    seen.add(start); a=start; addrs=[]
    while True:
        if in_txt(a) and a in decoded: break
        if not in_txt(a): break
        b=IMG[a-BASE:a-BASE+16]
        if len(b)<5: break
        try: ins=next(md.disasm(b,a))
        except StopIteration: break
        decoded[a]=(ins.size,ins.mnemonic,ins.op_str); addrs.append(a); a+=ins.size
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
    if addrs:
        blocks[start]=addrs; starts.add(start)
def succ(a):
    sz,m,o=decoded[a]; out=set(); nxt=a+sz
    if m in ('ret','retf','iret'): return out
    if m=='jmp':
        if o.startswith('0x'):
            t=int(o,16)
            if t in blocks: out.add(t)
        return out
    if m.startswith('j') and m!='jmp':
        if o.startswith('0x'):
            t=int(o,16)
            if t in blocks: out.add(t)
        if nxt in blocks: out.add(nxt)
        return out
    if m=='call':
        if o.startswith('0x'):
            t=int(o,16)
            if t in blocks: out.add(t)
        if nxt in blocks: out.add(nxt)
        return out
    if nxt in blocks: out.add(nxt)
    return out
total=len(decoded)
print('total insns', total, 'blocks', len(blocks))
for a,name in KNOWN.items():
    if a not in blocks: print(name, 'not decoded'); continue
    st=[a]; vis=set(); ins=0
    while st:
        b=st.pop()
        if b in vis: continue
        vis.add(b)
        for x in blocks[b]: ins+=1
        for s in succ(blocks[b][-1]): st.append(s)
    print('%-12s 0x%06x blocks=%4d insns=%5d' % (name,a,len(vis),ins))
