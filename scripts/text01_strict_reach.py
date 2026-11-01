import struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000); CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
v4=json.load(open('analysis/tmp/text01_union_v4.json'))
trusted={int(k,16):v for k,v in v4.items()}
inside=set()
for a,sz in trusted.items():
    for k in range(1,sz): inside.add(a+k)
# 全部编码候选
cands=set()
for i in range(0,len(IMG)-4):
    v=struct.unpack('<I', IMG[i:i+4])[0]
    for t in (v, v+BASE, v-BASE, v^0x40000000, (v&0xFFFFFF)+BASE):
        if in_txt(t): cands.add(t)
cands={c for c in cands if c not in inside and c not in trusted}
print('raw candidates', len(cands))
# 反向可达过滤：前向解码 <=24 且汇入已知或直接转移到已知
accepted=set()
for start in cands:
    a=start; ok=False; steps=0
    while steps<24:
        b=IMG[a-BASE:a-BASE+16]
        try: ins=next(md.disasm(b,a))
        except StopIteration: break
        if ins.mnemonic in ('call','jmp') or ins.mnemonic.startswith('j'):
            if ins.op_str.startswith('0x'):
                try: t=int(ins.op_str,16)
                except: t=None
                if t is not None and t in trusted: ok=True
        a+=ins.size; steps+=1
        if a in trusted: ok=True; break
        if ins.mnemonic in ('ret','retf','iret'): break
        if ins.mnemonic=='jmp': break
    if ok: accepted.add(start)
print('accepted (strict reach)', len(accepted), 'text0:', len([a for a in accepted if T0[0]<=a<T0[1]]), 'text1:', len([a for a in accepted if T1[0]<=a<T1[1]]))
def traverse(entries, dec):
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
merge=dict(trusted); traverse(accepted, merge)
def cov(dd):
    b0=set(); b1=set()
    for a,sz in dd.items():
        for k in range(sz):
            (b0 if T0[0]<=a<T0[1] else b1).add(a+k)
    return len(b0),len(b1)
c=cov(merge)
print('final insns %d text0 %.2f%% text1 %.2f%%' % (len(merge), 100.0*c[0]/(T0[1]-T0[0]), 100.0*c[1]/(T1[1]-T1[0])))
json.dump([hex(x) for x in sorted(accepted)], open('analysis/tmp/text01_strict_starts.json','w'))
