import json, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
v5=json.load(open('analysis/tmp/text01_union_v5.json'))
dec={int(k,16):v for k,v in v5.items()}
def traverse(entries, dec):
    queue=list(sorted(entries)); seen=set(); added=0
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
            dec[a]=ins.size; added+=1; a+=ins.size
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
    return added
def collect_targets(dec):
    ts=set()
    for a,sz in dec.items():
        b=IMG[a-BASE:a-BASE+16]
        try: ins=next(md.disasm(b,a))
        except StopIteration: continue
        if ins.mnemonic in ('call','jmp') and ins.op_str.startswith('0x'):
            try: ts.add(int(ins.op_str,16))
            except: pass
        for m in re.finditer(r'0x([0-9a-f]{5,8})', ins.op_str):
            ts.add(int(m.group(1),16))
    return ts
for it in range(20):
    ts={t for t in collect_targets(dec) if in_txt(t) and t not in dec}
    if not ts: print('stable at iteration', it); break
    added=traverse(ts, dec)
    print('iter %d: new entries %d added insns %d total %d' % (it, len(ts), added, len(dec)))
def cov(dd):
    b0=set(); b1=set()
    for a,sz in dd.items():
        for k in range(sz):
            (b0 if T0[0]<=a<T0[1] else b1).add(a+k)
    return len(b0),len(b1)
c=cov(dec)
print('final insns %d text0 %.2f%% text1 %.2f%%' % (len(dec), 100.0*c[0]/(T0[1]-T0[0]), 100.0*c[1]/(T1[1]-T1[0])))
json.dump({hex(k):v for k,v in dec.items()}, open('analysis/tmp/text01_union_v6.json','w'))
