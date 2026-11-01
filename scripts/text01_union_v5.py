import struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
v4=json.load(open('analysis/tmp/text01_union_v4.json'))
dec={int(k,16):v for k,v in v4.items()}
starts=[int(x,16) for x in json.load(open('analysis/tmp/text01_strict_starts.json'))]
starts=[a for a in starts if T0[0]<=a<T0[1]]
print('text0-only new starts', len(starts))
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
before=len(dec); traverse(starts, dec)
def cov(dd):
    b0=set(); b1=set()
    for a,sz in dd.items():
        for k in range(sz):
            (b0 if T0[0]<=a<T0[1] else b1).add(a+k)
    return len(b0),len(b1)
c=cov(dec)
print('v5 insns %d (added %d) text0 %.2f%% text1 %.2f%%' % (len(dec), len(dec)-before, 100.0*c[0]/(T0[1]-T0[0]), 100.0*c[1]/(T1[1]-T1[0])))
addrs=sorted(dec)
lines=['# Smonitor .text0/.text1 指令清单 v5（v4 + 严格可达的 text0 入口）','',
 'image base 0x%x; text0 0x%x-0x%x; text1 0x%x-0x%x; 指令数 %d; text0 %.2f%%; text1 %.2f%%'%(BASE,T0[0],T0[1],T1[0],T1[1],len(addrs),100.0*c[0]/(T0[1]-T0[0]),100.0*c[1]/(T1[1]-T1[0])),'']
for a in addrs:
    b=IMG[a-BASE:a-BASE+16]
    try: ins=next(md.disasm(b,a))
    except StopIteration: continue
    lines.append('0x%08x  %-8s %s'%(a,ins.mnemonic,ins.op_str))
open('analysis/SMONITOR-TEXT01-INSN-FULL.txt','w').write('\n'.join(lines))
json.dump({hex(k):v for k,v in dec.items()}, open('analysis/tmp/text01_union_v5.json','w'))
print('wrote listing', len(lines))
