import struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000); CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
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
# rizin
d=json.load(open('analysis/tmp/rizin_aflj.json'))
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
        trusted[a]=ins.size; a+=ins.size
# 计算缺口字符
covered=set()
for a,sz in trusted.items():
    for k in range(sz): covered.add(a+k)
gap=[a for a in range(T0[0],T0[1]) if a not in covered]
print('trusted insns', len(trusted), 'text0 gap bytes', len(gap))
# 反向可达：从缺口内每个偏移前向解码（仅 fallthrough），命中已知地址或直接跳入已知则接受
accepted=set()
for start in gap:
    a=start; ok=False; steps=0
    while steps<24:
        b=IMG[a-BASE:a-BASE+16]
        try: ins=next(md.disasm(b,a))
        except StopIteration: break
        # 若当前指令地址本身是已知入口（不太可能）
        # 直接转移到已知集合内 -> 接受
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
print('accepted starts', len(accepted))
extra=traverse(accepted, dict(trusted))
def cov(dec):
    b0=set(); b1=set()
    for a,sz in dec.items():
        for k in range(sz):
            (b0 if T0[0]<=a<T0[1] else b1).add(a+k)
    return len(b0),len(b1)
c=cov(extra)
print('after backward-reach: insns %d text0 %.2f%% text1 %.2f%%' % (len(extra), 100.0*c[0]/(T0[1]-T0[0]), 100.0*c[1]/(T1[1]-T1[0])))
json.dump([hex(x) for x in sorted(accepted)], open('analysis/tmp/text0_backreach_starts.json','w'))
