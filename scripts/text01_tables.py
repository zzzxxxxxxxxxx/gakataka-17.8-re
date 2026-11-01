import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000); CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
def entries_from_code():
    es=set()
    for i in range(CODE[0]-BASE, CODE[1]-BASE-5):
        if IMG[i] in (0xE8,0xE9):
            rel=struct.unpack('<i', IMG[i+1:i+5])[0]; t=BASE+i+5+rel
            if in_txt(t): es.add(t)
    return es
def table_entries():
    es=set(); refs=0
    for start in range(T0[0],T0[1],1):
        b=IMG[start-BASE:start-BASE+16]
        try: ins=next(md.disasm(b,start))
        except StopIteration: continue
        if ins.mnemonic not in ('jmp','call'): continue
        m=re.search(r'\[[^\]]*?\*4 \+ (0x[0-9a-f]+)\]', ins.op_str)
        if not m: continue
        tab=int(m.group(1),16)
        if not (BASE<=tab<BASE+len(IMG)): continue
        refs+=1
        for k in range(64):
            off=tab-BASE+k*4
            if off+4>len(IMG): break
            v=struct.unpack('<I', IMG[off:off+4])[0]
            if not in_txt(v): break
            es.add(v)
    print('jump-table refs', refs, 'targets', len(es))
    return es
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
base_entries=entries_from_code() | {0x47a71c,0x4795cc,0x479800,0x4731c9,0x47a85b,0x47404e,0x47b4d1}
dec1=traverse(base_entries)
tab=table_entries()
dec2=traverse(base_entries|tab)
def cov(dec):
    b0=sum(sz for a,sz in dec.items() if T0[0]<=a<T0[1]); b1=sum(sz for a,sz in dec.items() if T1[0]<=a<T1[1])
    return b0,b1
c1=cov(dec1); c2=cov(dec2)
print('before: insns %d text0 %d (%.2f%%) text1 %d (%.2f%%)' % (len(dec1), c1[0], 100.0*c1[0]/(T0[1]-T0[0]), c1[1], 100.0*c1[1]/(T1[1]-T1[0])))
print('after : insns %d text0 %d (%.2f%%) text1 %d (%.2f%%)' % (len(dec2), c2[0], 100.0*c2[0]/(T0[1]-T0[0]), c2[1], 100.0*c2[1]/(T1[1]-T1[0])))
