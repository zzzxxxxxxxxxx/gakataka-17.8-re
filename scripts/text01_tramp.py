import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000); CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
# 线性扫描 text0，解码指令序列
insns=[]
a=T0[0]
while a<T0[1]:
    b=IMG[a-BASE:a-BASE+16]
    if len(b)<5: break
    try: ins=next(md.disasm(b,a))
    except StopIteration:
        a+=1; continue
    insns.append(ins); a+=ins.size
print('linear insns', len(insns))
# 模式1：push imm32（0x68）值在 text 范围
cands=set()
for ins in insns:
    if ins.mnemonic=='push' and ins.op_str.startswith('0x'):
        try: v=int(ins.op_str,16)
        except: continue
        if in_txt(v): cands.add(v)
print('push-imm text targets', len(cands))
# 模式2：ret 前 6 条指令内出现 push imm32
ret_targets=set()
for i,ins in enumerate(insns):
    if ins.mnemonic not in ('ret','retf'): continue
    for j in range(max(0,i-6), i):
        p=insns[j]
        if p.mnemonic=='push' and p.op_str.startswith('0x'):
            try: v=int(p.op_str,16)
            except: continue
            if in_txt(v): ret_targets.add(v)
print('ret-near push targets', len(ret_targets))
# 模式3：mov dword ptr [esp], imm32 / mov [esp+..], imm32 然后 ret
espstore=set()
for i,ins in enumerate(insns):
    if ins.mnemonic=='mov' and 'esp' in ins.op_str and ins.op_str.startswith('dword ptr [esp'):
        parts=ins.op_str.split(', ')
        if len(parts)==2 and parts[1].startswith('0x'):
            try: v=int(parts[1],16)
            except: continue
            if in_txt(v): espstore.add(v)
print('esp-store targets', len(espstore))
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
    b0=sum(sz for x,sz in d.items() if T0[0]<=x<T0[1]); b1=sum(sz for x,sz in d.items() if T1[0]<=x<T1[1])
    return len(d),b0,b1
d0=traverse(base); s0=stat(d0)
print('baseline insns=%d text0=%d(%.2f%%) text1=%d(%.2f%%)' % (s0[0],s0[1],100.0*s0[1]/(T0[1]-T0[0]),s0[2],100.0*s0[2]/(T1[1]-T1[0])))
for name,extra in [('push',cands),('ret_near',ret_targets),('esp_store',espstore),('all',cands|ret_targets|espstore)]:
    d=traverse(base|extra); s=stat(d)
    print('%-9s insns=%d text0=%d(%.2f%%) text1=%d(%.2f%%)' % (name,s[0],s[1],100.0*s[1]/(T0[1]-T0[0]),s[2],100.0*s[2]/(T1[1]-T1[0])))
