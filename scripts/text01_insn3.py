import struct, json, os, base64
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read()
BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
CODE=(0x401000,0x46e000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
def in_code(a): return CODE[0]<=a<CODE[1]
md=Cs(CS_ARCH_X86, CS_MODE_32)
entries=set()
# 只扫 CODE 段内的 call/jmp 直接目标
for i in range(CODE[0]-BASE, CODE[1]-BASE-5):
    if IMG[i] in (0xE8,0xE9):
        rel=struct.unpack('<i', IMG[i+1:i+5])[0]
        tgt=BASE+i+5+rel
        if in_txt(tgt): entries.add(tgt)
for a in [0x47a71c,0x4795cc,0x479800,0x4731c9,0x47a85b,0x47404e,0x47b4d1,0x47ac56,0x478f52,0x475cea]:
    entries.add(a)
print('entries', len(entries))
decoded={}; blocks=[]
queue=list(sorted(entries)); seen=set(); unresolved=[]
while queue:
    start=queue.pop(0)
    if start in seen: continue
    seen.add(start)
    a=start; addrs=[]
    while True:
        if in_txt(a) and a in decoded: break
        if not in_txt(a): break
        b=IMG[a-BASE:a-BASE+16]
        if len(b)<5: break
        try: ins=next(md.disasm(b,a))
        except StopIteration: break
        decoded[a]=(ins.size,ins.mnemonic,ins.op_str)
        addrs.append(a); a+=ins.size
        if ins.mnemonic in ('ret','retf','iret'):
            break
        if ins.mnemonic=='jmp':
            op=ins.op_str
            if op.startswith('0x'):
                t=int(op,16)
                if in_txt(t) and t not in decoded: queue.append(t)
            break
        if ins.mnemonic.startswith('j') and ins.mnemonic!='jmp':
            op=ins.op_str
            if op.startswith('0x'):
                t=int(op,16)
                if in_txt(t) and t not in decoded: queue.append(t)
            # 条件跳转后继续 fallthrough
        if ins.mnemonic=='call':
            op=ins.op_str
            if op.startswith('0x'):
                t=int(op,16)
                if in_txt(t) and t not in decoded: queue.append(t)
            else: unresolved.append((ins.address,op))
    if addrs: blocks.append((start,addrs))
print('decoded', len(decoded), 'blocks', len(blocks), 'indirect-unresolved', len(unresolved))
# 校验：轨迹中的控制转移 src 是否都被解码
tr_files=[f for f in os.listdir('analysis/tmp') if f.startswith('live2_trace_') or f.startswith('api') and f.endswith('.json')]
hit=0; tot=0; miss=[]
for f in sorted(tr_files):
    p='analysis/tmp/'+f
    try: d=json.load(open(p))
    except Exception: continue
    def walk(o):
        global hit,tot
        if isinstance(o,dict):
            for k,v in o.items():
                if k in ('jumps','ext') and isinstance(v,list):
                    for item in v:
                        if isinstance(item,list) and item and isinstance(item[0],int):
                            a=item[0]
                            if in_txt(a):
                                tot+=1
                                if a in decoded: hit+=1
                                else: miss.append((f,hex(a)))
                else: walk(v)
        elif isinstance(o,list):
            for v in o: walk(v)
    walk(d)
print('trace text-src coverage: %d/%d = %.2f%%' % (hit,tot,100.0*hit/tot if tot else 0))
print('sample miss', miss[:10])
# 输出完整指令清单
lines=['# Smonitor .text0/.text1 指令级清单','','image base 0x%x; text0 0x%x-0x%x; text1 0x%x-0x%x'%(BASE,T0[0],T0[1],T1[0],T1[1]),'decoded %d insns, %d blocks'%(len(decoded),len(blocks)),'']
for s,addrs in blocks:
    lines.append('; block 0x%x (%d insns)'%(s,len(addrs)))
    for a in addrs:
        sz,m,o=decoded[a]
        lines.append('0x%08x  %-8s %s'%(a,m,o))
    lines.append('')
open('analysis/SMONITOR-TEXT01-INSN.txt','w').write('\n'.join(lines))
print('wrote analysis/SMONITOR-TEXT01-INSN.txt', len(lines), 'lines')