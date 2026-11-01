import json, re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000)
v5=json.load(open('analysis/tmp/text01_union_v5.json'))
dec={int(k,16):v for k,v in v5.items()}
covered=set()
for a,sz in dec.items():
    if T0[0]<=a<T0[1]:
        for k in range(sz): covered.add(a+k)
gaps=set()
for a in range(T0[0],T0[1]):
    if a not in covered: gaps.add(a)
md=Cs(CS_ARCH_X86, CS_MODE_32)
refs=0; imm=0; samples=[]
for a,sz in dec.items():
    if not (T0[0]<=a<T0[1]): continue
    b=IMG[a-BASE:a-BASE+16]
    try: ins=next(md.disasm(b,a))
    except StopIteration: continue
    if ins.mnemonic in ('call','jmp') and ins.op_str.startswith('0x'):
        try: t=int(ins.op_str,16)
        except: t=None
        if t in gaps: refs+=1; samples.append((hex(a),hex(t)))
    for m in re.finditer(r'0x([0-9a-f]{5,8})', ins.op_str):
        v=int(m.group(1),16)
        if v in gaps: imm+=1; samples.append((hex(a),hex(v)))
print('direct call/jmp -> gap:', refs)
print('immediates -> gap:', imm)
print('samples', samples[:10])
