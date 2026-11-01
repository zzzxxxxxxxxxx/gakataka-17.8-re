import json
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
v6=json.load(open('analysis/tmp/text01_union_v6.json'))
dec={int(k,16):v for k,v in v6.items()}
md=Cs(CS_ARCH_X86, CS_MODE_32)
def cov(dd):
    b0=set(); b1=set()
    for a,sz in dd.items():
        for k in range(sz):
            (b0 if T0[0]<=a<T0[1] else b1).add(a+k)
    return len(b0),len(b1)
c=cov(dec)
addrs=sorted(dec)
lines=['# Smonitor .text0/.text1 指令清单 v6（引用不动点扩展后）','',
 'image base 0x%x; text0 0x%x-0x%x; text1 0x%x-0x%x; 指令数 %d; text0 %.2f%%; text1 %.2f%%'%(BASE,T0[0],T0[1],T1[0],T1[1],len(addrs),100.0*c[0]/(T0[1]-T0[0]),100.0*c[1]/(T1[1]-T1[0])),'']
for a in addrs:
    b=IMG[a-BASE:a-BASE+16]
    try: ins=next(md.disasm(b,a))
    except StopIteration: continue
    lines.append('0x%08x  %-8s %s'%(a,ins.mnemonic,ins.op_str))
open('analysis/SMONITOR-TEXT01-INSN-FULL.txt','w').write('\n'.join(lines))
print('wrote', len(lines), 'lines; text0 %.2f%% text1 %.2f%%' % (100.0*c[0]/(T0[1]-T0[0]), 100.0*c[1]/(T1[1]-T1[0])))
