import math, struct
from collections import Counter
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
def region(a,b): return IMG[a-BASE:b-BASE]
def ent(b):
    if not b: return 0
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
def stats(name,a,b):
    d=region(a,b)
    e=ent(d)
    printable=sum(1 for x in d if 32<=x<127 or x in (9,10,13))
    runs=[]; cur=b''; 
    for x in d:
        if 32<=x<127: cur+=bytes([x])
        else:
            if len(cur)>=5: runs.append(cur)
            cur=b''
    if len(cur)>=5: runs.append(cur)
    ptr=0
    for i in range(0,len(d)-4,4):
        v=struct.unpack('<I', d[i:i+4])[0]
        if BASE<=v<BASE+len(IMG) or 0x900000<=v<0xd00000: ptr+=1
    print('%s: size=%d entropy=%.2f printable=%.1f%% strings>=5=%d sample=%s pointer_dwords=%d (%.1f%%)' % (
        name,len(d),e,100.0*printable/len(d),len(runs),[r[:30].decode() for r in runs[:4]],ptr,100.0*ptr/(len(d)//4)))
stats('text0',*T0)
stats('text1',*T1)
# 4KB 块熵分布
for name,(a,b) in [('text0',T0),('text1',T1)]:
    vals=[ent(region(x,min(x+4096,b))) for x in range(a,b,4096)]
    hi=sum(1 for v in vals if v>7.2); lo=sum(1 for v in vals if v<3.0)
    print(name,'4KB blocks',len(vals),'entropy>7.2:',hi,'<3.0:',lo,'max=%.2f min=%.2f avg=%.2f'%(max(vals),min(vals),sum(vals)/len(vals)))
