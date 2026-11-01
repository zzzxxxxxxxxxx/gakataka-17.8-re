import json, math, re
from collections import Counter
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
v5=json.load(open('analysis/tmp/text01_union_v5.json'))
dec={int(k,16):v for k,v in v5.items()}
covered=set()
for a,sz in dec.items():
    if T0[0]<=a<T0[1]:
        for k in range(sz): covered.add(a+k)
gaps=[]; cur=None
for a in range(T0[0],T0[1]):
    if a not in covered:
        if cur is None: cur=[a,a]
        else: cur[1]=a
    else:
        if cur: gaps.append(tuple(cur)); cur=None
if cur: gaps.append(tuple(cur))
total=sum(b-a+1 for a,b in gaps)
print('text0 gaps:', len(gaps), 'bytes', total, '(%.2f%%)' % (100.0*total/(T0[1]-T0[0])))
def ent(b):
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
def pr(b): return sum(1 for x in b if 32<=x<127 or x in (9,10,13))/len(b)
big=[g for g in gaps if g[1]-g[0]>=8]
print('gaps >=8:', len(big))
print('%-14s %5s %6s %5s %6s' % ('range','size','ent','pr','strs'))
for a,b in big[:20]:
    d=IMG[a-BASE:b-BASE+1]
    strs=re.findall(rb'[\x20-\x7e]{5,}', d)
    print('%#08x-%#08x %5d %6.2f %5.2f %6d' % (a,b,len(d),ent(d),pr(d),len(strs)))
# 分类统计
import statistics
ents=[ent(IMG[a-BASE:b-BASE+1]) for a,b in big]
print('gap entropy mean %.2f min %.2f max %.2f' % (statistics.mean(ents), min(ents), max(ents)))
print('gaps with >=1 string>=5:', sum(1 for a,b in big if re.search(rb'[\x20-\x7e]{5,}', IMG[a-BASE:b-BASE+1])))
# TPF0/DFM 特征
print('TPF0 in gaps:', sum(IMG[a-BASE:b-BASE+1].count(b'\xff\x0a\x00') for a,b in big))
