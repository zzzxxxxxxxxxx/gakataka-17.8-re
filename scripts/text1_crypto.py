import math
from collections import Counter
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
d=IMG[0x47c000-BASE:0x4c7000-BASE]
# 1) 两份拷贝的差异位置
b=0x14f000
diffs=[i for i in range(len(d)) if d[i]!=IMG[b+i]]
print('copy size', len(d), 'diff bytes', len(diffs), 'first diffs', diffs[:10], [hex(0x47c000+i) for i in diffs[:10]])
# 2) 周期密钥检测：按 L 分组后的平均熵
def ent(b):
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
print('overall entropy %.3f' % ent(d))
results=[]
for L in range(2,65):
    es=[]
    for r in range(L):
        seg=d[r::L]
        if len(seg)>50: es.append(ent(seg))
    results.append((sum(es)/len(es), L))
results.sort()
print('lowest avg-per-residue entropy L:', [(round(e,3),L) for e,L in results[:8]])
print('highest:', [(round(e,3),L) for e,L in results[-4:]])
# 3) 自相关（相等字节比例）
for shift in (1,2,4,8,16,32):
    same=sum(1 for i in range(len(d)-shift) if d[i]==d[i+shift])
    print('shift',shift,'equal frac %.4f' % (same/(len(d)-shift)))
# 4) 已知明文串位置之间的距离（可能是数据结构分隔）
import re
runs=[(m.start(),m.group(0)) for m in re.finditer(rb'[\x20-\x7e]{8,}', d)]
print('runs', len(runs))
for off,s in runs[:6]:
    print(hex(0x47c000+off), s[:50])
