import json
from collections import Counter
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
v5=json.load(open('analysis/tmp/text01_union_v5.json'))
dec={int(k,16):v for k,v in v5.items()}
covered=set()
for a,sz in dec.items():
    if 0x46e000<=a<0x47c000:
        for k in range(sz): covered.add(a+k)
gaps=[]; cur=None
for a in range(0x46e000,0x47c000):
    if a not in covered:
        if cur is None: cur=[a,a]
        else: cur[1]=a
    else:
        if cur: gaps.append(tuple(cur)); cur=None
if cur: gaps.append(tuple(cur))
for a,b in sorted(gaps, key=lambda g:-(g[1]-g[0]))[:8]:
    d=IMG[a-BASE:b-BASE+1]
    c=Counter(d).most_common(5)
    print('%#08x-%#08x size=%d top=%s head=%s' % (a,b,len(d),[(hex(k),v) for k,v in c], d[:24].hex()))
