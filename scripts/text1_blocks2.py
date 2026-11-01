import re, math
from collections import Counter
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T1=(0x47c000,0x4c7000)
d=IMG[T1[0]-BASE:T1[1]-BASE]
print('TPF0 count', d.count(b'\xff\x0a\x00'))
strs=re.findall(rb'[\x20-\x7e]{8,}', d)
print('strings>=8:', len(strs))
for s in strs[:20]: print('  ', s[:80].decode('latin1'))
strs16=re.findall(rb'(?:[\x20-\x7e]\x00){8,}', d)
print('utf16le strings>=8:', len(strs16))
for s in strs16[:10]:
    print('  u16', s.decode('utf-16le','replace')[:80])
# 可打印块分布
def pr(b): return sum(1 for x in b if 32<=x<127 or x in (9,10,13))/len(b)
rows=[(i,pr(d[i:i+4096])) for i in range(0,len(d),4096)]
hi=[r for r in rows if r[1]>0.8]; lo=[r for r in rows if r[1]<0.1]; mid=[r for r in rows if 0.1<=r[1]<=0.8]
print('blocks', len(rows), '>0.8:', len(hi), 'mid:', len(mid), '<0.1:', len(lo))
print('max printable %.3f min %.3f' % (max(r[1] for r in rows), min(r[1] for r in rows)))
