import math, zlib, re, struct
from collections import Counter
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T1=(0x47c000,0x4c7000)
d=IMG[T1[0]-BASE:T1[1]-BASE]
print('size', len(d), 'first64', d[:64].hex())
print('entropy', -sum((v/len(d))*math.log2(v/len(d)) for v in Counter(d).values()))
# 魔数
magics={'zlib78':b'\\x78','gzip':b'\\x1f\\x8b','bz2':b'BZh','xz':b'\\xfd7zXZ\\x00','zstd':b'\\x28\\xb5\\x2f\\xfd','mz':b'MZ','7z':b'7z\\xbc\\xaf\\x27\\x1c'}
for k,m in magics.items():
    print('magic', k, d.find(m))
# zlib 尝试解压
ok=0; samples=[]
for i in range(len(d)-2):
    if d[i]==0x78 and d[i+1] in (0x01,0x5e,0x9c,0xda):
        try:
            out=zlib.decompress(d[i:])
            ok+=1
            if len(samples)<3: samples.append((hex(T1[0]+i), len(out), out[:60]))
        except Exception: pass
print('zlib candidates', ok, samples)
def printable_ratio(b):
    return sum(1 for x in b if 32<=x<127 or x in (9,10,13))/len(b)
words=[b'the',b'and',b'error',b'failed',b'could',b'not',b'file',b'process',b'window',b'not found',b'ordinal']
def score(b):
    return sum(b.count(w) for w in words)
print('plain printable %.3f score %d' % (printable_ratio(d), score(d)))
best=[]
for k in range(256):
    x=bytes(c^k for c in d)
    pr=printable_ratio(x); sc=score(x)
    best.append((pr,sc,k,'xor'))
    a=bytes((c+k)&0xff for c in d)
    best.append((printable_ratio(a),score(a),k,'add'))
    s=bytes((c-k)&0xff for c in d)
    best.append((printable_ratio(s),score(s),k,'sub'))
best.sort(reverse=True)
print('top transforms:')
for pr,sc,k,op in best[:8]:
    print('  %s k=%02x printable=%.3f score=%d' % (op,k,pr,sc))
# base64 特征
alph=set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\\r\\n')
b64=sum(1 for c in d if c in alph)/len(d)
print('base64 alphabet ratio %.3f' % b64)
# UTF-16LE 可打印
le=bytes(d[i] for i in range(0,len(d)-1,2))
print('utf16le high-byte-zero ratio %.3f' % (sum(1 for i in range(1,len(d),2) if d[i]==0)/(len(d)//2)))
# 重复 16 字节块
blocks=Counter(bytes(d[i:i+16]) for i in range(0,len(d)-16,16))
print('16B block duplicates', sum(1 for v in blocks.values() if v>1), 'max', blocks.most_common(1)[0][1] if blocks else 0)
