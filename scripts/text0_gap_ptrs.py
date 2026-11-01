import json, struct
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
def ptr_density(data):
    n=len(data)//4
    if n==0: return 0,0,0
    text=0; img=0
    for i in range(n):
        v=struct.unpack('<I', data[i*4:i*4+4])[0]
        if T0[0]<=v<T0[1] or T1[0]<=v<T1[1]: text+=1
        if BASE<=v<BASE+len(IMG): img+=1
    return text/n, img/n, n
allgap=b''.join(IMG[a-BASE:b-BASE+1] for a,b in gaps)
t,i,n=ptr_density(allgap)
print('gaps: bytes %d dwords %d text_ptr %.2f%% img_ptr %.2f%%' % (len(allgap), n, 100*t, 100*i))
dat=IMG[T0[0]-BASE:T0[1]-BASE]
t2,i2,n2=ptr_density(dat)
print('whole text0: text_ptr %.2f%% img_ptr %.2f%%' % (100*t2, 100*i2))
# 每个大缺口密度
print('per-gap text_ptr density (size>=32):')
for a,b in gaps:
    if b-a+1<32: continue
    d=IMG[a-BASE:b-BASE+1]
    tt,ii,nn=ptr_density(d)
    print('  %#08x-%#08x size=%4d text_ptr=%5.1f%% img_ptr=%5.1f%%' % (a,b,len(d),100*tt,100*ii))
