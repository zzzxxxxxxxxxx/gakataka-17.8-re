import math
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
payload=IMG[0x47c000-BASE:0x47c000-BASE+0x4ae00]
text0=IMG[0x46e000-BASE:0x46e000-BASE+0x57344]
win=128
def ent(a):
    c=[0]*256
    for x in a: c[x]+=1
    n=len(a); s=0.0
    for v in c:
        if v: p=v/n; s-=p*math.log2(p)
    return s
t0=text0[:win]
best=[]
for op in (0,1,2):
    for off in range(0, len(payload)-win, 64):
        p=payload[off:off+win]
        if op==0: r=bytes(x^y for x,y in zip(p,t0))
        elif op==1: r=bytes((x-y)&0xff for x,y in zip(p,t0))
        else: r=bytes((y-x)&0xff for x,y in zip(p,t0))
        best.append((ent(r), off, op))
best.sort()
print('min:', [(round(e,2),hex(0x47c000+o),['xor','sub','rsub'][op]) for e,o,op in best[:8]])
print('text0 chunk entropy', round(ent(t0),2))
