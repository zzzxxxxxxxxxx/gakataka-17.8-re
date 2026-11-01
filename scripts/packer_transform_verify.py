import json
d=json.load(open('analysis/tmp/packer_iter_trace.json'))
tr=d['trace']
packed=open('analysis/tmp/Smonitor-packed.exe','rb').read()
stage=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
payload=packed[0x1200:0x1200+0x4ae00]
def f(x): return (((x^0x0C)-1)&0xff)
def ror6(x): return ((x>>6)|((x<<2)&0xff))&0xff
def ff(x): return (ror6((((x^0x0C)-1)&0xff))-1)&0xff
# 解析 trace：寄存器键 19=EAX,23=EDI,29=ESI
lits=[]; stores=[]
prev=None
for a,r in tr:
    a=int(a,16)
    eax=int(r.get('19','0x0'),16); edi=int(r.get('23','0x0'),16); esi=int(r.get('29','0x0'),16)
    if a==0x4b0411:  # lodsb
        src_off=esi-0x47c000
        raw=payload[src_off] if 0<=src_off<len(payload) else None
        lits.append((esi,raw))
    if a==0x4b0424:  # stosb
        stores.append(edi)
print('lit reads', len(lits), 'stores', len(stores))
n=min(len(lits),len(stores))
ok=0; bad=[]
for i in range(n):
    esi,raw=lits[i]; edi=stores[i]
    if raw is None: continue
    got=ff(raw)
    exp=stage[edi-BASE] if 0<=edi-BASE<len(stage) else None
    if got==exp: ok+=1
    elif len(bad)<8: bad.append((hex(esi),raw,hex(edi),hex(got) if got is not None else None,hex(exp) if exp is not None else None))
print('f matched %d/%d' % (ok,n))
print('bad', bad)
