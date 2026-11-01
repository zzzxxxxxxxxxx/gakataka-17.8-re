import json
samples=json.load(open('analysis/tmp/packer_loop_samples.json'))
stage=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
def rol2(x): return ((x<<2)&0xff)|(x>>6)
def f(x): return rol2(((x^0x0C)-1)&0xff)
ok=0; ok_minus=0; tot=0; errs=[]
for s in samples:
    if s.get('raw') is None or s.get('dl') is None: continue
    dest=s.get('edi2') or s.get('edi')
    if not (0x401000<=dest<0x4c7000): continue
    img=stage[dest-BASE]
    tot+=1
    if f(s['raw'])==img: ok+=1
    elif (f(s['raw'])-1)&0xff==img: ok_minus+=1
    else:
        if len(errs)<8: errs.append((hex(s['esi']),hex(dest),s['raw'],s['dl'],f(s['raw']),img))
print('total', tot, 'f match', ok, 'minus1 match', ok_minus)
for e in errs: print(e)
