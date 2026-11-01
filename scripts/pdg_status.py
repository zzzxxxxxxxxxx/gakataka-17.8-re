import json, subprocess, re, time
d=json.load(open('analysis/tmp/rizin_aflj.json'))
T0=(0x46e000,0x47c000)
funcs=sorted(f['offset'] for f in d if T0[0]<=f['offset']<T0[1])
CH=100
res={}
t0=time.time()
for i in range(0,len(funcs),CH):
    chunk=funcs[i:i+CH]
    cmds=['e scr.color=0']
    for a in chunk:
        cmds.append('echo ==== 0x%x'%a)
        cmds.append('s 0x%x'%a); cmds.append('af'); cmds.append('pdg')
    cmds.append('q')
    args=['rizin','-q']
    for c in cmds: args+=['-c',c]
    args.append('analysis/unpacked-auto/Smonitor-stage2.exe')
    r=subprocess.run(args, capture_output=True, text=True, timeout=180)
    out=r.stdout
    parts=re.split(r'^==== (0x[0-9a-f]+)\s*$', out, flags=re.M)
    for k in range(1,len(parts),2):
        a=int(parts[k],16); body=parts[k+1]
        m=re.search(r'fcn\.00([0-9a-f]{6})\(', body)
        if m:
            got=int('0x'+m.group(1),16)
            res[a]={'status':'ok' if got==a else 'other','got':hex(got),'chars':len(body)}
        else:
            res[a]={'status':'fail','chars':len(body),'body_head':body.strip()[:120]}
    print('chunk %d/%d elapsed %.1fs' % (i//CH+1,(len(funcs)+CH-1)//CH,time.time()-t0))
from collections import Counter
c=Counter(v['status'] for v in res.values())
print('status', dict(c))
fails=sorted(k for k,v in res.items() if v['status']=='fail')
others=sorted(k for k,v in res.items() if v['status']=='other')
print('fails', len(fails), [hex(x) for x in fails[:20]])
print('others', len(others), [hex(x) for x in others[:10]])
json.dump({hex(k):v for k,v in res.items()}, open('analysis/tmp/pdg_status.json','w'))
