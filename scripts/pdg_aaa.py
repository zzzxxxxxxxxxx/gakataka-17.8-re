import json, subprocess, re, time
d=json.load(open('analysis/tmp/rizin_aflj.json'))
T0=(0x46e000,0x47c000)
funcs=sorted(f['offset'] for f in d if T0[0]<=f['offset']<T0[1])
lines=['e scr.color=0','aaa']
for a in funcs:
    lines.append('echo ==== 0x%x'%a)
    lines.append('pdg @ 0x%x'%a)
lines.append('q')
open('analysis/tmp/pdg_aaa.rz','w').write('\n'.join(lines))
t0=time.time()
r=subprocess.run(['rizin','-q','-i','analysis/tmp/pdg_aaa.rz','analysis/unpacked-auto/Smonitor-stage2.exe'], capture_output=True, text=True, timeout=1800)
print('elapsed %.1fs'%(time.time()-t0), 'returncode', r.returncode, 'stdout', len(r.stdout), 'stderr', len(r.stderr))
open('analysis/tmp/pdg_aaa_out.txt','w').write(r.stdout)
parts=re.split(r'^==== (0x[0-9a-f]+)\s*$', r.stdout, flags=re.M)
res={}
for k in range(1,len(parts),2):
    a=int(parts[k],16); body=parts[k+1]
    m=re.search(r'fcn\.00([0-9a-f]{6})\(', body)
    if m:
        got=int('0x'+m.group(1),16)
        res[a]={'status':'ok' if got==a else 'other','got':hex(got),'chars':len(body)}
    else:
        res[a]={'status':'fail','chars':len(body)}
from collections import Counter
c=Counter(v['status'] for v in res.values())
print('status', dict(c))
fails=sorted(k for k,v in res.items() if v['status']=='fail')
print('fails', len(fails), [hex(x) for x in fails[:10]])
print('others', len([1 for v in res.values() if v['status']=='other']))
json.dump({hex(k):v for k,v in res.items()}, open('analysis/tmp/pdg_aaa_status.json','w'))
