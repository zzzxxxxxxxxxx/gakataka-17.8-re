import json, subprocess, re, time
cands=[int(x,16) for x in json.load(open('analysis/tmp/text0_cand_funcs.json'))]
CH=60; out=[]; t0=time.time(); status={}
for i in range(0,len(cands),CH):
    chunk=cands[i:i+CH]
    cmds=['e scr.color=0']
    for a in chunk:
        cmds.append('echo ==== 0x%x'%a)
        cmds.append('s 0x%x'%a); cmds.append('af'); cmds.append('pdg')
    cmds.append('q')
    args=['rizin','-q']
    for c in cmds: args+=['-c',c]
    args.append('analysis/unpacked-auto/Smonitor-stage2.exe')
    r=subprocess.run(args, capture_output=True, text=True, timeout=300)
    parts=re.split(r'^==== (0x[0-9a-f]+)\s*$', r.stdout, flags=re.M)
    for k in range(1,len(parts),2):
        a=int(parts[k],16); body=parts[k+1]
        m=re.search(r'fcn\.00([0-9a-f]{6})\(', body)
        if m:
            got=int('0x'+m.group(1),16)
            status[a]={'status':'ok' if got==a else 'contained','got':hex(got),'chars':len(body)}
            out.append(body)
        else:
            status[a]={'status':'fail'}
    print('chunk %d elapsed %.1fs' % (i//CH+1, time.time()-t0))
open('analysis/SMONITOR-TEXT0-CAND-FUNCS.txt','w').write('\n'.join(out))
from collections import Counter
c=Counter(v['status'] for v in status.values())
print('status', dict(c))
extra=[a for a,v in status.items() if v['status']=='ok']
print('new function starts decompiled:', len(extra), [hex(x) for x in extra[:10]])
json.dump({hex(k):v for k,v in status.items()}, open('analysis/tmp/text0_cand_status.json','w'))
print('output size', len('\n'.join(out)))
