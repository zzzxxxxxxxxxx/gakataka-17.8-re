import json, subprocess, time, os, re
d=json.load(open('analysis/tmp/rizin_aflj.json'))
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
funcs=[f['offset'] for f in d if T0[0]<=f['offset']<T0[1]]
funcs=sorted(funcs)
print('text0 funcs', len(funcs))
outpath='analysis/SMONITOR-TEXT0-DECOMPILED-FULL.txt'
CH=80
ok=0; fail=0; t0=time.time()
with open(outpath,'w') as fout:
    for i in range(0,len(funcs),CH):
        chunk=funcs[i:i+CH]
        cmds=['e scr.color=0']
        for a in chunk:
            cmds.append('s 0x%x'%a); cmds.append('af'); cmds.append('pdg')
        cmds.append('q')
        args=['rizin','-q']
        for c in cmds: args += ['-c',c]
        args.append('analysis/unpacked-auto/Smonitor-stage2.exe')
        try:
            r=subprocess.run(args, capture_output=True, text=True, timeout=180)
        except Exception as e:
            print('chunk',i,'timeout',e); fail+=len(chunk); continue
        txt=r.stdout
        fout.write(txt)
        got=len(re.findall(r'^[A-Za-z_][\w \*]*fcn\.00[0-9a-f]+\(', txt, flags=re.M))
        ok+=got; fail+=len(chunk)-got
        print('chunk %d/%d ok=%d fail_in_chunk=%d elapsed=%.1fs' % (i//CH+1,(len(funcs)+CH-1)//CH,got,len(chunk)-got,time.time()-t0))
print('total requested', len(funcs), 'decompiled', ok, 'missing', fail)
print('output size', os.path.getsize(outpath))
