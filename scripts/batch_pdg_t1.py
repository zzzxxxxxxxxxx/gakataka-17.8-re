import json, subprocess, time, os, re
d=json.load(open('analysis/tmp/rizin_aflj.json'))
T1=(0x47c000,0x4c7000)
funcs=sorted(f['offset'] for f in d if T1[0]<=f['offset']<T1[1])
print('text1 funcs', len(funcs))
outpath='analysis/SMONITOR-TEXT1-DECOMPILED.txt'
CH=50
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
        try: r=subprocess.run(args, capture_output=True, text=True, timeout=180)
        except Exception as e:
            print('chunk',i,'timeout'); fail+=len(chunk); continue
        fout.write(r.stdout)
        got=len(re.findall(r'^[A-Za-z_][\w \*]*fcn\.00[0-9a-f]+\(', r.stdout, flags=re.M))
        ok+=got; fail+=len(chunk)-got
        print('chunk %d ok=%d fail=%d' % (i//CH+1,got,len(chunk)-got))
print('requested',len(funcs),'ok',ok,'fail',fail,'size',os.path.getsize(outpath))
# 简单质量指标：抽取前几个函数的行数
txt=open(outpath).read()
heads=[(m.start(),m.group(0)) for m in re.finditer(r'^[A-Za-z_][\w \*]*fcn\.00[0-9a-f]+\(', txt, flags=re.M)]
print('head count', len(heads))
for k in range(min(5,len(heads))):
    s=heads[k][0]; e=heads[k+1][0] if k+1<len(heads) else len(txt)
    print('func', heads[k][1].strip()[:60], 'chars', e-s)
