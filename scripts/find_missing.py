import json, re
d=json.load(open('analysis/tmp/rizin_aflj.json'))
T0=(0x46e000,0x47c000)
funcs=sorted(f['offset'] for f in d if T0[0]<=f['offset']<T0[1])
txt=open('analysis/SMONITOR-TEXT0-DECOMPILED-FULL.txt').read()
heads=set()
for m in re.finditer(r'fcn\.00([0-9a-f]{6})\(', txt):
    heads.add(int('0x'+m.group(1),16))
missing=[a for a in funcs if a not in heads]
print('funcs', len(funcs), 'decompiled heads', len(heads), 'missing', len(missing))
print('missing addrs', [hex(a) for a in missing])
json.dump([hex(a) for a in missing], open('analysis/tmp/text0_missing.json','w'))
