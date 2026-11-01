import json, struct, subprocess, re, time
d=json.load(open('analysis/tmp/rizin_aflj.json'))
T0=(0x46e000,0x47c000)
known=set(f['offset'] for f in d if T0[0]<=f['offset']<T0[1])
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
# 用上一轮的并集：text0 内已解码地址里、非 rizin 函数起点的地址作为候选（取每个 0x100 区间首个）
u=json.load(open('analysis/tmp/text01_union_v2.json'))
cand=[]
for k in u:
    a=int(k,16)
    if T0[0]<=a<T0[1] and a not in known: cand.append(a)
cand=sorted(cand)
print('candidates (decoded, not rizin func)', len(cand))
# 去重：间隔 < 0x80 的只保留首个
picked=[]
for a in cand:
    if not picked or a-picked[-1]>=0x80: picked.append(a)
print('picked candidates', len(picked), [hex(x) for x in picked[:10]])
json.dump([hex(x) for x in picked], open('analysis/tmp/text0_cand_funcs.json','w'))
