IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T1=(0x47c000,0x4c7000)
needle=b'The procedure entry point'
print('whole-file occurrences of procedure entry point:', [hex(BASE+i) for i in range(len(IMG)) if IMG.startswith(needle,i)][:10])
needle2=b'The ordinal %u could not be'
print('ordinal occurrences:', [hex(BASE+i) for i in range(len(IMG)) if IMG.startswith(needle2,i)][:10])
# 字符串上下文
i=IMG.find(needle)
if i>=0:
    print('ctx before', IMG[i-16:i].hex(), 'after', IMG[i+len(needle):i+len(needle)+16].hex())
    print('VA', hex(BASE+i), 'in text1' if T1[0]<=BASE+i<T1[1] else 'outside text1')
# 字节频率：0x00 占比
for name,a,b in [('text0',0x46e000,0x47c000),('text1',0x47c000,0x4c7000),('CODE',0x401000,0x459000)]:
    d=IMG[a-BASE:b-BASE]
    z=d.count(0)/len(d)
    print(name,'size',len(d),'zero frac %.4f'%z)
# 统计 text1 中可见字符串总长度占比
import re
runs=re.findall(rb'[\x20-\x7e]{4,}', IMG[T1[0]-BASE:T1[1]-BASE])
print('text1 printable runs>=4:', len(runs), 'total chars', sum(len(r) for r in runs), 'of', T1[1]-T1[0])
