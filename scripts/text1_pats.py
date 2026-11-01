IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
def region(a,b): return IMG[a-BASE:b-BASE]
t0=region(0x46e000,0x47c000); t1=region(0x47c000,0x4c7000)
# 与 text1 相同的拷贝区
dup=IMG[0x14f000:0x14f000+0x4b000]
def pats(d):
    return {
      'push ebp;mov ebp,esp': d.count(b'\x55\x8b\xec'),
      'push ebx;push esi': d.count(b'\x53\x56'),
      'ret': d.count(b'\xc3'),
      'call rel32': sum(1 for i in range(len(d)-5) if d[i]==0xE8),
      'jmp rel32': sum(1 for i in range(len(d)-5) if d[i]==0xE9),
      'mov eax,[ebp+': d.count(b'\x8b\x45'),
      'nop': d.count(b'\x90'),
      'int3': d.count(b'\xcc'),
      'mov [esp+4],eax': d.count(b'\x89\x44\x24\x04'),
    }
print('text0', pats(t0))
print('text1', pats(t1))
print('dup  ', pats(dup))
# 随机数据基线（用 text1 的熵近似随机对比：从文件超大随机区任意取）
import os
rnd=os.urandom(len(t1))
print('random', pats(rnd))
