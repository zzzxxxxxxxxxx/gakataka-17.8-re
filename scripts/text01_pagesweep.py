import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T0=(0x46e000,0x47c000)
md=Cs(CS_ARCH_X86, CS_MODE_32)
# 复用 gaps 结果文件不存在，重算：直接对每个 4KB 页做线性扫描覆盖率
def sweep(a,n):
    data=IMG[a-BASE:a-BASE+n]; cov=0; ok=0; i=0
    while i < len(data):
        b=data[i:i+16]
        if len(b)<5: break
        try: ins=next(md.disasm(b, a+i))
        except StopIteration:
            i+=1; continue
        # 简单启发：合法且不是明显数据触发的怪指令
        if ins.mnemonic in ('add','or','adc','sbb','and','sub','xor','cmp','push','pop','mov','lea','test','inc','dec','call','jmp','nop','ret'):
            cov+=ins.size; ok+=1; i+=ins.size
        else:
            i+=1
    return cov, n
for start in range(T0[0],T0[1],4096):
    n=min(4096,T0[1]-start)
    cov=0; i=0
    data=IMG[start-BASE:start-BASE+n]
    while i<len(data):
        b=data[i:i+16]
        try: ins=next(md.disasm(b,start+i))
        except StopIteration:
            i+=1; continue
        cov+=ins.size; i+=ins.size
    print('%#x-%#x n=%d linear_cov=%d (%.1f%%)' % (start,start+n,n,cov,100.0*cov/n))
