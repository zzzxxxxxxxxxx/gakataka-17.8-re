import struct, json
from unicorn import *
from unicorn.x86_const import *
packed=open('analysis/tmp/Smonitor-packed.exe','rb').read()
BASE=0x400000; TEB=0x30000000; STACK=0x20000000; STACKSZ=0x100000; SCRATCH=0x22000000
uc=Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(BASE,0x200000); uc.mem_map(STACK,STACKSZ); uc.mem_map(TEB,0x10000); uc.mem_map(SCRATCH,0x100000); uc.mem_map(0,0x10000)
uc.mem_write(BASE, packed[0:0x400]); uc.mem_write(0x460000, packed[0x400:0x600])
uc.mem_write(0x468000, packed[0x600:0x1200]); uc.mem_write(0x47c000, packed[0x1200:0x1200+0x4ae00])
uc.mem_write(0x4c7000, packed[0x4c000:0x4c200])
def w32(a,v): uc.mem_write(a, struct.pack('<I', v & 0xffffffff))
w32(TEB,0xFFFFFFFF); w32(TEB+4,STACK+STACKSZ); w32(TEB+8,STACK); w32(TEB+18,TEB); w32(TEB+0x30,TEB+0x1000); w32(TEB+0x1008,BASE)
sp=STACK+STACKSZ-0x1000; w32(sp,0)
uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp); uc.reg_write(UC_X86_REG_FS_BASE,TEB)
for r in (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI): uc.reg_write(r,0)
started=[False]; trace=[]; writes=[]
def hook(uc,addr,size,user):
    if started[0] and len(trace)<600:
        regs={r:uc.reg_read(r) for r in (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_ESP,UC_X86_REG_EBP)}
        trace.append([addr, regs])
uc.hook_add(UC_HOOK_CODE, hook)
def memw(uc,access,addr,size,value,user):
    if 0x401000<=addr<0x402000:
        writes.append((addr,value&0xff,uc.reg_read(UC_X86_REG_EIP)))
        if not started[0]: started[0]=True
uc.hook_add(UC_HOOK_MEM_WRITE, memw)
try: uc.emu_start(0x4AE041, 0xFFFFFFF0, count=8000000)
except UcError as e: print('err', str(e)[:80])
print('trace len', len(trace), 'writes', len(writes))
json.dump({'trace':[[hex(a), {str(k):hex(v) for k,v in r.items()}] for a,r in trace], 'writes':[(hex(a),v,hex(e)) for a,v,e in writes]}, open('analysis/tmp/packer_iter_trace.json','w'))
# 打印前 80 条 trace
for a,r in trace[:80]:
    print('%#08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x esp=%08x' % (a, r[UC_X86_REG_EAX], r[UC_X86_REG_EBX], r[UC_X86_REG_ECX], r[UC_X86_REG_EDX], r[UC_X86_REG_ESI], r[UC_X86_REG_EDI], r[UC_X86_REG_ESP]))
print('writes head', [(hex(a),v,hex(e)) for a,v,e in writes[:10]])
