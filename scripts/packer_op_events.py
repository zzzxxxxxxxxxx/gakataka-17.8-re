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
events=[]; reads=[]
def hook(uc,addr,size,user):
    if len(events)>2000: return
    if addr==0x4b0424:
        events.append(('lit', uc.reg_read(UC_X86_REG_EDI), uc.reg_read(UC_X86_REG_EAX)&0xff))
    elif addr==0x4aeaf4:
        events.append(('lit2', uc.reg_read(UC_X86_REG_EDI), uc.reg_read(UC_X86_REG_EAX)&0xff))
    elif addr==0x4c31d2:
        ecx=uc.reg_read(UC_X86_REG_ECX); esi=uc.reg_read(UC_X86_REG_ESI); edi=uc.reg_read(UC_X86_REG_EDI)
        events.append(('match', edi, esi, ecx))
uc.hook_add(UC_HOOK_CODE, hook)
def memr(uc,access,addr,size,value,user):
    if 0x47c000<=addr<0x4c7000 and len(reads)<3000:
        reads.append((uc.reg_read(UC_X86_REG_EIP), addr, size))
uc.hook_add(UC_HOOK_MEM_READ, memr)
try: uc.emu_start(0x4AE041, 0xFFFFFFF0, count=3000000)
except UcError as e: print('err', str(e)[:60])
print('events', len(events), 'reads', len(reads))
for e in events[:40]: print(e)
print('--- reads sample')
for r in reads[:30]: print('read', hex(r[0]), hex(r[1]), r[2])
json.dump({'events':events, 'reads':[[hex(a),hex(b),c] for a,b,c in reads]}, open('analysis/tmp/packer_op_events.json','w'))
