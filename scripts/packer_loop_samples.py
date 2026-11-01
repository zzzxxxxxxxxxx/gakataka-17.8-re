import struct, json
from unicorn import *
from unicorn.x86_const import *
packed=open('analysis/tmp/Smonitor-packed.exe','rb').read()
BASE=0x400000; TEB=0x30000000; STACK=0x20000000; STACKSZ=0x100000; SCRATCH=0x22000000
uc=Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(BASE,0x200000); uc.mem_map(STACK,STACKSZ); uc.mem_map(TEB,0x10000); uc.mem_map(SCRATCH,0x100000); uc.mem_map(0,0x10000)
uc.mem_write(BASE, packed[0:0x400])
uc.mem_write(0x460000, packed[0x400:0x600])
uc.mem_write(0x468000, packed[0x600:0x1200])
uc.mem_write(0x47c000, packed[0x1200:0x1200+0x4ae00])
uc.mem_write(0x4c7000, packed[0x4c000:0x4c200])
def w32(a,v): uc.mem_write(a, struct.pack('<I', v & 0xffffffff))
w32(TEB,0xFFFFFFFF); w32(TEB+4,STACK+STACKSZ); w32(TEB+8,STACK); w32(TEB+0x18,TEB); w32(TEB+0x30,TEB+0x1000); w32(TEB+0x1008,BASE)
sp=STACK+STACKSZ-0x1000; w32(sp,0)
uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp); uc.reg_write(UC_X86_REG_FS_BASE,TEB)
for r in (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI): uc.reg_write(r,0)
samples=[]; writes=[]
def hook(uc,addr,size,user):
    if addr==0x4b0bfa:
        esi=uc.reg_read(UC_X86_REG_ESI); edi=uc.reg_read(UC_X86_REG_EDI)
        if len(samples)<2000:
            try: raw=struct.unpack('<B', uc.mem_read(esi,1))[0]
            except UcError: raw=None
            samples.append({'addr':addr,'esi':esi,'edi':edi,'raw':raw})
        else:
            samples.append({'addr':addr,'esi':esi,'edi':edi,'raw':None})
    elif addr==0x4b0c04 and samples and samples[-1].get('dl') is None:
        samples[-1]['dl']=uc.reg_read(UC_X86_REG_EDX)&0xff
        samples[-1]['edi2']=uc.reg_read(UC_X86_REG_EDI)
uc.hook_add(UC_HOOK_CODE, hook)
def memw(uc,access,addr,size,value,user):
    if 0x401000<=addr<0x401200 and len(writes)<100: writes.append((addr,value&0xff))
uc.hook_add(UC_HOOK_MEM_WRITE, memw)
try:
    uc.emu_start(0x4AE041, 0xFFFFFFF0, count=2000000)
except UcError as e:
    print('err', str(e)[:80])
print('samples', len(samples))
for s in samples[:10]: print({k:(hex(v) if isinstance(v,int) and v and v>0xff else v) for k,v in s.items()})
json.dump(samples, open('analysis/tmp/packer_loop_samples.json','w'))
