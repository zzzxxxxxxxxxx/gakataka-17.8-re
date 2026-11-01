import struct, json
from unicorn import *
from unicorn.x86_const import *
packed=open('analysis/tmp/Smonitor-packed.exe','rb').read()
BASE=0x400000
uc=None
TEB=0x30000000; STACK=0x20000000; STACKSZ=0x100000; SCRATCH=0x22000000
def w32(a,v): uc.mem_write(a, struct.pack('<I', v & 0xffffffff))
def r32(a): return struct.unpack('<I', uc.mem_read(a,4))[0]
def build():
    global uc
    uc=Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(BASE, 0x200000)
    uc.mem_map(STACK, STACKSZ)
    uc.mem_map(TEB, 0x10000)
    uc.mem_map(SCRATCH, 0x100000)
    uc.mem_map(0, 0x10000)
    uc.mem_write(BASE, packed[0:0x400])
    uc.mem_write(0x460000, packed[0x400:0x600])
    uc.mem_write(0x468000, packed[0x600:0x1200])
    uc.mem_write(0x47c000, packed[0x1200:0x1200+0x4ae00])
    uc.mem_write(0x4c7000, packed[0x4c000:0x4c200])
    # TEB
    w32(TEB+0, 0xFFFFFFFF)     # SEH end
    w32(TEB+4, STACK+STACKSZ)
    w32(TEB+8, STACK)
    w32(TEB+0x18, TEB)
    w32(TEB+0x30, TEB+0x1000)  # PEB in TEB map
    w32(TEB+0x1000+0x08, BASE) # PEB.ImageBaseAddress
    sp=STACK+STACKSZ-0x1000
    w32(sp, 0)
    uc.reg_write(UC_X86_REG_ESP, sp); uc.reg_write(UC_X86_REG_EBP, sp)
    uc.reg_write(UC_X86_REG_FS_BASE, TEB)
    uc.reg_write(UC_X86_REG_EAX, 0); uc.reg_write(UC_X86_REG_EBX, 0)
    uc.reg_write(UC_X86_REG_ECX, 0); uc.reg_write(UC_X86_REG_EDX, 0)
    uc.reg_write(UC_X86_REG_ESI, 0); uc.reg_write(UC_X86_REG_EDI, 0)
    return uc
def dispatch_seh(fault_eip, fault_type):
    rec=r32(TEB+0)
    tries=0
    while rec not in (0, 0xFFFFFFFF) and tries<16:
        tries+=1
        nxt=r32(rec); handler=r32(rec+4)
        # EXCEPTION_RECORD
        exc=SCRATCH+0x10000+ (tries*0x100)
        code = 0xC0000005 if fault_type=='mem' else 0xC000001D
        w32(exc+0, code); w32(exc+4,0); w32(exc+8,0); w32(exc+12,fault_eip)
        w32(exc+16,2); w32(exc+20,1); w32(exc+24,fault_eip)
        # CONTEXT
        ctx=SCRATCH+0x20000+(tries*0x300)
        for i in range(0,0x2cc,4): w32(ctx+i,0)
        w32(ctx+0xb8, fault_eip)       # Eip
        w32(ctx+0xc0, uc.reg_read(UC_X86_REG_EFLAGS))
        w32(ctx+0xc4, uc.reg_read(UC_X86_REG_ESP))
        w32(ctx+0xb4, uc.reg_read(UC_X86_REG_EBP))
        w32(ctx+0x9c, uc.reg_read(UC_X86_REG_EDI))
        w32(ctx+0xa0, uc.reg_read(UC_X86_REG_ESI))
        w32(ctx+0xa4, uc.reg_read(UC_X86_REG_EBX))
        w32(ctx+0xa8, uc.reg_read(UC_X86_REG_EDX))
        w32(ctx+0xac, uc.reg_read(UC_X86_REG_ECX))
        w32(ctx+0xb0, uc.reg_read(UC_X86_REG_EAX))
        # 调用 handler：ret to sentinel
        sentinel=0x220F0000
        fx=SCRATCH+0x30000+(tries*0x100)
        frame=fx
        w32(frame, sentinel)       # ret addr
        w32(frame+4, exc)          # pExceptionRecord
        w32(frame+8, rec)          # EstablisherFrame
        w32(frame+12, ctx)         # pContextRecord
        w32(frame+16, 0)           # pDispatcherContext
        uc.reg_write(UC_X86_REG_ESP, frame)
        uc.reg_write(UC_X86_REG_EIP, handler)
        try:
            uc.emu_start(handler, sentinel, count=200000)
        except UcError as e:
            print('  handler fault', str(e)[:80]); return None
        eax=uc.reg_read(UC_X86_REG_EAX)
        if eax==0:
            new_eip=rt=struct.unpack('<I', uc.mem_read(ctx+0xb8,4))[0]
            print('  SEH continue at', hex(new_eip), 'handler', hex(handler), 'code', hex(code))
            return new_eip
        elif eax==1:
            print('  SEH search next, handler', hex(handler))
            rec=nxt; continue
        else:
            print('  SEH disposition', hex(eax)); return None
    print('  SEH unhandled')
    return None
uc=build()
writes=[]; execs={}; fault_log=[]
def hook_code(uc,addr,size,user):
    execs[addr]=execs.get(addr,0)+1
def hook_memw(uc,access,addr,size,value,user):
    if 0x401000<=addr<0x4c8000 and len(writes)<300000:
        writes.append((addr,size,value&0xffffffff if value is not None else None))
def hook_mem_invalid(uc,access,addr,size,value,user):
    fault_log.append((access, addr))
    return False
uc.hook_add(UC_HOOK_CODE, hook_code)
uc.hook_add(UC_HOOK_MEM_WRITE, hook_memw)
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)
eip=0x4AE041
steps=0; seh_count=0
while steps<200:
    steps+=1
    try:
        uc.emu_start(eip, 0xFFFFFFF0, count=1000000)
        cur_eip=uc.reg_read(UC_X86_REG_EIP)
        print('chunk end eip', hex(cur_eip), 'writes', len(writes))
        if cur_eip in (0, 0xFFFFFFF0): break
        eip=cur_eip
    except UcError as e:
        fe=uc.reg_read(UC_X86_REG_EIP)
        print('fault at', hex(fe), str(e)[:80])
        new=dispatch_seh(fe, 'mem')
        if new is None: break
        eip=new; seh_count+=1
print('steps', steps, 'exec addrs', len(execs), 'writes', len(writes), 'seh', seh_count)
import collections
c=collections.Counter()
for a,s,v in writes:
    if 0x46e000<=a<0x47c000: c['text0']+=1
    elif 0x401000<=a<0x459000: c['CODE']+=1
    elif 0x459000<=a<0x46e000: c['data']+=1
    elif 0x47c000<=a<0x4c7000: c['text1']+=1
print('write targets', dict(c))
# dump 内存到文件并对比
open('analysis/tmp/packer_seh_dump.bin','wb').write(uc.mem_read(BASE, 0x200000))
print('dump written')
hot=sorted(execs.items(), key=lambda kv:-kv[1])[:40]
print('hot exec:', [(hex(a),c) for a,c in hot[:20]])
json.dump({'writes':[(hex(a),s,hex(v) if v is not None else None) for a,s,v in writes], 'exec':len(execs), 'hot':[(hex(a),c) for a,c in hot]}, open('analysis/tmp/packer_seh_run.json','w'))