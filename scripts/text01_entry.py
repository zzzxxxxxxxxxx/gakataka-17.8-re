import json, struct
from unicorn import *
from unicorn.x86_const import *
src=open('analysis/tmp/smon_uni_api5.py').read(); i=src.index('cfgp=')
ns={}; exec(src[:i], ns)
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
def emulate_at(entry, selfv, tag, limit=200000):
    ns['BUMP'][0]=ns['SCRATCH']; ns['LOG'].clear()
    uc=ns['build']()
    sp=ns['STACK']+ns['STACKSZ']-0x400; uc.mem_write(sp,struct.pack('<I',ns['DEAD']))
    uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp)
    uc.reg_write(UC_X86_REG_EAX,selfv); uc.reg_write(UC_X86_REG_EDX,0); uc.reg_write(UC_X86_REG_ECX,selfv)
    uc.reg_write(UC_X86_REG_EBX,0); uc.reg_write(UC_X86_REG_ESI,0); uc.reg_write(UC_X86_REG_EDI,0)
    uc.reg_write(UC_X86_REG_EIP,entry); uc.reg_write(UC_X86_REG_FS_BASE,0x30000000)
    ex=set(); API=ns['API']
    def hook(uc,addr,size,u):
        if in_txt(addr): ex.add(addr)
        if addr in API:
            name,argc,fn=API[addr]
            esp=uc.reg_read(UC_X86_REG_ESP)
            try: args=list(struct.unpack('<%dI'%(argc+1), uc.mem_read(esp,4*(argc+1))))[1:]
            except UcError: args=[0]*argc
            ret=fn(uc,args)
            retaddr=struct.unpack('<I', uc.mem_read(esp,4))[0]
            uc.reg_write(UC_X86_REG_EAX, ret & 0xffffffff)
            uc.reg_write(UC_X86_REG_ESP, esp+4+4*argc)
            uc.reg_write(UC_X86_REG_EIP, retaddr)
    uc.hook_add(UC_HOOK_CODE,hook)
    err=None
    try: uc.emu_start(entry, ns['DEAD'], count=limit)
    except UcError as e: err=str(e)
    eip=uc.reg_read(UC_X86_REG_EIP)
    print('%-18s err=%-30s eip=%#x text0=%-4d text1=%d' % (tag,str(err),eip,len([a for a in ex if T0[0]<=a<T0[1]]),len([a for a in ex if T1[0]<=a<T1[1]])))
    return ex
res={}
for entry,selfv,tag in [(0x458788,ns['SELF'],'timer_458788'),(0x406415,0,'pe_entry_6415'),(0x46ee55,ns['SELF'],'text0_dispatch_46ee55'),(0x4589c8,ns['SELF'],'dispatch_caller_4589c8')]:
    try: res[tag]=sorted(emulate_at(entry,selfv,tag))
    except Exception as e: print(tag,'FAIL',str(e)[:150]); res[tag]=[]
json.dump(res, open('analysis/tmp/text01_dyn_entry.json','w'))
# 静态引用 text1 的入口
import struct as st
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
CODE=(0x401000,0x46e000); T1=(0x47c000,0x4c7000)
refs=[]
for i in range(CODE[0]-BASE, CODE[1]-BASE-5):
    if IMG[i] in (0xE8,0xE9):
        rel=st.unpack('<i', IMG[i+1:i+5])[0]; t=BASE+i+5+rel
        if T1[0]<=t<T1[1]: refs.append((BASE+i,t))
print('CODE->text1 direct refs', len(refs), [(hex(a),hex(b)) for a,b in refs[:10]])
