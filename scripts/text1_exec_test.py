import json, struct
from unicorn import *
from unicorn.x86_const import *
src=open('analysis/tmp/smon_uni_api5.py').read(); i=src.index('cfgp=')
ns={}; exec(src[:i], ns)
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
def runs(entry, selfv, limit=20000):
    ns['BUMP'][0]=ns['SCRATCH']; ns['LOG'].clear()
    uc=ns['build']()
    sp=ns['STACK']+ns['STACKSZ']-0x400; uc.mem_write(sp,struct.pack('<I',ns['DEAD']))
    uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp)
    uc.reg_write(UC_X86_REG_EAX,selfv); uc.reg_write(UC_X86_REG_EDX,0); uc.reg_write(UC_X86_REG_ECX,selfv)
    uc.reg_write(UC_X86_REG_EBX,0); uc.reg_write(UC_X86_REG_ESI,0); uc.reg_write(UC_X86_REG_EDI,0)
    uc.reg_write(UC_X86_REG_EIP,entry); uc.reg_write(UC_X86_REG_FS_BASE,0x30000000)
    cnt=[0]; API=ns['API']
    def hook(uc,addr,size,u):
        cnt[0]+=1
        if addr in API:
            name,argc,fn=API[addr]
            esp=uc.reg_read(UC_X86_REG_ESP)
            try: args=list(struct.unpack('<%dI'%(argc+1), uc.mem_read(esp,4*(argc+1))))[1:]
            except UcError: args=[0]*argc
            ret=fn(uc,args)
            retaddr=struct.unpack('<I', uc.mem_read(esp,4))[0]
            uc.reg_write(UC_X86_REG_EAX, ret&0xffffffff); uc.reg_write(UC_X86_REG_ESP, esp+4+4*argc); uc.reg_write(UC_X86_REG_EIP, retaddr)
    uc.hook_add(UC_HOOK_CODE,hook)
    err=None
    try: uc.emu_start(entry, ns['DEAD'], count=limit)
    except UcError as e: err=str(e)
    return cnt[0], err
d=json.load(open('analysis/tmp/rizin_aflj.json'))
t0=sorted(f['offset'] for f in d if T0[0]<=f['offset']<T0[1])[:8]
t1=sorted(f['offset'] for f in d if T1[0]<=f['offset']<T1[1])[:12]
print('== text0 sample')
for a in t0:
    c,e=runs(a, ns['SELF']); print('%#x insns=%d err=%s' % (a,c,e))
print('== text1 sample')
for a in t1:
    c,e=runs(a, ns['SELF']); print('%#x insns=%d err=%s' % (a,c,e))
