import json, struct
from unicorn import *
from unicorn.x86_const import *
src=open('analysis/tmp/smon_uni_api5.py').read(); i=src.index('cfgp=')
ns={}; exec(src[:i], ns)
T1=(0x47c000,0x4c7000); T0=(0x46e000,0x47c000)
def emulate_at(entry, selfv, tag, limit=50000):
    ns['BUMP'][0]=ns['SCRATCH']; ns['LOG'].clear()
    uc=ns['build']()
    sp=ns['STACK']+ns['STACKSZ']-0x400; uc.mem_write(sp,struct.pack('<I',ns['DEAD']))
    uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp)
    uc.reg_write(UC_X86_REG_EAX,selfv); uc.reg_write(UC_X86_REG_EDX,0); uc.reg_write(UC_X86_REG_ECX,selfv)
    uc.reg_write(UC_X86_REG_EBX,0); uc.reg_write(UC_X86_REG_ESI,0); uc.reg_write(UC_X86_REG_EDI,0)
    uc.reg_write(UC_X86_REG_EIP,entry); uc.reg_write(UC_X86_REG_FS_BASE,0x30000000)
    ex=set(); API=ns['API']
    def hook(uc,addr,size,u):
        if T1[0]<=addr<T1[1] or T0[0]<=addr<T0[1]: ex.add(addr)
        if addr in API:
            name,argc,fn=API[addr]
            esp=uc.reg_read(UC_X86_REG_ESP)
            try: args=list(struct.unpack('<%dI'%(argc+1), uc.mem_read(esp,4*(argc+1))))[1:]
            except UcError: args=[0]*argc
            ret=fn(uc,args)
            retaddr=struct.unpack('<I', uc.mem_read(esp,4))[0]
            uc.reg_write(UC_X86_REG_EAX, ret & 0xffffffff); uc.reg_write(UC_X86_REG_ESP, esp+4+4*argc); uc.reg_write(UC_X86_REG_EIP, retaddr)
    uc.hook_add(UC_HOOK_CODE,hook)
    err=None
    try: uc.emu_start(entry, ns['DEAD'], count=limit)
    except UcError as e: err=str(e)
    eip=uc.reg_read(UC_X86_REG_EIP)
    t1=sorted(a for a in ex if T1[0]<=a<T1[1]); t0=len([a for a in ex if T0[0]<=a<T0[1]])
    print('%-22s err=%-30s eip=%#x text0=%-4d text1=%-3d' % (tag,str(err),eip,t0,len(t1)))
    return ex
# 扫描整个镜像 text0 CODE 区域对 text1 的引用
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
refs=set()
for i in range(0x401000-BASE, 0x47c000-BASE-5):
    if IMG[i] in (0xE8,0xE9):
        rel=struct.unpack('<i', IMG[i+1:i+5])[0]; t=BASE+i+5+rel
        if T1[0]<=t<T1[1]: refs.add(t)
print('refs into text1:', [hex(x) for x in sorted(refs)])
allset=set()
for a in sorted(refs):
    try: allset |= emulate_at(a, ns['SELF'], 'entry_%x'%a)
    except Exception as e: print(hex(a),'FAIL',str(e)[:120])
json.dump(sorted(allset), open('analysis/tmp/text01_dyn_t1entry.json','w'))
print('union text1', len([x for x in allset if T1[0]<=x<T1[1]]), 'text0', len([x for x in allset if T0[0]<=x<T0[1]]))
