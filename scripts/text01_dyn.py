import json, struct, os
from unicorn import *
from unicorn.x86_const import *
src=open('analysis/tmp/smon_uni_api5.py').read()
idx=src.index('cfgp=')
ns={}
exec(src[:idx], ns)
build=ns['build']; API=ns['API']; BUF=ns['BUF']; STACK=ns['STACK']; STACKSZ=ns['STACKSZ']; SELF=ns['SELF']; DEAD=ns['DEAD']
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
def emulate(cmdbytes, tag, limit=3000000):
    ns['BUMP'][0]=ns['SCRATCH']; ns['LOG'].clear()
    uc=build(); uc.mem_write(BUF,cmdbytes)
    sp=STACK+STACKSZ-0x400; uc.mem_write(sp,struct.pack('<I',DEAD))
    uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp)
    uc.reg_write(UC_X86_REG_EAX,SELF); uc.reg_write(UC_X86_REG_EDX,BUF); uc.reg_write(UC_X86_REG_ECX,SELF)
    uc.reg_write(UC_X86_REG_EBX,0); uc.reg_write(UC_X86_REG_ESI,0); uc.reg_write(UC_X86_REG_EDI,0)
    uc.reg_write(UC_X86_REG_EIP,0x4589f8); uc.reg_write(UC_X86_REG_FS_BASE,0x30000000)
    executed=set(); api_log=[]
    def hook(uc,addr,size,u):
        if in_txt(addr): executed.add(addr)
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
            api_log.append((addr,name))
    uc.hook_add(UC_HOOK_CODE,hook)
    err=None
    try: uc.emu_start(0x4589f8, DEAD, count=limit)
    except UcError as e: err=str(e)
    print('%-3s err=%-24s executed_text=%d api=%d' % (tag,str(err),len(executed),len(api_log)))
    return executed
cfgp=b'C:\\Users\\zzx\\AppData\\Roaming\\gakataka\\class\\config\\config.cfg\x00'
xpay=json.load(open('analysis/tmp/smon_api_table.json')).get('X_payload')
import datetime
dt=46327.520474537036
xbytes=b'X'+b'\x00\x00\x00'+struct.pack('<d',dt)
tests=[(b'Q'+cfgp,'Q'),(b'S\x00','S0'),(b'S\x01','S1'),(b'T\x01','T1'),(b'Whello\x00','W'),(xbytes,'X'),(b'U\x00','U0'),(b'U\x01','U1'),(b'V\x00','V0'),(b'V\x01','V1')]
allset=set(); per={}
for cmd,tag in tests:
    try:
        s=emulate(cmd,tag)
    except Exception as e:
        print(tag,'FAIL',str(e)[:150]); s=set()
    per[tag]=sorted(s); allset|=s
json.dump({k:v for k,v in per.items()}, open('analysis/tmp/text01_dyn_addrs.json','w'))
print('union executed text addrs', len(allset), 'text0', len([a for a in allset if T0[0]<=a<T0[1]]), 'text1', len([a for a in allset if T1[0]<=a<T1[1]]))
