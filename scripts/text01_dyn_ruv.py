import json, struct
from unicorn import *
from unicorn.x86_const import *
T0=(0x46e000,0x47c000); T1=(0x47c000,0x4c7000)
def in_txt(a): return T0[0]<=a<T0[1] or T1[0]<=a<T1[1]
def load(path):
    src=open(path).read(); i=src.index('variants=')
    ns={}; exec(src[:i], ns); return ns
def emulate(ns, cmdbytes, tag, limit=3000000):
    ns['BUMP'][0]=ns['SCRATCH']; ns['LOG'].clear()
    uc=ns['build'](); uc.mem_write(ns['BUF'],cmdbytes)
    sp=ns['STACK']+ns['STACKSZ']-0x400; uc.mem_write(sp,struct.pack('<I',ns['DEAD']))
    uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp)
    uc.reg_write(UC_X86_REG_EAX,ns['SELF']); uc.reg_write(UC_X86_REG_EDX,ns['BUF']); uc.reg_write(UC_X86_REG_ECX,ns['SELF'])
    uc.reg_write(UC_X86_REG_EBX,0); uc.reg_write(UC_X86_REG_ESI,0); uc.reg_write(UC_X86_REG_EDI,0)
    uc.reg_write(UC_X86_REG_EIP,0x4589f8); uc.reg_write(UC_X86_REG_FS_BASE,0x30000000)
    ex=set(); api=[]
    API=ns['API']
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
            api.append(name)
    uc.hook_add(UC_HOOK_CODE,hook)
    err=None
    try: uc.emu_start(0x4589f8, ns['DEAD'], count=limit)
    except UcError as e: err=str(e)
    print('%-14s err=%-28s text0=%-4d text1=%-3d api=%d' % (tag,str(err),len([a for a in ex if T0[0]<=a<T0[1]]),len([a for a in ex if T1[0]<=a<T1[1]]),len(api)))
    return ex
uv=load('analysis/tmp/smon_uni_uv2.py')
r=load('analysis/tmp/smon_uni_r3.py')
variants_uv=[('U1',b'U\x01\x00\x00\x00'),('U0',b'U\x00\x00\x00\x00'),('V1',b'V\x01\x00\x00\x00'),('V0',b'V\x00\x00\x00\x00')]
variants_r=[('R_dir',b'R'+b'C:\\Program Files (x86)\\gakataka\\Student\\\x00'),('R_dir_noslash',b'R'+b'C:\\Program Files (x86)\\gakataka\\Student\x00'),('R_empty',b'R\x00'),('R_dot',b'R.\x00')]
res={}
for tag,cmd in variants_uv:
    try: res[tag]=sorted(emulate(uv,cmd,tag))
    except Exception as e: print(tag,'FAIL',str(e)[:150]); res[tag]=[]
for tag,cmd in variants_r:
    try: res[tag]=sorted(emulate(r,cmd,tag))
    except Exception as e: print(tag,'FAIL',str(e)[:150]); res[tag]=[]
json.dump(res, open('analysis/tmp/text01_dyn_addrs_ruv.json','w'))
print('union', len(set(x for v in res.values() for x in v)))
