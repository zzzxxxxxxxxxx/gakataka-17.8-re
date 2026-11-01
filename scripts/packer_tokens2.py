import struct, json
from unicorn import *
from unicorn.x86_const import *
packed=open('analysis/tmp/Smonitor-packed.exe','rb').read()
payload=packed[0x1200:0x1200+0x4ae00]
BASE=0x400000; TEB=0x30000000; STACK=0x20000000; STACKSZ=0x100000; SCRATCH=0x22000000
uc=Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(BASE,0x200000); uc.mem_map(STACK,STACKSZ); uc.mem_map(TEB,0x10000); uc.mem_map(SCRATCH,0x100000); uc.mem_map(0,0x10000)
uc.mem_write(BASE, packed[0:0x400]); uc.mem_write(0x460000, packed[0x400:0x600])
uc.mem_write(0x468000, packed[0x600:0x1200]); uc.mem_write(0x47c000, payload)
uc.mem_write(0x4c7000, packed[0x4c000:0x4c200])
def w32(a,v): uc.mem_write(a, struct.pack('<I', v & 0xffffffff))
w32(TEB,0xFFFFFFFF); w32(TEB+4,STACK+STACKSZ); w32(TEB+8,STACK); w32(TEB+18,TEB); w32(TEB+0x30,TEB+0x1000); w32(TEB+0x1008,BASE)
sp=STACK+STACKSZ-0x1000; w32(sp,0)
uc.reg_write(UC_X86_REG_ESP,sp); uc.reg_write(UC_X86_REG_EBP,sp); uc.reg_write(UC_X86_REG_FS_BASE,TEB)
for r in (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI): uc.reg_write(r,0)
tokens=[]; last_tok=None
def hook(uc,addr,size,user):
    if len(tokens)>4000: return
    if addr==0x4b0436:
        tokens.append({'esi':uc.reg_read(UC_X86_REG_ESI),'ops':[]})
    elif addr==0x4b0424 or addr==0x4aeaf4:
        if tokens: tokens[-1]['ops'].append(('lit', uc.reg_read(UC_X86_REG_EDI), uc.reg_read(UC_X86_REG_EAX)&0xff))
    elif addr==0x4c31d2:
        if tokens: tokens[-1]['ops'].append(('match', uc.reg_read(UC_X86_REG_EDI), uc.reg_read(UC_X86_REG_ESI), uc.reg_read(UC_X86_REG_ECX)))
uc.hook_add(UC_HOOK_CODE, hook)
try: uc.emu_start(0x4AE041, 0xFFFFFFF0, count=4000000)
except UcError as e: print('err', str(e)[:60])
print('tokens', len(tokens))
rows=[]
for i,t in enumerate(tokens[:80]):
    nxt=tokens[i+1]['esi'] if i+1<len(tokens) else None
    consumed=(nxt-t['esi']) if nxt is not None else None
    raw=payload[t['esi']-0x47c000:t['esi']-0x47c000+max(0,consumed or 0)]
    ops=sum(1 for o in t['ops'])
    rows.append((hex(t['esi']),consumed,raw.hex() if raw else '', len(t['ops']), t['ops'][:2]))
for r in rows: print(r)
json.dump({'tokens':[{'esi':t['esi'],'ops':t['ops']} for t in tokens[:4000]]}, open('analysis/tmp/packer_tokens.json','w'))