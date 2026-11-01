import frida, json, time, math
from collections import Counter
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
session=dev.attach(2924)
pages=[0,1,3,50,52,53,56,70]
script=session.create_script(r'''
var pages=%s;
var mod=Process.getModuleByName('Smonitor.exe');
var start=mod.base.add(0x7c000);
for (var k=0;k<pages.length;k++) {
  var p=pages[k];
  var u8=new Uint8Array(start.add(p*4096).readByteArray(4096));
  var hex=''; for (var i=0;i<u8.length;i++) hex += ('0'+u8[i].toString(16)).slice(-2);
  send({p:p, hex:hex});
}
send({done:true});
''' % json.dumps(pages))
got={}
def on_msg(m,d):
    if m['type']=='send':
        pl=m['payload']
        if pl.get('done'): got['done']=True
        else: got[pl['p']]=bytes.fromhex(pl['hex'])
    else: print('err', json.dumps(m)[:200])
script.on('message', on_msg); script.load(); time.sleep(6); session.detach()
print('got pages', sorted(k for k in got if isinstance(k,int)))
disk=open('analysis/tmp/Smonitor-packed.exe','rb').read()[0x1200:0x1200+0x4ae00]
def ent(b):
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
def pr(b): return sum(1 for x in b if 32<=x<127)/len(b)
for p in pages:
    if p not in got: continue
    m=got[p]; d=disk[p*4096:(p+1)*4096]
    diff=sum(1 for i in range(4096) if m[i]!=d[i])
    print('page %2d diff_bytes=%-5d mem_ent=%.2f disk_ent=%.2f mem_pr=%.2f disk_pr=%.2f head_mem=%s head_disk=%s' % (
        p, diff, ent(m), ent(d), pr(m), pr(d), m[:12].hex(), d[:12].hex()))
json.dump({str(k):v.hex() for k,v in got.items() if isinstance(v,bytes)}, open('analysis/tmp/text1_live_bytes.json','w'))