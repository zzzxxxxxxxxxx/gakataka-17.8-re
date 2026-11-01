import frida, json, time
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
session=dev.attach(2924)
script=session.create_script(r'''
var out={base:null,pages:[],err:null};
try {
  var mod=Process.getModuleByName('Smonitor.exe');
  out.base=mod.base.toString();
  var start=mod.base.add(0x7c000);
  for (var p=0;p<75;p++) {
    try {
      var u8=new Uint8Array(start.add(p*4096).readByteArray(4096));
      var s=0,nz=0;
      for (var i=0;i<u8.length;i++){ s=(s+u8[i])&0xffffffff; if(u8[i]!==0) nz++; }
      out.pages.push([s>>>0,nz]);
    } catch(e) { out.pages.push(['ERR', String(e)]); }
  }
} catch(e){ out.err=String(e); }
send(out);
''')
res={}
def on_msg(m,d):
    if m['type']=='send': res.update(m['payload'])
    else: print('err', json.dumps(m)[:200])
script.on('message', on_msg); script.load(); time.sleep(3); session.detach()
print('base', res.get('base'), 'pages', len(res.get('pages',[])))
disk=open('analysis/tmp/Smonitor-packed.exe','rb').read()[0x1200:0x1200+0x4ae00]
def psum(b): return [sum(b)&0xffffffff, sum(1 for x in b if x!=0)]
diff=[]; errs=0
for p in range(75):
    bd=disk[p*4096:(p+1)*4096]
    if not bd: break
    pg=res['pages'][p]
    if isinstance(pg[0],str): errs+=1; continue
    if pg != psum(bd): diff.append(p)
print('errs', errs, 'diff pages', len(diff), diff[:20])
json.dump({'base':res.get('base'),'diff_pages':diff,'pages':res.get('pages')}, open('analysis/tmp/text1_live_pages.json','w'))
