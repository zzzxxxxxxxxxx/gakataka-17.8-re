import frida, json, time
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
session=dev.attach(2924)
script=session.create_script(r'''
var mod=Process.getModuleByName('Smonitor.exe');
var start=mod.base.add(0x6e000);  // text0 VA 0x46e000 = base+0x6e000
var pages=[];
for (var p=0;p<14;p++) {
  var u8=new Uint8Array(start.add(p*4096).readByteArray(4096));
  var hex=''; for (var i=0;i<u8.length;i++) hex += ('0'+u8[i].toString(16)).slice(-2);
  pages.push(hex);
}
send({base:mod.base.toString(), pages:pages});
''')
res={}
def on_msg(m,d):
    if m['type']=='send': res.update(m['payload'])
    else: print('err', json.dumps(m)[:200])
script.on('message', on_msg); script.load(); time.sleep(4); session.detach()
print('base', res.get('base'), 'pages', len(res.get('pages',[])))
st=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
diff=[]
out=open('analysis/tmp/text0_live_pages.bin','wb')
for p,hexs in enumerate(res.get('pages',[])):
    mem=bytes.fromhex(hexs)
    stat=st[0x6e000+p*4096:0x6e000+(p+1)*4096]
    d=sum(1 for i in range(4096) if mem[i]!=stat[i])
    diff.append(d)
    out.write(mem)
out.close()
print('diff bytes per page:', diff)
print('pages with diff>64:', [p for p,d in enumerate(diff) if d>64])
