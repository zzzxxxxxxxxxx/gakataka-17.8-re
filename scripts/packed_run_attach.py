import frida, json, time
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
for p in dev.enumerate_processes():
    if 'packed_smon' in p.name.lower():
        try: dev.kill(p.pid)
        except Exception: pass
st=dev.attach(7736)
setup=st.create_script(r'''
function k32(n){ return Process.getModuleByName('kernel32.dll').findExportByName(n); }
var CreateProcessA = new NativeFunction(k32('CreateProcessA'),'int',['pointer','pointer','pointer','pointer','int','uint32','pointer','pointer','pointer','pointer']);
var hProc=null, hThread=null;
rpc.exports = { create: function(path, flags){
  var pi=Memory.alloc(16); var si=Memory.alloc(0x44);
  for (var i=0;i<0x44;i++) si.add(i).writeU8(0);
  si.writeU32(0x44);
  var pathp=Memory.allocUtf8String(path);
  var ok=CreateProcessA(NULL, pathp, NULL, NULL, 0, flags, NULL, NULL, si, pi);
  hProc=pi.readPointer(); hThread=pi.add(4).readPointer();
  return {ok:ok, pid:pi.add(8).readU32()};
}};
''')
setup.load()
r=setup.exports_sync.create('C:\\Users\\zzx\\AppData\\Local\\Temp\\packed_smon.exe', 0)
print('create', r)
pid=r.get('pid')
if pid and r.get('ok'):
    time.sleep(1.0)
    ok=False
    for t in range(5):
        try:
            s=dev.attach(pid); print('attached at', t); ok=True; break
        except Exception as e:
            print('attach', t, str(e)[:100]); time.sleep(0.7)
    if ok:
        sc=s.create_script(r'''
        var out={};
        try { out.mods=Process.enumerateModules().slice(0,12).map(function(m){return [m.name,m.base.toString(),m.size];}); } catch(e){ out.err=String(e); }
        send(out);
        ''')
        sc.on('message', lambda m,d: print('msg', json.dumps(m)[:600]))
        try: sc.load()
        except Exception as e: print('script load err', str(e)[:150])
        time.sleep(1.5)
        s.detach()
st.detach()
