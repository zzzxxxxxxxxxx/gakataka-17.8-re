import frida, json, time
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
path='C:\\Users\\zzx\\AppData\\Local\\Temp\\packed_smon.exe'
pid=dev.spawn([path])
print('spawned pid', pid)
session=dev.attach(pid)
script=session.create_script(r'''
var blocks=[]; var allocs=[]; var excs=[];
var main = Process.enumerateThreads()[0];
var mods = Process.enumerateModules();
var base = mods.length ? mods[0].base : ptr(0x400000);
try {
  Stalker.follow(main.id, {
    events: { block: true },
    onReceive: function(events) {
      var p=Stalker.parse(events, {annotate:false});
      for (var i=0;i<p.length;i++) if (p[i][0]==='block') blocks.push([p[i][1].toString(), p[i][2].toString()]);
    }
  });
} catch(e) { send({stalkerErr:String(e)}); }
try {
  var va = Process.getModuleByName('kernel32.dll').findExportByName('VirtualAlloc');
  var vp = Process.getModuleByName('kernel32.dll').findExportByName('VirtualProtect');
  Interceptor.attach(va, { onEnter: function(a){ allocs.push(['alloc', a[0].toString(), a[1].toString()]); } });
  Interceptor.attach(vp, { onEnter: function(a){ allocs.push(['protect', a[0].toString(), a[1].toString(), a[2].toString()]); } });
} catch(e) { send({apiErr:String(e)}); }
Process.setExceptionHandler(function(details){
  if (excs.length<20) excs.push({type:String(details.type), address: details.address ? details.address.toString() : null});
  return false;
});
rpc.exports = { get: function(){ return {blocks: blocks.slice(0,20000), allocs: allocs.slice(0,500), excs: excs, base: base.toString()}; } };
send({ready:true, base: base.toString(), threads: Process.enumerateThreads().length});
''')
info={}
def on_msg(m,d):
    if m['type']=='send': info.update(m['payload'])
    else: print('msg', json.dumps(m)[:200])
script.on('message', on_msg)
script.load()
dev.resume(pid)
time.sleep(5)
try: res=script.exports_sync.get()
except Exception as e: res={'err':str(e)[:200]}
print('base', res.get('base'), 'blocks', len(res.get('blocks',[])), 'allocs', len(res.get('allocs',[])), 'excs', len(res.get('excs',[])))
if res.get('blocks'): print('block sample', res['blocks'][:10])
if res.get('allocs'): print('alloc sample', res['allocs'][:8])
if res.get('excs'): print('excs', res['excs'][:5])
json.dump(res, open('analysis/tmp/packed_spawn_trace.json','w'))
session.detach()
try: dev.kill(pid)
except Exception: pass
