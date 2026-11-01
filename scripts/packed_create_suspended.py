import frida, json, time
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
smon=dev.attach(2924)
setup=smon.create_script(r'''
function k32(n){ return Process.getModuleByName('kernel32.dll').findExportByName(n); }
var cp = new NativeFunction(k32('CreateProcessA'),'int',['pointer','pointer','pointer','pointer','int','uint32','pointer','pointer','pointer','pointer']);
var rt = new NativeFunction(k32('ResumeThread'),'uint32',['pointer']);
var ct = new NativeFunction(k32('TerminateProcess'),'int',['pointer','uint32']);
var ch = new NativeFunction(k32('CloseHandle'),'int',['pointer']);
var target=null, hThread=null, hProc=null;
rpc.exports = {
  create: function(path){
    var pi=Memory.alloc(16);
    var pathp=Memory.allocUtf8String(path);
    var ok=cp(NULL, pathp, NULL, NULL, 0, 0x4 /*CREATE_SUSPENDED*/, NULL, NULL, pi, pi.add(8));
    var pid=pi.readU32(); var th=pi.add(0x0c).readPointer? null : null;
    hProc = pi.readPointer(); hThread = pi.add(8).readPointer();
    // CreateProcessA 的 pi: hProcess(0), hThread(4), pid(8), tid(0xc)
    hProc = pi.readPointer();
    hThread = pi.add(4).readPointer();
    pid = pi.add(8).readU32();
    return {ok: ok, pid: pid, err: (typeof GetLastError==='function')?0:0};
  },
  resume: function(){ return rt(hThread); },
  kill: function(){ ct(hProc, 1); ch(hProc); ch(hThread); return true; }
};
''')
setup.load()
r=setup.exports_sync.create('C:\\Users\\zzx\\AppData\\Local\\Temp\\packed_smon.exe')
print('create', r)
pid=r.get('pid')
if pid:
    trace=dev.attach(pid)
    ts=trace.create_script(r'''
    var blocks=[]; var allocs=[];
    rpc.exports = { get: function(){ return {blocks: blocks.slice(0,20000), allocs: allocs.slice(0,200)}; } };
    function start(){
      var th=Process.enumerateThreads();
      if (!th.length) return 'nothread';
      try {
        Stalker.follow(th[0].id, { events:{block:true}, onReceive:function(events){
          var p=Stalker.parse(events,{annotate:false});
          for (var i=0;i<p.length;i++) if (p[i][0]==='block') blocks.push([p[i][1].toString(), p[i][2].toString()]);
        }});
      } catch(e) { return String(e); }
      return 'ok';
    }
    rpc.exports.start=start;
    ''')
    ts.on('message', lambda m,d: print('tmsg', json.dumps(m)[:200]))
    ts.load()
    print('trace loaded')
    print('resume result', setup.exports_sync.resume())
    time.sleep(4)
    try: res=ts.exports_sync.get()
    except Exception as e: res={'err':str(e)[:150]}
    print('blocks', len(res.get('blocks',[])))
    if res.get('blocks'): print('sample', res['blocks'][:10])
    json.dump(res, open('analysis/tmp/packed_resume_trace.json','w'))
    try: setup.exports_sync.kill()
    except Exception: pass
    trace.detach()
smon.detach()
