import frida, json, time
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
smon=dev.attach(2924)
setup=smon.create_script(r'''
function k32(n){ return Process.getModuleByName('kernel32.dll').findExportByName(n); }
var CreateProcessA = new NativeFunction(k32('CreateProcessA'),'int',['pointer','pointer','pointer','pointer','int','uint32','pointer','pointer','pointer','pointer']);
var ResumeThread = new NativeFunction(k32('ResumeThread'),'uint32',['pointer']);
var TerminateProcess = new NativeFunction(k32('TerminateProcess'),'int',['pointer','uint32']);
var CloseHandle = new NativeFunction(k32('CloseHandle'),'int',['pointer']);
var hProc=null, hThread=null;
var lastErr=0;
rpc.exports = {
  create: function(path){
    var pi=Memory.alloc(16);
    var pathp=Memory.allocUtf8String(path);
    var ok=CreateProcessA(NULL, pathp, NULL, NULL, 0, 0x4, NULL, NULL, NULL, pi);
    hProc=pi.readPointer();
    hThread=pi.add(4).readPointer();
    var pid=pi.add(8).readU32();
    return {ok:ok, pid:pid, hproc:hProc.toString(), hthread:hThread.toString()};
  },
  resume: function(){ return ResumeThread(hThread); },
  kill: function(){ try { TerminateProcess(hProc,1); } catch(e){} try { CloseHandle(hProc); } catch(e){} try { CloseHandle(hThread); } catch(e){} return true; }
};
''')
setup.load()
r=setup.exports_sync.create('C:\\Users\\zzx\\AppData\\Local\\Temp\\packed_smon.exe')
print('create', r)
pid=r.get('pid')
if pid and r.get('ok'):
    try:
        trace=dev.attach(pid); print('attached trace')
    except Exception as e:
        print('attach err', str(e)[:150]); trace=None
    if trace:
        ts=trace.create_script(r'''
        var blocks=[];
        rpc.exports = {
          start: function(){
            var th=Process.enumerateThreads();
            if (!th.length) return 'nothread';
            try {
              Stalker.follow(th[0].id, { events:{block:true}, onReceive:function(events){
                var p=Stalker.parse(events,{annotate:false});
                for (var i=0;i<p.length;i++) if (p[i][0]==='block') blocks.push([p[i][1].toString(), p[i][2].toString()]);
              }});
            } catch(e) { return String(e); }
            return 'ok';
          },
          get: function(){ return {blocks: blocks.slice(0,20000)}; }
        };
        ''')
        ts.on('message', lambda m,d: print('tmsg', json.dumps(m)[:200]))
        ts.load()
        print('start', ts.exports_sync.start())
        print('resume', setup.exports_sync.resume())
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
