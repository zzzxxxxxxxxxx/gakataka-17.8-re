import frida, json, time
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
# 清理遗留 packed_smon
for p in dev.enumerate_processes():
    if 'packed_smon' in p.name.lower():
        try: dev.kill(p.pid); print('killed', p.pid)
        except Exception as e: print('kill err', p.pid, str(e)[:80])
# 用 Student 作启动器
st=dev.attach(7736)
setup=st.create_script(r'''
function k32(n){ return Process.getModuleByName('kernel32.dll').findExportByName(n); }
var CreateProcessA = new NativeFunction(k32('CreateProcessA'),'int',['pointer','pointer','pointer','pointer','int','uint32','pointer','pointer','pointer','pointer']);
var ResumeThread = new NativeFunction(k32('ResumeThread'),'uint32',['pointer']);
var TerminateProcess = new NativeFunction(k32('TerminateProcess'),'int',['pointer','uint32']);
var hProc=null, hThread=null;
rpc.exports = {
  create: function(path){
    var pi=Memory.alloc(16);
    var si=Memory.alloc(0x44);
    for (var i=0;i<0x44;i++) si.add(i).writeU8(0);
    si.writeU32(0x44);
    var pathp=Memory.allocUtf8String(path);
    var ok=CreateProcessA(NULL, pathp, NULL, NULL, 0, 0x4, NULL, NULL, si, pi);
    hProc=pi.readPointer(); hThread=pi.add(4).readPointer();
    return {ok:ok, pid:pi.add(8).readU32(), hproc:pi.readPointer().toString()};
  },
  resume: function(){ return ResumeThread(hThread); },
  kill: function(){ try{TerminateProcess(hProc,1);}catch(e){} return true; }
};
''')
setup.load()
r=setup.exports_sync.create('C:\\Users\\zzx\\AppData\\Local\\Temp\\packed_smon.exe')
print('create', r)
pid=r.get('pid')
if pid and r.get('ok'):
    try:
        trace=dev.attach(pid); print('attached new pid', pid)
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
        ts.on('message', lambda m,d: print('tmsg', json.dumps(m)[:150]))
        ts.load()
        print('stalker start', ts.exports_sync.start())
        print('resume', setup.exports_sync.resume())
        time.sleep(4)
        try: res=ts.exports_sync.get()
        except Exception as e: res={'err':str(e)[:150]}
        print('blocks', len(res.get('blocks',[])))
        if res.get('blocks'): print('sample', res['blocks'][:10])
        json.dump(res, open('analysis/tmp/packed_student_trace.json','w'))
        trace.detach()
st.detach()