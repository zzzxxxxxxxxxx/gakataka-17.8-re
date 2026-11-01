import frida, json, time
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
session=dev.attach(2924)
script=session.create_script(r'''
var ranges=[];
var th=Process.enumerateThreads();
send({msg:'start', base:Process.getModuleByName('Smonitor.exe').base.toString(), threads:th.length});
var tids=[];
for (var i=0;i<th.length;i++) {
  var id=th[i].id; tids.push(id);
  try {
    Stalker.follow(id, {
      events: { block: true, exec: true },
      onReceive: function(events) {
        var p=Stalker.parse(events, {annotate:false});
        for (var k=0;k<p.length;k++) {
          var e=p[k];
          if (e[0]==='block' || e[0]==='exec') ranges.push([e[1].toString(), e[2].toString(), e[0]]);
        }
      }
    });
  } catch(e) { send({msg:'follow_err', id:id, err:String(e)}); }
}
setTimeout(function(){
  for (var i=0;i<tids.length;i++) { try{ Stalker.unfollow(tids[i]); }catch(e){} }
  Stalker.flush();
  send({msg:'done', n:ranges.length});
}, 6000);
rpc.exports = { get: function(){ return ranges; } };
''')
def on_msg(m,d):
    if m['type']=='send': print('msg', m['payload'])
    else: print('err', m)
script.on('message', on_msg)
script.load()
time.sleep(9)
try: ranges=script.exports_sync.get()
except Exception as e:
    ranges=[]; print('get err', str(e)[:200])
print('block events', len(ranges))
json.dump({'base':0x400000,'ranges':ranges}, open('analysis/tmp/stalker_blocks.json','w'))
print('sample', ranges[:6])
session.detach()
