import frida, json, time, sys
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
pid=2924
session=dev.attach(pid)
script=session.create_script(r'''
var ranges=[];
var base=Process.getModuleByName('Smonitor.exe').base;
var tid=null;
var th=Process.enumerateThreads();
if (th.length) tid=th[0].id;
send({msg:'start', base:base.toString(), threads:th.length, tid:tid});
var timer=null;
if (tid!==null) {
  Stalker.follow(tid, {
    events: { block: true },
    onReceive: function(events) {
      var p=Stalker.parse(events, {annotate:false});
      for (var i=0;i<p.length;i++) {
        var e=p[i];
        if (e[0]==='block') ranges.push([e[1].toString(), e[2].toString()]);
      }
    }
  });
  timer=setTimeout(function(){ Stalker.unfollow(tid); Stalker.flush(); send({msg:'done', n:ranges.length}); }, 6000);
} else {
  send({msg:'nothread'});
}
rpc.exports = { get: function(){ return ranges; } };
''')
out=[]
def on_msg(m,d):
    if m['type']=='send':
        print('msg', m['payload'].get('msg'), m['payload'].get('base'), m['payload'].get('threads'), m['payload'].get('n'))
    else:
        print('err', m)
script.on('message', on_msg)
script.load()
time.sleep(8)
try:
    ranges=script.exports_sync.get()
except Exception as e:
    ranges=[]
    print('get err', str(e)[:200])
print('block events', len(ranges))
json.dump({'base':0x400000,'ranges':ranges}, open('analysis/tmp/stalker_blocks.json','w'))
if ranges:
    print('sample', ranges[:5])
session.detach()
