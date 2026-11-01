import frida, json
mgr=frida.get_device_manager(); dev=mgr.add_remote_device('127.0.0.1:27042')
session=dev.attach(2924)
script=session.create_script(r'''
function k32(name) {
  var m = Process.getModuleByName('kernel32.dll');
  return m.findExportByName(name) || m.getExportByName(name);
}
var hFile=null;
var CreateFileW = k32('CreateFileW');
var WriteFile = k32('WriteFile');
var CloseHandle = k32('CloseHandle');
rpc.exports = {
  open: function(path) {
    var p = Memory.allocUtf16String(path);
    var fn = new NativeFunction(CreateFileW, 'pointer', ['pointer','uint32','uint32','pointer','uint32','uint32','pointer']);
    hFile = fn(p, 0x40000000 /*GENERIC_WRITE*/, 0, NULL, 2 /*CREATE_ALWAYS*/, 0x80, NULL);
    return hFile.toString();
  },
  writeChunk: function(hexstr) {
    var bytes = [];
    for (var i=0;i<hexstr.length;i+=2) bytes.push(parseInt(hexstr.substr(i,2),16));
    var buf = Memory.alloc(bytes.length);
    buf.writeByteArray(bytes);
    var written = Memory.alloc(4);
    var fn = new NativeFunction(WriteFile, 'int', ['pointer','pointer','uint32','pointer','pointer']);
    var ok = fn(hFile, buf, bytes.length, written, NULL);
    return [ok, written.readU32()];
  },
  close: function() { new NativeFunction(CloseHandle,'int',['pointer'])(hFile); return true; }
};
''')
script.load()
path='C:\\Users\\zzx\\AppData\\Local\\Temp\\packed_smon.exe'
print('open', script.exports_sync.open(path))
data=open('analysis/tmp/Smonitor-packed.exe','rb').read()
CH=32768; off=0; total=0
while off<len(data):
    chunk=data[off:off+CH]
    ok,wr=script.exports_sync.write_chunk(chunk.hex())
    total+=wr
    off+=CH
print('wrote', total, 'of', len(data))
print('close', script.exports_sync.close())
session.detach()
