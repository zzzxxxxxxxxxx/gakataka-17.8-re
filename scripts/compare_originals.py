import struct, hashlib, os
paths=['analysis/tmp/Smonitor-packed.exe','analysis/student/app/Smonitor.exe','analysis/offline-disk/extracted/disk/Program Files (x86)/gakataka/Student/Smonitor.exe','analysis/dynamic/transfer/up_Smonitor_Smonitor.exe-20261031-184618.bin','analysis/unpacked-auto/Smonitor-stage2.exe']
needle=b'The procedure entry point'
for p in paths:
    if not os.path.exists(p): print(p,'missing'); continue
    d=open(p,'rb').read()
    pe=struct.unpack('<I', d[0x3c:0x40])[0] if len(d)>0x40 else 0
    ok = pe and d[pe:pe+4]==b'PE\x00\x00'
    secs=[]
    if ok:
        nsec=struct.unpack('<H', d[pe+6:pe+8])[0]
        optsz=struct.unpack('<H', d[pe+20:pe+22])[0]
        so=pe+24+optsz
        for i in range(nsec):
            o=so+i*40
            name=d[o:o+8].rstrip(b'\x00').decode('latin1')
            vs,va,rs,rp=struct.unpack('<IIII', d[o+8:o+24])
            secs.append('%s@%x/%x'%(name,va,rs))
    pos=[i for i in range(len(d)) if d.startswith(needle,i)][:5]
    print('%s size=%d md5=%s pe=%s occurrences=%s' % (p, len(d), hashlib.md5(d).hexdigest()[:12], ok, [hex(x) for x in pos]))
    print('   sections:', ' '.join(secs[:12]))
