import struct, os
p='analysis/tmp/Smonitor-packed.exe'
d=open(p,'rb').read()
pe=struct.unpack('<I', d[0x3c:0x40])[0]
nsec=struct.unpack('<H', d[pe+6:pe+8])[0]; optsz=struct.unpack('<H', d[pe+20:pe+22])[0]
imgbase=struct.unpack('<I', d[pe+24+28:pe+24+32])[0]
print('file size', len(d), 'image base', hex(imgbase))
so=pe+24+optsz
for i in range(nsec):
    o=so+i*40
    name=d[o:o+8].rstrip(b'\x00').decode('latin1')
    vs,va,rs,rp=struct.unpack('<IIII', d[o+8:o+24])
    print('%-8s VA %#x VS %#x rawptr %#x RS %#x' % (name, va, vs, rp, rs))
