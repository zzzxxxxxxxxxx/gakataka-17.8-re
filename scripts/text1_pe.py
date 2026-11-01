import struct
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
T1=(0x47c000,0x4c7000)
d=IMG[T1[0]-BASE:T1[1]-BASE]
# 扫描 MZ 且 e_lfanew 指向 PE 签名
cands=[]
for i in range(len(d)-0x40):
    if d[i:i+2]==b'MZ':
        e=struct.unpack('<I', d[i+0x3c:i+0x40])[0]
        if 0 < e < 0x10000 and i+e+4<=len(d) and d[i+e:i+e+4]==b'PE\x00\x00':
            cands.append(i)
print('valid PE candidates', len(cands), [hex(T1[0]+i) for i in cands[:10]])
for off in cands[:5]:
    e=struct.unpack('<I', d[off+0x3c:off+0x40])[0]
    pe=off+e
    machine=struct.unpack('<H', d[pe+4:pe+6])[0]
    nsec=struct.unpack('<H', d[pe+6:pe+8])[0]
    opt=struct.unpack('<H', d[pe+20:pe+22])[0]
    magic=struct.unpack('<H', d[pe+24:pe+26])[0]
    print('cand at file off %#x VA %#x e_lfanew=%#x machine=%#x nsec=%d optsz=%d magic=%#x' % (off, BASE+off, e, machine, nsec, opt, magic))
    # section names
    sec=pe+24+opt
    for k in range(min(nsec,8)):
        so=sec+k*40
        name=d[so:so+8].rstrip(b'\x00')
        vs,va,rs,rp=struct.unpack('<IIII', d[so+8:so+24])
        print('   sec', name, 'va', hex(va), 'vsz', vs, 'raw', rp, rs)
