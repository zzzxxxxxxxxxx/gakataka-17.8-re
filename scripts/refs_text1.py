import struct
IMG=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
imgbase=BASE
ranges=[('text1',0x47c000,0x4c7000),('copy',0x54f000,0x59b000)]
# 1) 直接 E8/E9 目标
for name,a,b in ranges:
    refs=[]
    for i in range(IMG.__len__()-5):
        if IMG[i] in (0xE8,0xE9):
            rel=struct.unpack('<i', IMG[i+1:i+5])[0]
            t=BASE+i+5+rel
            if a<=t<b: refs.append((BASE+i, t))
    print(name,'direct refs',len(refs),[(hex(x),hex(y)) for x,y in refs[:8]])
# 2) 4 字节立即数/指针值
for name,a,b in ranges:
    hits=[]
    for i in range(0,len(IMG)-4):
        v=struct.unpack('<I', IMG[i:i+4])[0]
        if a<=v<b: hits.append((BASE+i,v))
    print(name,'dword refs',len(hits),[(hex(x),hex(y)) for x,y in hits[:8]])
