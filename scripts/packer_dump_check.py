dump=open('analysis/tmp/packer_seh_dump.bin','rb').read()
stage=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read(); BASE=0x400000
def match(va, n):
    off=va-BASE
    a=dump[off:off+n]; b=stage[off:off+n]
    if not b: return 0,0
    s=sum(1 for x,y in zip(a,b) if x==y)
    return s, len(b)
for name,va,n in [('CODE',0x401000,0x58000),('text0',0x46e000,0xe000),('DATA',0x459000,0x2000),('idata',0x45c000,0x3000),('text1',0x47c000,0x4b000)]:
    s,t=match(va,n)
    print('%-6s match %d/%d = %.1f%%' % (name,s,t,100.0*s/t))
# 非零且与stage不同的字节数
for name,va,n in [('CODE',0x401000,0x58000),('text0',0x46e000,0xe000)]:
    off=va-BASE
    diff=sum(1 for i in range(n) if dump[off+i]!=stage[off+i])
    print(name,'diff bytes',diff)
