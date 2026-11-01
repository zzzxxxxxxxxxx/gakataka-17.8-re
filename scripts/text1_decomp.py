import struct, os, lzma, zlib
orig=open('analysis/tmp/Smonitor-packed.exe','rb').read()
stage=open('analysis/unpacked-auto/Smonitor-stage2.exe','rb').read()
a=orig[0x1200:0x1200+0x4ae00]
b=stage[0x7c000:0x7c000+0x4ae00]
same=sum(1 for i in range(len(a)) if a[i]==b[i])
print('orig .text1 vs stage2 text1: equal %.2f%%' % (100.0*same/len(a)))
# 原始载荷头
print('orig payload head', a[:64].hex())
print('orig payload entropy', -sum((v/len(a))*__import__('math').log2(v/len(a)) for v in __import__('collections').Counter(a).values()))
# 尝试常见解压
def try_decomp(name, fn):
    try:
        out=fn()
        print(name, 'OK len', len(out), out[:40])
    except Exception as e:
        print(name, 'fail', str(e)[:80])
try_decomp('zlib@0', lambda: zlib.decompress(a))
try_decomp('raw-deflate@0', lambda: zlib.decompress(a, -15))
try_decomp('lzma-alone@0', lambda: lzma.decompress(a))
try_decomp('lzma-raw@0', lambda: lzma.decompress(a, format=lzma.FORMAT_RAW, filters=[{'id':lzma.FILTER_LZMA1,'dict_size':1<<20}]))
for modname in ('lz4','zstandard','brotli'):
    try:
        m=__import__(modname); print('module', modname, 'available')
    except Exception: print('module', modname, 'missing')
