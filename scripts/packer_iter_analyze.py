import json
d=json.load(open('analysis/tmp/packer_iter_trace.json'))
w=d['writes']; tr=d['trace']
print('writes', len(w))
for x in w[:16]: print(x)
# 找 trace 中与写入相关的指令（写 eip）
stores=[x[2] for x in w[:8]]
print('store eips', stores)
# 打印 trace 中这些 eip 附近的记录
for e in set(stores):
    print('== around', e)
    for i,(a,r) in enumerate(tr):
        if a==e:
            for j in range(max(0,i-6), min(len(tr), i+3)):
                print('   ', tr[j])
            break
