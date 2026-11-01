# Smonitor 打包器与解包器分析

## 定位结论

- 原始 Smonitor.exe（311,808 字节）是打包后的 PE：`AddressOfEntryPoint = 0xAE041`，即 VA `0x4AE041`，落在 `.text1` 内；
- 文件里只有 `.text1`（raw 0x1200，大小 0x4AE00 = 307,200 字节）、`.rdata`（0x200）、`.rsrc`（0xc00）、尾部 `.reloc`（0x200）有磁盘数据；CODE/DATA/.text0 等段 SizeOfRawData 为 0；
- 因此 `.text1` = 打包器 stub + 压缩/混淆载荷，启动时由 stub 解包写入 CODE/DATA/.text0 等段。

## 解包器仿真（Unicorn + 自定义内存布局）

脚本 analysis/tmp/packer_seh_emul4.py：

- 按原始文件映射：0x400000 起 2MB（头部、.rdata、.rsrc、.text1、尾部 .reloc 按文件写入，其余段清零）；
- TEB/PEB 最小化：fs:[0] = -1、fs:[0x18] = TEB、fs:[0x30] = PEB、PEB.ImageBaseAddress = 0x400000；
- 从 0x4AE041 开始连续 emu_start（每块 count=1,000,000），记录执行地址与写内存；
- 异常时用 fs:[0] 链做 SEH 分发（本载荷实际未安装 SEH，未触发）。

## 仿真结果：解包输出与真实内存一致

| 区域 | 匹配 |
|---|---|
| CODE（0x401000，0x58000 字节） | 360448/360448 = 100.0% |
| .text0（0x46E000，0xE000） | 57334/57344 = 100.0%（10 字节为运行期补丁） |
| DATA（0x459000，0x2000） | 8188/8192 = 100.0% |
| .text1（0x47C000，0x4B000） | 307160/307200 = 100.0% |
| .idata（0x45C000，0x3000） | 10609/12288 = 86.3% |

idata 不完全是因为仿真环境没有真实 kernel32/ntdll，解包器解析导入表时拿不到函数地址；不影响代码/数据段的解包结果。

仿真结束时在 0xB08D1 处取指异常（缺导入/API 环境），但解包输出已经完整。

## 解包算法观察（尚未完全还原）

执行热点（采样计数）：

- 0x4B0BD7~0x4B0BE6：每字节复制/解码循环（约 78 万次）；
- 0x47C43C / 0x4C4A3A：push/ret 跳板（push 目标地址 + ret 转移）；
- 0x4ADB71：pushal/push esi/lea esp/ call 0x4B0BD7 的分发入口；
- 逐字节变换序列：`mov dl,[esi]; xor dl,0x0C; dec dl; ror dl,6; dec dl`，
  即可能的变换 f(x) = rol2((x ^ 0x0C) - 1)（与部分采样吻合），但把 2000 个采样与最终镜像逐字节对照只有 9 个匹配，
  说明它更可能是中间步骤/混淆诱饵，而非最终输出映射。

结论：解包器已经能完整跑通并证明输出正确；压缩/加密算法的具体形式仍未还原（跳板链 + 中间变换混在一起，需要进一步动态插桩按输出字节反推）。

## 可复现命令

    analysis/tmp/univenv/bin/python analysis/tmp/packer_seh_emul4.py

输出：analysis/tmp/packer_seh_dump.bin（2MB 内存快照）、analysis/tmp/packer_seh_run.json（写入与热点）。