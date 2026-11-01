# 反混淆尝试记录（2026-10-31 19:05）

## 方法

1. 用提权 PowerShell（SysWOW64，SeDebugPrivilege）打开 SYSTEM 服务 Smonitor 进程，按模块基址导出真实内存镜像。
2. 与静态脱壳镜像 Smonitor-stage2.exe 逐页对比。
3. 枚举进程全部内存区，只扫可执行区段的关键字，定位含关机能力与监控逻辑的区域。
4. 对 .text0/.text1 “加密样”区段做 40 次运行时抽样，与静态镜像逐页哈希比对，抓取任何时刻被改写的页。

## 结果

### 1. 静态镜像没有被就地解密

live 模块镜像（Smonitor.exe base 0x400000，SizeOfImage 0xC8000）与 Smonitor-stage2.exe 逐页对比，
绝大多数页完全一致；差异页只有 DATA/BSS 和运行期指针。也就是说 .text0/.text1（0x46e000-0x4c7000）
在内存中仍是静态镜像里的字节，不是“解压到别处”。

### 2. 运行期抽样：这些页是自修改/按需解密层

40 次采样（每次间隔 250ms）里共有 11 页出现过与静态值不同的内容，差异是 4-20 字节的连续小段，
形态为：

- 0x47756c: 68 a1 76 9d 83 e8 df 78 ff ff（push imm32; call 0x46ee55）
- 0x47125c: 68 a9 76 1d b8 e8 6f d0 ff ff（push imm32; call 0x46e2d5）
- 0x47c5f4: 60 e8 1c 76 00 00（pushal; call 0x483c16）

即运行期在加密页里写入跳转/调用桩，指向 .text0/.text1 起始附近的解码代码。这符合
“按需解密 + 执行后回写”的保护层特征，而不是普通加壳。

### 3. Smonitor 进程内有可用的关机能力

可执行区扫描发现 base=0x890000 的映像即为 lib.dll（RVAs 与 lib-stage2.dll 完全一致）：

- 0x93c3fc NtShutdownSystem
- 0x93c410 RtlAdjustPrivilege
- 0x93c424 ZwShutdownSystem
- 0x93c948 SeShutdownPrivilege
- 0x93df1c Software\Microsoft\Windows\CurrentVersion\Policies\System

服务以 LocalSystem 运行，进程里已映射包含 ShutWindow 实现的 lib.dll，因此本地执行重启在权限上
完全可行。

### 4. 服务命令协议（REA 反编译 + 入口点补丁副本）

0x4589f8 的命令处理器按首字节分派：Q/R/S/T/U/V/W/X。S 设置 taskmgr/perfmon 清理开关，
T 设置并持久化 ar，U/V 分别调用 0x4795cc/0x47a71c 与 0x479800/0x4731c9（受保护层函数），
W/X 为其它处理。

## 未完成的部分

- 保护层的 VM/自修改逻辑没有还原成高级逻辑；这需要 VM 指令提升或对每个桩做单步跟踪，
  不是本会话能完成的工作量。
- 没有学校现场的策略状态，无法触发“违规→重启”进而抓取调用链。

## 产物

- 活内存模块镜像：analysis/dynamic/transfer/up_Smonitor_Smonitor.exe-*.bin、up_Smonitor_lib.dll-*.bin
- 解密区抓取：analysis/dynamic/transfer/up_region-20261031-190225.bin（含运行期改写页）
- 静态对照：analysis/dynamic/transfer/smon_static.bin
- 入口点补丁分析副本：analysis/unpacked-auto/Smonitor-entry-handler.exe、Smonitor-entry-timer.exe

## 保护层的新结论（2026-10-31 20:20）

### 1. 保护区是明文混淆，不是加密

对 Smonitor 的 .text0/.text1 做静态反汇编发现：0x47a71c 等入口处是合法的 x86 指令，
形态是 pushfd / pushal / xchg / bswap / ret imm / jmp 组成的变形跳板链，例如：

    0x47a71c: pushfd
    0x47a71d: xchg dword ptr [esp], eax
    0x47a720: bswap ax
    0x47a723: jmp 0x471940

    0x471940: lea eax, [ebp*8 - 0x75c9537d]
    0x471947: mov eax, dword ptr [0x45c804]
    0x47194c: jmp 0x47ac56

这说明保护层不是整段加密后解密执行，而是控制流/指令变形混淆；运行期只在 11 个页面上
写入少量桩（每次 U/V 调用时都能抓到，已保存 66 份页面快照）。

### 2. 本地命令分派的真实代码（Smonitor CODE 0x4589f8）

    al = byte ptr [cmd]; eax -= 0x51; switch(eax)
    0x51 Q: call 0x458854
    0x52 R: 解析字符串后 call 0x457f98 / 0x4581b0
    0x53 S: byte[this+0xfb] = (data == 1)
    0x54 T: byte[this+0xf8] = (data == 1); call 0x4583a4（持久化 ar）
    0x55 U: data==1 ? call 0x457fe0 : call 0x457fd8
    0x56 V: data==1 ? call 0x457ff0 : call 0x457fe8
    0x57 W: call 0x4588c4(this, data)
    0x58 X: call 0x457fb8(data[0], data[4])

这些 call 目标都是 thunk，其中：
- 0x457fd8: jmp 0x47a71c（U0，进入保护区）
- 0x457fe0: jmp 0x476a19（U1，进入保护区）
- 0x457ff0: jmp 0x478419（V1，进入保护区）

### 3. U0 的实际执行链（动态抓到）

在 lib.dll 的 RegSetValueExA 上下硬件断点，发 U0 命令，寄存器/栈为：

    rip=0x76ff0190 (RegSetValueExA)
    返回地址 0x96c753  -> lib 基址 0x8c0000 + 0xac753
    上一级返回 0x8c4bac -> lib + 0x4bac
    再上一级 0x458b05   -> Smonitor 中 call 0x457fd8 的返回点

写入的值名是 Start（USBSTOR），即 U0 = 禁用 USB 存储；U1 = 启用。
这证明受保护区函数会回调普通 lib 代码完成实际动作，lib 函数本身可继续静态分析。

### 4. 产物

- analysis/tmp/prot/hit*-*.bin：在 0x47a71c 断点处导出的运行期页面（66 份）
- analysis/tmp/regcall*.log：注册表 API 断点与返回地址日志
- analysis/unpacked-auto/Smonitor-entry-U0.exe：入口改为 0x47a71c 的分析副本
- analysis/unpacked-auto/lib-entry-4bac.dll：入口改为 0x4bac 的 lib 分析副本（Ghidra 对 lib 的 PE 导入表报错，暂不可用）

### 5. 下一步

跳板链（0x471940 -> 0x47ac56 -> ...）用静态反汇编跟随会掉进变形指令；
要还原语义，需要动态指令跟踪：
- 用 Frida Stalker 或 QEMU 单步从 0x47a71c 开始记录执行过的指令序列，
- 再按实际执行路径重建基本块，跳过未执行的混淆填充。
完成后再在这些函数里找对 ShutWindow/SeShutdown 或重启相关 API 的调用。


## 工具评估（2026-10-31）

- D810（Ghidra 插件）：面向 MBA/常量折叠/不透明度谓词化简。本样本是 pushal/pushfd/ret imm 的栈式控制流混淆，
  Ghidra 无法建立该区域 CFG，D810 没有有效输入，不适用。
- ROParser（Cherest-San/ROParser，Computers & Security 2026）：Python，miasm+angr，支持 x86_32 PE 与 Raindrop 模式，
  思路正确（符号执行恢复 ROP 链 CFG）。但其 PE 模式把 [chain_begin, chain_end) 当作“静态 ROP 链表”读取
  （_load_rop_chain 逐 dword 当 gadget 地址），Raindrop 模式则要求 .rop 格式输入。
- 静态扫描 Student-stage2 / Smonitor-stage2 的可写数据区：指向可执行区且落在合法 gadget 上的 dword 最长连续序列
  仅 4 / 3 个，说明样本里没有静态 ROP 链表；本样本的调度栈是运行时用 pushal/ret imm 现场构造的。
  因此 ROParser 不能直接吃这份样本，需要自定义 loader（把代码区当链数据源或先做模拟执行抽链）。
- 更轻的等效做法：Unicorn 具体执行 + 记录 ret 目标重建 CFG（本会话已用它拿到执行器 -> lib!ShutWindow(mode,-1,-1)）。


### ROParser 实测（2026-10-31 22:5x）

- 环境：analysis/tmp/ropvenv（Python 3.14）。依赖走华为云镜像
  https://repo.huaweicloud.com/repository/pypi/simple 安装；实测下载速度：
  华为云 5.7MB/s（miasm sdist）、USTC/腾讯/华为 1.6MB/s 串行（4 并发 6.6MB/s）、
  清华/BFSU 对 miasm sdist 返回 403、官方 PyPI 经 VPN 反而很慢。
- 兼容性：miasm==0.1.5（PyPI）在 Python 3.14 下无法加载（ast 模块没有 Str）。
  改装 GitHub master（commit c3c6115，2026-10-30，已改用 ast.Constant）后正常。
- 自带用例：-i testcase/programs/raindrop/simple.rop -m raindrop 成功，
  恢复出 4 blocks / 4 edges（110 条指令），说明工具本身可运行。
- 对 Student-stage2 实测：（配置 analysis/tmp/ropjson/student_exec.json，
  functions exec_reboot=0x5854a4..0x5854ae、restart_flow=0x585404..0x585875）

      python main.py -i student_exec.json -o out_student -m pe

  结果失败：KeyError: 4069217875（0xF28Axxxx）——PE loader 把函数区间的代码字节
  当成 ROP 链表 dword 去取 gadget，说明输入模型不匹配。
- 全段扫描佐证：可执行段作为数据 dword 扫描时，指向合法 gadget 的最长连续序列
  CODE 段 23 个（代码噪声）、.text0/.text1 为 0；数据段最长 4 个，没有静态 ROP 链表。

