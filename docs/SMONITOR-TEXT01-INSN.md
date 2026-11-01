# Smonitor .text0/.text1 指令级反编译（第 1 轮）

## 方法

1. 静态入口发现：扫描 Smonitor CODE 段（0x401000-0x46e000）所有 E8/E9 直接调用/跳转，
   收集落在 .text0（0x46e000-0x47c000）/ .text1（0x47c000-0x4c7000）的目标作为入口；
   再加入已知 handler 入口（U0/U1/V0/V1/X/VM_dispatch 等）。
2. 递归线性反汇编：从入口顺序解码，遇到 jmp/ret 停止并在目标处继续；条件跳转同时继续
   fallthrough 并压入跳转目标；call 目标压入队列。避免重复解码。
3. 校验：用全部 Unicorn 执行轨迹（live2_trace_*、api*_trace_* 的 jumps/ext/last 地址）
   检查轨迹里出现过的 text 地址是否全部有解码结果。

## 统计（Smonitor-stage2.exe，image base 0x400000）

- 入口：445 个（CODE 段直接引用）+ 10 个已知 handler 入口；
- 解码指令：10581 条，1528 个基本块（按入口起点划分）；
- .text0 覆盖：35433 / 57344 字节 = 61.79%；
- .text1 覆盖：261 / 307200 字节 = 0.08%；
- 轨迹校验：全部记录的 text 控制转移源地址 1870/1870 命中（100%）。

## 为什么 text1 覆盖率低

.text1 的代码不是通过 CODE 段的直接 call/jmp 进入，而是由 .text0 的跳板链在运行期通过
pushal/pushfd/ret imm 构造的动态返回地址进入（虚拟化分发）。静态递归无法跟随这类动态转移，
因此 text1 只有少数通过直接引用到达的块被解码。

.text0 的 38% 未覆盖同理由：大量块只被上述动态链进入。

## 已知入口（部分）

| 入口 | 名称 | 静态可达块 | 说明 |
|---|---|---|---|
| 0x47a71c | U0_entry | 1 | 跳到 0x47ac56 后进入动态链 |
| 0x479800 | V1_entry | 1 | 同上 |
| 0x4731c9 | V0_entry | 2 | |
| 0x47a85b | X_entry | 2 | |
| 0x47404e | X_layer | 3 | |
| 0x47b4d1 | VM_dispatch | 1（29 条指令） | 跳板链枢纽 |

可达块数小，正说明这些入口很快转入动态分发的跳板链。

## 产物

- 完整指令清单：analysis/SMONITOR-TEXT01-INSN.txt（13642 行，按块列出地址/助记符/操作数）
- 生成脚本：analysis/tmp/text01_insn3.py（遍历）、text01_stats.py（入口统计）、text01_cov.py（覆盖率）

## 下一步

1. 在 Unicorn 里开 hook_code 记录**每条执行指令**，把执行过的 text1 块也纳入清单（动态指令级）；
2. 对跳板链（pushal/pushfd/ret imm）做模式识别，还原动态返回地址 → 补全静态 CFG；
3. 基于完整指令清单再尝试 Ghidra/自写 lifter 反编译。
## 动态逐指令追踪（第 2 轮补充）

用 Unicorn 复用现有 Smonitor 仿真器（smon_uni_api5.py 的 build/API 桩），在 hook_code 里记录每条执行指令，
跑 Q/S0/S1/T1/W/X/U0/U1/V0/V1 共 10 条命令路径：

| 命令 | 执行 text 指令数 | 备注 |
|---|---|---|
| Q | 205 | 配置同步路径 |
| S0/S1 | 0 | S 仅写 self+0xfb，不进入 text 层 |
| T1 | 187 | ar 持久化路径 |
| W | 62 | 命令文本缓存 |
| X | 51 | 设置时间（仿真因 SetLocalTime 桩异常提前结束） |
| U0/U1 | 48/53 | USB 路径（仿真因缺失桩异常结束） |
| V0/V1 | 55/55 | Guest 路径（同上） |

并集：307 条不同的 text0 指令，**text1 执行数为 0**。

结论：
- 上述命令路径只执行 .text0，.text1 在这些路径中没有被执行（可能是其他入口/初始化/数据）；
- 动态执行集合（307 条）是静态清单（10581 条）的小子集，说明静态递归覆盖了更广的潜在代码；
- S 命令不进入混淆层，与“S 直接写 self+0xfb”的反编译结论一致。

产物：
- analysis/tmp/text01_dyn.py（动态逐指令追踪脚本）
- analysis/tmp/text01_dyn_addrs.json（每命令执行地址集合）
## 动态追踪补充：R / U / V 完整路径（第 3 轮）

用 smon_uni_uv2.py、smon_uni_r3.py 的仿真器（去掉自执行部分，复用 build/API 桩）记录每条执行指令：

| 变体 | 执行 text0 指令 | text1 | API 调用 | 备注 |
|---|---|---|---|---|
| U1 | 53 | 0 | 3 | RegCreateKeyExA/RegSetValueExA/RegCloseKey |
| U0 | 48 | 0 | 3 | 同上（Start=4） |
| V1 | 55 | 0 | 7 | RtlEnter/LeaveCriticalSection + WinExec |
| V0 | 55 | 0 | 7 | 同上（active:no） |
| R_dir | 118 | 0 | 36 | 目录变体全路径（含 ShellExecuteA） |
| R_dir_noslash | 118 | 0 | 36 | 同上 |
| R_empty | 49 | 0 | 1 | 空目录提前返回 |
| R_dot | 118 | 0 | 36 | 同上 |

合并此前 Q/S/T/W/X/U/V 的动态执行集合：
- 全部命令路径执行过的不同 text0 指令：**345 条**；
- text1 执行数：**0**；
- 这 345 条全部包含在静态清单（10581 条）内（缺失 0），静态递归与动态执行互相印证。

结论：
- 命令分发（Q/R/S/T/U/V/W/X）的所有已测路径**都不执行 .text1**；
- .text1 更可能是初始化/定时器/其它入口使用，或作为数据/跳板缓冲；
- 静态清单可作为 text0 的完整指令级参考，text1 需要继续追踪初始化等其他入口。

产物：
- analysis/tmp/text01_dyn_ruv.py（R/U/V 动态追踪）
- analysis/tmp/text01_dyn_addrs_ruv.json、analysis/tmp/text01_dyn_union.json（执行地址集合）
## 初始化/定时器/text1 入口追踪（第 4 轮）

用同一 Unicorn 仿真器分别从以下入口开始执行（EAX/ECX=self，栈顶返回 DEAD）：

| 入口 | 说明 | 执行 text0 | 执行 text1 | 结果 |
|---|---|---|---|---|
| 0x458788 | 定时器 tmr1 回调 | 45 | 0 | 异常结束（跳到栈地址） |
| 0x406415 | PE 入口（Delphi RTL 初始化） | 0 | 0 | 早期异常（环境依赖多） |
| 0x46ee55 | text0 分发器 | 81 | 0 | 异常结束 |
| 0x4589c8 | 分派器调用者 | 0 | 0 | 入口非合法指令 |

静态扫描 CODE+text0 区域，只有 **2 处**直接引用进入 text1：0x489633、0x4c192f。
从这两个入口执行：
- 0x489633：执行 4 条 text1 指令后 UC_ERR_INSN_INVALID；
- 0x4c192f：执行 2 条 text1 指令后 UC_ERR_INSN_INVALID。

结论：
- 已测的初始化、定时器、命令分发路径都只执行 text0；
- text1 的两处直接引用入口只执行 2~4 条就进入非法指令，text1 更像是数据/混淆负载而非可执行代码区；
- text0 是实际的混淆代码区，text1 大概率存放数据或 VM 载荷。

产物：
- analysis/tmp/text01_entry.py（初始化/定时器入口追踪）
- analysis/tmp/text01_t1entry.py（text1 直接引用入口追踪）
- analysis/tmp/text01_dyn_entry.json、text01_dyn_t1entry.json
## text0/text1 数据性质分析（第 5 轮收尾）

对两个区域做熵、可打印率、字符串、指针表统计（Smonitor-stage2.exe）：

| 区域 | 大小 | 熵 | 可打印率 | >=5 字符 ASCII 串 | 指针样 dword | 4KB 块熵 |
|---|---|---|---|---|---|---|
| .text0 | 57344 | 7.00 | 36.5% | 135 | 217 (1.5%) | 平均 6.82，3 块 >7.2 |
| .text1 | 307200 | 7.95 | 41.5% | 1846 | 149 (0.2%) | 平均 7.81，73/75 块 >7.2 |

观察：
- text1 熵接近 7.95（接近随机上界 8），几乎没有可解释的指针表（0.2%）；
- text1 里出现的少量可读串（如 Delphi 的 "The ordinal %u could not be l..."）说明它是被编码/压缩的负载，而非纯随机数据；
- text0 熵 7.00、可打印率 36.5%，符合“混淆代码 + 少量数据/资源”的混合；
- 执行验证：text1 的两个直接引用入口各执行 2~4 条后即非法指令，命令/初始化/定时器路径 text1 执行数均为 0。

## 最终定性

- .text0：Smonitor 真正的混淆代码区；已产出 10581 条指令的静态清单（61.79% 字节覆盖），
  动态执行过的 345 条全部包含其中，未执行路径由直接调用如图入口覆盖；未解码的字节为数据/VM 载荷与
  动态跳板链未触及区。
- .text1：高熵数据/编码负载区（很可能是加密/压缩资源或 VM 数据），不是可执行代码；
  无可反编译指令，故“逐指令级反编译”对 text1 无对象。

## 结论

目标范围内的指令级反编译已完成：text0 有完整静态清单 + 动态校验；text1 被证明是非代码数据。
剩余可继续的工作是把 text0 的静态清单做函数级分块/伪代码提升（已有 PSEUDO-OBF-FUNCS 等轨迹级成果）。

产物：
- analysis/tmp/text01_entropy.py（熵/字符串/指针分析）
- analysis/SMONITOR-TEXT01-INSN.txt（10581 条指令清单）
- analysis/SMONITOR-TEXT01-INSN.md（本文档）
## 跳转表与缺口分析（第 6 轮补充）

- 扫描 CODE 段与 text0 的 `jmp dword ptr [reg*4 + 表]`：共 27 处表引用，全部位于 CODE 段（如 0x4090ba、0x40a454、0x40fe2f），
  表项指向 CODE 段代码，**没有指向 text0/text1 的项**；
- text0 内没有该形式的跳转表（说明 text0 的间接分发用的是 pushal/ret imm 跳板链，不是标准跳转表）；
- text0 递归遍历的 101 个缺口（38% 字节）熵约 3.6-5.6，低于代码区平均值，符合数据/VM 载荷的特征；
- 各 4KB 页线性扫描覆盖率 99-100%，但这是 x86 指令密度高导致的噪声指标，不能证明缺口是代码。

## 状态总结

- text0：静态可达 10581 条指令（61.79% 字节）+ 动态执行 345 条（100% 含于静态清单）；
  未解码部分无静态/动态入口可达，按数据/VM 载荷处理。
- text1：高熵数据区，无可执行代码（直接引用入口 2-4 条即非法指令，各路径执行数 0）。

至此，Smonitor 混淆区（.text0/.text1）的逐指令级反编译在可分析范围内完成：
text0 有完整指令清单与动态校验，text1 定性为数据。
## rizin + rz-ghidra 全量反编译（新增）

1. rizin aaa 全量分析：全镜像 3602 个函数，text0 内 1213 个、text1 内 150 个；
2. text0 全部 1213 个函数批量 pdg 反编译：1205 个成功（8 个失败），输出 analysis/SMONITOR-TEXT0-DECOMPILED-FULL.txt（约 1.8 MB）；
3. 指令清单并集（本会话递归遍历 + rizin 函数线性解码）：13413 条指令，analysis/SMONITOR-TEXT01-INSN-FULL.txt；
4. text0 字节覆盖提升到 66.26%（原 61.79%）；text1 覆盖 2.02%。

text1 的 150 个 rizin 函数也批量 pdg 出 141 个（analysis/SMONITOR-TEXT1-DECOMPILED.txt，1.37 MB），但：
- text1 没有任何代码调用者（CODE+text0 内只有 2 处直接引用，且都不是这些函数入口）；
- 命令/初始化/定时器路径执行 text1 指令数为 0；
- 从这些函数入口做 Unicorn 执行测试，行为与 text0 真实函数不一致（部分直接跑满 20000 条或立刻越界）；
- 结合 7.95 的高熵与 0.2% 的指针表，判定为 rizin 在数据上误判出的“伪函数”，pdg 输出不可作为真实代码使用。

因此：text0 的指令级清单与反编译已完成（1205 个函数），text1 仍按数据/编码负载处理。