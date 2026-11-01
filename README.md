# 伽卡他卡电子教室 17.8 学生端逆向分析（Smonitor / lib.dll / Student）

对 `Smonitor.exe`、`lib.dll`、`Student.exe` 的保护、看护、命令协议与混淆层做静态 + 动态逆向，
并把可观测功能还原成高级伪代码；本仓库整理反编译文档、指令级清单、打包器分析与分析脚本。

## 关键结论（摘要）

- 任务管理器秒关由 `Student.exe` 执行（OpenProcess + TerminateProcess）；
- 客户端被杀后由 `Smonitor.exe` 用 CreateProcessAsUserA 重新拉起（保护开启时）；
- 教师端命令经 TCP（9 字节头：type + len(u32 LE) + magic `52 21 15 52`）到 Student，再转发 Smonitor；
- Smonitor 命令分派器（0x4589f8）已用 Ghidra 反编译：Q/R/S/T/U/V/W/X 八个分支；
- Q 配置同步、R 重启链、S taskmgr 标志、T ar 持久化、U USB 存储、V Guest、W 命令文本、X 设置时间；
- lib.dll 的 KillProc/ShutWindow/RunUpdt/SetGate/IsRunInVM/USB/Guest/Taskbar 等函数已反编译并加语义注解；
- Smonitor 混淆区 `.text0`：53718 条指令清单（字节覆盖 85.60%），约 1523 个函数入口已 rz-ghidra 反编译；
  剩余 14.4% 字节经熵/指针/引用/在线内存对比判定为数据，不再产出指令；
- `.text1` 是打包器载荷：PE 入口 `AddressOfEntryPoint = 0xAE041` 位于 `.text1` 内；
  已用 Unicorn 完整仿真解包并复现真实内存（CODE/text0/DATA/text1 100% 匹配，.idata 86.3% 因缺导入环境）；
- 解包算法：字面量变换 `f(x) = ((((x ^ 0x0C) - 1) ror 6) - 1) & 0xFF`（已逐字节验证），
  匹配复制由 `rep movsb` 完成；LZ 控制字段（字面量长度/匹配长度/距离的位域）尚未形式化。

## 目录结构

    docs/        30 篇逆向分析文档（协议、保护、伪代码、指令级分析、text1 编码、打包器等）
    artifacts/   19 个产物（指令清单、全函数反编译、函数表、逐地址状态、并集/动态集合）
    scripts/     74 个分析脚本（rizin/rz-ghidra 批量反编译、Unicorn 动态追踪、覆盖统计、frida、打包器）

## 产物索引

- `artifacts/SMONITOR-TEXT0-DECOMPILED-FULL.txt`（1.8 MB）：text0 全函数 rz-ghidra 反编译（1205 个）
- `artifacts/SMONITOR-TEXT0-CAND-FUNCS.txt`（724 KB）：候选起点新增的 318 个函数反编译
- `artifacts/SMONITOR-TEXT01-INSN-FULL.txt`（1.8 MB）：指令并集清单 v6（53718 条）
- `artifacts/SMONITOR-TEXT01-INSN.txt`（390 KB）：早期递归遍历清单（10581 条）
- `artifacts/SMONITOR-TEXT1-DECOMPILED.txt`（1.4 MB）：text1 的 rizin 伪函数输出（判定为数据误判，仅供参考）
- `artifacts/rizin_aflj.json`（3.2 MB）：rizin aaa 函数表（3602 个函数）
- `artifacts/pdg_status.json`、`pdg_aaa_status.json`：逐地址 pdg 状态（精确/包含/失败）
- `artifacts/text01_union_v2..v6.json`：各阶段并集结果（v6 为 53718 条最终清单的源数据）
- `artifacts/text01_dyn_*.json`：Unicorn 动态执行过的 text0 指令地址集合
- `artifacts/text0_cand_status.json`：候选函数起点逐地址状态

## 文档索引

- `docs/PSEUDO-FINAL.md`：总汇（分派器、命令处理、保护逻辑、协议、lib 函数）
- `docs/PSEUDO-DISPATCHER.md`：分派器与 handler 反编译
- `docs/PSEUDO-LIB.md`、`docs/PSEUDO-LIB-ANNOTATED.md`：lib 函数 C 伪代码与语义注解
- `docs/PSEUDO-COMMANDS.md`、`docs/PSEUDO-HIGHLEVEL.md`：8 个命令的语义级伪代码
- `docs/PSEUDO-OBF-FUNCS.md`、`PSEUDO-OBF-STRUCT.md`、`PSEUDO-OBF-TRACE.md`：混淆层执行路径伪代码
- `docs/SMONITOR-TEXT01-INSN.md`：text0/text1 指令级分析、动态追踪、覆盖率、rizin 全量反编译
- `docs/SMONITOR-TEXT0-DECOMPILED.md`：text0 全函数反编译说明与失败核查
- `docs/SMONITOR-TEXT1-ENCODING.md`：text1 编码格式分析
- `docs/SMONITOR-PACKER.md`：打包器/解包器定位、仿真验证、算法观察、解包工具用法
- `docs/SMONITOR-TEXT01-LINEARIZED.md`：早期 Unicorn 轨迹线性化
- `docs/REBOOT-MECHANISM.md`：保护/重启/协议相关的动态实验记录
- `docs/DEOBFUSCATION.md`、`docs/VM-PROTECTION.md`：混淆与反调试分析
- `docs/RE-STATE.md`：当前覆盖状态与残余未知
- `docs/REA-FINDINGS.md`：REA/Ghidra 反编译记录

## 复现要点

仓库内 `scripts/` 是分析脚本的副本，脚本内部引用工作区路径（`analysis/tmp/...`），
运行前需要有对应的 unpacked 二进制与运行时快照。

1. 批量反编译 text0（rizin + rz-ghidra）：

       rizin -q -c 'e scr.color=0' -c 's 0x46e265' -c 'af' -c 'pdg' -c 'q' analysis/unpacked-auto/Smonitor-stage2.exe

2. 从原始 packed Smonitor.exe 解包（Unicorn 仿真）：

       analysis/tmp/univenv/bin/python scripts/unpack_smonitor.py analysis/tmp/Smonitor-packed.exe out_image.bin

3. 生成最终并集指令清单：

       analysis/tmp/univenv/bin/python analysis/tmp/text01_write_v6.py

4. 动态逐指令追踪（需要 Unicorn 与 smon_live_map.json 等运行时快照）：

       analysis/tmp/univenv/bin/python analysis/tmp/text01_dyn.py

5. text1 编码分析：

       analysis/tmp/univenv/bin/python analysis/tmp/text1_encoding.py

## 已知限制

- text0 仍有 14.4% 字节（8509 字节）没有入口覆盖：熵均值 4.82、指针密度 0、被引用地址重试解码失败、
  在线内存无批量解密，判定为数据/VM 载荷；
- rz-ghidra 输出受混淆栈帧影响，寄存器语义需结合执行轨迹阅读；
- text1 的解包器已定位并可完整仿真，但 LZ 控制字段格式未形式化；`.idata` 因缺 kernel32/ntdll 只复现 86.3%；
- 动态追踪只覆盖已触发过的命令路径。

## 当前状态（2026-11-01）

| 项目 | 状态 |
|---|---|
| text0 指令清单 | 53718 条（CODE 引用、指针候选、rizin 函数、反向可达、严格可达、引用不动点） |
| text0 字节覆盖 | 85.60%（其余 14.4% 经证据判定为数据） |
| text0 函数反编译 | 约 1523 个入口（rizin 表 1205 + 候选起点 318） |
| text1 | 打包器载荷；解包器已定位（入口 0xAE041）并仿真复现（CODE/text0/DATA/text1 100%） |
| 解包工具 | `scripts/unpack_smonitor.py`，输入 packed exe，输出 2MB 镜像；已验证 |
| 算法细节 | 字面量变换 f 已验证；匹配复制 rep movsb；控制位格式未形式化 |
| 仓库提交 | 14 次（初始整理、覆盖扩展、候选函数、打包器定位/仿真、解包工具与本次 README 更新） |

## 状态总结

详见 `docs/RE-STATE.md` 与 `docs/SMONITOR-PACKER.md`：
text0 指令级反编译已到引用不动点（85.60% 字节，剩余为数据）；
text1 判为打包器载荷且解包器已定位、仿真复现，工具已交付。