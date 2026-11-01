# 伽卡他卡电子教室 17.8 学生端逆向分析（Smonitor / lib.dll / Student）

对 `Smonitor.exe`、`lib.dll`、`Student.exe` 的保护、看护、命令协议与混淆层做静态 + 动态逆向，
并把可观测功能还原成高级伪代码；本仓库整理反编译文档、指令级清单与分析脚本。

## 关键结论（摘要）

- 任务管理器秒关由 `Student.exe` 执行（OpenProcess + TerminateProcess）；
- 客户端被杀后由 `Smonitor.exe` 用 CreateProcessAsUserA 重新拉起（保护开启时）；
- 教师端命令经 TCP（9 字节头：type + len(u32 LE) + magic `52 21 15 52`）到 Student，再转发 Smonitor；
- Smonitor 命令分派器（0x4589f8）已用 Ghidra 反编译：Q/R/S/T/U/V/W/X 八个分支；
- Q 配置同步、R 重启链、S taskmgr 标志、T ar 持久化、U USB 存储、V Guest、W 命令文本、X 设置时间；
- lib.dll 的 KillProc/ShutWindow/RunUpdt/SetGate/IsRunInVM/USB/Guest/Taskbar 等函数已反编译并加语义注解；
- Smonitor 混淆区 `.text0` 已完成：13413 条指令清单、1205 个函数 rz-ghidra 反编译；
- `.text1` 判定为打包器载荷（高熵、含明文 Delphi 字符串与明文跳板，无标准压缩/加密头），具体算法未识别。

## 目录结构

    docs/        逆向分析文档（协议、保护、伪代码、指令级分析、text1 编码分析等）
    artifacts/   指令级清单与反编译输出（text0 全函数、并集清单、函数表、动态执行集合）
    scripts/     分析脚本（rizin/rz-ghidra 批量反编译、Unicorn 动态追踪、熵/字符串/编码分析、frida 探测）

## 产物索引

- `artifacts/SMONITOR-TEXT0-DECOMPILED-FULL.txt`：text0 全函数 rz-ghidra 反编译（约 1.8 MB）
- `artifacts/SMONITOR-TEXT01-INSN-FULL.txt`：text0/text1 指令并集清单（13413 条）
- `artifacts/SMONITOR-TEXT01-INSN.txt`：早期递归遍历清单（10581 条）
- `artifacts/SMONITOR-TEXT1-DECOMPILED.txt`：text1 的 rizin 伪函数输出（判定为数据误判，仅供参考）
- `artifacts/rizin_aflj.json`：rizin aaa 函数表（3602 个函数）
- `artifacts/pdg_status.json`、`pdg_aaa_status.json`：逐地址 pdg 状态（精确/包含/失败）
- `artifacts/text01_dyn_*.json`：Unicorn 动态执行过的 text0 指令地址集合

## 文档索引

- `docs/PSEUDO-FINAL.md`：总汇（分派器、命令处理、保护逻辑、协议、lib 函数）
- `docs/PSEUDO-DISPATCHER.md`：分派器与 handler 反编译
- `docs/PSEUDO-LIB.md`、`docs/PSEUDO-LIB-ANNOTATED.md`：lib 函数 C 伪代码与语义注解
- `docs/PSEUDO-COMMANDS.md`、`docs/PSEUDO-HIGHLEVEL.md`：8 个命令的语义级伪代码
- `docs/PSEUDO-OBF-FUNCS.md`、`STRUCT.md`、`TRACE.md`：混淆层执行路径伪代码
- `docs/SMONITOR-TEXT01-INSN.md`：text0/text1 指令级分析、动态追踪、覆盖率、rizin 全量反编译
- `docs/SMONITOR-TEXT0-DECOMPILED.md`：text0 全函数反编译说明与失败核查
- `docs/SMONITOR-TEXT1-ENCODING.md`：text1 编码格式分析
- `docs/SMONITOR-TEXT01-LINEARIZED.md`：早期 Unicorn 轨迹线性化
- `docs/REBOOT-MECHANISM.md`：保护/重启/协议相关的动态实验记录
- `docs/DEOBFUSCATION.md`、`docs/VM-PROTECTION.md`：混淆与反调试分析

## 复现要点

1. 用 rizin + rz-ghidra 批量反编译 text0：

       rizin -q -c 'e scr.color=0' -c 's 0x46e265' -c 'af' -c 'pdg' -c 'q' analysis/unpacked-auto/Smonitor-stage2.exe

2. 生成并集指令清单：

       analysis/tmp/univenv/bin/python analysis/tmp/text01_full.py

3. 动态逐指令追踪（需要 Unicorn 环境与 smon_live_map.json 等运行时快照）：

       analysis/tmp/univenv/bin/python analysis/tmp/text01_dyn.py

4. text1 编码分析：

       analysis/tmp/univenv/bin/python analysis/tmp/text1_encoding.py

注意：脚本依赖 `analysis/tmp/` 下的运行时快照与二进制（未纳入本仓库，体积与敏感性原因），
复现前需先准备对应 VM 快照与 unpacked 二进制。

## 已知限制

- text0 仍有约 1/3 字节没有函数入口，按数据/VM 载荷处理；
- rz-ghidra 输出受混淆栈帧影响，寄存器语义需结合执行轨迹阅读；
- text1 的压缩/加密算法未识别；解包器未定位；
- 动态追踪只覆盖已触发过的命令路径。