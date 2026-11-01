# Student-stage2 混淆层 CFG 提取（Unicorn 具体执行）

## 方法

脚本 analysis/tmp/uni_cfg3.py：

- 把 Student-stage2 映像映射到 0x400000；
- 用活进程内存 dump（up_Student_Student.exe-20261031-184631.bin）覆盖 .data/BSS，
  因为保护层在全局里存的是运行期编码指针；
- 伪造 self、栈、TEB，从指定入口具体执行；
- 记录执行过的 EIP，按 call/jmp/ret/条件跳转切基本块，记录块间边；
- 遇到 fetch 未映射时记录外部跳转目标，并通过 lib 导出表反推 lib 基址
  （多个目标共同约束出 0xcb0000），把目标映射成导出名；
- 输出 analysis/tmp/cfg/<场景>.json 与 .dot。

## 场景与结果

| 场景 | 入口 | 参数 | 步数 | 块 | 边 | 外部目标 |
|---|---|---|---|---|---|---|
| exec_mode1 | 0x5854a4 | EDX=1 | 54 | 10 | 9 | lib!ShutWindow (0xac9a0) |
| exec_mode2 | 0x5854a4 | EDX=2 | 54 | 10 | 9 | lib!ShutWindow (0xac9a0) |
| shutdown_flow | 0x585370 | EDX=0 | 68 | 14 | 13 | lib!ShutWindow |
| restart_flow | 0x585404 | EDX=0 | 68 | 14 | 13 | lib!ShutWindow |
| shutdown_confirm | 0x585370 | EDX=1 | 58 | 11 | 10 | lib!ShowBoxYN (0xac7c0) |
| restart_confirm | 0x585404 | EDX=1 | 58 | 11 | 10 | lib!ShowBoxYN (0xac7c0) |
| restart_countdown | 0x585404 | EDX=0, count=30 | 28 | 8 | 7 | 0x94（UI 助手路径，模拟无法继续） |

## 解读

- 执行器（0x5854a4）无论 mode=1/2，经过 0x561840 -> 0x5ee145 -> ... 的混淆跳板后，
  最终都是尾调用 lib!ShutWindow(mode,-1,-1)；mode=1 重启、mode=2 关机。
- 流程函数在 confirm 参数（EDX=1）时先调用 lib!ShowBoxYN 弹确认框，确认后才进入
  倒计时/执行器；EDX=0 且倒计时为 0 时直接进入执行器。
- 倒计时分支调用 UI 助手（0x561a28 方向）后进入 GUI/导入表相关代码，当前模拟环境
  （未映射 lib 与 Win32 导入解析）无法继续，但静态逻辑已在伪代码里确认：
  对话框到期后触发执行器。

## 局限

- 每个场景只覆盖一条具体路径（分支靠参数/全局值控制），不是完整符号化 CFG；
- self 对象和部分全局是伪造/取自旧 dump，具体值可能影响分支；
- lib 未映射进模拟器，执行到第一个 lib 导出即停止（正好给出边界结论）。

## 产物

- analysis/tmp/uni_cfg3.py（提取器）
- analysis/tmp/cfg/*.json、*.dot（7 个场景）
