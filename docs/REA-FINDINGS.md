# REA/Ghidra 复核结果（2026-10-31 18:40）

## 为什么改用 REA

之前的字节扫描只能证明“某地址有调用”，不能给出调用关系全貌。本轮用 REA（Ghidra 12.1.2）
对两个脱壳镜像做了正式反编译与交叉引用查询。

## Student-stage2.exe

- REA 反编译命令分派函数 FUN_005833d0：switch 覆盖 case 0..0x28；case 0x11 读取倒计时后
  调用 FUN_00585370（关机）或 FUN_00585404（重启）。
- procedure_callers(FUN_00585404) = ["0x5833d0"]，procedure_callers(FUN_00585370) = ["0x5833d0"]；
  即重启/关机只由网络命令分派入口调用。
- FUN_005833d0 本身没有静态调用者（由网络层经间接分发调用），与报告结论一致。
- 多个 case（0x18、0x1a、0x1e、0x1f、0x24、0x25 等）会跳进 0x5e8xxx-0x5ea5xx 的保护层函数，
  Ghidra 只能显示 thunk，反编译不完整。

## Smonitor-stage2.exe

- REA 的自动分析只覆盖 CODE 段的一部分；服务逻辑区 0x458200-0x458e18 没有函数
  （脱壳镜像入口/引用被破坏，Ghidra 递归分析到不了）。
- 为绕过这一点，复制镜像并只改 AddressOfEntryPoint 到目标地址，再让 Ghidra 从入口建函数。
  用该方法成功反编译服务命令处理器 0x4589f8：命令字节 Q/R/S/T/U/V/W/X
  - S(0x53)：设置 +0xfb = (参数==1)（taskmgr/perfmon 清理开关）
  - T(0x54)：设置 +0xf8 = (参数==1) 并持久化 ar
  - U(0x55)：参数 1 调 0x4795cc，否则调 0x47a71c
  - V(0x56)：参数 1 调 0x479800，否则调 0x4731c9
- U/V 指向 0x46e000+ 的 .text0/.text1 区段，反汇编结果为 pusha/xchg/乱跳，说明这是
  脱壳器保留的混淆/保护层，不是可直接反编译的常规代码。设备监控、违规处理这类逻辑
  很可能就在这一层，因此字符串扫描和 Ghidra xref 都找不到。
- Smonitor 进程在 config 的 mt=49670 端口监听，Student 主动连 127.0.0.1:49670
  （实验机 netstat 实测），服务以 LocalSystem 运行，具备直接关机/发命令的权限。

## 结论边界

- 在可反编译的代码里，重启唯一入口是网络命令 0x11。
- Smonitor 的隐藏层（System 权限）是唯一能在本地执行违规处理并触发重启的组件候选；
  要证实必须解开这一层，或让目标机出现该状态。
- REA 本身无法强制为未分析区域建函数（只有 decompile/analysis 接口），
  Ghidra headless 在当前沙箱写缓存目录被拒；本次用入口点补丁副本绕过，产物：
  analysis/unpacked-auto/Smonitor-entry-handler.exe、Smonitor-entry-timer.exe。
