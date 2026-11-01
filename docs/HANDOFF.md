# 伽卡他卡电子教室 17.8 逆向分析交接

更新时间：2026-10-31 17:56 CST（17:30 后补充动态验证，见 analysis/DYNAMIC.md）

## 1. 目标与约束

目标是解释伽卡他卡电子教室学生端的以下行为，并找出触发条件：

- 任务管理器出现后立即被关闭；
- CMD、PowerShell 可能触发学生电脑重启；
- 学生端进程和伴随服务被杀后会被恢复；
- 学校电脑上的学生端**不连接教师端**，但仍会自行检测 CMD/PowerShell 并重启；
- 需要确认是否能够阻止强制重启，以及阻止点位于哪一层。

硬约束：

- 不在宿主机原生运行样本；只允许在隔离 Windows QEMU 中动态运行；
- 不把实验网桥接到真实校园网；
- 当前学生机和教师机使用持久磁盘，**不要再加 `-snapshot`**；
- 当前虚拟机实验环境仍可能在运行，除非用户明确要求，不要关闭 QEMU 或删除磁盘；
- QEMU HMP monitor socket 同一时间只接受一个客户端，切换前先关闭旧连接。

## 2. 当前最重要的事实

用户后来纠正了一个关键前提：

> 学校电脑上的学生端不连接教师端，自己检测到 CMD/PowerShell 就会重启。

因此，教师端通过协议 `0x11` 下发重启的结论只能解释教师在线场景，**不能作为学校
离线重启行为的最终解释**。下一阶段必须重点追学生端本地的
`IsConsoleActive`/控制台检测与 `lib.dll!ShutWindow` 调用链。

静态分析目前遇到的主要困难：

- `Student-stage2.exe` 中没有明文 `cmd.exe`、`powershell.exe`、`pwsh.exe` 或
  “命令提示符”字符串；
- `lib-stage2.dll` 中也没有这些明文匹配项；
- Student 的 PE 导入表被裁减，只静态导入 `lib.dll!ClientInfoFA`，大量 lib 调用
  通过自定义加载/间接分派完成；
- Student 的 Delphi 运行时代码经过混淆，Ghidra 对部分函数边界和间接调用恢复不完整。

不能因为“没有字符串”就断言不存在本地检测。当前更可能的情况是：

1. 以控制台窗口/会话属性做通用检测，而不是比较 `cmd.exe` 文件名；
2. 规则数据经过加密、哈希或运行时构造；
3. 学校安装的是不同版本、不同下发的策略包或定制版；
4. 检测逻辑位于 Student 运行时解密/动态解析的模块中。

## 3. 证据与产物

完整静态报告：

```text
analysis/REPORT.md
```

重点章节：

- 第 3-5 节：任务管理器、进程枚举/终止、防杀和重新拉起；
- 第 6 节：`ShutWindow` 底层能力；
- 第 11-13 节：实测现象、开机自启和教师端软件黑名单；
- 第 14 节：教师端 `0x11` 重启/关机命令链。

原始安装包：

| 文件 | SHA-256 |
|---|---|
| `netclassv17.8.exe` | `8be6dadf9dcad9c12a993351a1f7cb536a09ec3ab958f154d60f9b185821d911` |
| `netclass_teacher_v17.8.exe` | `345036f3f493f7b02d39b564c85b1d54176ce1be228d8be6543b91d031e783cb` |

主要脱壳产物：

| 产物 | SHA-256 |
|---|---|
| `analysis/unpacked-auto/lib-stage2.dll` | `df13edbba3bf589d725c15e5d1c0409cfdeb123bd3e57c5a7726249ddd6b1861` |
| `analysis/unpacked-auto/Student-stage2.exe` | `b21c2412f65f7963211c60ea60f50bec4d0293d0019275aa28d89b2ecc0e4883` |
| `analysis/unpacked-auto/Smonitor-stage2.exe` | `96d990bf8995b3b36b940dcb4430547e7e5f3a00b334807422f3c7e2e1145c74` |
| `analysis/unpacked-auto/Teacher-stage2.exe` | `4697f1ee203f69b6b546c33546d3bbfbb675c9c06ca7da92dd8cfe3de5319dd5` |

REA/Ghidra 会话快照：

```text
analysis/rea-lib-unpacked-session.reatar
analysis/rea-student-stage2.reatar
analysis/rea-student-restart32.reatar
analysis/rea-student-autostart.reatar
analysis/rea-smonitor-stage2.reatar
analysis/rea-teacher-stage2.reatar
```

## 4. 已确认的静态结论

### 4.1 任务管理器为什么立即消失

`Smonitor.exe` 注册为自动启动的 `Smsvc` LocalSystem 服务。其 100 ms 定时器在开关
置位时直接查找并终止：

```text
taskmgr.exe
perfmon.exe
```

同时 `lib.dll!DisableTaskMgr` 可以写入当前用户的：

```text
Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr = 1
```

因此任务管理器问题至少有两层：系统策略和 100 ms 用户态轮询终止。

### 4.2 防杀和重新拉起

- `StartKillPro` 启动 `TProKillThd`，按目标名称/路径轮询并终止进程；
- `StartMonPro/StartMonPro2` 启动 `TProMonThd`，发现被监视进程不在时调用
  `WinExec(..., SW_SHOWNORMAL)` 拉起；
- `Smsvc` 服务失败恢复配置为 60 秒后重启服务；
- `config.cfg` 中 `ar=1` 让服务持续检查并拉起 `Student.exe`；
- `ms=0` 不能解释成“保护关闭”，当前已安装快照中确实同时存在 `ms=0` 和 `ar=1`。

`taskkill` 报“找不到进程”与以下事实相符：持久组件主要是服务 `Smsvc` 和
`Smonitor.exe`，不能只看前台 `Student.exe`；同时还要考虑权限、会话隔离和服务
保护。

### 4.3 底层强制重启/关机能力

`lib-stage2.dll!ShutWindow`：

```text
VA     0x4ac9a0
export ordinal 408
```

已确认动作映射：

```text
参数 0 -> 不重启，关机
参数 1 -> 重启
其他   -> 断电关机
```

主路径可以调用：

```text
NtShutdownSystem
ZwShutdownSystem
RtlAdjustPrivilege
```

旧接口回退路径使用与 `ExitWindowsEx` 高度一致的标志：

```text
action 0 -> 0x04 = EWX_FORCE
action 1 -> 0x06 = EWX_REBOOT | EWX_FORCE
action 2 -> 0x0d = EWX_SHUTDOWN | EWX_FORCE | EWX_POWEROFF
```

所以“强制重启”底层能力是确定的。尚缺的是学校离线环境中是谁调用
`ShutWindow(1)`。

### 4.4 教师端远程重启链路

这部分独立于学校离线场景，但仍保留用于区分实验环境行为。

教师端公共发送函数：

```text
Teacher-stage2.exe!FUN_005b95f4
```

命令格式：

```text
byte[0] = 命令号
byte[1] = 子类型/动作
byte[2..] = 倒计时字符串
```

命令 `0x11`：

```text
0x11,0 -> Student-stage2.exe!0x585370 -> 关闭电脑
0x11,1 -> Student-stage2.exe!0x585404 -> 重启电脑
```

Student 命令处理器为 `Student-stage2.exe!0x5833d0`，它把 `packet+2` 解析为
倒计时整数。倒计时大于零时显示“%d 秒后将关闭/重启电脑”；否则立即投递动作。

教师端直接发送 `0x11` 的静态位置：

| 地址 | 子类型 | 场景 |
|---|---:|---|
| `0x5b185b` | 0 | 退出教师端并关闭学生电脑 |
| `0x5b683b` | 0 | 手动关闭所有/选中学生电脑 |
| `0x5b6963` | 1 | 手动重启所有/选中学生电脑 |
| `0x5b7c2a` | 0 | 手动关闭单台学生电脑 |
| `0x5b7d1a` | 1 | 手动重启单台学生电脑 |

结论：教师在线且有策略下发时，`0x11,1` 是已证实的系统重启入口；但它不是学校
离线场景的答案。

## 5. 本轮新增的本地窗口/会话监控线索

`lib-stage2.dll` 的导出表中存在以下本地控制函数：

| 导出 | Ordinal | VA | 当前认识 |
|---|---:|---|---|
| `StartMonPro` | 255 | `0x4aa6a4` | 本地进程监视包装 |
| `CloseWindowCN` | 261 | `0x4aa650` | 按窗口类和标题关闭窗口 |
| `CloseWindow` | 262 | `0x4aa618` | 关闭指定窗口及其子窗口 |
| `IsConsoleActive` | 344 | `0x4adf6c` | 枚举 WTS 会话，判断活动控制台会话 |
| `ShutWindow` | 408 | `0x4ac9a0` | 系统关机/重启/断电 |

### 5.1 `IsConsoleActive`

`IsConsoleActive` 延迟解析并使用：

```text
wtsapi32.dll!WTSEnumerateSessionsA
wtsapi32.dll!WTSQuerySessionInformationA
wtsapi32.dll!WTSQueryUserToken
wtsapi32.dll!WTSFreeMemory
```

返回 `-1` 表示没有找到活动控制台会话；其他返回值表示控制台会话 ID。
该函数本身**不重启系统**，但很可能是上层本地保护逻辑用来判断“用户是否在交互
控制台中执行程序”的条件。

### 5.2 `StartMonWindow` 与 `CloseWindowCN`

`StartMonWindow` 创建窗口监视线程。当前恢复出的 `CloseWindowCN` 目标包括：

```text
类 #32770，标题“Internet 协议 (TCP/IP) 属性”
类 #32770，标题“Internet 协议版本 4 (TCP/IPv4) 属性”
类 Windows.UI.Core.CoreWindow，标题“任务视图”
```

这说明学生端确实有本地窗口监控/关闭机制，但目前恢复出的固定目标不包含 CMD 或
PowerShell。不能把“任务视图/网络设置被关闭”误写成 CMD 重启路径。

### 5.3 Student 本地重启仍未闭合

目前证据边界：

```text
Student 收到 0x11 子类型 1 -> 0x585404 -> 重启处理
lib!ShutWindow(1)         -> 真正重启
```

尚未恢复：

```text
离线 Student 监控线程 -> 检测控制台/CMD/PowerShell -> 调用 ShutWindow(1)
```

下一步的最高优先级是动态取得 `lib!ShutWindow` 被调用时的调用栈。返回地址会直接
指出是 Student 本地代码、教师协议处理，还是另一个动态模块。

## 6. QEMU 实验环境

### 6.1 学生机

目录：

```text
vm/win10-22h2/
```

规格：

```text
q35 + KVM
4 vCPU（1 socket x 2 cores x 2 threads）
8192 MiB RAM
UEFI/OVMF
100 GiB sparse raw 持久盘
WSLg GTK 显示
NAT e1000e
实验网 e1000e
```

实验网：

```text
QEMU multicast: 230.0.0.1:1234
MAC: 52:54:00:00:10:10
IP: 192.168.50.10/24
```

端口：

```text
宿主机 127.0.0.1:13389 -> 客户机 3389
宿主机 127.0.0.1:13390 -> 客户机 5985
```

关键文件：

```text
windows10.raw       当前持久实验盘
windows10-clean.raw 未安装电子教室的干净副本
windows10-base.raw  学生端安装后的归档副本
OVMF_VARS.fd        UEFI 变量
monitor.sock        HMP
qmp.sock            QMP
labnet.pcap         学生实验网抓包
```

### 6.2 教师机

目录：

```text
vm/win10-teacher-22h2/
```

实验网：

```text
QEMU multicast: 230.0.0.1:1234
MAC: 52:54:00:00:10:11
IP: 192.168.50.1/24
```

端口：

```text
宿主机 127.0.0.1:23389 -> 客户机 3389
宿主机 127.0.0.1:23390 -> 客户机 5985
```

关键文件：

```text
windows10.raw  当前持久教师盘
monitor.sock   HMP
qmp.sock       QMP
```

实验网抓包：

```text
vm/win10-22h2/labnet.pcap
vm/captures/teacher-labnet.pcap
```

截至交接时，两个 pcap 的最后写入时间均为 2026-10-31 16:37，文件仍在增长，说明
QEMU 实验环境大概率仍活跃。不要只凭沙箱内 `ps` 看不到进程就判断虚拟机已停止；
当前沙箱的进程视图与宿主 WSL 进程视图可能隔离。

此前记录的终端 session ID：

```text
学生 QEMU   6082
教师 QEMU   70973
HTTP 8000   90927
HTTP 8001   1848
```

这些 ID 只对原终端会话有效，不能跨环境重启复用。优先通过 monitor socket、
端口和脚本判断状态。

## 7. 操作辅助工具

键盘输入：

```text
vm/qemu-type.py
```

鼠标/绝对坐标点击：

```text
vm/qemu-qmp-click.py
```

实验网配置：

```text
vm/setup-lab-network.ps1 -Role student
vm/setup-lab-network.ps1 -Role teacher
```

启动脚本：

```text
vm/win10-22h2/run-vm.sh run
vm/win10-teacher-22h2/run-teacher.sh run
```

进入 HMP 前先确认没有旧 `ncat`/`socat` 客户端占用 socket。HMP 同一时间只允许一个
客户端连接。

## 8. 当前实验状态与已知差异

在最近一次已记录的实验状态中：

- 教师机与学生机已连接；
- 教师端显示“学生端已保护”；
- 任务管理器会立即被关闭；
- CMD/PowerShell 仍能打开，没有出现学校电脑上的立即重启；
- 软件控制曾下发：

```text
0c 02 "cmd.exe,powershell.exe,pwsh.exe" 00
```

- 但实验机的黑名单匹配/处理结果与学校离线电脑并不一致。

这个差异不能被简单解释成“实验没配好”。用户的学校环境明确不需要教师端连接，
因此后续应把教师网卡断开，确认学生端仍可独立触发重启，然后再追本地调用栈。

另一个潜在差异是版本/策略包。若获授权，应优先从学校终端获取并核对：

```text
Student.exe
Smonitor.exe
lib.dll
config/config.cfg
Smsvc 服务配置
```

至少计算 SHA-256，确认是否与本地 17.8 安装包完全一致。版本不同会导致现有地址和
判定逻辑不能直接套用。

## 9. 建议的下一步动态验证

### 9.1 先证明是纯离线触发

1. 不关闭学生 QEMU；
2. 让教师 VM 离线，或断开教师实验网卡；
3. 确认学生端仍在运行、`Smsvc` 仍在运行；
4. 再次打开 CMD 和 PowerShell；
5. 记录重启是否仍发生。

若仍重启，即可排除教师端实时下发。

### 9.2 捕获重启前的完整事件

在客户机内启用：

```text
Process Monitor
  - Process/Thread Create/Exit
  - Registry SetValue
  - File Write
  - Network TCP/UDP
  - 关注 Student.exe、Smonitor.exe、cmd.exe、powershell.exe

WPR/ETW
  - Microsoft-Windows-Kernel-Process
  - Microsoft-Windows-Kernel-Registry
  - Microsoft-Windows-TaskScheduler
```

Windows 开机后立即把日志复制出客户机。系统一旦重启，内存中的现场会丢失。

### 9.3 动态断点

优先按导出名而不是写死 VA：

```text
lib.dll!ShutWindow
lib.dll!IsConsoleActive
lib.dll!StartMonWindow
lib.dll!CloseWindowCN
```

脱壳静态镜像中可用的 RVA：

```text
lib!ShutWindow        RVA 0x0ac9a0
lib!IsConsoleActive   RVA 0x0adf6c
Student!0x585404      RVA 0x185404
Student!0x5854a4      RVA 0x1854a4
```

断在 `ShutWindow` 时重点记录：

- 调用线程；
- 返回地址；
- 参数值；
- 模块基址与所属模块；
- 调用前的最后窗口标题、前台窗口、进程名；
- 是否存在 `0x11` 网络报文。

### 9.4 判定树

```text
CMD/PowerShell 启动
  |
  +-- 是否收到 0x11,1？
  |     |
  |     +-- 是：谁发送？教师、缓存策略服务、其他本地组件
  |     +-- 否：继续
  |
  +-- Student 是否直接调用 ShutWindow？
        |
        +-- 是：记录返回地址和上层条件
        +-- 否：其他模块/服务调用？
```

### 9.5 网络侧

即使没有教师端，也要保留抓包以排除：

- 云端/更新服务器的任务下发；
- 本机其他伽卡他卡进程的 IPC 或 UDP；
- 学校环境中被遗忘的本地策略服务。

重启前最后一个自定义协议报文的命令字节尤其重要。`0x11` 是已确认的重启/关机
命令号。

## 10. 当前结论清单

已证实：

- 任务管理器有 `DisableTaskMgr` 策略层和 `Smsvc` 定时终止层；
- `Smonitor`/`Smsvc` 有自动启动、进程拉起和失败恢复能力；
- `lib.dll!ShutWindow` 能通过 Nt/Zw 路径或强制 `ExitWindowsEx` 路径重启；
- 教师在线场景中的 `0x11,1` 会进入 Student 重启处理；
- `lib.dll` 有本地窗口监控和活动控制台会话检测能力；
- 当前恢复出的固定窗口关闭目标主要是网络属性对话框和任务视图。

尚未闭合：

- 学校离线 Student 本地检测 CMD/PowerShell 的具体条件；
- 本地检测调用 `ShutWindow(1)` 的准确代码位置和调用栈；
- CMD/PowerShell 是按控制台窗口类型、进程名、窗口标题还是加密策略名单识别；
- 学校程序哈希是否与本地 17.8 样本一致；
- 是否存在教师端以外的云端、服务或持久策略通道。

## 11. 安全与实验边界

- 分析仅限用户控制的隔离虚拟机；
- 不经由实验网桥接校园网；
- 不提供绕过学校管理策略的操作步骤；
- 若要处理学校终端，应由设备管理员在教师端撤销对应限制、处置服务或在获授权后
  正式卸载客户端；
- 动态测试可能瞬间触发客户机重启，执行前应确认持久盘状态和日志落盘位置。

## 12. 17:56 动态验证更新（本轮）

本轮已启动学生机（离线，教师机未启动）并完成动态实验，详细记录见 `analysis/DYNAMIC.md`。
与第 10 节结论相关的更新：

- 确认教师 0x0c 黑名单会持久化到 `config.cfg`（`stc=2`、`stcw` 密文），解释了离线仍有软件控制；实测动作为“关闭标题匹配窗口”，`stc=0` 即关闭该行为。
- 挂起 Student.exe 可阻止关窗口，恢复后继续关闭；执行者是 Student.exe，不是 Smonitor/Smsvc。
- 本机 17.8 全过程中未复现“打开 CMD/PowerShell 自动重启”，两个 pcap 也没有 0x11。
- 学校终端“离线重启”仍未闭合，下一步应取得学校端的程序与 config.cfg 哈希/内容比对；不要把它并入已证实的 0x11 教师命令链。

