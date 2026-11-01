# 伽卡他卡电子教室 17.8 静态逆向报告

分析日期：2026-10-31  
分析对象：学生端安装包及其 `app/lib.dll`  
约束：没有在宿主机原生启动样本；脱壳只使用 Unicorn/Unipacker 模拟执行，函数语义通过 Ghidra 静态反编译恢复。

## 1. 结论摘要

已经确认学生端 `lib.dll` 不是单纯 UI 模块，而是一个包含系统控制能力的常驻功能库。与本问题直接相关的机制有四层：

1. `DisableTaskMgr` 把当前用户的 `DisableTaskMgr` 策略写成 `1`，从系统策略层关闭任务管理器。
2. `Smonitor.exe` 实际注册为 `Smsvc` 服务；其 100 ms 定时器在开关置位时显式杀死 `taskmgr.exe` 和 `perfmon.exe`，与“任务管理器启动后立即消失”的现象直接吻合。
3. `StartKillPro` 创建 `TProKillThd` 轮询线程；线程按名称/路径查找被禁进程，找到后打开进程句柄并终止。
4. `StartMonPro/StartMonPro2` 创建 `TProMonThd` 守护线程；目标进程不存在时调用 `WinExec(..., SW_SHOWNORMAL)` 将其重新拉起。
5. `ShutWindow` 可按动作编号执行普通关机、重启或断电关机；`Student.exe` 内另有面向用户的关机/重启提示和倒计时入口。

需要严格区分的是：

- 已确认的是 `lib.dll` 的“能力实现”；
- `StartKillPro`、`ShutWindow` 等入口在 `lib.dll` 内没有业务调用者，只有导出表引用，因此真正触发它们的是上层 `Student.exe`、教师端命令或其他动态调用者；
- 现镜像未恢复“哪个协议命令、哪次本地检测、何种阈值会导致重启”的完整判定代码。不能仅凭本报告把所有重启都归因于本地检测。

发行包中仍未发现 `.sys` 内核驱动。现有证据指向用户态策略限制、用户态进程枚举/终止和用户态守护线程。

## 2. 样本与脱壳产物

原始安装包：

| 文件 | SHA-256 |
|---|---|
| `netclassv17.8.exe` | `8be6dadf9dcad9c12a993351a1f7cb536a09ec3ab958f154d60f9b185821d911` |
| `netclass_teacher_v17.8.exe` | `345036f3f493f7b02d39b564c85b1d54176ce1be228d8be6543b91d031e783cb` |

`innoextract` 解出的学生端核心模块：

| 模块 | SHA-256 | 作用 |
|---|---|---|
| `app/Student.exe` | `25f403758bb0d8428632cac67946a1db400bb128dd43c4734f7c15041b198d1d` | 学生端主程序 |
| `app/Smonitor.exe` | `05862f6c1ddbd4cff1ec6b1087dda9413377f5e72be74910bddde9f9a44276a1` | 学生包独有伴随/监视程序 |
| `app/lib.dll` | `cd4060506c4505fad0ff8a7e54d66bb04b72c138b86f1a03a562b8202fd0a0ee` | 控制、进程、钩子、关机等主要导出模块 |
| `app/libx.dll` | `9a4ece196d637c281c858f3d27ee74022efc8da296af296050db14f7e4615eef` | UPX 小型辅助 DLL |

原始 `lib.dll` 的常见代码/数据节 raw size 为 0，业务代码位于高熵节。使用 Unipacker 在 Unicorn 中模拟脱壳后得到：

| 产物 | SHA-256 | 状态 |
|---|---|---|
| `analysis/unpacked-auto/lib-stage1.dll` | `d2012356b47aea7dd467134c8f851c3b8e4c8862c026cc4e84413485fe6ff0cd` | 过早转储，关键函数仍为 0 |
| `analysis/unpacked-auto/lib-stage2.dll` | `df13edbba3bf589d725c15e5d1c0409cfdeb123bd3e57c5a7726249ddd6b1861` | 代码已解密；Ghidra 识别约 7164 个函数、3131 个字符串 |

第二阶段镜像的导入目录仍不完整，Ghidra/objdump 会报异常 RVA。因此本文把两部分证据分开标注：

- 函数体、常量、字符串和交叉引用来自 `lib-stage2.dll` 的静态分析；
- `OpenProcess`、`TerminateProcess`、`WinExec`、Toolhelp、令牌和桌面 API 的完整名称清单来自 Unipacker 模拟加载器重建的内存导入表。

随后使用低开销 API/业务入口探针，在第一次从解包后的 `CODE` 区域调用导入函数时停止并转储，得到：

| 产物 | SHA-256 |
|---|---|
| `analysis/unpacked-auto/Student-stage2.exe` | `b21c2412f65f7963211c60ea60f50bec4d0293d0019275aa28d89b2ecc0e4883` |
| `analysis/unpacked-auto/Smonitor-stage2.exe` | `96d990bf8995b3b36b940dcb4430547e7e5f3a00b334807422f3c7e2e1145c74` |
| `analysis/unpacked-auto/Teacher-stage2.exe` | `4697f1ee203f69b6b546c33546d3bbfbb675c9c06ca7da92dd8cfe3de5319dd5` |

`Student-stage2.exe` 的 PE 入口字段被 Unipacker 写坏，但解密后的 `CODE`、资源和大量业务字符串已经可分析，Ghidra 识别约 7410 个函数。较早的 `analysis/unpacked-auto/Student-stage1-attempt.exe` 仍保留为失败尝试记录。

## 3. 任务管理器禁用：已证实

### 3.1 调用链

```text
DisableTaskMgr()
  -> FUN_004af61c(1)
     -> FUN_004ac70c(
          HKEY_CURRENT_USER,
          "Software\Microsoft\Windows\CurrentVersion\Policies\System",
          "DisableTaskMgr",
          1)
```

关键地址：

| 名称 | VA | Evidence |
|---|---:|---|
| `DisableTaskMgr` | `0x4af680` | `ev_2bca65a0d4aab55df6c37f1d09e31b07757618305fd9163679f59f04bb39f904` |
| 策略写入包装 | `0x4af61c` | `ev_2cfff9d6a30f8485579e69addf6966f3d7aeb3bcd0aae9524c155e08ba766da8` |
| 通用注册表写入函数 | `0x4ac70c` | `ev_0f83f2766d793b2d742cc6eef7a5d33a9a172b5b5a58cfd26c394fcd4d06cf06` |
| 原始字符串区 | `0x4af620` | `ev_fbb4032428eaf2131cf9a2a85d792dcd3164f5cf1c1d65f70dce5b32b9e3ac5f` |

`FUN_004ac70c` 的指令参数与 Win32 注册表 API 对齐：

```c
RegCreateKeyExA(
    HKEY_CURRENT_USER,
    subkey,
    0, 0, 0,
    KEY_WOW64_32KEY | KEY_SET_VALUE,   // 0x20006
    NULL,
    &key,
    NULL);

RegSetValueExA(
    key,
    "DisableTaskMgr",
    0,
    REG_DWORD,
    &value,
    4);

RegCloseKey(key);
```

因此 `DisableTaskMgr()` 写入的是当前用户 DWORD `1`；`EnableTaskMgr()` 走同一路径写入 `0`。这是“策略禁用”，不是伪造任务管理器窗口，也不是阻止所有进程创建。

## 4. 进程枚举与终止：核心链已证实，API 名称有一层推断

### 4.1 `KillProc`

```text
KillProc(target)
  pid = GetProcId(target)
  if pid != 0:
      TermProc(pid)
```

- `KillProc`：`0x4a9a58`
- `GetProcId`：`0x4a960c`
- `GetProcIdBySId`：`0x4a9364`
- `GetProcName`：`0x4a9910`
- `TermProc`：`0x4a9a78`

Evidence：

- `KillProc`：`ev_8ce0c4300de2e69cb663fc206ceabbcb8ab09c0661744687b1b753b03c3ba8e9`
- `GetProcIdBySId`：`ev_1bf040743b3da7b5f2400d6dd4f4855ae353b4d21d21502044048581d73857b2`
- `GetProcName`：`ev_c3796fc7a0f0512f92aef9a3a85fd3a965aed61b0341aa341b49281e3b590694`
- `TermProc` 指令：`ev_4b4e67847a60b8dd0fd57cd1893d847ebbcfe6beb13d29fd3912f37488f59dfa`

### 4.2 枚举逻辑

`GetProcIdBySId` 先加载 `kernel32.dll`，按名字取得 Toolhelp API，然后：

1. 调用 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS = 2, 0)`。
2. 将进程项结构的首字段设为 `0x128`，对应 32 位 `PROCESSENTRY32A`。
3. 调用 `Process32First`，失败则退出。
4. 循环调用 `Process32Next`，每次从快照项取得 PID。
5. 用 `OpenProcess` + PSAPI `GetModuleFileNameExA` 解析该 PID 的可执行路径。
6. 与传入的目标名称/路径做大小写不敏感比较。
7. 若第二个参数不是 `-1`，还要求 PID 完全相等。

Toolhelp 名称已直接在镜像中确认：

```text
kernel32.dll
CreateToolhelp32Snapshot
Process32First
Process32Next
```

字符串数据 Evidence：`ev_e4a17d96b5432ead9505bf2e7b209c0f529728f99792616e3f3d8dd1a1309490`。  
PSAPI 与 `GetModuleFileNameExA` 字符串：`ev_7db23c5eb6c44b0b177433c6f866d080854b4b7350e7e7e6785427c585c22a1c`、`ev_9424d252e528659e11e1d5f31d0a667b09147fbf9e7b13e75cc640109930ca38`。

### 4.3 `TermProc`

`TermProc(pid)` 的汇编为：

```asm
push 0
push pid
push 0
push 1
call 0x4077a0
push eax
call 0x407840
```

这与 `OpenProcess(PROCESS_TERMINATE=1, FALSE, pid)` 后对句柄执行终止操作完全吻合。Unipacker 重建导入表同时包含：

```text
OpenProcess
TerminateProcess
CloseHandle
```

由于中间经过 Delphi 动态导入分发器，本阶段不能把 `0x4077a0/0x407840` 的 API 名称当作 Ghidra 自动识别结果；结论应记为“高置信推断”，而不是“符号已直接解析”。

### 4.4 周期清理线程

导出 `StartKillPro` 在模块内没有业务调用者，只出现在导出表中。它构造 `TProKillThd`：

- 类名明文：`TProKillThd`
- VMT/类引用：`0x4a8f24`
- `Execute` 方法指针：`0x4ab5e8`
- 线程对象字段：`+0x40` 目标名称/路径，`+0x44` 轮询间隔

`TProKillThd.Execute` 的循环在 `[self+0xd] == 0` 时持续运行：

```c
while (!self->Terminated) {
    KillProc(self->target);      // self + 0x40
    Wait(self->interval);        // self + 0x44
}
```

“Terminated”和最后的等待函数名属于根据 Delphi `TThread` 布局及参数用途作出的推断；循环、目标字段、间隔字段和 `KillProc` 调用本身由指令确认。

镜像内没有字面量 `taskmgr.exe`、`cmd.exe`、`regedit.exe` 等名单。结合“只有导出入口、没有库内调用者”，名单应来自外部模块/教师端命令或运行时拼接，而不是写死在 `lib.dll`。这解释了为什么不同课堂策略可以启用不同清理名单。

## 5. 防杀与重新拉起：已恢复用户态守护线程

`StartMonPro2` 准备被监视程序路径；`StartMonPro` 是带默认参数的包装。真正执行守护逻辑的是 `TProMonThd.Execute`：

- 类名明文：`TProMonThd`
- 类引用：`0x4a8ea8`
- `Execute` 方法指针：`0x4ab4fc`
- `+0x40`：被监视的目标
- `+0x44`：可选的另一目标，若非空则先对其调用 `KillProc`
- `+0x48`：轮询间隔

伪代码等价于：

```c
while (!self->Terminated) {
    if (StrLen(self->killTarget) > 0)
        KillProc(self->killTarget);

    if (GetProcId(self->watchedTarget) == 0)
        WinExec(self->watchedTarget, SW_SHOWNORMAL);  // flags = 1

    Wait(self->interval);
}
```

Evidence：

- `StartMonPro2`：`ev_051b2f9b8f09f0db1673567cf6fa29bd7d43b0e06265d60b1957b95dbfc6f8b7`
- `TProMonThd` 运行时类数据：`ev_1436dd35239aec45efb110169aef0c1974f5d80b8f2749f89cb3d5ba68d41532`
- `TProMonThd.Execute` 原始指令：`objdump` 源范围 `0x4ab4fc..0x4ab58c`
- 构造函数：`ev_bafde699d47b944648e359edbdb7682f7a69205fa6c44fed01e67ae9292de56a`

`0x407870` 获得调用参数 `(target, 1)`，且 Unipacker 导入清单存在 `WinExec`，故将其标为 `WinExec(target, SW_SHOWNORMAL)` 的高置信推断。

### 5.1 `Smonitor.exe` 实际是 `Smsvc` 服务

`Smonitor-stage2.exe` 中已直接恢复出服务信息：

```text
Service name:   Smsvc
Display name:   Smonitor Service
Class:          TSmsvc
Timer:          tmr1，100 ms
```

相关 Evidence：

- `taskmgr.exe` 字符串：`ev_47863e5b21a381a22142908d1b9c3a36cb846d4636b657f527fb831a8030e362`
- `Student-stage2.exe` 总览：`ev_44b3711884092e5dc9f372e0137477308c26a1ac196b0ab392fdb882a3993eaf`
- 教师端进程预设列表原始字节：`ev_d4177e49a6d96a16bcec463fb912d96591e15b1e291d0de334a4b22448f4254a`
- `lib.dll!SetSvcFailure`：`ev_f2fc83738a6ae97ec0afa05e13af2bf374e50e1a40d0bc805304554777504d02`

`ServiceCreate` 位于 `0x458604`，将 `tmr1.Interval` 设为 `0x64` 并启用定时器。方法表清楚记录了：

```text
ServiceCreate  -> 0x458604
ServiceDestroy -> 0x4586c0
ServiceStart   -> 0x4586d0
tmr1Timer      -> 0x458788
```

这解释了为什么按普通前台程序去 `taskkill` 不对路：实际持久组件是 Windows 服务，服务名不是 `Smonitor.exe`。

### 5.2 任务管理器被二次终止

`tmr1Timer` 在 `[this+0xfb] != 0` 时执行：

```c
KillProc("taskmgr.exe");
KillProc("perfmon.exe");
```

两条字符串位于 `0x45883c` 和 `0x458848`。由于定时器是 100 ms，任务管理器即使成功创建窗口，也很容易在显示后立即被结束。这与用户实测现象一致。

`0x4589f8` 处的服务命令处理函数按首字节 `Q..X` 分派：

- `S` 分支把接收缓冲区第一个数据字节与 `1` 比较，并写入 `[this+0xfb]`；
- 因此该开关由运行时的控制命令设置，而不是固定为永远开启；
- `R` 分支还会处理 `Student.exe` 和 `lib.dll`，说明服务同时负责学生端相关恢复工作。

该命令处理函数是通过 Delphi 方法表间接调用的，因此 Ghidra 的普通直接 xref 没有把它自动串起来；字节级指令和方法表数据足以确认上述字段操作。

### 5.3 服务级防杀

`lib.dll!SetSvcFailure`（`0x4ae524`，Evidence `ev_f2fc83738a6ae97ec0afa05e13af2bf374e50e1a40d0bc805304554777504d02`）构造 `SERVICE_FAILURE_ACTIONS`：

```text
dwResetPeriod       = 86400 秒
cActions            = 3
SC_ACTION[0..2].Type  = SC_ACTION_RESTART (1)
SC_ACTION[0..2].Delay = 60000 ms
```

然后调用服务配置 API（参数等级为 `2`）。这表示服务被导致失败后，SCM 可在一分钟后重新启动它。因此“循环 taskkill”会遇到服务管理器恢复、用户态守护和重新拉起三层阻力。

## 6. 强制重启/关机：实现已证实，触发判据未知

### 6.1 导出 `ShutWindow`

`ShutWindow`：`0x4ac9a0`，导出序号 408。  
完整函数 Evidence：`ev_6c95c9823dc57ecb30dc35367ac2fc7ffa96198852e189a86da248e942cedeaa`

动作编号由 `FUN_004b213c` 映射：

```text
参数 0 -> SHUTDOWN_ACTION 0（不重启，关机）
参数 1 -> SHUTDOWN_ACTION 1（重启）
其他   -> SHUTDOWN_ACTION 2（断电关机）
```

映射函数 Evidence：`ev_a4596e3bb63d1ea3cdb5dd0596122f0f15fd4daccc48522b689979985a97f47c`

### 6.2 主路径

程序延迟解析 `ntdll.dll` 中的：

```text
NtShutdownSystem
RtlAdjustPrivilege
ZwShutdownSystem
```

解析函数 Evidence：`ev_6c1fd35522a101e9a967ea7d108ce93ed4c851e35f55335c571be9b38d9b1f47`

可用路径为：

```c
SeShutdown();                         // 启用 SeShutdownPrivilege
action = map_shutdown_action(code);
NtShutdownSystem(action);             // 0 关机 / 1 重启 / 2 断电
```

若走 `ZwShutdownSystem` 分支：

```c
action = map_shutdown_action(code);
RtlAdjustPrivilege(
    SE_SHUTDOWN_PRIVILEGE,            // 0x13
    TRUE,
    FALSE,
    &oldValue);
ZwShutdownSystem(action);
```

`SeShutdownPrivilege` 字符串位于 `0x4ac948`；`SeShutdown` 最终调用 `SetPrivilege(SeShutdownPrivilege, enabled)`，其内部通过令牌包装设置 `TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY`（`0x28`），再调用 `AdjustTokenPrivileges`。

### 6.3 回退路径

旧接口回退函数 `FUN_004ac95c` 按动作选择：

```text
code 0 -> 0x407ca8(0x04, 0)
code 1 -> 0x407ca8(0x06, 0)
code 2 -> 0x407ca8(0x0d, 0)
```

这些常量与旧式 `ExitWindowsEx` 标志高度吻合：

```text
0x04 = EWX_FORCE
0x06 = EWX_REBOOT | EWX_FORCE
0x0d = EWX_SHUTDOWN | EWX_FORCE | EWX_POWEROFF
```

因此回退分支存在强制重启路径，尤其是 `code=1` 时的 `0x06`。API 名称应标为“高置信推断”，因为该调用仍经过动态导入层。

### 6.4 谁能触发

`ShutWindow` 在 Ghidra 中唯一的内部 xref 是导出表项 `0x62ddfa`，没有 `lib.dll` 内的普通调用者。`SeShutdown` 也被直接导出。结论是：

- “强制重启”的底层能力确实存在；
- 本地检测逻辑与教师端命令协议位于调用 `ShutWindow` 的上层代码；
- 当前 `lib.dll` 镜像本身不能证明“检测到任务管理器/CMD 就立即重启”；
- 也不能排除该重启是教师端显式下发、看门狗超时或别的策略分支。

## 7. 运行时导入能力

Unipacker 模拟加载器恢复出的相关导入包括：

### kernel32

```text
OpenProcess
TerminateProcess
SuspendThread
ResumeThread
CreateProcessA
WinExec
Sleep
CreateToolhelp32Snapshot
Process32First
Process32Next
DeviceIoControl
```

### user32

```text
SetWindowsHookExA
UnhookWindowsHookEx
FindWindowA
FindWindowExA
EnumWindows
GetForegroundWindow
ExitWindowsEx
OpenInputDesktop
OpenDesktopA
```

### advapi32

```text
RegCreateKeyExA
RegSetValueExA
SetFileSecurityA
OpenProcessToken
AdjustTokenPrivileges
OpenSCManagerA
OpenServiceA
StartServiceA
ControlService
```

这些导入证明该库具备用户态进程清理、窗口/桌面控制、全局钩子、令牌特权、服务操作和关机能力。`StartMonPro` 在模块内没有业务调用者，进一步说明“何时启用哪组限制”主要由外部业务层决定。

## 8. 证据分界

| 主题 | 已观测/已证实 | 推断 | 仍未知 |
|---|---|---|---|
| 任务管理器 | 写入 HKCU 策略；`Smsvc` 每 100 ms 杀 `taskmgr.exe`/`perfmon.exe` | 任务管理器即使绕过策略启动，也会被服务定时器结束 | 哪个控制命令启用该开关 |
| 进程枚举 | Toolhelp 快照、`PROCESSENTRY32A`、PSAPI 路径解析、名称/PID 比较 | 用于禁止 CMD/注册表编辑器/调试工具 | 具体列表和动作字段的协议编码 |
| 进程终止 | `KillProc -> TermProc`，OpenProcess 参数形状 | 后续为 `TerminateProcess` | 动态 API 绑定未在静态导入表中恢复成符号 |
| 周期清理 | `TProKillThd.Execute` 循环和无内部调用者 | 外部业务层传入目标与间隔 | 具体轮询间隔值和名单下发格式 |
| 防杀恢复 | `TProMonThd.Execute` 用 `WinExec(...,1)` 拉起目标；`Smsvc` 配有 60 秒失败恢复 | 用于恢复 `Student.exe`/监视服务 | 服务恢复动作实际由哪个上层入口注册 |
| 重启 | `ShutWindow` 动作映射、Nt/Zw 调用、强制回退；`Student` 另有重启/关机用户提示和倒计时 | 动作 1 触发重启，动作 2 关机/断电 | CMD/PowerShell 命中的具体策略和上层命令 |

## 9. 复现方法

不要原生执行样本。当前可用流程是：

1. 用 `innoextract` 解包安装器。
2. 用 `analysis/unpack_first_business.py` 让 `lib.dll`、`Student.exe`、`Smonitor.exe`、`Teacher.exe` 在 Unicorn 中执行解包 stub。
3. 在写执行状态改变或首次进入已解密业务代码时转储第二阶段文件。
4. 用 REA + Ghidra 搜索 `DisableTaskMgr`、`KillProc`、`TProKillThd`、`TProMonThd`、`Smsvc`、`ShutWindow`、`NtShutdownSystem`。
5. 对 Delphi VMT 和方法表做解码，再检查对象偏移、虚方法及明确的方法指针。

建议关注的关键 VA：

```text
0x4af680  DisableTaskMgr
0x4af61c  DisableTaskMgr -> registry helper
0x4ac70c  registry setter
0x4a9a58  KillProc
0x4a9364  GetProcIdBySId
0x4a9a78  TermProc
0x4aa7f4  StartKillPro
0x4ab5e8  TProKillThd.Execute (raw method pointer)
0x4aa6a4  StartMonPro
0x4aa6c8  StartMonPro2
0x4ab49c  TProMonThd constructor
0x4ab4fc  TProMonThd.Execute (raw method pointer)
0x4ac9a0  ShutWindow
0x4ac928  SeShutdown
0x4ac930  SeShutdown2
0x4ac878  SetPrivilege
0x4ac3a8  resolve ntdll shutdown functions
```

## 10. 防御侧观测建议

在授权隔离环境中，若要验证实际触发条件，应优先采集：

- Registry：`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr`
- Process Create/Terminate：`Student.exe`、`Smonitor.exe`、目标工具和重新拉起的进程
- Image Load：`lib.dll`、`PSAPI.dll`、目标工具 DLL
- ETW：内核进程、注册表、线程创建/终止
- Windows 安全日志：`4688`、`4657`、`4672`
- 网络：教师端命令下发的方向、时序和重启前最后一次控制消息

这样才能把静态确认的“能力”与“哪个检测条件实际触发重启”对应起来。

## 11. 对照实测现象后的补充结论

用户实测：

- 任务管理器窗口能出现，但随后立即消失；
- `cmd.exe` 和 PowerShell 启动后马上触发系统重启；
- `taskkill /F /T /IM Student.exe /IM Smonitor.exe` 报找不到进程；
- 没有在用户态找到阻止强制重启的稳定办法。

这组现象与静态代码能够对应到两个不同层次：

| 现象 | 已能解释的部分 | 尚不能完全解释的部分 |
|---|---|---|
| 任务管理器立即关闭 | `Smsvc` 的 100 ms `tmr1Timer` 明确调用 `KillProc("taskmgr.exe")` 和 `KillProc("perfmon.exe")` | 哪个控制命令把 `+0xfb` 置为 1 |
| CMD/PowerShell 触发重启 | `Student-stage2.exe` 中存在显式关机 `0x585370`、重启 `0x585404` 和动作参数传递路径；教师端资源中有“命令提示符”、`Cmd.exe`、常用安全软件等预设进程项 | 具体由本地轮询、服务命令还是教师端“禁止运行程序”规则触发 |
| taskkill 报找不到 | 持久组件是名为 `Smsvc` 的服务，不是普通前台 `Student.exe`；服务还配置了失败自动恢复 | 当时具体进程名、会话权限和目标机器的策略 |

这里可以确定 `Smonitor.exe` **不是** CMD/PowerShell 重启的直接执行者：它静态引用的关机相关导入里没有 `ShutWindow`，且其专项清理字符串只有 `taskmgr.exe` 与 `perfmon.exe`。重启功能主要在 `Student.exe`/`lib.dll` 一侧。

在获授权的个人设备或实验环境中，排查持久化可以从只读状态开始：

```text
sc query Smsvc
sc qc Smsvc
sc qfailure Smsvc
tasklist /svc
tasklist /v /fi "imagename eq Smonitor.exe"
tasklist /v /fi "imagename eq Student.exe"
```

若确实是管理员并要合法维护终端，应在服务管理器中同时处理：

1. `Smsvc` 当前状态和启动类型；
2. 服务的失败恢复动作，否则停止后仍可能被 SCM 拉起；
3. `Student.exe` 的计划任务、Run/RunOnce、启动目录和服务安装逻辑；
4. 学校/教师端的“禁止运行程序”策略，否则客户端重装或策略下发后会重新生效。

只杀前台进程或只清 `DisableTaskMgr` 注册表值不是完整解法。反过来，如果终端由学校管理员管理，关闭这套服务会绕过管理策略，应先取得设备管理员/学校授权；最稳妥的处置是让管理员在教师端策略中取消对应程序限制和“违规后重启”动作，或正式卸载客户端。

## 12. 开机自启与“默认保护”

本节依据实际安装后的 Windows 磁盘只读快照，不依据安装向导界面推测。快照采集时
教师端已经连上学生端并开启保护。

### 12.1 自启入口是 `Smsvc` 服务，不是 Run 键或启动目录

磁盘中的服务注册为：

```text
ControlSet001\Services\Smsvc
  ImagePath   = C:\Program Files (x86)\gakataka\Student\Smonitor.exe
  DisplayName = Smonitor Service
  ObjectName  = LocalSystem
  Type        = 16   # SERVICE_WIN32_OWN_PROCESS
  Start       = 2    # SERVICE_AUTO_START
  ErrorControl = 1
```

因此 `Smonitor.exe` 在系统启动时由服务控制管理器自动运行，并拥有 LocalSystem
权限。本次安装快照中同时确认：

- HKLM `Microsoft\Windows\CurrentVersion\Run` 只有 `SecurityHealth`；
- HKCU Run 只有 OneDrive 和 Edge；
- 两个 Startup 目录都只有 `desktop.ini`；
- 计划任务中未发现 gakataka、Smonitor、Smsvc 或 Student 项；
- `Winlogon\Userinit` 和 `Shell` 均未被替换。

所以学校电脑上不需要用户登录后手动双击 `Student.exe`，也不需要登录启动项。
常驻服务先于用户桌面启动。

### 12.2 安装器如何注册服务

`lib-stage2.dll` 的服务安装路径位于 `0x4af017` 起。它先停止并清理旧
`Smonitor.exe`/`Smsvc`，随后构造：

```text
"Smonitor.exe" /INSTALL /SILENT
```

并通过 `WinExec` 启动该命令，最后调用服务启动包装。字符串位于 `lib-stage2.dll`
`0x4af20c`、`0x4af224`、`0x4af23c`，Evidence：
`ev_b2d004647b2e7c64ddb49f935f95b2d8a635791f73a2bbb64bf302fbfea6e9d8`、
`ev_6e82c27ee6c9a0e3b8120cf7ef7ce4855133df56fdf5066cf7b7408a60c9551c`。

### 12.3 `ar=1` 是持久化的“开机拉起学生端”开关

安装包原始 `app/config/config.cfg` 只有：

```ini
[config]
md=2d9d49174fc64363ccce9b654828875f
ms=0
```

实际安装并开启保护后的文件为：

```ini
[config]
md=2d9d49174fc64363ccce9b654828875f
ms=0
mt=49670
ar=1
...
```

`Smonitor` 的 `0x4582cc` 读取 `[config] ar`（默认 false），
`ServiceCreate` 将结果放进对象 `+0xf8`，同时把 `+0xf9/+0xfa/+0xfb` 清零。
`0x4583a4` 则把 `+0xf8` 写回 `ar`。

100 ms 的 `tmr1Timer` 在 `ar` 为真时检查 `Student.exe` 是否运行；不存在时调用
进程启动路径将其重新拉起。控制命令 `T1`（实际分派地址 `0x458adb`）设置
`+0xf8=1` 并持久化 `ar=1`，`T0` 则关闭并写回 `ar=0`。

这解释了为什么老师第一次启用保护后，后续开机看起来自动进入保护状态：
安装器先注册自启服务，保护控制再写入 `ar=1`，之后由服务持续拉起
`Student.exe`。

### 12.4 哪些状态持久，哪些由教师端重新下发

不能把“学生端自动启动”和“教师策略仍生效”混为同一件事：

| 状态 | 持久化位置 | 重启后 |
|---|---|---|
| `Smsvc` 自动启动 | 服务注册表 `Start=2` | 保留 |
| 自动拉起 `Student.exe` | `config.cfg` 的 `ar=1` | 保留 |
| 杀 `taskmgr.exe`/`perfmon.exe` 的 `+0xfb` | 仅服务进程内存，由 `S1/S0` 命令控制 | 清零 |
| 其他教师端限制/违规重启规则 | 教师端连接会话、学生端运行态及可能的缓存数据 | `Student.exe` 重连后重新下发 |

因此学校环境里“刚开机就已经在保护”通常不是一组静态 Run 项，而是：

```text
开机
  -> SCM 自动启动 Smsvc
  -> Smonitor 读取 ar=1
  -> 拉起 Student.exe
  -> Student 重连教师端
  -> 教师端重新下发进程限制、重启规则等瞬态策略
```

本快照中 `ms=0`，而保护实际已经开启，所以不能把 `ms=0` 解释为“保护关闭”。
目前可确认的持久自启/自恢复开关是 `ar`。

## 13. “任务管理器关闭但 CMD/PowerShell 不重启”的实测差异

在师生机已连接、教师端显示“学生端已保护”的状态下，单独测试得到：

- 任务管理器仍然立即关闭；
- CMD 和 PowerShell 可以正常打开；
- 学生端进程和教师端连接都保持正常。

这不是矛盾，而是两组不同策略：

1. `Smsvc` 的 `tmr1Timer` 每 100 ms 检查 `taskmgr.exe` 和 `perfmon.exe`，属于专门的固定清理逻辑；
2. CMD/PowerShell 的限制来自教师端“软件控制”，不是“保护”按钮本身。

教师端“软件控制”窗口的实测初始状态是：

```text
黑名单：空
控制模式：不控制
```

此时保护虽然开启，任务管理器仍会被服务关闭，但 CMD/PowerShell 不会被软件控制
规则处理。

教师端操作路径实际为：

```text
右键在线学生
  -> 学生端控制
  -> 启用软件黑名单

工具栏“软件控制”
  -> 黑名单
  -> 添加关键字
  -> 控制模式选择“黑名单”
  -> 关闭
```

界面明确注明规则是“窗口标题包含此关键字”。因此较稳妥的关键字包括：

```text
命令提示符
Windows PowerShell
PowerShell
Cmd.exe
cmd
```

`Teacher-stage2.exe` 的预设“安全软件”数据中也同时存在：

```text
命令提示符
Cmd.exe
```

这进一步说明不能只按普通进程名理解 `cmd.exe` 一条规则。

实验网抓包在 14:33:02 捕获到教师端向学生端发送：

```text
UDP 192.168.50.1:230 -> 192.168.50.10:49837
0c 02 63 6d 64 2e 65 78 65 2c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2c
70 77 73 68 2e 65 78 65 00
ASCII: cmd.exe,powershell.exe,pwsh.exe
```

因此下发通道已经工作。仅填写 `.exe` 名称而没有设置黑名单模式，或关键字无法包含
实际窗口标题时，仍不会得到与学校终端相同的行为。

需要特别说明：软件黑名单负责“识别/处理窗口”，而用户此前看到的“打开
CMD/PowerShell 后自动重启”还可能叠加了教师端的保护/违规动作。完整重启判定仍需
在教师端真实下发对应规则后，以进程、注册表和重启时序共同确认；不能仅凭本节的
窗口黑名单报文把重启直接归因于 `Smonitor`。

## 14. 强制重启/关机的触发面（教师端命令链补充）

本节继续做静态核对，不运行样本。新增证据把教师端控制报文、学生端处理函数和
`lib.dll` 的关机能力连成了一条完整链路。

### 14.1 协议字段与动作

教师端发送控制报文的公共函数是 `Teacher-stage2.exe!FUN_005b95f4`，Evidence：
`ev_f10e10e6736dcbfc2031bb8cd565f1f4819955dfe9b811b821be71552fdefb14`。

它把参数组成如下缓冲区：

```text
byte[0] = 命令号（CL 传入）
byte[1] = 动作/子类型
byte[2..] = 附带字符串（通常是倒计时秒数）
```

命令号 `0x11` 的动作字段为：

| byte[1] | 学生端入口 | 实际动作 |
|---|---|---|
| `0` | `Student-stage2.exe!0x585370` | 关闭电脑 |
| 非 `0`（正常发送 `1`） | `Student-stage2.exe!0x585404` | 重启电脑 |

学生端命令处理器 `0x5833d0` 将 `byte[2..]` 解析为整数，存入
`DAT_005928f0`，再按 `byte[1]` 分派：

```c
countdown = atoi(packet + 2);

if (packet[1] == 0)
    stop_computer(self, 0);      // 0x585370
else
    restart_computer(self, 0);   // 0x585404
```

完整命令处理器伪代码 Evidence 仍为
`ev_1b3807b71c10dc15741a262de33926fc849cd8fc4f595b4ee4549179ba12c88e`。

`0x585370` 内的提示为“确定要关闭电脑吗”，无倒计时时向 `0x5854a4` 传递动作
编号 `2`。`0x585404` 内的提示为“确定要重启电脑吗”，无倒计时时传递动作编号
`1`。两者都检查同一个全局倒计时值：

这里的 `1/2` 是 `Student.exe` 上层事件/界面动作编号，不应与
`lib.dll!ShutWindow` 的 `0/1/其他` 参数编号直接混为一谈；后者是在更底层的
导出函数中映射到 `NtShutdownSystem`、`ZwShutdownSystem` 和 `ExitWindowsEx`
标志。

```text
countdown > 0  -> 显示“%d 秒后将关闭/重启电脑”并设置定时器
countdown <= 0 -> 立即投递关机/重启动作
```

倒计时到期后的回调位于 `Student-stage2.exe!0x584e97`；它比较定时器到期时间和
当前计数，满足条件后调用 `0x5854a4(self, saved_action)`。

### 14.2 教师端所有直接发送命令 `0x11` 的位置

对 `Teacher-stage2.exe` 中所有直接调用 `0x5b95f4` 的位置做了受限静态搜索。与
`0x11` 有关的路径如下：

| 教师端地址 | 子类型 | 界面/触发条件 | 目标 |
|---|---:|---|---|
| `0x5b185b` | `0` | 退出教师端，且当前策略要求关闭学生电脑 | 广播全部在线学生 |
| `0x5b683b` | `0` | “立即关闭所有/选中的学生端电脑，继续吗”确认后 | 广播或逐台发送 |
| `0x5b6963` | `1` | “立即重启所有/选中的学生端电脑，继续吗”确认后 | 广播或逐台发送 |
| `0x5b7c2a` | `0` | “确定要关闭 `[学生名]` 的电脑吗”确认后 | 单台学生 |
| `0x5b7d1a` | `1` | “确定要重启 `[学生名]` 的电脑吗”确认后 | 单台学生 |

其中：

- 发送 `0x11, 0` 会关闭学生电脑；
- 发送 `0x11, 1` 会重启学生电脑；
- `EDX = -1` 表示向当前列表广播；否则 `EDX` 是学生列表索引；
- 调用处的附带字符串会作为倒计时秒数下发，字符串 `"0"` 表示立即执行。

因此，教师在界面上执行“重启学生端电脑”是一个已证实的强制重启触发条件。
单机和批量操作走同一协议字段，只是目标选择方式不同。

### 14.3 其它教师端“重启/关闭”文字不是系统重启

教师端还有“立即重启所有学生端”“关闭学生端”“清理程序”等操作。这些操作对应的
命令号不是 `0x11`，其用途是重启/结束学生端客户端或清理客户端启动的应用程序，
不能据此推断为 Windows 重启。只有明确带“学生端电脑”的重启/关闭操作进入了
上面这条 `0x11` 链路。

### 14.4 软件黑名单命中是否自动重启

这轮静态搜索得到的是有边界的负结论：

- 教师端所有直接写入命令 `0x11` 的调用点都位于上述显式关机/重启 UI 路径；
- 没有发现软件黑名单接收代码直接调用 `0x11` 的静态边；
- 但是，教师端和 Delphi 事件分发中存在间接调用和动态分派，不能把“没有直接
  xref”升级为“全局绝不可能自动发送”；
- 已保存抓包只证明了黑名单 `0x0c 02 "cmd.exe,powershell.exe,pwsh.exe"` 能下发，
  尚未证明它命中了“自动重启”动作。

所以当前最可信的结论是：

| 现象/条件 | 结论 | 置信度 |
|---|---|---|
| 教师手动“重启学生端电脑” | 必走 `0x11` 子类型 `1`，最终进入重启路径 | 已证实 |
| 教师手动“关闭学生端电脑” | 必走 `0x11` 子类型 `0`，最终进入关机路径 | 已证实 |
| 教师退出时关闭学生电脑 | 走 `0x11` 子类型 `0`，属于关机而非重启 | 已证实 |
| 打开 CMD/PowerShell 后自动重启 | 存在自动策略链，但尚未定位其产生 `0x11` 的准确判定点 | 尚未闭合 |
| 任务管理器被秒关 | 是 `Smsvc` 固定杀进程路径，不是系统重启 | 已证实 |
| 学生端进程被杀后被拉起 | 是 `Smonitor`/`ar=1` 守护路径，不是系统重启 | 已证实 |
| `Smsvc` 服务失败后一分钟恢复 | 仅恢复服务，不是重启 Windows | 已证实 |

下一步要闭合“CMD/PowerShell 自动重启”，应优先动态记录学生端收到的最后一个
`0x11` 报文、发生时间和调用来源，并在 `Student-stage2.exe!0x585404`、
`0x5854a4`、`lib.dll!ShutWindow` 三处设置断点。这样能直接区分教师自动下发、
学生本地策略和兼容性回退路径，而不用继续在 Delphi 的间接调用图上盲找。
