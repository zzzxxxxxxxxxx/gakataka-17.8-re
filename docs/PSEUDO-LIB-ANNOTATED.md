# lib.dll 语义注解版伪代码

在 analysis/PSEUDO-LIB.md（原始 Ghidra 输出）基础上，用动态仿真轨迹与调用序列标注 FUN_/DAT_ 的语义。

## 函数语义表

| 函数 | 语义 | 证据 |
|---|---|---|
| ShutWindow | 关机/重启核心：按模式分支，调用 SeShutdown 或回调指针，再执行内部关机 | Ghidra 反编译 + 前几轮 lib 仿真 |
| SeShutdown / SeShutdown2 | 提升关机权限并调用系统关机 | 反编译 + SetPrivilege 链 |
| SetPrivilege | 调整当前进程令牌权限（SeShutdownPrivilege） | 反编译 + 早期断点日志 |
| GetProcId / GetProcIdBySId / GetProcIdASId | 用 Toolhelp32 快照按进程名/SID 查 PID | 反编译 + killproc 轨迹 |
| TermProc | 打开目标进程并 TerminateProcess | killproc 轨迹 |
| KillProc | GetProcId → TermProc 的组合封装 | 反编译 + killproc_emul6.json |
| RunUpdt | 拼 UpdtFile 命令行（"%s %s UpdtFile \"%s\" \"%s\" \"%s\""）并执行 | Ghidra 反编译（格式串 0x4af370）+ R 轨迹 |
| SetGate | WMI 设置默认网关（SetGateways） | 早期静态/动态结论 |
| IsRunInVM | 读 \\.\PHYSICALDRIVE0 INQUIRY 厂商串判断虚拟机 | 早期动态验证（QEMU 返回 0） |
| DisableUsbStore / EnableUsbStore | UsbStor Start=4 / 3 | 早期 lib 导出活体验证 + U 轨迹 |
| DisableGuest / EnableGuest | net user Guest /active:no / yes | 早期活体验证 + V 轨迹 |
| HideTaskbar / ShowTaskbar | FindWindow(Shell_TrayWnd) + ShowWindow | 早期静态/动态 |
| CopyScreen 等屏幕函数 | 屏幕截图/屏保状态检测 | 反编译可读 |

## KillProc：反编译 + 动态序列

    undefined4 KillProc(void)
    {
      int pid = GetProcId();          // Toolhelp32 快照，遍历进程名
      if (pid == 0) return 0;
      return TermProc();              // OpenProcess(PROCESS_TERMINATE) + TerminateProcess
    }

动态轨迹（analysis/tmp/killproc_emul6.json）：

    CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    Process32First(snapshot, &pe)
    CloseHandle(snapshot)
    OpenProcess(PROCESS_TERMINATE=0x1, FALSE, pid=0x1234)
    TerminateProcess(handle, 0)

## RunUpdt：命令行拼装

Ghidra 输出中的关键字符串与调用：

    0x4af370: 格式串（含 UpdtFile），形如
              " %s %s UpdtFile \"%s\" \"%s\" \"%s\""
    FUN_0040aff8  -> Delphi Format()
    FUN_004050f0  -> 字符串处理
    FUN_004a9cac  -> 执行（ShellExecute 链，见 PSEUDO-LIB 与 R 轨迹）

与 R 轨迹观测一致：

    ShellExecuteA(NULL, "rundll32.exe",
        "\"<dir>lib.dll\",UpdtFile \"<dir>\" \"<dir>\" \"Student.exe\"",
        NULL, SW_SHOWNORMAL)

## ShutWindow：分支结构（Ghidra 输出）

    int ShutWindow(void)
    {
      if (*DAT_0051a898 == 2) {                 // 模式/状态：2 = 走关机路径
        int r = -1;
        FUN_004ac3a8();                         // 关机前准备（内部）
        if (参数含 0 或回调为空) {
          if (另一组回调为空) {
            FUN_004b213c(参数1);                // 内部处理
            return FUN_004ac95c() ? -1 : 0;
          } else {
            ... 依次调用 DAT_0051c254 / DAT_0051c250 回调 ...
          }
        } else {
          SeShutdown();                         // 提权 + 关机
          FUN_004b213c(参数1);
          (*DAT_0051c24c)();
        }
      } else {
        FUN_004b213c(参数1);
        return FUN_004ac95c() ? -1 : 0;
      }
      return r;
    }

注解：
- DAT_0051a898 是模式/状态全局；==2 时进入关机分支；
- DAT_0051c24c / c250 / c254 是函数指针回调（关机前通知/清理）；
- FUN_004b213c 疑似参数/环境处理（多分支共用）。

## SetPrivilege 反编译

    undefined4 SetPrivilege(void)
    {
      undefined4 r = 0;
      FUN_005319e9();            // 取当前进程句柄/令牌
      FUN_005262b4();            // 打开令牌
      if (FUN_005523ae() != 0) { // LookupPrivilegeValue / 权限查询
        r = FUN_00549640();      // AdjustTokenPrivileges
      }
      FUN_0052d185();            // 清理
      return r;
    }

对应 SeShutdown2 -> SetPrivilege() 的关机权限提升链（SeShutdownPrivilege）。

## 产物

- 原始反编译：analysis/PSEUDO-LIB.md
- 动态轨迹：analysis/tmp/killproc_emul6.json（KillProc 调用序列）
- 本文档：analysis/PSEUDO-LIB-ANNOTATED.md
