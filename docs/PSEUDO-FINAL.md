# 伽卡他卡电子教室（17.8）保护/客户端逻辑：高级伪代码总汇

本文把多轮反编译、Unicorn 仿真与执行轨迹 lifting 的成果合并成一份 C 风格伪代码，按模块组织。

方法：
- 非混淆区（Smonitor CODE、lib.dll）：REA/Ghidra 直接反编译；
- 混淆区（Smonitor .text0/.text1）：入口补丁 + Ghidra（只能到外壳）+ 基于 Unicorn 执行轨迹的 lifter
  （控制转移、直线语句、调用嵌套、字段访问、效果注解）；
- 语义验证：教师端抓帧、frida 钩子、注册表/进程/网络状态核对。

## 1. Smonitor 命令分派器（0x4589f8，Ghidra 反编译）

    void DispatchCommand(Smonitor *self, byte *cmd)
    {
        switch (cmd[0]) {
        case 'Q': Q_Handler(self, cmd + 1); break;
        case 'R': R_Handler(self, cmd + 1); break;
        case 'S': self->flag_taskmgr = (cmd[1] == 1); break;
        case 'T': self->flag_ar = (cmd[1] == 1); PersistAr(self, cmd[1]); break;
        case 'U': cmd[1] == 1 ? U_Enable() : U_Disable(); break;
        case 'V': cmd[1] == 1 ? V_Enable(cmd+1) : V_Disable(cmd+1); break;
        case 'W': W_Handler(self, cmd + 1); break;
        case 'X': X_Handler(self, cmd + 1); break;
        }
    }

## 2. 命令处理函数

    // Q：用户配置 -> 安装配置 + 安全属性 + ar 持久化
    void Q_Handler(Smonitor *self, char *cfgPath)
    {
        if (FindFirstFileA(cfgPath) == INVALID) return;
        CopyFileA(cfgPath, INSTALL_CFG, FALSE);
        GetFileSecurityA(INSTALL_DIR, 4, ...); SetFileSecurityA(INSTALL_CFG, 4, sd);
        WritePrivateProfileStringA("config", "ar", "1", INSTALL_CFG);
        WritePrivateProfileStringA(NULL, NULL, NULL, INSTALL_CFG);
    }

    // R：重启客户端/服务（rundll32 lib!UpdtFile）
    void R_Handler(Smonitor *self, char *dir)
    {
        if (!PathExists(dir)) return;
        self->flag_taskmgr = 0;
        normalize_dir(dir);
        ShellExecuteA(NULL, "rundll32.exe",
            "\"<dir>lib.dll\",UpdtFile \"<dir>\" \"<dir>\" \"Student.exe\"",
            NULL, SW_SHOWNORMAL);
    }

    // S：任务管理器/性能监视器保护标志（self+0xfb）
    void S_Handler(Smonitor *self, byte enable) { self->flag_taskmgr = (enable == 1); }

    // T：ar 标志 + 持久化（self+0xf8）
    void T_Handler(Smonitor *self, byte enable)
    {
        self->flag_ar = (enable == 1);
        WritePrivateProfileStringA("config", "ar", enable ? "1" : "0", INSTALL_CFG);
        WritePrivateProfileStringA(NULL, NULL, NULL, INSTALL_CFG);
    }

    // U：USB 存储（UsbStor Start = 3/4）
    void U_Handler(Smonitor *self, byte enable)
    {
        HKEY h; DWORD start = enable ? 3 : 4;
        RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\UsbStor", ...);
        RegSetValueExA(h, "Start", 0, REG_DWORD, &start, 4);
        RegCloseKey(h);
    }

    // V：访客账户（net user Guest /active:yes|no）
    void V_Handler(Smonitor *self, byte enable)
    {
        RtlEnterCriticalSection(&cs);
        WinExec(enable ? "net user Guest /active:yes" : "net user Guest /active:no", 0);
        RtlLeaveCriticalSection(&cs);
    }

    // W：远程执行命令文本缓存
    void W_Handler(Smonitor *self, char *text) { strcpy(self->commandText /*self+0x13d36ac*/, text); }

    // X：设置本地时间（8 字节 Delphi TDateTime）
    void X_Handler(Smonitor *self, byte *cmd)
    {
        double t = *(double *)(cmd + 1);
        SYSTEMTIME st = DelphiToSystemTime(t);
        SetLocalTime(&st);
    }

## 3. 保护/看护逻辑

    // 3.1 任务管理器秒关（Student 进程内，保护开启时）
    // 动态验证：Student OpenProcess(目标pid, PROCESS_TERMINATE) + TerminateProcess(handle, 0)
    // 保护关闭后不再杀 taskmgr；保护标志由教师端"开启/关闭保护"经 0x0D 帧下发（Q + S 1/0）。
    void ProtectionLoop_Student(void)
    {
        for (;;) {
            foreach (proc in Toolhelp32Snapshot()) {
                if (proc.name == "taskmgr.exe" && self->flag_taskmgr)
                    TerminateProcess(OpenProcess(PROCESS_QUERY_INFORMATION), ...);
            }
        }
    }

    // 3.2 客户端被杀后自动重启（Smonitor 进程内，保护开启时）
    // 动态验证：CreateProcessAsUserA("C:\\Program Files (x86)\\gakataka\\Student\\Student.exe")
    // 新进程 ParentProcessId = Smonitor PID；保护关闭时不重启。
    void Smonitor_Watchdog(void)
    {
        for (;;) {
            if (self->protection_on && !ProcessExists("Student.exe"))
                CreateProcessAsUserA(..., "C:\\Program Files (x86)\\gakataka\\Student\\Student.exe", ...);
        }
    }

    // 3.3 Student 启动自检（单实例 + 服务/文件检查）
    // 0x161848("Student.exe") = CreateMutexA(name) + GetLastError==183（已有实例则退出）
    // 0x1618D0("Smsvc") 等 = 服务状态检查；失败弹"程序重要文件丢失/程序服务启动失败"后退出。
    bool CheckSingleInstance(const char *name)
    {
        HANDLE m = CreateMutexA(NULL, FALSE, name);
        if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(m); return false; }
        return true;
    }

## 4. lib.dll 辅助函数（节选，完整见 PSEUDO-LIB.md / PSEUDO-LIB-ANNOTATED.md）

    // 4.1 KillProc：Toolhelp 找 PID -> OpenProcess(PROCESS_TERMINATE) -> TerminateProcess
    int KillProc(const char *name)
    {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        Process32First(...); // 遍历匹配 name
        CloseHandle(snapshot);
        OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        TerminateProcess(handle, 0);
    }

    // 4.2 RunUpdt：拼 UpdtFile 命令行并执行（供 R 命令调用）
    void RunUpdt(char *a, char *b, char *c, char *d)
    {
        cmd = Format(" %s %s UpdtFile \"%s\" \"%s\" \"%s\"", ...);
        Execute(cmd); // ShellExecute 链
    }

    // 4.3 ShutWindow：按模式选择 SeShutdown 或回调
    int ShutWindow(int mode, int a, int b)
    {
        if (g_mode == 2) {
            prepare();
            if (...) { ... 回调 ... } else { SeShutdown(); }   // SeShutdown -> SetPrivilege -> 关机
        }
        return r;
    }

    // 4.4 其他
    void SetGate(...)      { /* WMI Win32_NetworkAdapterConfiguration.SetGateways */ }
    int  IsRunInVM(...)    { /* \\.\PHYSICALDRIVE0 INQUIRY 厂商串 -> VMWARE/VIRTUAL/VBOX */ }
    void DisableUsbStore() { /* UsbStor Start = 4 */ }
    void EnableUsbStore()  { /* UsbStor Start = 3 */ }
    void DisableGuest()    { /* net user Guest /active:no */ }
    void EnableGuest()     { /* net user Guest /active:yes */ }
    void HideTaskbar()     { /* FindWindow("Shell_TrayWnd") + ShowWindow(0) */ }

## 5. 协议（教师/学生/Smonitor）

教师 -> Student（TCP，9 字节头：type + len(u32 LE) + magic 52 21 15 52）：

    0x0D 01/00      开启/关闭保护（Student 转发 Smonitor：Q + S 1/0）
    0x11 01 30 00   远程重启（sub=1，延时 "0"）
    0x11 00 30 00   远程关机（sub=0）
    0x13 00         重启学生端
    0x13 01         关闭学生端
    0x0E 00 <cmd>   远程执行命令行（NUL 结尾）
    0x12 00 <text> 00 <font> 00 ... 0x0C 00 00 00   发送消息
    0x0C 00/01/02 <list>                             软件白/黑名单、应用
    0x1A 00/01/02                                    禁用上网控制/上网白/黑名单
    0x27 00 <double TDateTime>                       设置日期时间

Student -> Smonitor（本地 TCP，同样 9 字节头 + magic）：

    Q + cfgPath     配置同步
    S 0/1           taskmgr 保护标志
    R + dir         重启链
    U 0/1, V 0/1    USB/Guest
    W + text        命令文本
    X + TDateTime   设置时间

## 6. 证据索引

- analysis/PSEUDO-DISPATCHER.md：分派器与 handler 反编译
- analysis/PSEUDO-LIB.md、PSEUDO-LIB-ANNOTATED.md：lib 函数 C 伪代码与语义
- analysis/PSEUDO-COMMANDS.md、PSEUDO-HIGHLEVEL.md：8 命令语义级伪代码 + API 序列
- analysis/PSEUDO-OBF-FUNCS.md / STRUCT.md / TRACE.md：混淆层执行路径伪代码
- analysis/REBOOT-MECHANISM.md：全部实验记录与动态证据
- 动态轨迹：analysis/tmp/api*_trace_*.json、live2_trace_*.json、killproc_emul6.json

## 7. 已知限制

- Smonitor .text0/.text1 的 VM/跳板链未逐指令反编译，上述 handler 以“执行轨迹 + API 效果”还原；
- 字段访问（self+0xfb 等）来自反编译/偏移观测，非完整结构体定义；
- 未执行分支不可见（轨迹法固有）；
- 教师端 UI 的部分按钮（屏幕广播等）未纳入本总汇。

结论：保护、重启、监控、USB/Guest、时间/配置同步、客户端自启/看护等**可观测行为**均已还原为高级伪代码；
混淆层的指令级细节保留为执行轨迹形式（PSEUDO-OBF-FUNCS/STRUCT/TRACE）。
