# Smonitor 命令处理函数伪代码（基于具体执行轨迹重建）

来源：
- Smonitor 分派器与命令字母语义来自静态审查（CODE 段 0x4589f8）与多轮动态抓帧；
- 每个 handler 的 API 序列来自 Unicorn 活上下文具体执行轨迹（analysis/tmp/api*_trace_*.json）；
- 被调用的实际动作函数在 lib.dll 中，已用 REA/Ghidra 反编译，见 analysis/PSEUDO-LIB.md。

说明：Smonitor 的 .text0/.text1 是“按需解密 + 自修改桩 + 虚拟化分发”的混淆层，Ghidra 无法建立函数
（本次 REA 分析在 0x4589f8 未发现 procedure）；因此 handler 以“执行轨迹 + API 调用 + 内存副作用”形式
还原为伪代码，而不是逐指令反编译。

## 分派器

    // Smonitor 命令分派器, VA 0x4589f8
    void DispatchCommand(Smonitor *self, byte *cmd, int len)
    {
        switch (cmd[0] - 'Q') {
        case 0x00: Q_Handler(self, cmd); break;      // 'Q'
        case 0x01: R_Handler(self, cmd); break;      // 'R'
        case 0x02: self->flag_taskmgr = (cmd[1] == 1); break;                    // 'S'
        case 0x03: self->flag_ar = (cmd[1] == 1); PersistAr(self, cmd[1]); break; // 'T'
        case 0x04: U_Handler(self, cmd[1]); break;   // 'U'  USB 存储
        case 0x05: V_Handler(self, cmd[1]); break;   // 'V'  Guest 账户
        case 0x06: W_Handler(self, cmd); break;      // 'W'  命令文本
        case 0x07: X_Handler(self, cmd); break;      // 'X'  设置时间
        default: break;
        }
    }

## Q：用户配置复制到安装目录并加安全属性

    // 轨迹：analysis/tmp/api5_trace_Q.json（8 条 API 日志，58 条调用）
    void Q_Handler(Smonitor *self, byte *cmd)
    {
        const char *userCfg =
            "C:\\Users\\zzx\\AppData\\Roaming\\gakataka\\class\\config\\config.cfg";
        const char *installDir = "C:\\Program Files (x86)\\gakataka\\Student\\config\\";
        const char *installCfg = "C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg";

        if (FindFirstFileA(userCfg, &findData) == INVALID_HANDLE_VALUE) return;
        CopyFileA(userCfg, installCfg, FALSE);           // 复制用户配置
        GetFileSecurityA(installDir, 4, NULL, 0, &need); // DACL 大小
        GetFileSecurityA(installDir, 4, sd, need, &got);
        SetFileSecurityA(installCfg, 4, sd);             // 设置安全属性
        FindFirstFileA(installCfg, &findData);           // 确认存在
        WritePrivateProfileStringA("config", "ar", "1", installCfg);
        WritePrivateProfileStringA(NULL, NULL, NULL, installCfg);
    }

## R：解析目录后通过 rundll32 调用 lib!RunUpdt（客户端/服务重启链）

    // 轨迹：analysis/tmp/api5_trace_R.json -> R_dir/R_dir_noslash（36 条 API）
    void R_Handler(Smonitor *self, byte *cmd)
    {
        char *dir = cmd + 1;                 // 目录参数（可带/不带尾部反斜杠）
        GetFileAttributesA(dir);             // 目录存在性探测
        GetModuleFileNameA(NULL, ownPath, 0x105);
        // 规范化目录（补/去尾部反斜杠，见 R_dir 与 R_dir_noslash 差异）
        ShellExecuteA(NULL,
                      "rundll32.exe",
                      "\"<dir>lib.dll\",UpdtFile \"<dir>\" \"<dir>\" \"Student.exe\"",
                      NULL, SW_SHOWNORMAL);
    }

UpdtFile 的完整语义见 analysis/PSEUDO-LIB.md 的 RunUpdt，以及前几轮 Unicorn 仿真：
KillProc(Student) → 停 Smsvc → KillProc(Smonitor) → 复制/时间/安全属性 → StartService →
ShellExecute(Student.exe)。

## S：任务管理器/性能监视器保护标志

    // 轨迹：analysis/tmp/api*_trace_S1.json（仅内存写，无外部 API）
    void S_Handler(Smonitor *self, byte *cmd)
    {
        self->flag_taskmgr = (cmd[1] == 1);   // self+0xfb
    }

## T：ar 标志并持久化到安装配置

    // 轨迹：analysis/tmp/api4_trace_T1.json
    void T_Handler(Smonitor *self, byte *cmd)
    {
        self->flag_ar = (cmd[1] == 1);        // self+0xf8
        const char *installCfg =
            "C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg";
        FindFirstFileA(installCfg, &findData);
        FindClose(findData);
        WritePrivateProfileStringA("config", "ar", cmd[1] ? "1" : "0", installCfg);
        WritePrivateProfileStringA(NULL, NULL, NULL, installCfg);
    }

## U：USB 存储启用/禁用

    // 轨迹：analysis/tmp/api5_trace_UV.json -> U0/U1
    void U_Handler(Smonitor *self, byte enable)
    {
        HKEY hKey;
        DWORD start = enable ? 3 : 4;
        RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                        "SYSTEM\\CurrentControlSet\\Services\\UsbStor",
                        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);
        RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE *)&start, 4);
        RegCloseKey(hKey);
    }

## V：访客账户启用/禁用

    // 轨迹：analysis/tmp/api5_trace_UV.json -> V0/V1（WinExec 调用）
    void V_Handler(Smonitor *self, byte enable)
    {
        RtlEnterCriticalSection(&cs);
        WinExec(enable ? "net user Guest /active:yes"
                       : "net user Guest /active:no", 0);
        RtlLeaveCriticalSection(&cs);
    }

## W：命令文本缓存（远程执行命令）

    // 轨迹：analysis/tmp/api3_trace_W.json（无外部 API，纯内存写）
    void W_Handler(Smonitor *self, byte *cmd)
    {
        strcpy(self->commandText, (char *)(cmd + 1));   // NUL 结尾
    }

## X：设置日期时间

    // 轨迹：analysis/tmp/api3_trace_X.json（SetLocalTime 调用）
    void X_Handler(Smonitor *self, byte *cmd)
    {
        double t = *(double *)(cmd + 4);      // Delphi TDateTime（1899-12-30 起天数）
        SYSTEMTIME st;
        DelphiTimeToSystemTime(t, &st);
        SetLocalTime(&st);
    }

## 证据

- Q: analysis/tmp/api5_trace_Q.json（FindFirstFileA/CopyFileA/GetFileSecurityA/SetFileSecurityA/
  WritePrivateProfileStringA 全链路）
- R: analysis/tmp/api5_trace_R.json（R_dir 等 5 组目录参数变体，ShellExecuteA 命令行已验证）
- S/T/W：analysis/tmp/api*_trace_S1.json、api4_trace_T1.json、api3_trace_W.json
- U/V：analysis/tmp/api5_trace_UV.json（注册表 Start=3/4、net user Guest yes/no）
- X：analysis/tmp/api3_trace_X.json（SetLocalTime 参数为 1899-12-06 的 Delphi TDateTime 换算值）
- 分派器：CODE 段 0x4589f8 静态审查 + 多轮教师端抓帧（Q/R/S/T/U/V/W/X 全字母）
