# 语义级高层伪代码（每命令折叠为 API 效果）

来源：Smonitor 分派器反编译（PSEUDO-DISPATCHER）、lib 反编译（PSEUDO-LIB）、Unicorn API 轨迹、
以及运行期伪代码 lifter（PSEUDO-OBF-FUNCS 中可直接看到 self+0xfb/self+0xf8 等字段写）。

## Q

    void Q_Handler(Smonitor *self, char *cfgPath)
    {
        if (FindFirstFileA(cfgPath) == INVALID) return;
        CopyFileA(cfgPath, INSTALL_CFG, FALSE);                    // 用户配置 -> 安装配置
        GetFileSecurityA(INSTALL_DIR, 4, ...); SetFileSecurityA(INSTALL_CFG, 4, sd);
        FindFirstFileA(INSTALL_CFG);
        WritePrivateProfileStringA("config", "ar", "1", INSTALL_CFG);
        WritePrivateProfileStringA(NULL, NULL, NULL, INSTALL_CFG);
    }

观测到的 API 序列：
  - ('FindFirstFileA', 'C:\\Users\\zzx\\AppData\\Roaming\\gakataka\\class\\config\\config.cfg')
  - ('CopyFileA', 'C:\\Users\\zzx\\AppData\\Roaming\\gakataka\\class\\config\\config.cfg', 'C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg', 0)
  - ('GetFileSecurityA', 'C:\\Program Files (x86)\\gakataka\\Student\\config\\', 4, 0, 0)
  - ('GetFileSecurityA', 'C:\\Program Files (x86)\\gakataka\\Student\\config\\', 4, 570425344, 256)
  - ('SetFileSecurityA', 'C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg', 4, 570425344)
  - ('FindFirstFileA', 'C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg')
  - ('WritePrivateProfileStringA', 'config', 'ar', '1', 'C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg')
  - ('WritePrivateProfileStringA', None, None, None, 'C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg')

## R

    void R_Handler(Smonitor *self, char *dir)
    {
        if (!PathExists(dir)) return;                              // 目录校验
        self->flag_taskmgr = 0;                                    // 先关 taskmgr 保护
        normalize_dir(dir);                                        // 补/去尾部反斜杠
        ShellExecuteA(NULL, "rundll32.exe",
            "\"<dir>lib.dll\",UpdtFile \"<dir>\" \"<dir>\" \"Student.exe\"",
            NULL, SW_SHOWNORMAL);                                  // 重启客户端/服务
    }

观测到的 API 序列：
  - [R_dir] ('GetFileAttributesA', 'C:\\Program Files (x86)\\gakataka\\Student\\')
  - [R_dir] ('GetFileAttributesA', 'C:\\Program Files (x86)\\gakataka\\Student\\')
  - [R_dir] ('ShellExecuteA', None, 'rundll32.exe', '"C:\\Program Files (x86)\\gakataka\\Student\\lib.dll",UpdtFile "C:\\Program Files (x86)\\gakataka\\Student\\" "C:\\Program Files (x86)\\gakataka\\Student\\" "Student.exe"', None, 1)
  - [R_dir_noslash] ('GetFileAttributesA', 'C:\\Program Files (x86)\\gakataka\\Student')
  - [R_dir_noslash] ('GetFileAttributesA', 'C:\\Program Files (x86)\\gakataka\\Student')
  - [R_dir_noslash] ('ShellExecuteA', None, 'rundll32.exe', '"C:\\Program Files (x86)\\gakataka\\Studentlib.dll",UpdtFile "C:\\Program Files (x86)\\gakataka\\Student\\" "C:\\Program Files (x86)\\gakataka\\Student" "Student.exe"', None, 1)
  - [R_empty] ('GetFileAttributesA', '')
  - [R_dot] ('GetFileAttributesA', '.')
  - [R_dot] ('GetFileAttributesA', '.')
  - [R_dot] ('ShellExecuteA', None, 'rundll32.exe', '".lib.dll",UpdtFile "C:\\Program Files (x86)\\gakataka\\Student\\" "." "Student.exe"', None, 1)
  - [R_dir_noexe] ('GetFileAttributesA', 'C:\\Program Files (x86)\\gakataka\\Student\\')
  - [R_dir_noexe] ('GetFileAttributesA', 'C:\\Program Files (x86)\\gakataka\\Student\\')

## S

    void S_Handler(Smonitor *self, byte enable)
    {
        self->flag_taskmgr = (enable == 1);   // self+0xfb
    }

观测到的 API 序列：
  - (无外部 API；仅内存写，v14 伪代码中表现为 ebx->ffb = al)

## T

    void T_Handler(Smonitor *self, byte enable)
    {
        self->flag_ar = (enable == 1);                              // self+0xf8
        FindFirstFileA(INSTALL_CFG); FindClose(...);
        WritePrivateProfileStringA("config", "ar", enable?"1":"0", INSTALL_CFG);
        WritePrivateProfileStringA(NULL, NULL, NULL, INSTALL_CFG);
    }

观测到的 API 序列：
  - ('FindFirstFileA', 'C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg')
  - ('FindClose', '0x1')
  - ('WritePrivateProfileStringA', 'config', 'ar', '1', 'C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg')
  - ('WritePrivateProfileStringA', None, None, None, 'C:\\Program Files (x86)\\gakataka\\Student\\config\\config.cfg')

## U

    void U_Handler(Smonitor *self, byte enable)
    {
        HKEY h; DWORD start = enable ? 3 : 4;
        RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\UsbStor", ...);
        RegSetValueExA(h, "Start", 0, REG_DWORD, &start, 4);
        RegCloseKey(h);
    }

观测到的 API 序列：
  - [U1] ('RegCreateKeyEx', '0x80000002', 'SYSTEM\\CurrentControlSet\\Services\\UsbStor')
  - [U1] ('RegSetValueEx', '0x501', 'Start', 4, 3, 4)
  - [U0] ('RegCreateKeyEx', '0x80000002', 'SYSTEM\\CurrentControlSet\\Services\\UsbStor')
  - [U0] ('RegSetValueEx', '0x501', 'Start', 4, 4, 4)
  - [V1] ('WinExec', 'net user Guest /active:yes', 0)
  - [V0] ('WinExec', 'net user Guest /active:no', 0)

## V

    void V_Handler(Smonitor *self, byte enable)
    {
        RtlEnterCriticalSection(&cs);
        WinExec(enable ? "net user Guest /active:yes" : "net user Guest /active:no", 0);
        RtlLeaveCriticalSection(&cs);
    }

观测到的 API 序列：
  - [U1] ('RegCreateKeyEx', '0x80000002', 'SYSTEM\\CurrentControlSet\\Services\\UsbStor')
  - [U1] ('RegSetValueEx', '0x501', 'Start', 4, 3, 4)
  - [U0] ('RegCreateKeyEx', '0x80000002', 'SYSTEM\\CurrentControlSet\\Services\\UsbStor')
  - [U0] ('RegSetValueEx', '0x501', 'Start', 4, 4, 4)
  - [V1] ('WinExec', 'net user Guest /active:yes', 0)
  - [V0] ('WinExec', 'net user Guest /active:no', 0)

## W

    void W_Handler(Smonitor *self, char *text)
    {
        strcpy(self->commandText /* self+0x13d36ac */, text);  // 仅内存缓存
    }

观测到的 API 序列：
  - (无外部 API；仅字符串复制)

## X

    void X_Handler(Smonitor *self, byte *cmd)
    {
        double t = *(double *)(cmd + 1);      // Delphi TDateTime, 1899-12-30 起天数
        SYSTEMTIME st = DelphiToSystemTime(t);
        SetLocalTime(&st);
    }

观测到的 API 序列：
  - ('SetLocalTime', (1899, 12, 6, 30, 0, 0, 0, 0))
