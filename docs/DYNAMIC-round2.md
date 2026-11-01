# 动态验证第二轮（2026-10-31 18:00–18:15）

补充 `analysis/DYNAMIC.md`，针对“学校同版本但打开 CMD/PowerShell 或反复杀 Student 会重启”的反馈做了追加实验。
**结论：在本机同版本 17.8.24.111 上，这三条路径都无法触发重启。** 本构建里唯一到达重启的静态路径仍是网络命令 0x11。

## 1. 追加实验结果

| 实验 | 配置/动作 | 结果 |
|---|---|---|
| 反复杀 Student | Smsvc 运行，taskkill /f /im Student.exe 连续 20 次（每次都被互拉进程/服务拉起） | 无重启，QMP 无 RESET/SHUTDOWN |
| ms | `ms=1` + `stc=2`，重启 Student 后打开 CMD | 仍只关窗口，无重启 |
| stc | `stc=3` + `stcw` 原值，重启 Student 后打开 CMD | 不关窗口、不重启（与 0/1 相同） |
| stc 语义汇总 | 0/1/3 = 不动作；2 = 关闭标题命中关键字的窗口 | 无“重启”模式 |

## 2. 静态补充

- 教师端 FUN_005b95f4 的 0x0c 发送封装有三个分支（子类型 0/1/2）：0 清空、1/2 各带一份全局字符串（黑/白名单）。0x0c 报文里没有动作字段。
- 教师端“学生端控制”菜单完整文本只有：远程开机/关机/重启、开启保护、重启学生端、启用/禁用软件黑名单、白名单、上网控制、软件透视、收集文件、禁用网关等；没有“违规处理/违规重启”选项。
- Student-stage2.exe 中没有任何关机 API 名称（NtShutdownSystem/ZwShutdownSystem/ExitWindowsEx 等），这些字符串只在 lib-stage2.dll 里。
- Student 里重启函数 0x585404 的直接调用点只有网络命令分派函数中的 0x584054；进入条件仍是收到 0x11 且 byte[1]!=0。
- 用 32 位 PowerShell 枚举 Student 模块确认 lib.dll 在内存基址 0xD20000（模块大小 0x232000）；按 RVA 在 Student 内存中扫描 lib!ShutWindow/IsConsoleActive/CloseWindowCN 等函数指针没有命中。该负结果依赖 RVA 与静态转储一致，不能单独作为“Student 不调用这些导出”的证明。

## 3. 对学校现象的解释（更新）

同版本字符串只能证明显示版本一致，不能证明二进制一致：客户端带自动更新组件（updt、pool.db、ssleay 等），lib.dll 或 Student.exe 可能被更新而版本号不变。
同时，本构建下“打开 CMD → 重启”没有可达的本地代码路径，因此学校现象更可能是下面之一：

1. 触发时网络上确实有主机下发 0x11（教师端、学生管理器或其它服务端），只是现场看起来“没连教师”；
2. 学校机器的 lib.dll/Student.exe 与本地安装包不一致（自动更新或定制），本地动作被改成重启；
3. 学校环境有安装包之外的服务/策略组件（例如 GateFace 套件或第三方管理软件）在触发重启。

## 4. 建议的判定方法（按成本排序）

1. 在会重启的学校机器上抓一次触发前后的流量（Wireshark/pktmon，过滤 TCP 230/231/233/234 与 UDP 230），看有没有 0x11 报文；这是区分“网络触发”和“本地/二进制差异”的最快方式。
2. 对学校机器的 Student.exe、lib.dll、Smonitor.exe、config/config.cfg 取 SHA-256，与 REPORT.md 里的本地哈希比对，并看 config.cfg 的 ms/stc/stcw 值。
3. 记录学校机器上同时运行的进程与服务（Student、Smonitor、Smsvc、Gateface/GFServer/StudentManager 等）和监听端口。

## 5. 本机状态

- 配置已恢复为实验前内容（stc=2、ms=0、stcw 原密文），Student 与 Smsvc 运行中，桌面已登录；
- 实验期间留过一个 config.cfg.bak/config.cfg.before-ms 备份与 C:/Users/zzx 下的 a.ps1、e.ps1、mycmd.exe、myprog.exe 等测试文件，可随时删除。
