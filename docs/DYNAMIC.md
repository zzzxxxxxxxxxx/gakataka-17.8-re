# 伽卡他卡 17.8 学生端动态验证补充（2026-10-31 17:30–17:56）

本文件补充 `HANDOFF.md` 与 `REPORT.md`，只记录本轮在隔离 QEMU 中实测到的新事实及其边界。
静态结论仍以 `REPORT.md` 为准；本轮新增两条并行取证：`analysis/offline-disk/`（磁盘）与
`analysis/pcap/`（抓包）。

## 1. 本轮做了什么

- 17:34 以 VNC display 启动学生机（教师机未启动，保持离线），旧 pcap 未覆盖，新抓包写入
  `vm/win10-22h2/labnet-offline-20261031.pcap`。
- 通过 HMP sendkey 登录（用户 zzx），放行登录时的 Student.exe UAC 提权。
- 建立两条客户机控制通道（不改变网络拓扑）：隐藏 PowerShell 轮询 agent（`task.txt`/`result-*`）
  与提权 agent（`etask.txt`/`eresult-*`），经 QEMU user net 的 `10.0.2.2:8000` 与宿主通信。
- 实验结束后已把 `config.cfg` 恢复为原始内容，重启客户机，回到“学生端运行、Smsvc 运行、
  未连教师机”的干净状态。

## 2. 关键结论

1. **离线时本地确实有软件控制，且策略持久化在 `config.cfg`。** 教师端 14:33 下发的
   `0c 02 "cmd.exe,powershell.exe,pwsh.exe"` 被学生端写入
   `C:\Program Files (x86)\gakataka\Student\config\config.cfg`：`stc=2`，`stcw` 变为
   约 62 字节的十六进制密文。这是学校电脑“不连教师端仍有策略”的直接原因。
2. **本地动作是关闭窗口，不是重启。** 离线打开 CMD：窗口出现后约 0.5 s 内被关闭，QMP 无
   RESET/SHUTDOWN 事件；反复启动 8 个 cmd + 5 个 powershell 也没有重启。整个实验期间没有观察
   到任何自动重启。
3. **执行者是 Student.exe，不是 Smonitor/Smsvc。** 挂起 Student.exe 后新开 CMD 保持不关；
   恢复 Student.exe 后约 1 s 内桌面已有的 CMD 被关闭；期间 Smonitor/Smsvc 一直运行。
4. **识别方式是窗口标题子串匹配，不是进程名或控制台类。** 把 cmd.exe 复制为 `mycmd.exe`
   （标题含 `cmd.exe`）仍被关闭；复制为 `myprog.exe`（标题不含关键字）保持；notepad 不受影响。
   Student.exe 内存中可见明文关键字表 `cmd.exe,powershell.exe,pwsh.exe`（32 位进程堆地址
   `0x41996232`，附近有 Delphi 控件字符串 `tmr2`/`TOOLBUTTON`），说明配置在运行时被解密为
   逗号分隔关键字，与教师端“窗口标题包含此关键字”的说明一致。
5. **`stc` 是控制模式开关（实测语义）：**

   | stc | 行为（CMD 标题命中 `stcw` 关键字时） |
   |---:|---|
   | 0 | 不处理，窗口保持 |
   | 1 | 本次实测未处理，窗口保持（未确认是否白名单模式） |
   | 2 | 关闭匹配窗口，无提示、无重启 |

6. **没有找到任何“违规→重启”的本地或教师端动作。** 教师端字符串中软件控制只有“启用/禁用
   软件黑名单/白名单、上网黑名单/白名单、控制模式、+ 添加”，重启相关字符串只出现在
   “远程重启/重启学生端/关机重启等待时间”等显式命令 UI；两个 pcap 全程没有 0x11 命令
   （详见 `analysis/pcap/REPORT.md`），教师端最后一条命令是 14:48:43.917（墙钟）的 0x0c
   黑名单下发。
7. **Student 有双进程互拉与自提权。** Stop-Process 循环无法稳定清零（另一实例或服务会拉起）；
   `Smsvc` 运行时（`ar=1`）持续拉起 Student.exe；登录和被杀后重启会出现 Student.exe 的 UAC
   提权请求（本实验需手动放行），说明该安装方式下学生端以提权身份运行；学校环境如何处理
   这一点尚未核对。

## 3. 对“学校电脑打开 CMD 就重启”的解释状态

本轮在本机 17.8 样本上没有复现自动重启：同一套本地检测存在，但动作是关窗口。因此该现象只能
归入以下未验证分支，不能再写成“已确认本地检测会重启”：

- 学校安装的客户端版本/策略与本地 17.8 不同，软件控制动作被配置为重启（本镜像里无该选项）；
- 学校终端上存在教师端在线或残留策略，由教师端显式下发 0x11（但用户明确说未连教师端）；
- 另一条尚未定位的本地机制（例如违规计数、考试模式或防篡改逻辑）触发重启。

要闭合，最低成本是取得学校终端的 `Student.exe`、`lib.dll`、`Smonitor.exe` 与
`config/config.cfg` 的 SHA-256（尤其 `stc`/`stcw` 与版本号），与本地样本比对；若一致，
再复测“教师在线下发后断网”的缓存动作。

## 4. 阻断点（按权限分层）

- 教师端 0x11 显式重启走 `NtShutdownSystem/ExitWindowsEx`，本地没有普通用户态钩子可拦；
  只能不接收该命令或移除客户端。
- 有管理员权限时可逆的做法：停用/删除 `Smsvc`（注意 `ar=1`、失败恢复与双进程互拉）；
  结束两个 Student.exe 实例并阻止自启；清空/删除 `config.cfg` 的 `stc`/`stcw`（本实验证明
  `stc=0` 即不再关窗口），或直接移除客户端目录。
- 学生用户权限下没有可靠的本地阻断手段，与 `REPORT.md` 的结论一致。

## 5. 复现用工具与命令

- `vm/qmp-screendump.py`：QMP 截图（PNG）；`vm/qmp-eventlog.py`：QMP 事件日志（看 RESET/SHUTDOWN）；
- `vm/qemu-type.py` 增加 `--delay-ms`、`--warmup-ms`，避免按键节奏导致文本错位；
- `analysis/dynamic/agent_server.py`：宿主 8000 端口文件服务 + POST 接收；
- 客户机 agent 脚本：`analysis/dynamic/transfer/agent.ps1`（普通）、`eagent.ps1`（提权）。
  重启客户机后 agent 不会自恢复，需要在 Run 对话框重新执行：
  `powershell -w hidden -ep bypass -File C:\Users\zzx\a.ps1`（提权版为 `e.ps1`）。

## 6. 当前状态与残留

- 学生机 QEMU 仍在运行（VNC `127.0.0.1:5901`，HMP/QMP 在 `vm/win10-22h2/`），教师机未启动；
- 客户机已重启并登录，学生端与 Smsvc 正常运行，`config.cfg` 已恢复原始内容（另有
  `config.cfg.bak` 为实验前备份，可删除）；
- 旧 pcap 未被覆盖；新抓包 `labnet-offline-20261031.pcap` 只含本轮离线流量；
- 客户机中留有本轮实验文件（`C:\Users\zzx\a.ps1`、`e.ps1`、`mycmd.exe`、`myprog.exe`、
  `config.cfg.bak`），不影响结论，需要干净镜像时可删除；
- 残留未验证：`stcw` 加密算法与明文结构、`stc=1` 的准确语义、教师在线时动作是否随策略变化、
  学校版本哈希。
