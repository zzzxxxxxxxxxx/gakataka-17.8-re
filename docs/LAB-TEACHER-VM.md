# 教师虚拟机实验室（2026-11-01 会话）

## 1. 启动教师 VM

教师 VM 位于 `vm/win10-teacher-22h2/`，启动脚本 `run-teacher.sh run`。
沙箱内看不到 `/dev/kvm`，需要 `danger-full-access` 提权执行：

```bash
setsid bash -lc 'cd /home/zzx/projects/jiakataka/vm/win10-teacher-22h2 && VM_DISPLAY=vnc ./run-teacher.sh run' \
  > /tmp/teacher-vm.log 2>&1 < /dev/null &
```

- VNC `127.0.0.1:5902`（5900+2），RDP hostfwd `127.0.0.1:23389`，WinRM `23390`
- 登录：用户 ZZX / 口令 580356（VNC：先按 Esc 唤出登录框，typefile 输入）
- 桌面路径：教师端 `C:\Program Files (x86)\gakataka\Teacher\Teacher.exe`
- 教师端需要 UAC 提权，且必须从交互会话启动；通过 SYSTEM 计划任务启动会落在 session 0，窗口不可见

## 2. 教师 VM 的三条控制通道（HTTP agent）

host 侧服务：`analysis/dynamic/agent_server.py analysis/dynamic/transfer-teacher --port 8001`

| 通道 | 脚本 | 任务/结果 | 权限 | 会话 |
| --- | --- | --- | --- | --- |
| 普通 | a.ps1 | taskT.txt / resultT | 普通用户 | 1 |
| SYSTEM | aAdmin.ps1 | taskA.txt / resultA | SYSTEM | 0 |
| 交互提权 | aInter.ps1 | taskI.txt / resultI | 管理员 | 1 |

交互提权任务用 `schtasks /create ... /ru ZZX /rp <pass> /rl HIGHEST /it` 创建，
可在 session 1 以管理员身份启动 GUI 程序（教师端）。

## 3. 教师端配置与协议

- `Teacher\config\config.cfg`（GBK）：`room=默认教室`、`ip=所有地址`、`last=46326`
- `Teacher\config\教室名.cfg`（GBK）：`port=230`、`nums=50`、`stc=2`、
  `pass=<pa 密文>`、`stcb=cmd.exe,powershell.exe,pwsh.exe`、`stcw=powershell,cmd`、
  `btext=肃静`、`parha/v/r` 为共享/点播/接收目录
- 教师端监听 TCP 230/233/234/235/237
- 上线下线发现协议：教师端每约 3 秒向 `255.255.255.255:230` 发 UDP 广播，
  载荷 73 字节，开头 `13 09 00 00 00 52 21 15 52`（type=0x13、len=9、魔数），
  后面带 `52-54-00-12-34-56`（MAC 字符串）与 `DESKTOP-S7HA...`（主机名）
- 广播的源 IP 决定学生回连地址；只有源 IP 可达时学生才能上线

## 4. 本轮遇到的问题

教师 VM 实验网卡（MAC 52:54:00:00:10:11）除了静态 192.168.50.1 之外，
Windows 反复自动加上 APIPA `169.254.83.90`，教师端因此：

- 窗口标题显示 `[本机IP地址: 10.0.2.15,169.254.83.90]`（或只剩 10.0.2.15）
- UDP 广播源 IP 为 `169.254.83.90`，学生无法回连，在线学生始终为 0

尝试过：netsh 静态地址、Remove-NetIPAddress、禁用 DHCP、
`IPAutoconfigurationEnabled=0`、重启网卡、调整接口 metric（实验网 1 / NAT 9000）。
结果：APIPA 被清除且 metric 生效，但教师端仍选择 NAT 地址 10.0.2.15；
最后一次重启后教师端停止广播（pcap 不再新增教师广播包）。

## 5. 下一步

1. 调整网卡绑定顺序：`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Linkage\Bind`
   把实验网卡 GUID 排到 NAT 前，再重启教师端；
2. 或临时禁用 NAT 网卡后重启教师端（会切断 agent 通道，需先用计划任务安排重启）；
3. 或在“设置管理 → 教室管理”里给教室配置地址，
   观察教师端是否按教室地址广播；
4. 广播源 IP 变成 192.168.50.1 后，学生端应自动上线，
   再执行真正的教师端实验（软件控制、远程重启、发送消息）。

## 6. 当前 VM 状态

- 学生 VM 运行中（VNC 5901，实验网 192.168.50.10，Smonitor 与 Student 正常）
- 教师 VM 运行中（VNC 5902，实验网 192.168.50.1，Teacher.exe 在 session 1 运行但无广播）
- host 侧 HTTP 服务：8000（学生 agent）、8001（教师 agent）
## 7. 2026-11-01 01:14-01:20 追加：官方脚本与地址选择问题

- 在教师 VM 以管理员执行了官方 `vm/setup-lab-network.ps1 -Role teacher`：
  - 实验网卡配置 192.168.50.1/24、metric 10
  - 设置了入站防火墙规则 "JiaKaTaKa Lab Inbound"（此规则对教师端 230 端口被学生访问很关键）
  - 网络配置文件设为 Private
- 教师端仍只在窗口标题显示 `本机IP地址: 10.0.2.15`，在线学生 0
- 实验网 pcap 里 UDP 230 广播记录止于 01:10:43（源 169.254.83.90）；此后任何重启的教师端实例都没有再从实验网卡发出广播
- 说明教师端很可能**只枚举 DHCP/自动配置得到的地址**，手工添加的静态 192.168.50.1 被忽略；
  之前它能从实验网卡广播，是因为那块网卡当时有 APIPA（DHCP 自动地址）
- 因此下一步方向：
  1. 验证 Teacher.exe 的地址枚举实现（提取 Teacher.exe 看 GetAdaptersInfo / DhcpEnabled 判断）
  2. 或在实验网段跑一个 DHCP 服务器，给教师端分配 192.168.50.1（让地址来源变成 DHCP）
  3. 或继续用“禁用 NAT 网卡 + 实验网卡 APIPA”的组合，把广播源改到实验网段


## 8. 2026-11-01 01:20-01:23 追加：APIPA 假设验证

验证了“教师端只枚举自动配置/DHCP 地址”的假设：

- 把教师 VM 实验网卡改回 DHCP/自动配置（删除 IPAutoconfigurationEnabled=0、Dhcp Enabled、重启网卡）后，
  网卡重新得到 APIPA `169.254.83.90`（PrefixOrigin=WellKnown）
- 重启教师端后，实验网 pcap 的 UDP 230 广播立即恢复，源 IP 为 `169.254.83.90`，
  时间戳从 01:20:06 起连续，载荷与之前一致（73 字节，type=0x13 len=9 + MAC/主机名）
- 教师端窗口标题也变回 `[本机IP地址: 10.0.2.15,169.254.83.90]`

说明手工静态地址（192.168.50.1）确实不被教师端枚举，自动配置地址（APIPA）可以。

### 学生端的对应处理

- 给学生 VM 的实验网卡添加了 `169.254.83.100/16`（通过 VNC/UAC 提权脚本 int addll.ps1），
  使其与教师端 APIPA 处于同一 link-local 子网
- 学生 VM 上 Student.exe 当前未运行；Smsvc/Smonitor 正常
- 学生 VM 的普通 HTTP agent 在 01:22:31 后停止响应（无新 result 文件），
  需要重新拉起（VNC 里用 encoded command 或 Run 对话框）

### 下一步

1. 恢复学生 VM 控制通道：重启普通 agent（参考教师 VM 的 bootstrap 方法）
2. 清理学生实验网卡上误加的 `192.168.50.1`，保留 192.168.50.10 与 169.254.83.100/16
3. 启动 Student.exe，观察它是否响应教师端 APIPA 广播（frida 挂 recvfrom/connect）
4. 若 Student 仍拒绝非配置教师 IP，则在实验网段跑 DHCP 服务器，
   给教师端分配 192.168.50.1（让地址来源变成 DHCP），从根上解决枚举问题


## 9. 2026-11-01 01:24-01:32 关键突破：Teacher 与 Student 已真实连通

### 生效的配置

- 教师 VM 实验网卡（Idx 14）：自动配置 APIPA `169.254.83.90/16` + 手工 `192.168.50.1/24`
- 学生 VM 实验网卡（Idx 2）：`192.168.50.10/24` + `169.254.83.100/16`
- 教师 VM 已运行官方 `setup-lab-network.ps1 -Role teacher`（防火墙放行 + Private 网络）
- 教师端广播源为 APIPA `169.254.83.90`，学生端能收到 73 字节 UDP 广播（frida 抓包确认 recvfrom）
- 学生端启动后主动连教师端，教师端日志记录：

    01:25:56 学生端上线: DESKTOP-S7HAS2J [169.254.83.100]
    01:31:02 学生端离线: DESKTOP-S7HAS2J [169.254.83.100]
    01:31:55 学生端上线: DESKTOP-S7HAS2J [169.254.83.100]

- 教师端界面底栏显示 在线学生 1，学生图标区域出现 DESKTOP-S...

### 关键结论

教师端只枚举自动配置（DHCP/APIPA）地址，手工静态 192.168.50.1 不参与广播；
因此双机实验必须让实验网卡同时具备 link-local 地址：
教师 169.254.83.90/16、学生 169.254.83.100/16，双方在同一 link-local 子网内即可发现与连接。

### 下一步（真正的教师端实验）

1. 用教师端工具栏“发送消息”下发文字消息，观察学生端弹窗
2. 用“软件控制”下发 `cmd.exe,powershell.exe,pwsh.exe` 黑名单，观察学生端关窗口行为
3. 用“远程重启/远程关机”下发显式命令，记录学生端重启链路与时序
4. 在教师端正向操作时抓取学生端 Student.exe 的收包与执行路径（frida）


## 10. 2026-11-01 01:33-01:42 真实教师端操作实验

### 发送消息

- 教师端“发送消息”向所有学生发送 `MSG-DETECT-4`
- 学生端 frida 抓包收到：先 9 字节头 `13 3b 00 00 00 52 21 15 52`（type=0x13，len=59），
  随后 59 字节载荷，含 `MSG-DETECT-4`、`Tahoma`、字体尺寸等字段
- 学生端进程内确实创建了“发送消息”窗口（hwnd 0x506f0），但窗口保持隐藏；
  自动显示逻辑可能与当前会话/焦点状态有关，未做进一步验证

### 远程重启（关键）

- 教师端点“远程重启”，弹出“立即重启所有学生端电脑，继续吗”（等待时间 0 = 不等待）
- 确认后时间线：
  - `01:37:11` 教师端确认
  - `01:37:14` 教师端日志：学生端离线 DESKTOP-S7HAS2J [192.168.50.10]
  - 学生机 VNC 变为 Windows 登录界面（用户 ZZX），说明为真实重启而非仅断连
  - 教师机 ping 学生 `192.168.50.10` 正常，link-local 地址与手工 agent 消失（重启后未恢复）
  - `01:41:33` 登录后 Student 自动启动并重新连回：学生端上线 DESKTOP-S7HAS2J [192.168.50.10]
  - 教师端底栏恢复 在线学生 1

结论：教师端“远程重启”是真实的机器重启链路：命令 → Student 执行 → Windows 重启 → 登录后
Student 自启并重新上线。实验室中该动作必须由教师端显式下发，本地离线检测本身只关窗口。

### 待做

- 教师端“软件控制”下发 cmd/powershell 黑名单，观察学生端关窗口行为
- 教师端“远程关机”对照实验
- 重启前学生端 frida 抓包记录命令帧，便于和协议层归一化结果对应


## 11. 2026-11-01 01:43-01:45 本地窗口规则验证（教师端在线）

学生机重启并登录后：

- 学生端界面显示 `登录成功，教师机: 192.168.50.1 [默认教室]`
- 用开始菜单打开 cmd（标题为“命令提示符”）：窗口保持，未被关闭
- 在 cmd 里执行 `title cmd.exe` 把标题改成关键字：约 2 秒内窗口被关闭，系统未重启
- 教师端仍在“在线学生 1”状态

结论：
- 本地窗口匹配动作仍然是“关闭窗口”，不是重启，与之前离线实验一致
- 窗口标题匹配是对 title 内容做的，普通“命令提示符”标题不触发，必须标题包含 `cmd.exe` 等关键字
- 学校电脑“打开 cmd 就重启”不是这条本地动作的直接结果，需要教师端显式下发 0x11 重启命令


## 12. 2026-11-01 01:45-01:50 教师-学生登录协议抓包与软件控制入口

### 登录协议帧（teacher-labnet.pcap，link-local 路径）

学生→教师（第一次连接，type 0x0d 握手）：

    0d 37 00 00 00 52 21 15 52                      (type=0x0d, len=0x37=55)
    载荷 55 字节：2b3350819abdc0ef7919c7f7c285835c 00
                  "52-54-00-00-10-10" 00 00 00 00 "DESKTOP-S7HAS2J" 00 00

教师→学生：

    0e 00 00 00 00 52 21 15 52                      (type=0x0e 应答)
    随后 363 字节多帧：
      17 0f 00 00 00 52 21 15 52 "169.254.83.100" 00   (type=0x17, 告知学生自身 IP)
      13 f8 00 00 00 52 21 15 52 ...                    (type=0x13, len=0xf8=248 登录配置，
                                                        内含 0b 00 01 01 01 00 1e 00 00 e6 ...
                                                        以及 "www.gakataka.com")

之后双方持续发送 1 字节 00 心跳包。

### 软件控制对话框

教师端“软件控制”对话框内容：

- 页签：白名单 / 黑名单（当前黑名单）
- 列表：powershell、cmd
- 按钮：+上网软件、+安全软件、+添加、-删除、-清空
- 控制模式下拉：黑名单
- 复选：应用到所有学生
- 按钮：生成内容、关闭
- 提示：控制窗口标题包含此列表关键字的程序运行，注意大小写

点“生成内容”会弹出“网址软件黑白名单”窗口，生成一段加密的 gakataka 配置块
（形如 `[gakataka]\n<base64-ish hex 行>\n[gakataka]`），说明这个入口是给
“课堂/空间网页自动同步配置”用的，不是直接向在线学生下发的发送按钮。
在线的软件控制策略可能由关闭对话框/切换模式时自动下发，需要在下一轮用抓包确认。

### 现状

- 学生机重启后学生端与教师端已重新连接：教师端“在线学生 1”
- 学生端 agent 与 frida-server 在重启后丢失，VNC 输入受中文输入法影响难以稳定执行长命令，
  下一轮需要先稳定输入通道（切英文、用 cmd 控制台逐行输入）再恢复


## 13. 2026-11-01 01:55-02:05 DSH 重启后恢复 + 软件控制命令帧

DSH 重启后 QEMU 与 host 服务全部消失，本轮重新拉起：

- `VM_DISPLAY=vnc VNC_DISPLAY=1 bash vm/win10-22h2/run-vm.sh run`（学生机，VNC 5901）
- `VM_DISPLAY=vnc VNC_DISPLAY=2 RDP_PORT=23389 WINRM_PORT=23390 LAB_NET_MAC=52:54:00:00:10:11 LAB_PCAP=vm/captures/teacher-labnet.pcap bash vm/win10-teacher-22h2/run-vm.sh run`（教师机，VNC 5902）
- host 服务：`agent_server.py analysis/dynamic/transfer --port 8000`、`... transfer-teacher --port 8001`
- 两台 VM 都已登录（ZZX/580356），教师端从桌面快捷方式启动并接受 UAC
- 教师端日志：`02:00:32 学生端上线: DESKTOP-S7HAS2J [192.168.50.10]`，在线学生 1
- 本次教师端标题 `[本机IP地址: 10.0.2.15,192.168.50.1]`，说明冷启动后 DHCP/APIPA 与静态地址都可以参与广播

### 新增的可靠输入通道：QEMU HMP sendkey

VNC 输入受中文输入法干扰严重（字母被转成中文候选词、长命令被截断），本轮改为
直接走 QEMU monitor 的 `sendkey` 硬件按键，彻底绕开输入法与 vncdotool 限制：

- 脚本 `analysis/tmp/hmptype.py`：把 ASCII 文本逐字符映射为 QEMU 键名（含 `shift-X` 大写、
  `spc`、`ret`、`dot`、`backslash`、`shift-minus` 等），通过 `vm/*/monitor.sock` 发送；
  `QEMU_MON` 环境变量选择学生或教师 VM
- 可稳定完成：登录、开 cmd、下载 agent、启动 agent/frida-server、读取 config

### 软件控制命令帧（新抓包）

教师端“软件控制”对话框：页签 白名单/黑名单，列表 powershell、cmd，
控制模式下拉 不控制/白名单/黑名单，按钮 生成内容/关闭，复选 应用到所有学生。

实际下发帧（teacher-labnet.pcap，192.168.50.1:230 → 192.168.50.10 方向）：

    选“不控制”并关闭：
      13 03 00 00 00 52 21 15 52        (type=0x13 通知帧)
      0c 00 00                          (type=0x0c, mode=0x00, 结束符)

    选“黑名单”并关闭：
      0c 01 70 6f 77 65 72 73 68 65 6c 6c 2c 63 6d 64 00
      (type=0x0c, mode=0x01 黑名单, 载荷 "powershell,cmd" 00)

学生端 config.cfg 同步变化：

    stc=1
    stcw=0F18F477C8D05EED98C087D9E2E243EB1B45FD6F1CD2FA1CF9C4FA16   (56 hex = 14 字符明文长度)
    pt=230, ar=1

- stcw 密文长度与 GetDec 实测规律一致（4 hex/明文字符），28 字节对应 "powershell,cmd" 的 14 字符
- 之前登录配置帧里 `stc=2` 时本地确实会关闭标题含 cmd.exe 的窗口（01:45 实验）；
  本轮下发黑名单后 `stc=1`，但已打开的 `C:\Windows\system32\cmd.exe` 窗口未被关闭，
  说明 stc 的取值语义或生效时机还需要进一步验证（可能需重启学生端加载新配置，或 1/2 语义与预期不同）

### 待做

1. 重启学生端后验证 stc=1 + stcw 列表是否按黑名单关窗口
2. 通过教师端再下发“白名单”，确认 stc 取值映射（0/1/2 分别对应什么）
3. 用 Student 内 GetDec（frida 或直接读明文）确认 stcw 解密结果

