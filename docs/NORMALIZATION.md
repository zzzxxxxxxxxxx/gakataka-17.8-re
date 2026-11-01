# 混淆层归一化结果

## 1. 编码 API 表（Student）

混淆层在 .data 里维护一张“编码指针表”，值是运行期地址按固定公式编码后的结果。
公式（由执行轨迹归一化得出，enc 为表内值）：

    t1 = enc + 0xA219ACE4
    t2 = rol32(t1, 30)
    t3 = ~t2
    t4 = -t3
    target = ~t4

反推 lib 基址 0xcb0000 后，表内 26 个槽位对应 lib.dll 导出：

    0x595b80 IsAdminRun        0x595b84 IsRunInVM       0x595b88 IsOverXP
    0x595b8c IsForWin          0x595b90 SetForWin       0x595b94 SetFullWin
    0x595b98 IsScreenSaverActive  0x595b9c SetDPI       0x595ba0 SetDateTime
    0x595ba4 GetAppDataPath    0x595ba8 DelFiles        0x595bac SelDirectory
    0x595bb0 GetDeskPath       0x595bb4 GetFileVer      0x595bb8 ChkAdminRun
    0x595bbc ChkInstance       0x595bc0 ShutWindow      0x595bc4 ShowBoxYN
    0x595bc8 RefDesktop        0x595bcc EnableSleep     0x595bd0 DisableSleep
    0x595bd4 RestoreScreenSaver 0x595bd8 HideTaskbar    0x595bdc ShowTaskbar
    0x595be0 ShowErr           0x595be4 ShowMsg         0x595be8 InitApp

每个槽位在混淆层里恰好有一个引用（0x5e8xxx-0x5f4xxx 区域的 stub），
说明这层是“lib API 调用包装层”。ShutWindow 的 stub 引用在 0x5ee151。

## 2. 轨迹级块归一化

脚本 analysis/tmp/uni_norm.py：Unicorn 执行时按控制流指令切块，记录每块：
入口/出口寄存器、栈窗口内变化的 dword、真实后继（ret/jmp 解析后的目标）、
间接跳转槽位解码值、指令清单。输出 analysis/tmp/norm/*.txt 和 *.json。

执行器（0x5854a4，mode=1）归一化结果的核心链条：

    block 0x5854a4  push -1; push -1; push edx; call 0x561840
    block 0x561840  jmp 0x5ee145
    block 0x5ee145  pushal; ...; mov eax,[0x595bc0]; call 0x5ed265
    block 0x5ed265  jmp 0x5f21f5
    block 0x5f21f5  lea esp,[esp+0x44]; call 0x5e6bed
    block 0x5e6bed  pushal; pushfd; jmp 0x5ee832
    block 0x5ee832  eax = eax + 0xa219ace4
    block 0x5f1c3d  rol eax,0x1e; not eax; neg eax
    block 0x5ece56  not eax; ret 0x54 -> 0x5f21fe
    block 0x5f21fe  ...; ret 0x4c -> 0xd5c9a0 (lib!ShutWindow)

栈差异显示最终布局为 [esp]=返回地址 0x5854ae、[esp+4]=mode、[esp+8]=-1、
[esp+0xc]=-1，即 lib!ShutWindow(mode,-1,-1)。

## 3. 局限与下一步

- 这是“具体执行轨迹”的归一化，不是全程序符号化反混淆；每条路径依赖入口参数和全局值。
- 寄存器/栈差异已经足够读语义；若要得到表达式级 IR，可把每块字节交给 miasm
  （analysis/tmp/ropvenv 已装 master 版）做 IR lifting 与 expr_simp。

## 4. API 包装层目录（归一化产物）

编码表槽位、包装跳板（jmp site）、以及正常代码可调用的入口：

    slot      API                 wrapper jmp
    0x595b80  IsAdminRun          0x5f374f
    0x595b84  IsRunInVM           0x5e8d56
    0x595b88  IsOverXP            0x5f48c9
    0x595b8c  IsForWin            0x5e8707
    0x595b90  SetForWin           0x5ecd79
    0x595b94  SetFullWin          0x5eec10
    0x595b98  IsScreenSaverActive 0x5f4a0e
    0x595b9c  SetDPI              0x5eec2f
    0x595ba0  SetDateTime         0x5f1c6f
    0x595ba4  GetAppDataPath      0x5e6d7d
    0x595ba8  DelFiles            0x5eeac1
    0x595bac  SelDirectory        0x5e83c9
    0x595bb0  GetDeskPath         0x5e9424
    0x595bb4  GetFileVer          0x5edc8b
    0x595bb8  ChkAdminRun         0x5f0bac
    0x595bbc  ChkInstance         0x5e80b4
    0x595bc0  ShutWindow          0x561840
    0x595bc4  ShowBoxYN           0x5ec573
    0x595bc8  RefDesktop          0x5e916e
    0x595bcc  EnableSleep         0x5f3cba
    0x595bd0  DisableSleep        0x5ee1be
    0x595bd4  RestoreScreenSaver  0x5ea72a
    0x595bd8  HideTaskbar         0x5ee256
    0x595bdc  ShowTaskbar         0x5e9493
    0x595be0  ShowErr             0x5e9f22
    0x595be4  ShowMsg             0x5ec9a4
    0x595be8  InitApp             0x5f1ddf

- 每个 API 在混淆层里恰有一个包装跳板；这些跳板都在混淆区内部互相调用，
  正常代码里只有 ShutWindow 存在对齐的真实调用者（0x5854a9，执行器内）。
- 机器可读版本：analysis/tmp/obf_catalog.json
- 注意：用“任意字节上的 E8”扫描找混淆层入口会产生未对齐误报，
  不能作为“只有 10 个入口”的证据。


## 5. 签名归一化尝试（哨兵参数模拟）

思路：对每个包装跳板用哨兵值（EAX/EDX/ECX 及栈上标记 0xC0DE000n）启动 Unicorn，
在第一次 fetch 未映射时捕获目标地址与栈参数，从而把 stub 还原成
"lib API + 参数布局" 形式。

结果：27 个 stub 全部没有触发外部 fetch，说明它们在哨兵参数下没有走到 lib 调用。
原因是这层混淆把控制流和参数一起编码进栈布局（执行器路径里 mode 会参与 ret 链
的排列），随便填参数会让 ret 链跳到别处（落到我们映射的零页/哨兵页后空转），
并不会解码出 lib 指针。结论：签名归一化需要符号执行（符号参数 + 约束求解）或
真实运行时上下文，不能用纯具体哨兵。

## 6. 入口点扫描的修正

之前用"任意字节上的 E8"扫描得到"混淆层只有 10 个对外入口"是未对齐误报：
0x58cab5 等位置本身落在混淆代码中间（周围就是 pushfd/pushal/jmp 的混淆 idioms），
这些 E8 来自错位解码。可靠结论只有：ShutWindow 包装跳板 0x561840 存在对齐的真实
调用者 0x5854a9（执行器内）。


## 7. 混淆层真实对外接口（线性反汇编修正）

用连续线性反汇编（指令边界上取 E8，扫描 CODE 段 0x401000-0x58d000）重建调用图：

- 混淆层对外只有 3 个入口：
  - 0x58a110 <- 0x585ec3（函数 0x585e94；先设置 [0x592a6c]=0，检查 [0x5929c0]，
    传 EAX=该对象、DL=1）
  - 0x58b0f8 <- 0x5835b7（报文分派器 0x5833d0 的 type=9 分支）
  - 0x58c49c <- 0x583efa / 0x583f17（分派器 type=10 子命令 0x0b 区域）
- 27 个 API 包装跳板里只有 ShutWindow 的 0x561840 有层外对齐调用者（0x5854a9）。
- 结果文件：analysis/tmp/obf_calls_linear2.json

## 8. 入口探测：层内还直接调 Win32 API

对 3 个公开入口用 Unicorn 探测（EAX=0x900000 假对象 / EDX=0/1）：

    0x58a110  71 步后 fetch 于 0x75952b70
    0x58b0f8  401 步后 fetch 于 0x7739ff60
    0x58c49c  178 步后 fetch 于 0x755c1200

这些地址落在 Windows 系统 DLL 区间（0x75xxxxxx / 0x77xxxxxx），说明混淆层不仅调用
lib.dll 导出，还通过运行期解析的系统 API 指针直接调 Win32。也就是说层内存在第二类
“运行期函数指针（非编码或另一种编码）”，静态反汇编看不到名字。

下一步归一化需要把这批系统指针解析成 API 名：
- 方案 A：从 guest 磁盘提取 SysWOW64 的 DLL，用导出表 RVA 对解码地址做基址投票
  （与 lib 表相同的做法）；
- 方案 B：恢复 guest 内 frida-server 后直接读目标进程模块列表，按模块基址+偏移命名。


## 9. 运行时归一化（当前会话，新）

环境修复与基础设施：
- guest 的 QEMU 用户态网卡（以太网）此前被禁用，导致 hostfwd 和 10.0.2.2 全不通；
  已用提权 PowerShell 重新启用，恢复 10.0.2.15/默认网关 10.0.2.2。
- 防火墙已放行 frida-server64.exe（netsh 规则）；frida-server 现在监听 27046
  （旧的 27042/27043 因连接超时卡死，已全部结束并重启）。
- 提权命令通道恢复：guest 轮询 task.txt 执行并 POST 结果，结果文件在
  analysis/dynamic/transfer/result-*.bin。
- 发现 Smsvc 服务与 Smonitor.exe 已停止（进程列表里没有 Smonitor），已 Start-Service
  恢复；新 Smonitor PID 2384（session 0）。当前有两个遗留 Student 进程
  （2592、5388，session 1）。

用当前会话 frida 数据做系统 API 精确命名（analysis/tmp/map_live.py）：
- 从 Student 5388 读取 85 个模块基址与数据区 0x58d000-0x59b000；
- 数据区中 0x70000000-0x80000000 的指针 204 个成功映射到
  uxtheme(50) comctl32(25) oleaut32(22) user32(17) windows.storage(12) imm32(11)
  coreuicomponents(10) shell32(9) combase(9) kernel32(5) 等；
- lib 编码表 27 项用当前 lib 基址 0xcf0000 全部验证通过
  （例如 0x595bc0 -> 0xd9c9a0 = lib!ShutWindow）。

运行时挂钩（analysis/tmp/fr_hooks2.py，端口 27046）：
- 挂钩 27 个 API 包装跳板 + 3 个层入口（0x58a110/0x58b0f8/0x58c49c）；
- 在 80 秒窗口内（其中用 agent 触发 10 次 cmd 打开）Student 侧 0 命中；
- 说明 lab 配置下 cmd 违规路径不经过这些包装 API（与之前“无本地惩罚”一致）。
- Smonitor 因进程不在，未挂上；服务恢复后可重做其启动/违规路径观察。

产物：analysis/tmp/live_dump.json、map_live.py、entry_live.py、fr_hooks2.py、
hook_runtime2.log。

## 10. 启动序列归一化（当前会话，frida spawn + 分段挂钩）

方法：frida spawn Student 挂起启动；系统 DLL 的挂钩在 spawn 时立即安装（解包不会覆盖系统
DLL），层内地址的挂钩延迟 700ms 安装（等自解压完成，否则会被覆盖）。脚本：
analysis/tmp/fr_libhooks2.py、fr_syshooks2.py、parse_sys2.py。

结果（一次完整启动，时间相对 resume）：

    0.67-0.75s  解包阶段：LoadLibraryA x20、GetProcAddress x759、VirtualProtect x4
    0.98-1.06s  ChkAdminRun 包装 x10（调用者 0x428621）
                lib!ChkAdminRun x1（lib 内部再调 IsAdminRun；OpenProcessToken 当前进程）
                ChkInstance 包装 x1 -> lib!ChkInstance x1，CreateMutexA x1（单实例互斥体）
                CreateMutexW x4、RegOpenKeyExA x4、CreateThread x1
                SetWindowsHookExA/W 各 x1（idHook=5，WH_CBT）
                E_5e577f x4：EDX=0x5e4d0c（层内数据表），EAX=0xd64/0xc899/0xa21/0xc39d，
                    ECX 在 0x80000000 与 0x30000001 间切换
                E_5e4cd6 x2：EAX=0x90/0x80，EDX=0x5e4d0c
    14s 窗口内没有 WSAStartup/socket/connect/send —— 该实例没有进入网络初始化阶段。

归一化结论：
- 混淆层在启动期只被调用：ChkInstance 包装 1 次、ChkAdminRun 包装 10 次，
  以及两个层内初始化例程（0x5e577f/0x5e4cd6，合计 6 次，参数指向 .text0 数据表 0x5e4d0c）。
- 其余 25 个 API 包装在启动窗口内没有使用，说明它们由运行期事件（UI、教师命令、
  违规流程）触发，而不是启动流程。
- 解包器在 0.75s 前完成 759 次 GetProcAddress，属于保护壳的动态 API 解析阶段，
  与业务逻辑无关。
- 两个初始化例程不调用 VirtualProtect/GetProcAddress/Winsock，下一步可挂
  comctl32!InitCommonControlsEx、uxtheme!OpenThemeData、gdi32 等判定其具体功能。

## 11. 本地协议运行期归一化（当前会话）

在 frida spawn（系统 DLL 挂钩在 spawn 时安装，覆盖不到解包）下，抓到了完整的本地通道握手：

    0.815  WSAStartup / socket
    0.818  WSAStartup / socket / connect 127.0.0.1:61937（配置 mt）
    0.819  WSAStartup
    0.820  send(9)  0d 00 00 00 00 52 21 15 52   （C2S 握手）
    0.821  recv(...)
    0.823  recv -> 9  0e 00 00 00 00 52 21 15 52（S2C 回应）
    0.823  send(9)  13 02 00 00 00 52 21 15 52
    0.824  send(2)  53 01                        （命令 S，数据 1）
    0.824  socket（第二个 socket，教师连接方向）

- 所有这些调用都来自 lib.dll（caller 落在 lib 基址 0xe20000 的 0x6xxxx-0x9xxxx 区间），
  说明本地协议客户端实现不在 Student.exe，而在 lib.dll。
- 26 秒窗口内（期间触发 4 次 cmd 打开）没有更多 S2C/C2S 帧，本地通道在违规场景下静默。
- 日志：analysis/tmp/proto_trace.log、startup_net.log；脚本 fr_net.py、fr_proto.py。

### 修正：0x5e4d0c 不是数据表

层内入口 0x5e577f / 0x5e4cd6 被调用时 EDX=0x5e4d0c，之前判断为“层内数据表指针”。
静态核对 .text0 内容发现 0x5e4d0c 处是**混淆代码**（其内部还有 call 0x58cb03、call 0x58cac2），
而 0x58ca9c-0x58cb0b 是调用这两个入口的小 trampoline。因此 0x5e4d0c 是代码地址/
续延状态，不是数据表；这两个入口属于层的内部状态机，而不是“数据表初始化”。

## 12. lib.dll 本地协议客户端归一化（当前会话）

修正：之前把运行时 caller 换算成 RVA 时 lib 基址算错（lib 基址每次启动不同，例如 0xe20000、
0xe30000）。现在在 frida 脚本里直接用 caller - libbase 归一化，得到准确 RVA。

本地协议相关函数（lib 静态 VA = 0x400000 + RVA，代码位于运行时补丁区，
必须用活内存 dump 才能反汇编，静态文件里是乱码）：

    connect thunk  0x494ccc  （构造 sockaddr_in 后调 [0xf4a0c8]）
    recv thunk     0x494e3c  （调 [0xf4a410]）
    send thunk     0x4950ec  （调 [0xf4a308]）
    WSAStartup/socket 初始化点：0x4cf553/0x4cf55e、0x493a6c、0x4951d6、0x488a02
    运行时指针表（.data）：0xf4a0c8=connect、0xf4a308=send、0xf4a410=recv（WSA 动态解析）

即 lib 在启动时用 GetProcAddress 解析 Winsock，把函数指针存进 .data 指针表，
协议辅助函数只是查表调用的薄封装。

### 帧序列（RVA 归一化后，lib base 0xe30000 的一次启动）

    0.786 WSAStartup(rva 0xcf553)
    0.786 socket(rva 0xcf55e)
    0.788 WSAStartup(rva 0x93a6c) / socket(rva 0x951d6)
    0.789 connect(rva 0x94d11) -> 127.0.0.1:62220
    0.789 WSAStartup(rva 0x88a02)
    0.791 send(rva 0x95102, 9B)  0d 00 00 00 00 52 21 15 52
    0.791 recv(rva 0x94e52) -> 9B  0e 00 00 00 00 52 21 15 52
    0.791 send(rva 0x95102, 9B)  13 02 00 00 00 52 21 15 52
    0.792 send(rva 0x95102, 2B)  53 01
    0.793 socket(rva 0x951d6)

注意：sockaddr_in 的端口字段是网络字节序，日志里读取时未做字节序转换（显示 3315 实际为 62220）。

产物：analysis/tmp/live_lib_proto.json（活内存窗口）、live_lib_windows.json、脚本
fr_dump_proto.py / fr_proto_rva.py / lib_proto_dis2.py。

## 13. lib 协议栈对象模型归一化（当前会话）

运行时挂钩三个协议 thunk（send 0x4950ec、recv 0x494e3c、connect 0x494ccc）后，
得到调用者 RVA 与对象上下文，再配合活内存反汇编，还原出 lib 的协议栈结构：

    全局: [0xeea778] -> provider 对象 -> vtable（位于 .text0 的运行时数据区）

    vtable 偏移（wrapper 里实际调用）：
      +0x1c  connect
      +0x48  recv
      +0x54  send
      +0x5c  send2（三参数版本，另一个发送包装）
      +0x18  close、+0x20、+0x64（尚未命名）

    wrapper 函数：
      0x498c60  connect(self, addr)：push [esi+0x18]、[esi+0x20]，call [vt+0x1c]，
                成功后调 0x49922c、0x499250（连接后续处理）
      0x498cc8  recv(self, len)：call [vt+0x48]
      0x498cec  send(self, len)：call [vt+0x54]
      0x498d14  send2(self, ...)：call [vt+0x5c]，随后 call 0x493e8c

    vtable 槽的实体（ws2 thunk）：
      0x494ccc  connect：构造 sockaddr_in（family、网络序端口、IP），call [0xf4a0c8]
      0x494e3c  recv：call [0xf4a410]
      0x4950ec  send：call [0xf4a308]
      .data 指针表 0xf4a0c8/0xf4a308/0xf4a410 由启动期 GetProcAddress 填入

    运行时握手调用链（一次启动，lib base 0xdd0000）：
      connect wrapper 调用点 rva 0x98c7d  （0x498c7d = 0x498c60 内 call 之后）
      recv    wrapper 调用点 rva 0x98ce5
      send    wrapper 调用点 rva 0x98d0c（连续三次：9B 握手、9B 第二帧、2B 命令）

thunk 入口参数（Delphi 寄存器约定）：eax=对象/状态指针（如 0x27f2890）、
edx=0x528、ecx=状态值（0x954a30/0x956a40，不是 lib 内地址，属运行时状态/编码值），
栈参数为 fd 与长度。因此帧缓冲尚未定名，需继续向上追 wrapper 的调用者。

产物：analysis/tmp/live_lib_proto2.json（活内存窗口）、fr_thunks.py、parse_thunks.py、
lib_wrappers.py。

## 14. 帧格式与组帧函数归一化（当前会话）

在活内存里全库扫描魔数 52 21 15 52，命中 lib 静态 VA 0x4b275c / 0x4b2767，反汇编后还原组帧层：

### 帧格式（9 字节头 + 载荷）

    +0  byte   type（消息类型）
    +1  dword  length（载荷长度，小端）
    +5  dword  magic = 0x52152152（字节序 52 21 15 52）

### 关键函数（lib 静态 VA）

    0x4b2754  build_header(ecx=buf, al=type, edx=len)
              mov byte [ecx], al
              mov dword [ecx+1], edx
              mov dword [ecx+5], 0x52152152
    0x4b2764  is_header：cmp dword [eax+5], magic; sete al
    0x4b2770  check_len：dword[hdr+1]+9 == total
    0x4b2ad8  send_packet(eax=chan, dl=type, ecx=payload, [ebp+8]=payload_len)
              1) 虚方法 [edx+0x54] 检查通道
              2) 栈上构造 9 字节头
              3) 发送头部：call 0x49cbd4(buf=&hdr, len=9, flags=1)
              4) payload_len>0 时再发载荷：call 0x49cbd4(buf=payload, len, flags=1)
    0x4b2b6d / 0x4b2b8c  send_packet 的变体

### 握手序列修正

    之前把 53 01 当成独立 2 字节命令，实际是 type=0x13 消息的载荷：

    send(9):  0d 00 00 00 00 52 21 15 52   type=0x0d, len=0
    recv(9):  0e 00 00 00 00 52 21 15 52   服务端应答 type=0x0e
    send(9):  13 02 00 00 00 52 21 15 52   type=0x13, len=2
    send(2):  53 01                        该消息载荷（cmd S + data 1）

本地通道协议 = 9 字节头（type/len/magic）+ 载荷。

build_header 调用点 rva：0xb2b1a、0xb2bcd、0xb34c9、0xb358f、0xda571；
packet 构造 0x4b2714 调用点：0xd71d3 ~ 0xe0340 多个。

产物：analysis/tmp/live_lib_magic.json、live_lib_hdr_calls.json，脚本 fr_magic_scan.py、
fr_hdr_xrefs.py、fr_dump_magic.py、lib_magic_dis.py、hdr_calls_dis.py。
## 15. 收包/发包字节层与握手引擎归一化（当前会话）

### 字节级 I/O 封装（lib 静态 VA）

    0x49c82c   recv(sock, buf, len, flags=0)
    0x49c1c4   send(sock, buf, len, flags=0)

### 收包/发包函数

    0x4b2d00   recv_packet(channel, buf_obj)
               recv 9 字节头 -> is_header(校验 magic) -> 取 dword[hdr+1] 作为载荷长度
               -> 再 recv 载荷字节；失败时调用 0x4b2cbc（连接错误处理）
    0x4b2db8   send_packet_raw(channel, hdr_buf, payload_ptr, payload_len)
               先 send 9 字节头，再在 payload_len>0 时 send 载荷
    0x4b2ad8   send_packet(channel, dl=type, payload_ptr, payload_len)
               组装头部后调用上面的发送逻辑（见第 14 节）

### 握手引擎（lib 静态 VA）

    0x4dc170   send_type13(channel_obj, buf=edx, len=ecx)
               该函数 push len; dl=0x13; eax=[ebx+4]; call 0x4b2ad8
               即发送 type=0x13 的消息，载荷长度由 ecx 给出
    0x4dc138   send_type13_short(channel_obj)：dl=0x13、载荷取 [ebx+8]
               （对应无额外参数时的 0x13 消息）
    0x4dc10a   发送 type=0x0d（握手请求）的调用点（payload_len=0）
    0x4dc18d   发送 type=0x13（第二条消息，payload_len=2）的调用点

### 握手时序（最终归一化）

    send_packet(type=0x0d, len=0)             -> 0d 00 00 00 00 52 21 15 52
    recv_packet：9 字节头 0e ... 52 21 15 52（type=0x0e，服务端应答）
    send_packet(type=0x13, len=2, payload 53 01)
                                             -> 13 02 00 00 00 52 21 15 52 + 53 01

接收校验逻辑位于 0x4b2e04 区（is_header + dword[hdr+1] 长度检查），
连接异常路径调用 0x4b2cbc。

产物：analysis/tmp/live_lib_engine.json，脚本 fr_recv_hooks.py、parse_recv.py、
lib_recv_dis.py、lib_region_dis.py。
## 16. 收发包调用链证据（当前会话）

挂钩结果（两个独立 spawn 会话，lib base 不同，RVA 一致）：

    send_packet(0x4b2ad8) 调用者 rva 0xdc10a（type=0x0d，len=0）
    send_packet(0x4b2ad8) 调用者 rva 0xdc18d（type=0x13，len=2）
    send_raw(0x4b2db8)   调用者 rva 0xb2f0f
    io_send(0x49c1c4)    调用者 rva 0xb2dec（edx=header 缓冲、ecx=9）
    收包应答的 is_header 校验发生在 0x4b2e04 区域

即本地握手发包路径：
    引擎(0x4dc170/0x4dc10a) -> send_packet(0x4b2ad8) -> send_raw(0x4b2db8)
    -> io_send(0x49c1c4)

同时确认 lib 内存在第二套 socket 对象方法栈：
    0x49b444 recv 方法、0x49b4c4 send 方法、0x49b1ec connect 方法
    它们内部调用 wrapper 0x498cc8/0x498cec/0x498c60（查 vtable 后调 ws2 thunk）
    —— 这套栈由另一条调用路径使用（本地通道握手走的是上面的 packet 层）。

未闭合点：6 秒窗口内没有捕获到 0x49c82c(io_recv)/0x4b2d00(recv_packet) 的调用，
说明握手应答的读取路径尚未挂到（可能是阻塞在另一线程、或走 socket 对象方法栈）。
下一次抓包应同时挂 0x49c82c、0x4b2d00、0x49b444，并延长窗口到 15 秒。
## 17. 协议调用图（当前会话）

### 握手函数（lib 静态 VA 0x4dc0e0）

    push 0; eax=[ebx+4](channel); ecx=0(payload); dl=0x0d; call 0x4b2ad8   ; send type 0x0d
    eax=[ebx+4]; call 0x4b3064                                          ; wait_reply
    ... 之后 0x4dc170 发送 type 0x13（载荷 53 01）

### wait_reply(0x4b3064) 的调用点（rva）

    0xd7953、0xdc10d（握手函数内）、0xdc71f、0xdd994

### send_packet(0x4b2ad8) 的调用点（rva，消息发送者）

    0xdc105（type 0x0d）、0xdc188（type 0x13）、0xdb314、0xdc49f、0xdc714、
    0xdd989、0xddb16、0xddb62、0xddbc2、0xddc53、0xddebf、0xdee86、0xdef15、0xdef5b
    （即引擎层大约 12 个不同类型的消息发送点）

### 发送层次

    send_packet(0x4b2ad8) -> send_buf(0x49cbd4，内部调用点 0xb2b2b/0xb2b40)
    -> socket send 方法(0x49b4c4) -> wrapper(0x498cec) -> thunk(0x950ec) -> [0xf4a308]=ws2 send

send_buf(0x49cbd4) 的其他调用点：0xdc750、0xdcb75、0xdcb9b、0xde08f、0xdf017。

### 接收侧现状

recv_buf(0x49c230) 在活内存里没有任何 E8 调用点，说明 wait_reply 使用另一条接收路径。
下一步：dump 0x4b3000-0x4b3400 活内存，反汇编 wait_reply(0x4b3064)，
确定它的 recv 调用与 buffer 解析（is_header 0x4b2764 与之的关系）。

产物：analysis/tmp/full_io_trace.log、live_lib_sockmethods.json，脚本 fr_full_io.py、
parse_full_io.py、fr_dump_sockmethods.py、lib_sock_dis.py、fr_final_xrefs.py。
## 18. 接收/应答实现的归一化（当前会话）

对 0xb2000-0xb3800 活内存窗口（lib rva）反汇编后发现：

- wait_reply(0x4b3064) 是薄封装：`xor ecx,ecx; xor edx,edx; call 0x4b30b8; ret`，
  真正的接收实现在 0x4b30b8 附近（该区域混有数据表，函数入口需进一步定位）。
- 0x4b2f54 是“收 0x0d 并回 0x0e”的实现：
    1) 从 edx 复制 0x3a 字节消息模板到栈
    2) call 0x4b2edc（recv_into：channel、type 0x0d、缓冲区=ebp-0x1038、上限 0x1000）
    3) call 0x4b0818（把收到的数据与模板比对/解析）
    4) 失败时 call 0x4b2cbc（连接错误处理）
    5) call 0x4b2ad8 send_packet(type=0x0e, len=0) 回送应答
    6) 若 esi 非空，把 esi 指向的 0x37 字节复制到接收缓冲
- 0x4b3034 是“回 0x0e”的简化版本：先 0x4b2edc(type 0x0d) 再 send_packet(type 0x0e)。

因此 type 0x0d/0x0e 是握手请求/应答；lib 内同时包含客户端发送端(0x4dc0e0/0x4dc170)
与服务端应答端(0x4b2f54/0x4b3034)，Smonitor 与 Student 共用这套协议栈。

窗口开头的 0xb2000-0xb2083 是状态机跳转表（返回 1..7 等小整数），
对应消息处理后的状态迁移值，下一步可据此还原状态机。

产物：analysis/tmp/live_lib_recv2.json，脚本 fr_dump_recv2.py、lib_waitreply_dis.py、
lib_recvloop_dis.py。
## 19. 用 REA/Ghidra 反编译 lib（当前会话）

### 方法

1) frida 分块 dump 当前会话 lib.dll 的完整活内存镜像（2,301,952 字节，36 块 x 64KB，
   多轮补齐），保存 analysis/tmp/live_lib_full.bin。
2) 用静态 lib-stage2.dll 的 section 布局做骨架，把活内存按 VA 覆盖进对应 raw 偏移；
   保留文件头布局，只把 AddressOfEntryPoint 改成 0xb3064（wait_reply），
   并把 16 个 data directory 全部清零（原导入表损坏，REA 之前打不开）。
3) REA open_binary 成功，Ghidra 正常分析并反编译。

### REA 反编译结果（修正之前的标签）

    0x49c1c4  recv_bytes(channel, buf, len)：从通道队列循环读满 len 字节
    0x49cbd4  send_bytes(channel, buf, len, flush)：经缓冲对象发送（含 flush 语义）
    0x4b2754  build_header(buf, type, len)  -> [type][len:4][magic 0x52152152]
    0x4b2764  is_header(buf)：魔数校验
    0x4b2ad8  send_packet(ch, type, payload, len)：建头 -> send_bytes(9) -> 载荷
    0x4b2db8  recv_packet(ch, hdr, payload_buf, payload_len)：
              recv_bytes(9) -> is_header -> 按 hdr.len recv 载荷 -> 通道状态检查
    0x4b2edc  recv_expect(ch, expected_type, buf, len)：recv_packet + 类型比对，
              不符则 0x4b2cbc(disconnect)
    0x4b30b8  wait_reply(ch) = recv_expect(ch, 0x0e, 0, 0)
    0x4b3064  wait_reply 的入口封装
    0x4b2cbc  disconnect(ch)：调用通道 vtable +0x58
    0x49b4c4  send 方法：校验状态后调 0x498cec
    0x49c230  通道收包/轮询循环：vtable +0x50 等待数据并填入队列

### 修正后的握手语义

    发送 type=0x0d 的包（无载荷）
    wait_reply() 以 expected_type=0x0e 调用 recv_expect —— 明确等待类型 0x0e 的应答
    收到后发送 type=0x13、载荷 53 01

因此客户端状态机是“发 0x0d -> 等 0x0e -> 发 0x13”，类型必须严格匹配。

### 说明

之前的标签把 0x49c1c4/0x49cbd4 的收发方向弄反了（capstone 静态阅读容易误判），
REA 反编译的调用语义直接纠正。

产物：analysis/tmp/lib-live.dll（sha256 00893bc5...）、live_lib_full.bin、
build_liblive2.py、fr_dump_lib_full.py。
## 20. REA 反编译：接收方法与服务端握手（当前会话）

### 入口改写副本

lib-live.dll 里 REA 没给 0x49b444/0x4b2f54 建函数，用同样方法做入口改写副本：
保留 section 布局与活内存覆盖，把 AddressOfEntryPoint 改为目标 RVA（注意是 RVA 不是静态 VA），
清零 data directory。REA 打开后即可反编译：

    analysis/tmp/lib-live-e9b444.dll  entry=0x9b444
    analysis/tmp/lib-live-e4b2f54.dll entry=0xb2f54

### 0x49b444 —— 通道 recv 方法

    channel_recv(ch, buf, len)：
      检查 ch->vtable+0x48 状态；失败则弹错误并终止；
      否则 FUN_00498cc8(ch->[0x1c], buf, len, 0)（转发到内层对象 recv）

同理 0x49b4c4 是 channel_send（调 FUN_00498cec）。

### 0x4b2f54 —— 服务端握手应答

    handler(ch, template55, param3)：
      1) 从 template55 复制 0x37=55 字节到栈上 [ebp-0x38]
      2) FUN_004b2edc(ch, 0xd, stackbuf(0x1000), 0x1000)
         -> recv_expect(type=0x0d)，即接收客户端握手包（头部 9B + 载荷）
      3) FUN_004b0818() -> FUN_004ac76c -> FUN_00409588（内存比较）
         比较 [ebp-0x103c]（收到的载荷）与 [ebp-0x38]（55 字节模板）
      4) 不相等 -> FUN_004b2cbc(ch) 断开连接
      5) 相等 -> FUN_004b2ad8(ch, 0xe, 0, 0) 回送 type=0x0e、无载荷
      6) param3 != 0 时把 0x37 字节模板回写给调用者

结论：服务端握手 = “收 type 0x0d 包 -> 载荷与 55 字节模板 memcmp -> 相等才回 type 0x0e”。

### 已知函数地图（REA 归一化后）

    FUN_00409588  memcmp(a,b,len)
    FUN_004ac76c  memcmp 包装：相等返回 -1，不等返回 0
    FUN_004b0818  = FUN_004ac76c 的转发（比较两次 recv 结果与模板）
    FUN_004b2f54  服务端握手应答处理器
    FUN_004b2edc  recv_expect(type)
    FUN_004b2db8  recv_packet（收 9B 头 + magic 校验 + 收载荷）
    FUN_004b2ad8  send_packet（建头 + 发头 + 发载荷）
    FUN_0049b444  channel_recv -> FUN_00498cc8
    FUN_0049b4c4  channel_send -> FUN_00498cec

产物：analysis/tmp/lib-live-e9b444.dll、lib-live-e4b2f54.dll、build_entry_copies.py、fix_entry.py。
## 21. 协议层调用者图与客户端连接流程（当前会话，REA）

### 调用者图（REA procedure_callers）

    recv_expect(0x4b2edc)  <- 0x4b3034（服务端应答）、0x4b30b8（wait_reply）
    wait_reply 入口(0x4b3064) <- 0x4dc0e0、0x4dc65c
    send_packet(0x4b2ad8)  <- 0x4b3034、0x4d6fc4、0x4d7cf4、0x4dad10、0x4db2b0、0x4dc0e0、0x4dc170、0x4dc468、0x4dc65c
    客户端握手 0x4dc0e0     <- 0x50ddcc

### 发送函数分类

    generic 发送包装（带锁）：
      0x4d7cf4：FUN_4d5dc4 加锁 -> send_packet(ch->[0x40], type=param2, payload, len) -> FUN_4d5dd0 解锁
      0x4dad10：FUN_42fb18 加锁 -> send_packet(ch->[0x40], ...) -> FUN_42fb20 解锁
    type=0x13 载荷发送：
      0x4d6fc4 / 0x4db2b0：len 非 0 时查会话（FUN_4d495c / FUN_4d49bc），send_packet(ch->[0x68], 0x13, payload, len)
      0x4dc468：send_packet(*(ch+8)+0x68, 0x13, payload, len)，返回 -1/0

### 客户端连接流程（0x4dc65c 反编译）

    if (obj[0xd] != 0) return;                       // 已连接
    vtable+0x88(obj[0x88])；vtable+0x8c(obj[0x8c])；vtable+0x94(-1)  // 设置超时等选项
    if (!vtable+0x54()) return;                      // 状态检查
    FUN_4b2210(...)                                  // 初始化/清缓冲
    send_packet(ch, 0xd, obj+0x50, 0x37)             // type 0x0d，载荷 55 字节
    wait_reply(ch)                                   // 等待 type 0x0e
    send_bytes(ch, obj+0x8e, 0x41, 0)                // 再发 65 字节原始数据块
    recv_bytes(ch, &len, 8)                          // 先收 8 字节长度
    recv_into(ch, obj+0x44, len)                     // 按长度收数据块
    FUN_4dc638(obj, 0xd)；disconnect(ch)

### 两条 0x0d 握手变体（重要）

    0x4dc0e0：Smonitor 本地通道握手，send_packet(type=0x0d, len=0)，与运行期抓到的 0d0000000052211552 一致。
    0x4dc65c：教师/课堂通道连接，send_packet(type=0x0d, 载荷=55 字节)，然后 wait_reply(0x0e)，再交换 65 字节块和“8 字节长度+数据块”。

实验室没有教师连接，所以只观察到 len=0 的变体。55 字节载荷是客户端（机器/会话信息）模板，
正好对应服务端 0x4b2f54 里的 55 字节模板 memcmp 校验。

产物：REA 证据（lib-live.dll 会话），本节无新增文件。## 22. 通道辅助函数与线程入口（当前会话，REA）

### 线程入口

    0x50ddcc：无静态调用者（CreateThread 入口），逻辑为：
      if (stack_arg != 0) return FUN_004dc0e0();   // 进入 Smonitor 通道握手
    即本地通道握手跑在独立工作线程里。

### 读写辅助

    0x49c1c4  recv_bytes(ch, buf, len)：循环读满 len 字节
    0x49c4d8  recv_u32(ch, transform, default)：读 4 字节；transform 非 0 时经
              [*_DAT_00c7a778 + 0x44] 做一次变换（字节序/解码）
    0x49c82c  recv_into_buffer(ch, buf, len)：先 recv_bytes，再按需用 recv_u32 变换
              （调用者：0x4b2d00、0x4dc65c）
    0x49cbd4  send_bytes(ch, buf, len, flush)
    0x49d1c8  flush_buffer(ch, size)：把缓冲对象 [ch+0xb0] 中 size 字节经 send_bytes 发出，
              然后消费该缓冲（vtable+0x24），size 为 -1 时发全部

### 通道初始化/清理

    0x4b2210  channel_init(ch)：FUN_489a1c(ch, 0xffff, 8, 4) 与
              FUN_489ad4(ch, 0x98000004, ...) —— 设置 socket 选项（超时/缓冲一类）
    0x4b37c8  free_ptr(p)：释放并清零指针
    0x4dc638  channel_cleanup(obj)：FUN_4b37c8(obj+0x44) + thunk_FUN_0052dbe5()
              （释放接收缓冲并调用清理 thunk）

### 收发对象关系（已确认）

    recv_packet(0x4b2db8) -> recv_bytes(0x49c1c4)
    send_packet(0x4b2ad8) -> send_bytes(0x49cbd4)
    channel_recv(0x49b444) -> wrapper(0x498cc8) -> thunk(0x94e3c) -> [0xf4a410]
    channel_send(0x49b4c4) -> wrapper(0x498cec) -> thunk(0x950ec) -> [0xf4a308]
    0x49c230 是通道轮询循环（vtable+0x50 等待数据并填队列），由虚调用进入。

### 下一步

接收分发的静态调用者仍在虚调用后面，改用运行期挂钩：spawn 后同时挂
0x49c1c4、0x49c82c、0x49b444、0x49c230，窗口拉到 30 秒，
抓阻塞在 recv 的工作线程及其调用者 RVA，再反编译分发函数。

产物：REA 证据（lib-live.dll 会话），本节无新增文件。## 23. 接收分发的运行期证据（当前会话）

30 秒 spawn 窗口（lib base 0xe00000），挂 recv_bytes/recv_buf/ch_recv/poll_loop/recv_packet/thunk 后的事件：

    1.002 thunk_send  caller 0x98d0c（type 0x0d 头）
    1.002 recv_bytes  caller 0xb2dec（recv_packet 内，读 9B 应答）
    1.003 poll_loop   caller 0x9c1e6
    1.004 ch_recv     caller 0x9c2e4（poll_loop 内）
    1.005 thunk_recv  caller 0x98ce5
    1.005/1.006 thunk_send caller 0x98d0c（type 0x13 头 + 载荷 2B）

之后 30 秒内没有任何接收调用：本地通道在空闲时没有阻塞的收包线程被触发。

结论：
- 0x49c230(poll_loop) 只在握手读取过程中被调用一次（caller 0x9c1e6），
  不是常驻轮询线程；
- Student 完成握手后只发不收（实验室里 Smonitor 也不发后续消息），
  所以 type 0x13 消息的分发路径在实验室空闲状态下不会被执行；
- 这也解释了为什么之前所有动态实验都看不到“接收命令 -> 执行”的链路。

### 下一步（可执行）

在 guest 内用 PowerShell 起一个假的本地服务端替代 Smonitor：
1) 停 Smsvc、杀 Student；
2) 用 PowerShell TcpListener 监听配置里的 mt 端口；
3) 启动 Student，接受其连接，回 9 字节 0x0e 应答（0e0000000052211552），
   再主动发一条 type=0x13 的 9 字节头 + 载荷（例如 53 01 或其它命令）；
4) 同时用 frida 挂 recv_bytes/recv_packet/poll_loop，观察 Student 的分发与处理，
   从而把 type=0x13 的处理器链路抓出来。

产物：analysis/tmp/recv_dispatch_trace.log，脚本 fr_recv_dispatch.py、parse_recv_dispatch.py。## 24. 假服务端注入实验（当前会话）

### 方法

在 guest 内用 PowerShell 起假服务端（base64 落地 fakesrv.ps1）：

    TcpListener 127.0.0.1:<config mt>
    接受 Student 连接 -> 读 9 字节握手 -> 回 0e0000000052211552
    再读 11 字节（第二包 9B 头 + 2B 载荷）
    之后每 1.2 秒主动发一条 0x13 消息（9B 头 + 载荷 53 01），共 10 条

### 结果

假服务端完整走通了握手：

    接受连接 -> 读握手头 -> 回 0x0e -> 读第二包 -> 连发 10 条 0x13

但 Student 进程在启动早期就退出（spawn 后约 0.7s，frida 脚本的 installed 消息都没发出），
日志中连接立即 eof。对照实验：保持 Smsvc/Smonitor 运行时 Student 正常驻留，
停掉后 Student 启动即退出，说明 Student 启动依赖 Smonitor 存在（可能检查进程/互斥体/窗口）。

### 结论与下一步

注入思路可行，但必须在 Student 认为“服务存在”的前提下进行：
1) 让 Smsvc/Smonitor 保持运行；
2) 把 config.cfg 的 mt 改成假服务端端口（Smonitor 仍监听它自己的旧端口）；
3) 再 spawn Student，让它在启动时连到假服务端；
4) 假服务端完成 0x0d/0x0e 握手后发 0x13 消息，frida 挂 recv 系列函数观察分发。

注意：Smonitor 启动时会改写 config 的 mt，所以修改 mt 要在 Smonitor 已启动之后、Student 启动之前。

产物：analysis/tmp/fake_dispatch.log、fakesrv.ps1（guest 内）、fr_fake_dispatch.py、parse_fake.py。## 25. 假服务端注入：正常启动路径成功（当前会话）

### 关键发现：Student 启动时先做探测连接

假服务端日志显示 Student 会先建立一次“连上就关”的探测连接，然后再建正式连接。
单次 accept 的假服务端会吃掉探测连接，导致正式连接没人 accept；改为 accept 循环后正常。

### 正常启动 Student + 假服务端的完整记录

    00:21:02.462 listening
    00:21:02.494 accepted
    00:21:02.556 eof            <- 探测连接（连上就关）
    00:21:02.603 accepted       <- 正式连接
    00:21:02.666 hdr 0D-00-00-00-00-52-21-15-52
    00:21:02.666 sent 0e
    00:21:02.681 second 13-02-00-00-00-52-21-15-52-53-01   <- Student 的第二包（0x13 + 载荷）
    00:21:02.697 起每 1 秒发送 0x13 消息（53/54/55 与 53 00 轮换）

说明 Student 在 Smonitor 进程存在、config mt 指向假端口时能正常启动并完成握手，
并且会持续保持连接，具备接收 0x13 消息的条件。

### 未完成点

在 frida spawn 下同一套环境出现异常：frida 的 installed 标记没发出，
假服务端记录到大量 accepted/probe-closed（Smsvc 看门狗在反复重启 Student），
暂时没有拿到 spawn 模式下的分发事件。下一步把 ar 关掉、只留 Smonitor 存活，
再重试 spawn 捕获；或改为 attach 到已正常运行的 Student。

### 结论

假服务端注入方案在“正常启动”路径上已验证可用：握手、第二包、后续 0x13 消息都能收到。
接下来只需在稳定进程上挂 recv 系列钩子即可观察 type=0x13 的分发处理。

产物：analysis/tmp/fake_dispatch.log、diag_hooks.log、fr_fake_dispatch.py、fr_diag_hooks.py、parse_fake.py。## 26. attach 方案受挫与诊断（当前会话）

计划：正常启动 Student 连假服务端，然后 frida attach（非 spawn）挂接收函数。

实际情况：
- 该轮启动的 Student 存活约 3 秒后退出，假服务端日志里只有 listening，没有任何 accepted，
  说明 Student 根本没连到 45000 端口；
- frida attach 时报 TransportError: connection is closed（目标已退出）。

对比第 25 节成功记录（00:21:02）：那次 Student 正常连上假服务端并完成握手。
差异点：本次为了控制看门狗先重启了 Smsvc（Smonitor 换了新实例），
而第 25 节成功时没有重启服务。

结论：
- “Smonitor 已运行 + config mt 指向假端口” 这个组合在重启服务后不稳定，
  Student 可能在网络初始化前就因为别的原因退出（进程/服务状态检查）；
- 更稳的做法是不要再重启 Smsvc，直接复用当前 Smonitor 实例，只改 config mt 后启动 Student；
- 或者放弃假服务端，改为 attach 到已连真实 Smonitor 的 Student，用 frida 直接调用
  分发函数/伪造消息结构来触发处理器。

下一步优先尝试：不重启服务，只做“杀 Student -> 改 mt=45000 -> 起假服务端 -> 起 Student”，
复现第 25 节成功记录后立刻 attach。

产物：analysis/tmp/attach_dispatch.log（空）、fr_attach_dispatch.py。## 27. 假服务端场景的连接风暴与诊断（当前会话）

不重启服务直接复现第 25 节配置时，出现连接风暴：

    00:24:48.773 probe closed（同一毫秒内几十次）

清理时捕获到关键证据：`before_clean: stud=2 wer=0`，
即同一时刻存在两个 Student 实例，且没有崩溃对话框（WerFault=0）。

### 原因

- Smsvc 看门狗以缓存的 ar=1 运行；杀掉 Student 后立刻重启一个新的 Student；
- 我们手动再启动一个 Student，ChkInstance 让其中一个退出，看门狗又补一个，形成循环；
- 每个新 Student 启动后先对 config mt 指向的假服务端做探测连接，随即退出，
  于是假服务端看到大量 accepted/probe-closed。

### 处理

清理后恢复：smon=1800 port=64382、stud=1、mt=64382、ar=1，环境稳定。

### 两条更稳的注入路径（下一步择一）

1) 看门狗关掉的单实例路径：
   先把 config ar 改 0 并重启 Smsvc（让看门狗读到 ar=0），
   确认杀掉 Student 后不再自动重启、系统中只有一个 Student，
   再改 mt=45000、起假服务端、启动单个 Student，完成握手后立刻 attach。
   注意：第 18 节用同样顺序失败过，重试前要先确认 45000 端口只有一个假服务端实例，
   并确认 Smonitor 已完全初始化。

2) 教师通道路径（推荐）：
   Student 会主动连接教师机；把教师地址配置改为 host 侧地址 10.0.2.2 和指定端口，
   在 host 上起假教师服务端（不需要 guest 内假服务端、不动 mt/Smonitor），
   杀掉 Student 让看门狗自动重启，新 Student 会连接 host 假教师，
   触发 0x4dc65c 的教师通道握手（0x0d + 55 字节载荷 -> 0x0e -> 65 字节块），
   frida attach 到新 Student 观察后续消息处理。
   需要先查清教师地址对应的 config 键（CONFIG-KEYS.md 里待确认项）。

产物：本轮无新增文件。## 28. pi/pa 教师地址密文的读取路径（当前会话）

### 运行期证据

spawn 时钩 kernel32 的 GetPrivateProfileStringA/W，捕获到启动期读取的键与值：

    0.782 GetPrivateProfileStringA key=pa ret=64  val=0F19F506C8D05A999BBC86DBE2E143EF1836FD6261D5FA67FDC1FA11BF186221
    0.789 GetPrivateProfileStringA key=pi ret=48  val=0B1BF171CCD55A999CBAFADCE7E247991C3587631CD08667

同时读到 md/ms/mt/ar/pt/ps/po/fs/fc/bd/it/ul 等键（值解码有乱码，键名可辨）。

### 与离线磁盘报告对照

当前 guest config.cfg 实际值：

    pi=0B1BF171CCD55A999CBAFADCE7E247991C3587631CD08667   (48 hex)
    pa=0F19F506C8D05A999BBC86DBE2E143EF1836FD6261D5FA67FDC1FA11BF186221 (64 hex)
    pt=230

与 analysis/offline-disk/REPORT.md 里另一台机器的快照完全一致，
说明 pi/pa 不是每台机器随机生成，而是构建/安装期的固定密文（或按同一密钥生成）。

### 解密函数定位尝试

对 GetPrivateProfileStringA 返回缓冲区（栈地址 0x19f508）启用 MemoryAccessMonitor，
期望抓到首次读取该缓冲的指令地址；实际没有触发任何访问事件（既无命中也无错误）。
推测：Delphi RTL 在 API 返回后立刻复制，监控安装时机太晚或监控实现不覆盖该访问。

### 下一步

改用 frida Stalker：在 pi/pa 的 onLeave 里对当前线程 Stalker.follow 约 5-20ms，
记录紧随其后的调用/基本块，筛出 Student/lib 内新增执行的函数，再交给 REA 反编译；
若解密是延迟触发的，则改为 hook 网络发送（0x4dc65c 教师通道）并在发送前开启 Stalker。

产物：analysis/tmp/profile_trace.log、pi_monitor.log，脚本 fr_profile.py、fr_pi_monitor.py、parse_profile.py。## 29. pi/pa Stalker 跟踪与 pd 明文教师地址实验（当前会话）

### Stalker 结果

在 GetPrivateProfileStringA 返回 pi/pa 后对当前线程 Stalker.follow 15ms，抓其后的调用目标：

- pa 窗口：224 个目标，其中 Student 层地址 0x56xxxx/0x5exxxx 与 lib 0xe4xxxx 占多数；
  例：0x43e144(11)、0x43f7c4(15)、0x561920(2)、0x5e6bed(21)、0x5ece56(21)、
  以及 lib 0xe41e98(219)、0xe4216c(581)、0xe428a0(274) 等；
- pi 窗口：428 个目标，同样集中在 Student 层与 lib；
- 典型层内候选：0x5e6bed、0x5ece56（与已知 API wrapper 0x5e80b4/0x5ec573 同区域）。

注意：15ms 窗口包含大量 Delphi RTL 与初始化噪声，还不能直接认定解密函数；
需要结合“基线窗口（无 pi/pa 读取）”做差分，或对 0x56xxxx/0x5exxxx 的候选函数用 REA 反编译核对。

### pd 明文教师地址实验

配置键 pd 在启动时确实被读取（profile 日志里有 key=pd）。
实验：config 增加 pd=10.0.2.2、pt=12345，host 侧监听 0.0.0.0:12345，
启动 Student 并等待约 20 秒，host 监听端没有收到任何连接。

结论：本 build 不把 pd 当教师地址使用（或还需要其它键配合），教师连接地址仍由 pi/pa 密文决定。

### 环境处理

实验后已删除 pd、pt 恢复 230、ar 恢复 1、重启 Smsvc 并把 mt 改回 Smonitor 实际端口。

产物：analysis/tmp/stalker_pi.log、teacher_listen.log，脚本 fr_stalker_pi.py、parse_stalker.py、parse_stalker2.py、teacher_listen.py。## 30. 差分 Stalker 与十六进制解密特征扫描（当前会话）

### 差分 Stalker

分别以 config 键 mt（基线）、pa、pi 的读取为触发点，对同一线程 Stalker 15ms：

    pa: 320 目标 / 15978 次调用；pi: 380 目标 / 4113 次；baseline: 400 目标 / 2384 次

按“pa/pi 中 count>=3 且相对基线放大 >=2 倍”筛出候选，最密集的地址全部落在 lib.dll
（本次 lib 基址 0xd20000，RVA 0x1e98-0x5d2c），REA 反编译确认它们是 Delphi RTL：

    0x404ef0  string length 读取
    0x402edc  Move/memmove 实现（正反向复制）
    0x40216c  内存块链表分配
    0x404c30  字符串引用计数释放

即差分窗口抓到的是 Delphi 字符串/内存管理，不是解密算法本身。

### 十六进制解析特征扫描

对 lib 活镜像 CODE 段（RVA 0x1000-0x110000）搜索：

    sub al,0x30   3 处（0xacde、0x1039c8、0x105fdd）
    cmp al,0x39   2 处（0xacd4、0x888c8）
    imul reg,10   0 处
    0..9 / 0..F 递增表：只在 DATA 段 0x115af1、0x11c3fc 找到 Delphi 字符集分类表，不是十六进制解码器

说明 pi/pa 的解密不是简单的逐字符十六进制循环，或者该逻辑位于 Student 层/混淆代码里。

### 推断

结合教师连接函数 0x4dc65c 在实验室从未被调用（只观察到 0x4dc0e0 的 len=0 握手），
pi/pa 的解密很可能是**惰性**的：只有真要连教师机时才执行。实验室无教师，故抓不到。

### 下一步

两条路：
1) 清空 config 的 pi/pa（保持 pd/pt 指向 host），看 Student 是否退化为明文教师地址或尝试连接；
2) frida 在运行中的 Student 里直接调用教师连接函数 0x4dc65c（构造/复用通道对象），
   触发 0x0d + 55 字节载荷发送，再在 send_packet/0x4dc65c 处 dump 载荷，看是否包含解密后的教师地址。

产物：analysis/tmp/stalker_diff.log，脚本 fr_stalker_diff.py、parse_diff.py、scan_hexlib.py、scan_tables.py、fr_mods.py。## 31. 明文教师地址与网络外连实验（当前会话）

### 实验设置

- 备份 config 后清空 pi/pa（删除两行），加入 pd=10.0.2.2、pt=12346；
- host 侧监听 0.0.0.0:12346（45 秒）；
- 重启 Smsvc（看门狗 ar=0）后手动启动 Student。

### 结果

- host 监听端 45 秒内没有收到任何连接；
- config 实际值：mt=64765（Smonitor 端口）、ar=0、pt=12346、pd=10.0.2.2，pi/pa 已删除；
- 随后 attach 到运行中的 Student（pid 5960），挂 ws2_32 的 connect/WSAConnect/sendto/WSASendTo/gethostbyname/GetAddrInfoW，
  20 秒内没有任何网络调用（只有 ready 标记）。

### 结论

1) 本 build 不会用明文 pd 作为教师地址，也不会因为 pt 改变而在启动时尝试外连；
2) 启动后 Student 完全没有外连动作（连 DNS 查询都没有），教师连接是事件驱动的；
3) 结合第 30 节，pi/pa 解密属于惰性路径，实验室无教师触发，因此抓不到。

### 下一步

要触发教师连接，需要在运行中的 Student 里直接调用教师连接函数 0x4dc65c：
用 frida 在 Student 进程里构造/复用通道对象（或找到调用 0x4dc65c 的上层函数 0x50ddcc 的调用者），
调用后在其内部 send_packet(0x0d, obj+0x50, 0x37) 处 dump 55 字节载荷，
即可看到解密后的教师地址/会话信息，并顺带触发 0x0e 等待逻辑。

产物：analysis/tmp/teacher_listen23.log、net_attempts.log，脚本 teacher_listen23.py、fr_net_attempts.py。## 32. 导出函数 GetCastAddr / GetDec 的语义（当前会话）

### GetCastAddr（导出 0x4cf8e0）= 广播地址计算

REA 反编译（入口改写副本 lib-live-cast.dll）得到：

    GetCastAddr(ip_str, mask_str):
      FUN_4cf754(ip_str, out4)    // 按 '.' 拆分 4 段并转成 4 字节
      FUN_4cf754(mask_str, out4)
      for i in 0..3: result[i] = (ip[i] & mask[i]) | ~mask[i]   // 即 (a&b)+~b
      FUN_40aff8(格式串, result)  // sprintf 成点分字符串

结论：GetCastAddr 不是地址解密，而是由 IP 和掩码算定向广播地址。

### GetDec / GetDec2 / GetEnc / GetEnc2（导出 0xcda7c / 0xcda98 / 0xcd988 / 0xcd9a4）

汇编显示它们是 stdcall 封装：

    GetDec:  push 1；push 0；push arg3；push arg2；push arg1；call 0x4cdab8；ret 0xc
    GetDec2: 同样但多一个参数，ret 0x10

0x4cdab8 -> 0x4cd318 的反编译显示核心是 RC4 风格变换：
   - 用 key 字符串做 0x100 项 KSA（state 数组每项 3 个 dword：index/value 交替）；
   - PRGA 循环逐字节取 key 流；
   - 每轮与输入字节异或后再 ^0xFF，外层最多 10 轮（params 1..10）。

### 运行期证据：Student 层调用 GetDec 解密配置

spawn 时 hook GetDec（libbase+0xcda7c）捕到三次调用，返回地址均为 Student VA 0x5656c2
（位于 FUN_0056564c 内，经层内 thunk 0x5e8a00 调用）：

    0.77  src=pa    (64 hex)  返回 EAX=16   -> 明文长度 16
    0.77  src=stcw  (124 hex) 返回 EAX=31   -> 明文长度 31
    0.78  src=pi    (48 hex)  返回 EAX=12   -> 明文长度 12（12 字符正是点分 IP 的长度）

参数布局（GetDec 入口栈）：[esp+4]=源密文 Delphi 字符串指针，
[esp+8]=0x5656fc（层内地址，疑似固定 key 或 key 表），[esp+0xc]/[esp+0x10]=栈上变量。

### 结论

pi/pa/stcw 在 Student 层启动期用 lib 导出的 GetDec 解密，pi 明文长度 12，
高度对应点分十进制教师 IP。实验室没有教师连接，但解密本身在启动时就执行了，
因此下一步可以直接在运行期读出 GetDec 的输出（解出 pi 的 IP），再把教师连接指向该 IP。

### 下一步

1) 精确确认 GetDec 参数语义（dest 变量是 [esp+0xc] 还是 [esp+0x10]），读出三次调用的明文；
2) 或者用 frida 直接调用导出的 GetDec（stdcall，3 参数）对任意密文解密；
3) 拿到 pi 明文 IP 后，可把 host 假教师绑定到该网段并观察 Student 是否连接。

产物：analysis/tmp/getdec_trace.log、getdec2_trace.log，脚本 fr_getdec.py、fr_getdec2.py、dis_getdec.py、lib_exports_crypto.py、lib-live-cast.dll、lib-live-getdec.dll、lib-live-dec.dll。## 33. 配置解密成功：密钥与明文（当前会话）

### GetDec 的真实参数与密钥

运行期 hook（libbase+0xcda7c）抓到参数：

    [esp+4] = 源密文 Delphi 字符串指针
    [esp+8] = 0x5656fc（Student 内的常量地址）
    [esp+0xc] = 输出缓冲区（char*，明文直接写入，无长度前缀）
    返回 EAX = 明文长度

0x5656fc 处内存为 ASCII "gakataka2014\0\0" 紧跟代码（55 8b ec ...），
即 **GetDec 使用固定密钥 "gakataka2014"**。

### 解密得到的明文（实测）

    pa  (64 hex)  -> "www.gakataka.com"                        (16 字符)
    pi  (48 hex)  -> "192.168.50.1"                            (12 字符)  <-- 教师机 IP
    stcw(124 hex) -> "cmd.exe,powershell.exe,pwsh.exe"         (31 字符)

三次调用都来自 Student VA 0x5656c2（FUN_0056564c 内经层内 thunk 0x5e8a00）。

### 意义

- 教师机地址确实是加密存储的，明文为 192.168.50.1，端口由 pt 给出（默认 230）；
- 客户机第二网卡 192.168.50.10/24 正是教师所在网段，与 pi 明文一致；
- host 侧没有 192.168.50.x 接口（只有 192.168.6.194），所以假教师必须在 guest 内实现：
  可给 guest 第二网卡加 192.168.50.1 别名，在本机监听教师端口；
- GetEnc/GetEnc2 使用同一密钥，可用来把任意明文加密后写回 config（例如改 pi/pa 测试）。

### 下一步

1) 在 guest 内给 Ethernet 2 添加 192.168.50.1/24，监听 pt=230，观察 Student 是否连接；
2) 若不连接，则触发条件是教师端主动广播/发现：需要在 192.168.50.255 上发 UDP 广播探测；
3) 也可用 GetEnc 造出任意 pi 值（如 192.168.50.1 保持不变）做对照实验。

产物：analysis/tmp/getdec7_trace.log、getdec8_trace.log，脚本 fr_getdec6.py、fr_getdec7.py、fr_getdec8.py、parse_getdec8.py。