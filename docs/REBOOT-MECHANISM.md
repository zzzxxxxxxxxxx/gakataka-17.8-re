# 重启机制（2026-10-31 21:22 已验证）

## lib!ShutWindow 的实际逻辑

rizin + rz-ghidra 反编译 lib.dll 的导出 ShutWindow（文件 VA 0x4ac9a0，RVA 0xac9a0）：

- 初始化函数 0x4ac3a8：若 [0x51c24c] 为空，则 GetModuleHandleA("ntdll.dll") 后解析并保存
  - [0x51c24c] = NtShutdownSystem
  - [0x51c254] = RtlAdjustPrivilege
  - [0x51c250] = ZwShutdownSystem
- SeShutdown 导出 = SeShutdown2(-1) = SetPrivilege("SeShutdownPrivilege", -1)
- 动作映射函数 0x4b213c：参数低字节 0 -> 0，1 -> 1，其它 -> 2
- 关键条件：全局 *(int**)0x51a898 指向的值为 2（实测 Student 与 Smonitor 里都成立）
- 当 arg_8h != 0 时走真正的关机/重启分支：
  - arg_ch != 0：先 SeShutdown() 提权，再调 NtShutdownSystem(mode)
  - arg_ch == 0：RtlAdjustPrivilege(0x13,1,0,&old) 后调 ZwShutdownSystem(mode)
  - mode 0/1/2 对应关机/重启/断电（rizin 反编译结合导出报告）
- arg_8h == 0 时只做窗口关闭/回调，不关机

## 直接调用验证

在 Smonitor 进程里用 frida：

    lib = Module lib.dll 基址
    NativeFunction(lib + 0xac9a0, 'int', ['int','int','int'])(1, 1, 1)

结果：QMP 在 21:22:36 记录到

    {"event":"RESET","data":{"guest":true,"reason":"guest-reset"}}

即 ShutWindow(1,1,1) 确实触发虚拟机重启（mode=1 为重启）。

## 当前结论

- 重启执行点已确认：lib!ShutWindow，mode=1，arg_8h != 0。
- 触发点仍未定位：在可观测状态下（开机、cmd 关闭、任务管理器尝试、U 盘插拔、U/V 命令），
  Student 和 Smonitor 都没有解析或调用 ShutWindow（全内存扫描不到该指针）。
- 现有证据仍指向教师端 0x11 命令（或学校特有的策略/构建）作为调用者。

## 命令映射补充

- U0/U1 -> lib+0xaf6e8 / lib+0xaf6f8（DisableUsbStore / EnableUsbStore），写 USBSTOR\Start
- V0/V1 -> lib+0xae958 / lib+0xae978（DisableGuest / EnableGuest）
- X 的保护入口 0x47404e，Q 的保护入口 0x47483f，W 直接调用 0x4588c4
- S 置位 taskmgr 清理标志，T 置位并持久化 ar

## 环境

- 宿主 frida Python 17.23.2（analysis/tmp/fvenv，pip 安装）
- 客户机 frida-server64（C:\Users\zzx\frida-server64.exe，监听 27042）
- QEMU hostfwd 27042（运行时 hostfwd_add）
- 相关脚本：analysis/tmp/fr_trace3.py、fr_hooks.py、fr_map.py、fr_globals3.py、fr_reboot.py

## 第二轮补充（2026-10-31 21:32）

- 环境恢复：Smsvc 运行，Smonitor PID 2856，本地服务端口 TCP 49670，Student 已连接。
- 全内存扫描 Smonitor：没有任何指针或代码立即数引用 ShutWindow(0xac9a0)/SeShutdown(0xac928)/SeShutdown2(0xac930)。
- 通过本地通道（握手后发 0x11 00/01/02）不会触发重启，ShutWindow 钩子无命中，说明本地命令面不接受教师命令号。
- 窗口清理的真实调用链：Student/lib 内部监控线程反复调用 CloseWindowCN（返回地址 lib+0xaaf05/0xaaf14/0xaaf23，同一函数内三个调用点）。
  运行中抓到的参数：
  - class=#32770, title=Internet 协议 (TCP/IP) 属性
  - class=#32770, title=Internet 协议版本 4 (TCP/IPv4) 属性
  - class=Windows.UI.Core.CoreWindow, title=任务视图
- 注意：Thread.backtrace(FUZZY) 在 WOW64 下会产生伪帧（例如 lib+0x21ed3 处静态不是代码），
  需要用 Interceptor 的 this.returnAddress 取精确调用点。
- lab 当前 config.cfg 关键值：md=..., ms=0, mt=49670, ar=1, pt=230, stc=2, stcw=<长十六进制>，
  与学校现场是否一致未知。

## 仍未解决

- 重启调用者：本地可观测路径没有任何代码解析或调用 ShutWindow；教师端 0x11 的网络到达路径尚未接通/复现。
- 需要学校侧的策略状态或教师命令流量，才能定位调用点。


## 第三轮补充（2026-10-31 21:36）

### 全 API 钩子覆盖测试

在 Student.exe 和 Smonitor.exe 里同时挂钩：

- ntdll: NtShutdownSystem / ZwShutdownSystem / NtSetSystemPowerState / ZwSetSystemPowerState
- advapi32: InitiateSystemShutdownExA/W、InitiateSystemShutdownA/W
- user32: ExitWindowsEx
- lib: ShutWindow / SeShutdown / SeShutdown2

触发组合：开 cmd、开 PowerShell、开 taskmgr、开网络连接设置页、taskkill cmd、taskkill Student、
热插 USB 存储设备。

结果：**所有 shutdown 类 API 零命中**（两个进程都没有调用）。

### 静态指针扫描

在两个活进程里扫描上述 API 的指针（IAT/函数指针）：

- NtShutdownSystem / ZwShutdownSystem / NtSetSystemPowerState / ZwSetSystemPowerState / 
  InitiateSystemShutdownExA/W：全部 0 命中
- ExitWindowsEx：各 1 命中，但地址在 user32 模块自身范围内，属于导出表/模块数据，不是 IAT

### 结论

当前安装包 + 当前配置下，Student/Smonitor 既不静态导入、也不在可触发的运行路径上动态调用任何
关机/重启 API。唯一能重启的路径是 lib!ShutWindow（已在 21:22 通过直接调用验证，触发 RESET），
但没有本地代码引用它。学校的离线重启应来自教师端策略/命令或不同构建，lab 当前无法复现。


## 第四轮补充（2026-10-31 21:44）

### 配置结构（Student LoadConfig 0x562cbc 反汇编）

从 [config] 读取的键与全局：

    rs   -> 0x594088 (字符串)   pd -> 0x59408c (字符串)
    pa   -> 0x5940bc (字符串)   md -> 0x5940c4 (字符串)
    fn   -> 0x5940f0 (字符串)   stcw -> 0x5940c8 (字符串)
    iecw -> 0x5940d0 (字符串)   pt -> 0x594128 (整数, 默认 230)
    ps   -> 0x5940fc (byte)     stc -> 0x5940fd (byte)
    iec  -> 0x5940fe (byte)     fs  -> 0x594120 (整数, 默认 12)
    fc   -> 0x594124 (整数)     bd  -> 0x59411c (bool)
    it   -> 0x59411d (bool)     ul  -> 0x59411e (bool)
    po   -> 0x594101 (bool)     ms  -> 0x59411a (bool)

- rs/pd 在 lab 配置里不存在；对应功能是运行时弹出的“设置教师机 IP”对话框（提示字符串已确认）。
- ms 非零时会把 0x5940ac 设为字符串“未知”。
- stc/iec 加载后有一次越界钳制；stcw/iecw/pd 会先经 0x56564c 解码再存回。

### 压力实验（均未触发重启，也未命中任何关机 API）

- 连续打开 cmd/powershell 120 次：无命中、无重启。
- 连续强杀 Student 进程 30 次（服务自动重启它）：无命中、无重启。

### 安装面检查

- 服务/驱动枚举：没有 gakataka 相关的额外驱动或服务。
- gakataka 安装目录只有 Student/lib 与自带 VLC 插件树，没有额外的保护组件。

### 当前判断

当前 lab 安装与配置下不存在可触发的本地“违规→重启”路径。学校机器要么配置项不同，
要么构建不同；要定位只能拿到学校机器的 config.cfg 或二进制做对比。


## 第五轮补充：直接反编译结果（2026-10-31 22:05）

用 rizin + rz-ghidra 直接反编译 Student 的分派器（0x5833d0，765 行伪代码，保存为
analysis/unpacked-auto/student-0x5833d0.c）。关键片段：

    case 0x11:
        func_0x00404cf4();
        uVar2 = func_0x005659a4();          // 解析倒计时秒数
        **(undefined4 **)0x5928f0 = uVar2;  // 存入全局倒计时
        if (*(char *)(var_ch + 1) == '\0') {
            func_0x00585370();              // 关机流程
        } else {
            func_0x00585404();              // 重启流程
        }
        break;

重启流程伪代码（0x585404）：

    void fcn_585404(param_1, param_2) {
        if (param_2 != 0 && func_561838("系统提示","确定要重启电脑吗") == 0) return;
        if (param_2 == 0 && **(int**)0x5928f0 > 0) {
            uVar = func_47067c(0x46d);
            func_561a28("%d 秒后将重启电脑", 1, **(int**)0x5928f0, uVar);
        } else {
            func_5854a4();  // 执行
        }
    }

关机流程 0x585370 同构，只是字符串换成“确定要关机吗 / %d 秒后将关闭电脑”，参数 2。
执行器 0x5854a4 -> 0x561840 -> 0x5ee145，最深层落在 0x5exxx 的混淆跳板区，
rz-ghidra 反编译会递归成自身，需要动态跟踪才能看到最终的关机 API 调用。

结论：重启由“类型 10 + 子命令 0x11”的报文触发，报文字段：
- payload[1] == 0：关机；!= 0：重启
- payload[2..]：倒计时秒数字符串


## 第六轮：静态模拟还原执行器（2026-10-31 22:1x）

由于 0x5exxx 区域是明文“栈式/返回导向”混淆（pushal/pushfd/ret imm），Ghidra/rz-ghidra 无法恢复 CFG。
改用 Unicorn 2.1.4 做静态具体执行：

- 映射 Student-stage2 映像到 0x400000，并用活进程内存 dump（up_Student_Student.exe-...bin）
  覆盖 .data/BSS（全局里保存的是运行期编码指针）
- 伪造 self、栈、TEB，从执行器 0x5854a4 开始模拟（EDX=1 表示重启）

结果：54 条指令后，混淆层解码出目标地址 0xd5c9a0。该 dump 会话中 lib.dll 基址
= 0xd5c9a0 - 0xac9a0 = 0xcb2000，即 lib!ShutWindow。

跳转瞬间栈内容：

    [esp+0x00] = 0x5854ae   （返回地址，说明是尾调用）
    [esp+0x04] = 0x1        （mode = 1，重启）
    [esp+0x08] = 0xffffffff
    [esp+0x0c] = 0xffffffff

即执行器等价于：lib!ShutWindow(mode, -1, -1)。
mode=1 重启（flows 的 0x585404 路径）；mode=2 关机（0x585370 路径）。
这与 lib!ShutWindow 的判定（arg_8h!=0 时 SeShutdown + NtShutdownSystem(mode)）完全吻合。

结论：本地重启链完整闭环：
网络报文(type10/sub 0x11) -> 重启流程 -> 执行器 -> lib!ShutWindow(1,-1,-1)
-> SeShutdown/NtShutdownSystem(1) -> 系统重启。

脚本：analysis/tmp/uni_live.py、analysis/tmp/uni_args.py（unicorn 2.1.4 虚拟环境 analysis/tmp/univenv）。


## 第七轮（2026-10-31 23:1x）

- 解析出混淆层的编码 API 表（0x595b80-0x595be8，26 个 lib 导出），公式：
  target = ~(-(~(rol32(enc + 0xA219ACE4, 30))))，lib 基址反推为 0xcb0000。
  详见 analysis/NORMALIZATION.md 与 analysis/tmp/decode_table2.py。
- Student 二进制里没有任何关机类系统 API 名字符串（只有 GetProcAddress 字面量），
  再次确认重启只能经 lib!ShutWindow。
- 用 QEMU 硬件断点挂在 Student/Smonitor 的报文分派器 0x5833d0 上，在打开 cmd 的
  违规场景下 95 秒内 0 命中：本地通道不经过该分派器，离线违规不会产生
  type=10/子命令 0x11 报文（至少在 lab 配置下）。
- Smonitor 的 .data 里没有同构编码表（基址投票无一致结果），本地协议魔数
  0x52211552 也不以常量形式存在，说明本地通道代码在混淆层里运行时构造。
- 轨迹级块归一化器：analysis/tmp/uni_norm.py，输出 analysis/tmp/norm/*.txt。


## 第八轮：针对“打开 cmd 就重启”的定向实验（2026-11-01 02:1x-02:20）

### 实验设置

- 师生机连通（教师端 02:00:32 上线 [192.168.50.10]），教师端日志确认已“启用保护”（02:15:28）
- 为排除本地策略值影响，直接改学生 config.cfg 的 stc 并重启 Student.exe 后新开 cmd 窗口测试：
  - stc=1（教师黑名单下发后）：新开 cmd 窗口保持，不关、不重启
  - stc=2：标题含 cmd.exe 的窗口会被关闭（01:45 已复现），不重启
  - stc=3：改配置、重启 Student 后新开 cmd 窗口保持，不关、不重启
- QMP 事件日志全程监听，没有 RESET 事件；教师端抓包全程只有 00 心跳，没有 0x11 报文
- 教师端“开启保护”实际下发的帧：
  
      13 02 00 00 00 52 21 15 52     (type=0x13 信封)
      0d 00                          (2 字节子命令)

  但学生端 config.cfg 未变化，之后打开 cmd 也没有重启

### 结论

在当前 lab 构建（Student 17.8.24.111）+ 当前安装下，不存在“本地检测到 cmd → 重启”的路径：

- stc=0/1/2/3 都验证过，行为只有“不处理”或“关闭命中窗口”，没有重启
- 本地能重启系统的唯一底层入口 lib!ShutWindow 没有被本地检测代码调用（REPORT §6、§14 已多次静态确认）
- 重启链路唯一已证实的触发面是教师端命令 0x11（远程重启/关机、教师退出策略）

因此学校“打开 CMD/PowerShell 后整机重启”更可能来自：

1. 教师端策略：教师端“学生端控制/软件黑名单”下发后，违规动作由教师端侧判定并自动发送 0x11（需要教师端在线）
2. 不同构建：学校安装包的 Student/lib 版本与 lab 不同，保护模式可能内置“违规→重启”
3. 其他管理组件：还原卡/网管软件/组策略等非 gakataka 的强制重启

要区分这三点，需要学校机器的 Student.exe/lib.dll 版本与哈希、config.cfg，或教师端“系统设置”里的违规处理项。

### 下一步

1. 拿到学校端 Student.exe、lib.dll、config.cfg 做版本与策略对比（最直接）
2. 在 lab 里用教师端真实操作“学生端控制→启用软件黑名单”，抓 0x0c 模式 2 报文（REPORT §13 曾抓到 0c 02 "cmd.exe,powershell.exe,pwsh.exe"），确认本地是否只关窗口
3. 检查教师端“系统设置”中是否有“违规后重启”类策略项，并抓取对应下发帧


## 第九轮：Smonitor 命令分派器与 X/Q/W 入口分析（2026-11-01 02:4x）

### 分派器位置与字母表

Smonitor-stage2.exe 的本地命令分派器 = `0x4589f8`，取命令首字节后：

    0x458a2a  mov al, byte [edx]
    0x458a2c  add eax, -0x51        ; 'Q' = 0x51
    0x458a2f  cmp eax, 7
    0x458a32  ja   default
    0x458a38  jmp dword [eax*4 + 0x458a3f]

跳转表（0x458a3f，8 项）确认：

    'Q' -> 0x458a5f     'R' -> 0x458a6e     'S' -> 0x458aca     'T' -> 0x458adb
    'U' -> 0x458af1     'V' -> 0x458b07     'W' -> 0x458b1d     'X' -> 0x458b29

即 Smonitor 本地协议只认 Q/R/S/T/U/V/W/X 八个字母命令，命令缓冲区格式：
byte[0]=字母，byte[1]=开关值或参数起始，后面是字符串/数值参数。

### 各命令行为（静态 + 运行期注入验证）

- S：`+0x458aca`：`self[0xfb] = (arg[1]==1)` → 任务管理器/性能监视器清理开关。
  运行期在教师端“关闭保护/开启保护”时抓到 `S0` 和 `S1`，与 REPORT 第 10 节的 +0xfb 说法一致。
- T：`+0x458adb`：`self[0xf8] = (arg[1]==1)`，随后 `call 0x4583a4` 把 ar 写回 config.cfg
  → 自动拉起/保护开关（T1 开、T0 关）。
- U：`0x458af1`：arg[1]==1 → `0x457fe0 → jmp 0x476a19`，否则 `0x457fd8 → jmp 0x47a71c`，
  对应 lib!EnableUsbStore / DisableUsbStore（HKLM\SYSTEM\CurrentControlSet\Services\UsbStor\Start 4/3）。
- V：`0x458b07`：arg[1]==1 → `0x457ff0 → jmp 0x478419`，否则 `0x457fe8 → jmp 0x4731c9`，
  对应 lib!EnableGuest / DisableGuest（执行 net user Guest /active:yes|no）。
- Q：`0x458a5f → fcn 0x458854(self, arg字符串)`：
  1) 复制参数串；2) `0x408a1c(arg)` 校验；3) 通过则取 `self+0x100` 的字符串，
  把 `(arg, self->field_100)` 传给 `0x457fa8`（跳板 → `0x4729c5`，混淆层）；
  4) 最后重读 `self->f8` 并 `call 0x4583a4` 持久化 ar。
  运行期抓到：教师端切换保护时下发 `Q` + `C:\Users\zzx\AppData\Ro...` 路径字符串（两次）。
- R：`0x458a6e`：参数经 `0x408a2c` 校验；命中后 `self[0xfb]=0`，
  再比较 `self+0x100` 字符串与 `0x457f98`，相等则 `self[0xfa]=1`。
- W：`0x458b1d → fcn 0x4588c4(self, arg字符串)`：
  1) 复制参数；2) `0x404b04` 取数值/长度，<1 直接返回；3) `0x404a20`/`0x404a60` 取子串；
  4) `0x458008`（跳板 → `0x47b877`）比较；5) 组数组后 `0x409380(0x4589e8, 2, ...)`，
  格式串常量 `"%s: %s -> %s"`；6) 结果交给 `0x4067bc`（跳板 → `0x470a87`）。
  结论：W 是**带格式化的日志/追踪命令**（记录 “名字: 旧值 -> 新值”），不是防护动作本身。
- X：`0x458b29`：`push [arg+4]; push [arg]; call 0x457fb8`，
  `0x457fb8 → jmp 0x47404e`（X 入口）→ `0x47a85b: jmp 0x47a85b... 实际为 pushfd/pushal 混淆层`，
  先 `call 0x475cea`（→ `0x47b4d1`），最后 `jmp 0x47b2a0`。
  X 接收两个 dword 参数（[`arg`] 和 [`arg+4`]），与“设置日期时间”类操作的双整数形态相符，
  具体落到 SetLocalTime/SetSystemTime 还是其他双参动作，需要在混淆层里继续跟（未完成）。

### 混淆层说明

`.text0/.text1`（0x46e000-0x4c7000）是栈机式混淆层：pushal/pushfd/ret imm、
push 立即数 + ret 跳转，与 Student 的 0x5exxx 区域同类。Ghidra/rizin 只能反汇编，
反编译会递归成自身；Q 的 `0x4729c5`、W 的 `0x470a87`、X 的 `0x47a85b` 都在这层里。

### 动态注入结果

- 用 frida 在 Smonitor 里构造汇编 stub（mov eax,self; mov edx,cmd; call dispatcher）注入命令，
  dispatcher 钩子确认 T1/W/X/Q 四条命令都成功到达分派器：
  - `T1`：`54 31`
  - `W`："Wtest: 1 -> 2"
  - `X`：`58 01 00 00 00 02 00 00 00`
  - `Q`：`Q C:\Users\zzx\smon_test.txt`
- 但在 Smonitor 内挂的 RegSetValueExA/W、WinExec、CreateProcessA、WritePrivateProfileStringA/W、
  CreateFileA、DeleteFileA、SetLocalTime、SetSystemTime、ExitWindowsEx、MessageBoxA/W、
  NtShutdownSystem、以及 lib.dll 全部导出钩子中，W/X/Q 注入后**没有触发任何事件**。
  说明这三个命令的效果要么在混淆层内部完成（纯内存/内部状态），要么走了未覆盖的动态调用。
- 尝试为 X/Q/W 反编译入口时使用入口改写副本（smon-x.exe/smon-q.exe/smon-w.exe），
  Ghidra 能创建函数但函数体是混淆跳板，无法给出语义。
- frida-server 在“挂 lib.dll 全部 426 个导出”那一轮后失联（连接被关闭），Smonitor 可能被拖垮；
  这是本轮没能继续做 API 级动态验证的直接原因。

### 结论

- Smonitor 的本地命令面就是 8 个字母命令；X/Q/W 都不是“保护开关”，而是：
  W = 带格式化的日志/追踪命令；Q = 处理一个路径参数并持久化 ar 的辅助命令；
  X = 双 dword 参数的混淆层操作（疑似时间/日期或双值设置）。
- “保护”真正的控制面是 T（ar/自动拉起）和 S（任务管理器清理），U/V 是 USB/访客；
  这与实际行为（保护开启后 ar=1、taskmgr 被杀）一致。
- X/Q/W 的最终效果仍未闭合，需在混淆层用 Unicorn 具体执行（可复用 analysis/tmp/uni_live.py 的思路）
  或恢复 frida 后只挂少量关键 API 逐条注入验证。


## 第十轮：.text0/.text1 反混淆可行性评估（2026-11-01 03:0x）

### 混淆结构（已确认）

`.text0`（VA 0x46e000-0x47c000）和 `.text1`（0x47c000-0x4c7000）是**栈机式控制流混淆**：

- 每个基本块是一串 `push imm32` / `pushfd` / `pushal` / `mov dword [esp+N], reg`，
  以 `call <解码块>` 或 `ret imm16` 结束；
- 块与块之间用“往栈上写返回地址再 ret”的方式跳转，形成 8-9 条指令一块的链；
- 0x478f52 附近的解码块做的是：`push dword [esp+0x50]` → 用 `dl` 和立即数
  逐字节改写栈上那个返回地址（`mov byte [esp], dl` / `mov byte [esp+1], 0x89` …）
  → `push dword [esp+0x54]` → `ret 0x58`。
  即**下一跳地址是用运行期参数（dl）和栈上旧指针拼出来的**，不是纯立即数。

### 静态 Unicorn 执行结果（analysis/tmp/smon_uni.py）

从 W 的混淆入口 0x470a87 静态执行（镜像按 0x400000 映射，假 stack/heap/self）：

    基本块链：0x470a87 -> 0x4768de -> 0x475cea -> 0x47b4d1 -> 0x47b3b4
              -> 0x478f52 -> 0x47690a -> 0x479cf9 -> 0x479d01
    第 7 跳后 ret 到 0x1041e4（不在镜像范围内）→ UC_ERR_FETCH_UNMAPPED

说明只靠静态常量和空上下文无法还原：混淆块依赖调用者压栈的旧代码指针与参数字节。

### 结论：可以反混淆，但要带上下文

1. **静态线性化**只能解出“块图 + 每个块的立即数”，无法确定动态跳转边；
2. **符号执行（Unicorn + 真实参数/self/栈）可行**：需要从真实处理器入口（如 W 的
   0x4588c4、Q 的 0x458854）进入，并模拟 Delphi RTL 辅助函数
   （0x4046f8 LStrAsg、0x404b04 Pos、0x404a60 Copy、0x4049c0 PChar、0x409380 Format、
   0x4067bc 日志输出）以及 `self` 对象字段（+0xf8/+0xfa/+0xfb/+0x100）；
3. **动态 Stalker 轨迹最直接**：在 Smonitor 里注入 W/X/Q 命令的同时用 frida Stalker
   记录真实指令流，再把轨迹压成基本块图；本机已有注入框架（fr_smon_inject2.py），
   但目前 frida-server 因挂 lib 全部导出后失联，需要先重启。
4. 辅助素材已就绪：入口改写副本 smon-x/q/w.exe（Ghidra 可建函数）、分派跳转表、
   运行期 dispatcher 抓包（Q+S0+S1）、Unicorn 静态执行框架。

### 下一步

1. 恢复 frida-server，Stalker 跟踪一次 T1/W/Q/X 注入执行，导出指令轨迹；
2. 写轨迹→基本块图→伪代码的转换器（检测 push/pop/lea 栈调整，配对 ret 目标）；
3. 对无法静态确定的分支，用 Unicorn 在轨迹约束下补全，最后输出每个命令的调用图。


## 第十一轮：.text0/.text1 活上下文具体执行（反混淆成功路径）

### 11.1 之前静态执行为什么失败

静态文件里 Smonitor 的 IAT 槽位（import 目录 RVA 0xc22e9）是占位值 0x00104004、0x0010400c、
0x00104014…（间隔 8 字节，指向 .reloc 区的装载桩），不是可执行地址；运行时由装载器替换成真实 API 地址。
所以纯静态 Unicorn 从执行器/分派器进入，链走到第 7-8 个块就 ret 到 0x104xxx 这类占位区，UC_ERR_FETCH_UNMAPPED。

### 11.2 本轮方法（可复现）

1. **活镜像 dump**：frida attach Smonitor.exe（服务会话进程，frida 的 enumerate_processes 看不到它，
   要从 guest 的 `tasklist` 拿 PID 后直接 attach），按 base+SizeOfImage 读整模块，
   分块 base64 传回 host；同时用 Process.enumerateRanges 把 [0,0x3000000) 内所有可读区间
   （85 个区间，共 6.4MB，含堆、self 对象、运行时函数指针表）一起 dump 成
   `analysis/tmp/smon_live_map.json`。
   工具：`analysis/tmp/fr_dump_map.py`。
2. **真实 self 指针**：hook 分派器 0x4589f8，触发一次 Student 启动（Student 启动会给 Smonitor 发
   `S`、`Q config.cfg`、`T` 命令），从 onEnter 里读 EAX 得到 self（本次实例 0x13d2030）。
   工具：`analysis/tmp/fr_disp_again2.py`。
3. **Unicorn 具体执行**：把活镜像按 0x400000 映射，再映射 dump 下来的 85 个堆区间、
   0x70000000-0x80000000 系统 DLL 桩区（全填 0xC3 ret）、栈、命令缓冲；EAX=self、EDX=命令缓冲，
   从 0x4589f8 执行，按控制流记录块边界与外部调用。
   工具：`analysis/tmp/smon_uni_live2.py`、`smon_uni_args.py`、`smon_uni_x.py`。

### 11.3 已还原的命令链

| 命令 | 块链（分派器/混淆层） | 最终外部调用 |
|------|----------------------|--------------|
| S0/S1 | 458a38→458aca→458ad9→458b36→458b3e→458b4a→458b5f→404524…（9 跳，无混淆层） | 无（只写 self+0xfb 标志） |
| T1 | 458a38→…→4799cf→4776c3→475cea→47b4d1→47b3b4→478f52→4776da→4798ea→479888→476677 | kernel32!GetModuleFileNameA |
| Q | 458854→471bec→4786a2→4762ff→475cea→47b4d1→47b3b4→478f52→476304→478320 | ntdll!RtlEnterCriticalSection（Delphi RTL 堆路径） |
| W | 4588c4→471bec→4786a2→4762ff→475cea→47b4d1→47b3b4→478f52→476304→478320 | ntdll!RtlEnterCriticalSection |
| X | 458b29→457fb8→47404e→47a85b→(475cea→47b4d1→47b3b4→478f52)→47a87f→47b2a0 | **lib!SetDateTime**（0xb3dc4c，导出入口精确匹配） |

### 11.4 X 命令的语义（反混淆结果）

分派器 X 分支（0x458b29）源码形态：

    0x458b29  mov  eax, [ebp-4]      ; 命令参数指针
    0x458b2c  push dword [eax+4]     ; arg2
    0x458b2f  push dword [eax]       ; arg1
    0x458b31  call 0x457fb8          ; 混淆层入口（jmp 0x47404e）
    0x458b36  xor  eax, eax          ; 混淆层返回后的收尾

混淆层（.text0/.text1）不执行普通 bal 逻辑，而是**改写自己的返回地址**：在 0x47b2a0 块
把栈上的返回地址换成 lib!SetDateTime 的入口，然后 `ret`。Unicorn 在 0xb3dc4c 处停下时栈为：

    [esp]   = 0x458b36   ; 返回分派器
    [esp+4] = arg1
    [esp+8] = arg2

lib.dll 活进程内基址 0xa90000，SetDateTime 导出地址 0xb3dc4c（RVA 0xadc4c，frida 导出表精确匹配）。
SetDateTime 用 5 个参数，经 FUN_0040bc54 组装 16 字节日期时间结构（对 +4 的 wDayOfWeek 减 1，
再填 +8..+0xe 的时/分/秒/毫秒），再调 FUN_00407808 生效。

结论：**X 命令 = 设置本机日期/时间**（lib!SetDateTime），不是重启/关机类动作。
之前第十轮把 X 猜成“时间相关”得到证实。

### 11.5 仍然存在的限制

- Stalker 方案不可用：`Stalker.follow` 跟踪 frida 自己的 JS 线程拿不到块；用 CreateThread 起新线程跟踪
  会让 Smonitor 崩溃（Smsvc 1067），改用 Unicorn + 活数据后稳定。
- Q/W 的外部调用只到 Delphi RTL 的 RtlEnterCriticalSection（字符串/文件名处理的内存分配路径），
  真正语义（Q 读配置、W 拼日志）还要给 RTL/API 桩补返回值才能继续走到文件/日志 API。
- T1 的 GetModuleFileNameA 之后进入 RTL 循环，原因同样是桩返回值不真。
- 活块链目前是“单次执行轨迹”，不是全程序符号化；不同参数会走不同分支。

### 11.6 返回地址改写块的精确形态（X 命令实测）

0x47b2a0 块不是“算地址”，而是把已经算好的目标地址搬进返回槽：

    0x47b2a0  xchg  dword [esp+0x24], eax   ; 进块时 EAX=0xb3dc4c(目标)，交换后目标进栈槽
    0x47b2a4  mov   byte [esp], cl          ; cl=0
    0x47b2a7  mov   byte [esp+0x10], 0x6f
    0x47b2ac  push  dword [esp+0x24]        ; 压入目标
    0x47b2b0  ret   0x28                    ; 跳到 0xb3dc4c；ret 清栈后 [esp+4]=arg1,[esp+8]=arg2

实测进入 0x47b2a0 时：EAX=0xb3dc4c、ECX=0，栈上 [esp+0x1c]=0xb3dc4c、[esp+0x28]=0x458b36、
[esp+0x2c]=0x1（第一个参数），之后 ret 到 lib!SetDateTime，返回地址 0x458b36。
所以混淆层内部是“先把目标地址算进寄存器，再用统一尾块 pivot 返回地址”；
目标 0xb3dc4c 来自前面若干块对活内存中 lib 函数指针/编码表的运算。

## 第十二轮：Smonitor 分派器命令语义全部还原（Q/W/X/S/T）

### 12.1 方法升级

在第十一轮“活镜像 + 活 self + Unicorn 具体执行”基础上补了两层：

1. **映射 lib.dll 活内存**：frida 从 Smonitor 进程 dump lib.dll（base 0xa90000，size 0x232000，
   共 2,301,952 字节，分块 base64 回传，`analysis/tmp/lib_live.bin`），Unicorn 按同一基址映射。
   X 命令因此能真正进入 `lib!SetDateTime` 执行完毕。
2. **精确 API 桩**：Unicorn 在遇到外部调用地址时不再执行桩页的裸 `ret`（会破坏 stdcall 栈平衡），
   而是在 code hook 里按“函数名 + 参数个数”直接模拟：读栈参数、写返回值/缓冲区、
   `ESP += 4 + 4*argc`、`EIP = [esp]`，实现正确 stdcall 语义。未知外部地址先记录，
   用 frida 的模块导出表批量解析后补进桩表，迭代到命令完整返回 0xdeadbeef 为止。

### 12.2 已解析的外部 API

| 地址 | 函数 |
|------|------|
| 0x763510d0 | kernel32!GetModuleFileNameA |
| 0x7634f660 | kernel32!VirtualAlloc |
| 0x76366f80 | kernel32!SetLocalTime |
| 0x776b00c0 | ntdll!RtlEnterCriticalSection |
| 0x776ae8c0 | ntdll!RtlLeaveCriticalSection |
| 0x76353450 | kernel32!FindFirstFileA |
| 0x76353410 | kernel32!FindClose |
| 0x76353400 | kernel32!FileTimeToLocalFileTime |
| 0x7634be20 | kernel32!FileTimeToDosDateTime |
| 0x76348da0 | kernel32!WritePrivateProfileStringA |
| 0x76348b60 | kernel32!CopyFileA |
| 0x76350890 | kernel32!GlobalAlloc |
| 0x7634e420 | kernel32!GlobalLock |
| 0x77368030 | advapi32!GetFileSecurityA |
| 0x77369270 | advapi32!SetFileSecurityA |

安装配置路径：`C:\Program Files (x86)\gakataka\Student\config\config.cfg`
用户配置路径示例：`C:\Users\zzx\AppData\Roaming\gakataka\class\config\config.cfg`
（地址表见 `analysis/tmp/smon_api_table.json`）

### 12.3 各命令语义（仿真结果）

| 命令 | 轨迹规模 | 语义 | 关键 API 证据 |
|------|---------|------|--------------|
| S0/S1 | 9 跳 | 写 `self+0xfb`（taskmgr 清理开关） | 无外部调用；内存 diff：`0x13d212b`(self+0xfb) 0→1 |
| T0/T1 | 1245 跳，36 次 API | 把 `ar` 写进安装目录 config.cfg 的 `[config]` 段 | FindFirstFileA(安装 config.cfg) → WritePrivateProfileStringA("config","ar","0/1",路径) → 刷新(NULL,NULL,NULL,路径) |
| Q | 3684 跳，58 次 API | 用参数给的配置文件覆盖安装 config.cfg，修复时间戳与文件安全描述符，再写 ar | FindFirstFileA(用户 config) → FileTimeToLocalFileTime/FileTimeToDosDateTime → CopyFileA(用户 config → 安装 config, 覆盖) → GetFileSecurityA/GlobalAlloc/GlobalLock/GetFileSecurityA/SetFileSecurityA(恢复安全描述符) → WritePrivateProfileStringA("config","ar","1") 刷新 |
| W | 139 跳，4 次 API | 仅操作自身内存：把参数文本写入 self 字符串缓冲（0x13d36ac 起），不产生任何文件 I/O | 无文件 API；内存 diff 只有 `self+0x36ac` 一带字符串被替换为参数内容 |
| X | 80 跳，1 次 API | 设置本机日期/时间 | 混淆层 pivot 返回地址到 lib!SetDateTime(0xb3dc4c) → lib 内调 kernel32!SetLocalTime；X(1,2) 生成 SYSTEMTIME 1899-12-30 00:00:00 |

### 12.4 活体验证（T1）

在真实运行的 Smonitor（PID 5916，self=0x13d2030）里用 frida 注入 `T1` 命令，
hook `kernel32!WritePrivateProfileStringA`，实际捕获：

    WritePrivateProfileStringA(app="config", key="ar", val="1", file="C:\Program Files (x86)\gakataka\Student\config\config.cfg")
    WritePrivateProfileStringA(NULL, NULL, NULL, file=同上)   ; ini 刷新

与 Unicorn 仿真结果完全一致，证明“活上下文具体执行 + 精确桩”这条路还原出的行为可信。

### 12.5 与旧结论的关系

- 第七/八轮曾测出 stc=2 才关窗口、无本地 cmd 重启路径；本轮进一步确认 Smonitor 分派器的
  S/T/Q/W/X 五类命令没有重启/关机动作：S=任务管理器开关，T/Q 是配置持久化，
  W 是内存日志，X 是改系统时间。重启仍只能来自教师端 0x11 报文。
- Q 的“覆盖安装配置 + 恢复安全描述符”意味着教师侧改学生配置会以文件覆盖 + 权限修复的方式落地；
  学生端进程被杀后 Smsvc 会重启 Smonitor，符合“杀了又活”的表现。

### 12.6 产物

- `analysis/tmp/smon_uni_api4.py`：T0/T1 完整轨迹（1245 跳、36 API，含日志字符串）
- `analysis/tmp/smon_uni_api5.py`：Q 完整轨迹（3684 跳、58 API）
- `analysis/tmp/smon_w_diff.py`：W 内存 diff
- `analysis/tmp/fr_validate_T2.py`：T1 活体验证
- `analysis/tmp/lib_live.bin` / `lib_live_meta.json`：lib.dll 活镜像
- `analysis/tmp/smon_api_table.json`：地址→API 名与路径表

### 12.7 X 参数来源的进一步说明

分别仿真 X(1,2) 和 X(2026,1)，lib!SetDateTime 内部传给 kernel32!SetLocalTime 的
SYSTEMTIME 都稳定为 1899-12-30 00:00:00（即 TDateTime 0），说明：

- “X 经 lib!SetDateTime 调 SetLocalTime”这一目标关系是确定的（地址精确匹配 + pivot 返回地址）；
- 但具体日期值不是由命令缓冲的两个 dword 直接决定，而是 lib 内部
  （0x40bc54 组装 + 0x407808 生效）从混淆层寄存器/全局字段编码出来的；
- 要完全解出 X 的日期编码公式，还需继续跟踪 lib 的 .text0/.text1 混淆层
  （lib 也有 `.text0/.text1/.text2` 三段混淆区），本轮只做到目标函数级。

同样地，W 的“格式化日志”目前在仿真里体现为把参数文本写进 self 字符串缓冲
（0x13d36ac 一带），没有文件 I/O；若它最终通过定时器/其他通道落盘，需要再跟踪后续时序。

## 第十三轮：X 命令参数编码破解与四项活体验证

### 13.1 X 的两个 dword = 8 字节 Delphi TDateTime 双精度

上一轮遗留问题：X(1,2) 经 lib!SetDateTime 后 SetLocalTime 收到 1899-12-30 00:00:00（TDateTime 0），
换参数也不变。本轮验证了假设：命令缓冲里 `X` 后的 8 个字节就是 **IEEE754 little-endian double
表示的 Delphi TDateTime**（1899-12-30 起的天数），而不是两个独立整数。

仿真对照（`analysis/tmp/smon_x_float.py`，Unicorn 活镜像执行）：

| 注入的 TDateTime | 对应时间 | SetLocalTime 收到 SYSTEMTIME |
|---|---|---|
| 46327.0 | 2026-11-01 00:00:00 | (2026, 11, 0, 1, 0, 0, 0, 0) |
| 46327.52425925926 | 2026-11-01 12:34:56 | (2026, 11, 0, 1, 12, 34, 56, 0) |
| 36526.0 | 2000-01-01 00:00:00 | (2000, 1, 6, 1, 0, 0, 0, 0) |

wDayOfWeek 也正确（2026-11-01 是周日=0，2000-01-01 是周六=6）。
之前 X(1,2) 得到 1899-12-30 的原因：这两个 dword 拼成 uint64 `0x0000000200000001`，
按 double 解释约为 4.2e-314 ≈ 0，即 TDateTime 0，正好是 1899-12-30 00:00:00。

结论：X 命令 = 用参数里的 TDateTime 设置系统本地时间。

### 13.2 活体验证（真实 Smonitor，PID 5916，self=0x13d2030）

| 命令 | 注入内容 | 真实进程观察结果 |
|---|---|---|
| X | 当前时间 TDateTime 46327.1772297（2026-11-01 04:15:12.649） | hook kernel32!SetLocalTime 捕获 SYSTEMTIME = (2026, 11, 0, 1, 4, 15, 12, 650)，与注入时间一致 |
| S1 / S0 | 单字节标志 | self+0xfb 在 0x01 / 0x00 之间切换 |
| W | "r38-probe: x -> y" | self 字符串缓冲 0x13d36ac 从 `hello: 1 -> 2` 变为 `r38-probe: x -> y`；无文件 API |
| T1 | ar=1 | WritePrivateProfileStringA("config","ar","1",安装 config.cfg) + ini 刷新（上一轮验证） |

事件表：
- `analysis/tmp/fr_validate_X.py`：X 活体验证
- `analysis/tmp/fr_validate_SW.py`、`fr_validate_W2.py`：S 标志与 W 缓冲活体验证
- `analysis/tmp/fr_restore_S1.py`：验证结束后把 S 标志恢复为开启
- `analysis/tmp/fr_validate_T2.py`：T1 活体验证

### 13.3 修正第十二轮 12.7 的存疑

第十二轮曾认为“日期值来自 lib 内部编码、不是命令 dword 直接决定”。实际原因是
把两个 dword 当整数看；按 8 字节 double 解释后，参数就是 TDateTime，语义完全闭环。

### 13.4 当前语义总表

| 命令 | 语义 | 验证方式 |
|---|---|---|
| S0/S1 | self+0xfb = 任务管理器清理开关 | 仿真 + 活体 |
| T0/T1 | 写安装 config.cfg 的 [config] ar=0/1 | 仿真 + 活体 |
| Q | 覆盖安装 config.cfg + 修复时间戳/安全描述符 + 写 ar | 仿真（3684 跳、58 API） |
| W | 把命令文本写入 self 字符串缓冲（内存日志） | 仿真 + 活体 |
| X | 用 8 字节 TDateTime 设置系统本地时间 | 仿真 + 活体 |

### 13.5 Q 命令活体验证（备份/恢复方式）

用 frida 在 Smonitor 进程内直接调 WinAPI 完成备份与恢复，避免动 guest 键盘：

1. 备份：`CopyFileA(安装 config.cfg → config.bak38)` 成功；
2. 注入 Q，参数为用户配置路径 `C:\Users\zzx\AppData\Roaming\gakataka\class\config\config.cfg`；
3. 真实进程捕获到：
   - `CopyFileA(用户 config → 安装 config.cfg)`
   - `SetFileSecurityA(安装 config.cfg, info=4)`
   - `WritePrivateProfileStringA("config","ar","1",安装 config.cfg)` + ini 刷新
4. 恢复：`CopyFileA(config.bak38 → config.cfg)` 成功，随后 `DeleteFileA(config.bak38)` 清理。

与 Unicorn 仿真的 Q 轨迹（3684 跳、58 次 API，含 FindFirstFileA/FileTimeToLocalFileTime/
FileTimeToDosDateTime/GlobalAlloc/GlobalLock/GetFileSecurityA）一致。

至此 S/T/Q/W/X 五类命令全部完成“仿真还原 + 活体验证”。

工具：`analysis/tmp/fr_validate_Q.py`、`analysis/tmp/fr_cleanup_bak.py`。

## 第十四轮：.text0/.text1 线性化产物（轨迹反汇编）

### 14.1 做了什么

把第十二/十三轮的活上下文执行轨迹（`analysis/tmp/live2_trace_X.json`、
`api3_trace_W.json`、`api4_trace_T1.json`、`api5_trace_Q.json`）转成可读的反混淆产物：

- `analysis/SMONITOR-TEXT01-LINEARIZED.md`（108 KB）
- 工具：`analysis/tmp/linearize_traces.py`
  - 从活镜像 `smon_live_map.json` 和 lib 活镜像 `lib_live.bin` 取字节；
  - 用 capstone 按“上一跳目标 → 本次跳转源”切出真实执行的基本块；
  - 逐块反汇编，并把 call/jmp 目标解析成 `lib!导出名` / 外部 API 名 / `text0+偏移` / `text1+偏移`；
  - X、W 给完整反汇编清单，T1、Q 给紧凑块链表（起始/结束/末指令/注释）。

### 14.2 覆盖统计

| 轨迹 | 基本块数 | 说明 |
|------|---------|------|
| X | 81 | Smonitor 19 块 + lib 61 块 + 1 个 API 桩页 |
| W | 140 | Smonitor 136 块 + 4 个其它 |
| T1 | 1246 | 紧凑清单前 300 块 |
| Q | 3685 | 紧凑清单前 400 块 |

按 `ret imm16`（0xC2）粗估，.text0 约 696 个块、.text1 约 782 个块；X+W 两条轨迹覆盖到
17 个不同的混淆层块起点，说明这两条命令只走了一小部分路径，全量线性化还需要更多命令/参数样本。

### 14.3 线性化里确认的机制

- X 链：分派器 0x4589f8 → 跳表 → X 分支 0x458b29（压两个 dword）→ 跳板 0x457fb8 →
  0x47404e → 0x47a85b 处理块 → 若干混淆块 → pivot 0x47b2a0 →
  `ret 0x28` 跳到 lib!SetDateTime（0xb3dc4c）→ lib 内部（0xa9bc54/0xa9bae4/0xa9b858…）。
- pivot 块在清单里有完整指令：`xchg [esp+0x24],eax` 把已算好的目标放到返回槽，
  `mov byte [esp],cl` / `mov byte [esp+0x10],0x6f` 后 `push [esp+0x24]`、`ret 0x28`。
- lib+0xb858 块出现浮点换算：
  `fld qword [ebp+8]` → `fmul dword [ebx+0xba0190]` → `fistp qword [esp]`；
  0xba0190 处的常量是 float **86400000.0**（一天的毫秒数），
  这就是 TDateTime（天，double）→ 毫秒 → SYSTEMTIME 的转换点，和第十三轮 X=TDateTime 结论互相印证。

### 14.4 剩余工作

- 覆盖率低：需要给 T/Q/W 更多参数样本（不同路径）才能把 .text0/.text1 全量拉平。
- lib 的 `.text0/.text1/.text2` 三段混淆层还没有逐块线性化，只到 SetDateTime 内部调用级。

## 第十五轮：覆盖率矩阵与 .text0/.text1 分工确认

### 15.1 命令/参数变体覆盖率矩阵

用 `analysis/tmp/smon_coverage.py` 跑 13 个命令变体（Unicorn 活镜像 + API 桩），统计被执行的基本块：

| 变体 | 块数 | 新增块 |
|------|------|--------|
| S0 / S1 | 10 / 10 | 10 / 0 |
| T0 / T1 | 942 / 942 | 929 / 0 |
| Q_user / Q_missing | 3561 / 697 | 2452 / 2 |
| W1/W2/W3/Wempty | 140/126/118/39 | 28/1/0/2 |
| X0/X2026/X2000 | 81/81/70 | 60/0/1 |

并集覆盖（12 个进程内被踩到的块起点）：

| 区域 | 覆盖块数 | 按 ret imm16 粗估总块数 |
|------|---------|------------------------|
| Smonitor .text0 | 51 | ~696 |
| Smonitor .text1 | **0** | ~782 |
| lib.dll .text0 | 31 | ~589 |
| lib.dll .text1 | 18 | ~628 |
| lib.dll .text2 | 0 | ~2458 |

- .text0 页覆盖 12/14，缺 0x46e000、0x46f000 两页；
- .text1 75 页一个都没走到。
- 结果存 `analysis/tmp/obf_coverage.json`。

### 15.2 空闲期 Stalker 采样：定时器路径

frida 对运行中的 Smonitor（7 个线程）做 1.5–2 秒 Stalker block 采样：

- 总共 136,664 个块事件，其中 image 内只有 93 个不同块（CODE 70、.text0 23、.text1 0）；
- 主线程 tid 8180 的有序 .text0 序列里出现固定循环：
  `0x475cef → 0x47b500 → 0x47b3c0 → 0x478f6f` 在 2 秒内重复 4 次，
  前置块 `0x476242/0x476263`，前导 CODE 块 `0x454d9f/0x454da0/0x454dae/0x45440d/0x457e1c`；
- 这就是 Smonitor 空闲时的定时器（tmr1）路径：只走 .text0 的混淆块，不碰 .text1。

产物：`analysis/tmp/fr_stalker_idle_blocks.py`、`idle_image_blocks.json`、
`fr_stalker_order.py`、`idle_ordered_seqs.json`。

### 15.3 frida spawn 抓启动路径：.text1 是启动期解码层

用 `dev.spawn(Smonitor.exe)` 在进程入口暂停，attach 后对 4 个线程开 Stalker，
再 resume，抓启动期执行流（`analysis/tmp/fr_spawn_stream.py`）：

- 共 49,135 个 image 块事件，**全部落在 .text1**（180 个不同块），没有记录到任何外部 API 调用；
- 开头块 `0x4ae04b`，随后出现重复 10 块循环：
  `0x4c6781 → 0x4c6bd5 → 0x4c5432 → 0x4c5c24 → 0x4c6b2a → 0x4c692c → 0x4c5407 → 0x4c509f → 0x4c62ff → 0x4c4f09`，
  在前 120 个事件里重复约 10 次；
- 热块：`0x4b0bec` ×5623、`0x4c4a45` ×4921、`0x47c447` ×4920、`0x4b043b/0x4b0440` ×1480；
- 抓完启动流后进程因单实例检查退出。

结论：

- **.text0 = 运行期命令/定时器混淆层**（分派器 8 条命令、tmr1 定时器路径都在这里）；
- **.text1 = 启动期解码/初始化混淆层**（只在进程启动时执行，运行期和命令路径完全不碰）；
- 与静态证据一致：Ghidra 在 .text1 识别 0 个函数，静态 CODE→.text1 的相对 call/jmp 只有 1 条可疑命中
  （0x422cc2→0x4c192f，且源地址落在指令中间，属噪声）。

### 15.4 下一步

- .text1 启动流可能包含就地解码/自修改，用 post-startup 的活镜像反汇编不一定对应启动时刻的字节；
  需要在 spawn 暂停时 dump 一份 text1 原始字节，或对启动流做轨迹级线性化（记录寄存器/栈变化）。
- 启动流里的 10 块循环是解码器主体，下一步按第十一轮的方法给它补桩、在 Unicorn 里重放并归一化。

## 第十六轮：.text1 身份定案——它是明文解包器 stub

### 16.1 三份 .text1 对比：不是自修改

用 spawn 暂停点抓的 text1 原始字节、启动后快照、真实进程活镜像、静态 stage2 文件对比：

- 静态 stage2 与真实进程活镜像的 text1 只有 11 处、共 36 字节差异，
  全部是 **IAT 槽被装载器解析**（如 0x47c5f4、0x47de6f、0x4ae0ca、0xb4696→0x4c…对应槽位），
  不是启动期自修改；
- spawn 暂停快照与 stage2 的 text1 只有 8 字节差异（同样是装载器/IAT 相关），
  说明 **.text1 在磁盘上就是明文，没被加密**；
- 之前以为的“启动自修改”是我们自己 Interceptor 打补丁造成的假象。

### 16.2 spawn 暂停时各段状态（决定性证据）

frida spawn 在进程入口暂停时，直接读内存与 stage2（已解包镜像）对比：

| 区域 | spawn 暂停时与 stage2 不同的字节 | 结论 |
|------|----------------------------------|------|
| CODE (0x401000, 64KB) | 57,194 / 65,536（87%） | 磁盘上是**加密/压缩**的 |
| .text0 (0x46e000, 8KB) | 7,647 / 8,192（93%） | 磁盘上是**加密/压缩**的 |
| .text1 (0x47c000, 8KB) | 8 / 8,192（0.1%） | 磁盘上是**明文** |

### 16.3 启动热块寄存器：经典就地解包循环

对 spawn 启动流的热块挂 Interceptor 记录寄存器：

- 0x4b0bec 命中时：`EDI = 0x401003, 0x401008, 0x40100d, 0x401012…`（每次前进 5 字节，
  指向 CODE 段起始），`ESI = 0x47fe00, 0x47fe05…`（指向镜像内数据表）；
- 0x4c4f09（循环尾）命中时：`ESI = 0x4af7bf / 0x47de3b / 0x47de32` 来回移动，
  `EDX` 出现 0x7769fc80 等已解析 API 地址；
- 整个启动流 49,135 个块全在 .text1，没有外部调用——解码循环只在内存里搬运/解密。

这就是一个就地解包器：从 .text1 内的数据区读密文，解密后顺序写回 CODE（以及后续写 .text0）。

### 16.4 结论与修正

- **.text1 = 明文解包器 stub**（启动时执行一次，把 CODE 和 .text0 解密成真实载荷）；
- **CODE + .text0 = 加密载荷**，其中 CODE 是 Delphi RTL/分派器，.text0 是保护 VM 混淆层；
- 我们之前从活内存提取的 `analysis/unpacked-auto/Smonitor-stage2.exe` 就是**解密后的载荷镜像**，
  所以它的 CODE/.text0 与真实进程一致，而 .text1 保持 stub 原样；
- 这解释了为什么：命令/定时器路径只踩 .text0；空闲采样 .text1 为 0；Ghidra 在 .text1 识别 0 个函数；
  静态 CODE→.text1 相对引用只有噪声。

即“对 .text0/.text1 反混淆”这件事已经闭环：.text0 的 VM 层前面已逐块拉平并验证语义，
.text1 不是保护逻辑而是解包器，其行为就是解密 CODE/.text0。

### 16.5 产物

- `analysis/tmp/fr_spawn_paused_regions.py`：spawn 暂停时 CODE/text0/text1 快照与对比
- `analysis/tmp/fr_text1_patches3.py`、`fr_text1_compare.py`：text1 三份镜像对比
- `analysis/tmp/fr_startup_regs.py`：启动热块寄存器日志
- `analysis/tmp/spawn_paused_regions.json`、`text1_prestartup.bin`、`text1_poststartup.bin`

## 第十七轮：打包版文件证据与对 .text1 结论的修正

### 17.1 拿到原始磁盘文件

用 frida 在真实 Smonitor（PID 5916）进程里调 WinAPI
（CreateFileA/GetFileSize/ReadFile/CloseHandle）读取安装目录的原始
`C:\Program Files (x86)\gakataka\Student\Smonitor.exe`，得到 **311,808 字节**的打包版文件
（`analysis/tmp/Smonitor-packed.exe`），而之前从活内存提取的 `Smonitor-stage2.exe`
是 **1,683,456 字节**（解包后的内存镜像）。

### 17.2 打包版 PE 布局

| 节 | VA | virtual size | raw ptr | raw size |
|----|----|--------------|---------|----------|
| CODE | 0x1000 | 0x57eb8 | 0x400 | **0** |
| DATA | 0x59000 | 0x12d8 | 0x400 | **0** |
| BSS | 0x5b000 | 0xc19 | 0x400 | **0** |
| .idata | 0x5c000 | 0x259c | 0x400 | **0** |
| .tls | 0x5f000 | 0x10 | 0x400 | **0** |
| .rdata | 0x60000 | 0x18 | 0x400 | 0x200 |
| .reloc | 0x61000 | 0x648c | 0x600 | **0** |
| .rsrc | 0x68000 | 0x6000 | 0x600 | 0xc00 |
| .text0 | 0x6e000 | 0xde08 | 0x1200 | **0** |
| .text1 | 0x7c000 | 0x4acf2 | 0x1200 | **0x4ae00** |
| .reloc | 0xc7000 | 0x28 | 0x4c000 | 0x200 |

- 入口点 RVA **0xae041**（VA 0x4ae041），落在 .text1 内；
- 全文件唯一的大块 raw 数据就是 .text1 的 0x4ae00 字节；
- .text1 原始字节熵 7.947；
- 打包版与 stage2 的 .text1 逐字节对比：306,688 字节里只有 **40 字节不同**（IAT 槽/装载器字段），
  入口处两边的字节完全一致（`68cb77bd67e88b79010075ceb550d16b`）。

### 17.3 修正：.text1 = 明文 stub + 内嵌压缩载荷

第十六轮说“.text1 是明文解包器 stub”只对了一半。更准确的模型是：

- 磁盘上 `CODE/.data/.idata/.text0` 等节 **raw size 为 0**，装载后是零页；
- 真正存放在文件里的是 .text1 的 306KB 数据，它同时包含：
  1. **可执行的解包 stub**（入口 0x4ae041，即第 15 轮抓到的启动流开头 0x4ae04b 附近）；
  2. **压缩/加密后的 CODE、.text0 等节载荷数据**（这就是熵 7.947 的来源）；
- 启动时 stub 从 .text1 内嵌数据解压，顺序写回 CODE（第 16 轮热块 EDI=0x401003/0x401008/… 每步 +5），
  并把 .text0 也解出来（spawn 暂停时 .text0 与 stage2 差 93%）；
- 解包完成后 .text1 本身不再变化也不再执行（命令/定时器/空闲采样对 .text1 均为 0 命中）。

所以第 16 轮“CODE/.text0 是加密的”应改为“磁盘上不存在，由 .text1 内嵌载荷解压填充”；
“stage2 = 解密后的载荷镜像”结论不变，且其 .text1 就是打包版 .text1 的副本（40 字节装载器差异）。

### 17.4 产物

- `analysis/tmp/Smonitor-packed.exe`：原始磁盘打包版（311,808 字节）
- `analysis/tmp/fr_pull_packed.py`：frida 读文件工具
- `analysis/tmp/packed_compare.py`、`text1_threeway.py`：PE 布局与三份 text1 对比

### 17.5 直接证据：spawn 暂停时 CODE/.text0 是零页

读 spawn 暂停时的内存（`analysis/tmp/spawn_paused_regions.json`）：

- CODE 前 64KB：**100% 全零**（65536/65536 字节）；
- .text0 前 8KB：**100% 全零**；
- 同一范围在 stage2 里：CODE 零字节占 12.73%、.text0 零字节占 6.7%，且有真实代码
  （stage2 CODE 开头 `041040000307426f6f6c65616e...`）。

这直接证明：磁盘文件的 CODE/.text0 没有 raw 数据，装载后是零页，真实内容由 .text1 内嵌载荷
在启动时解压写入；之前第 16 轮“CODE/.text0 加密”的说法应改为“不存在于文件、由 stub 解压填充”。

## 第十八轮：三个主模块同一套壳

### 18.1 磁盘原始文件 vs 解包镜像

用 frida 在真实 Smonitor 进程里读安装目录原始文件：

| 模块 | 磁盘打包版 | 解包 stage2 | 比例 |
|------|-----------|-------------|------|
| Smonitor.exe | 311,808 | 1,683,456 | 5.4x |
| Student.exe | 1,031,680 | 3,100,672 | 3.0x |
| lib.dll | 840,704 | 2,347,008 | 2.8x |

（stage2 是从运行中进程内存 dump 的解包镜像；原始文件在 `analysis/tmp/Smonitor-packed.exe`、
`Student.orig.exe`、`lib.orig.dll`）

### 18.2 打包版 PE 共同特征

三个模块都是同一套壳：

- 除一个“大块节”外，所有代码/数据节的 **raw size 都是 0**（CODE、.data、.bss、.idata、.text0…）；
- 唯一的大块 raw 数据：
  - Smonitor：`.text1` va 0x7c000，raw 0x4ae00，熵 7.95；
  - Student：`.text1` va 0x1f6000，raw 0xf4000，熵 7.94；
  - lib：`.text2` va 0x165000，raw 0xcbc00，熵 7.95；
- **入口点全部落在这个大块节内**：
  - Smonitor entry RVA 0xae041 → VA 0x4ae041（.text1）；
  - Student entry RVA 0x1fc363 → VA 0x5fc363（.text1）；
  - lib entry RVA 0x165b6c → VA 0x565b6c（.text2）；
- 三个模块的 stub 开头指令形状一致（`68 imm32; e8 rel32; …`），但字节内容各不相同
  （两两比较 512 字节里 505–508 不同），说明同一壳、按模块用不同的密钥/加花。

### 18.3 Student.exe 的 spawn 暂停验证

与 Smonitor 相同方法 spawn Student.exe 并在入口暂停读内存：

- CODE 前 64KB：**100% 全零**（65536/65536）；
- .text0 前 8KB：**100% 全零**；
- .text1 前 8KB：只有 51 个零字节（其余是明文 stub 代码）。

与 Smonitor 的结论一致：磁盘上这些节没有数据，装载后为零页，真实内容由大块节里的
stub + 内嵌压缩载荷在启动时解压写入；解包完成后容器节不再执行。

### 18.4 产物

- `analysis/tmp/lib.orig.dll`、`Student.orig.exe`：原始磁盘文件
- `analysis/tmp/fr_pull_files.py`：frida 读文件工具
- `analysis/tmp/packed_layouts.py`、`packer_stub_compare.py`：三模块布局/stub 对比
- `analysis/tmp/fr_student_spawn_zero2.py`：Student 启动零页验证

## 第十九轮：standalone 运行实验（负结果）与环境恢复

### 19.1 目的

想绕过单实例检查：先停掉真实 Smsvc（释放实例锁），再用 frida spawn 一份 Smonitor，
看它能否跑完解包并进入解密后的 CODE，从而直接验证“解包产物 = stage2”。

### 19.2 结果

- 用 frida 在真实 Smonitor（SYSTEM）里 WinExec `cmd /c sc stop Smsvc` 停服务，
  等待 8–10 秒后 spawn Smonitor；
- spawn 实例仍然只执行 .text1：Stalker 统计 **16,367 次 text1 块执行、180 个不同块，
  CODE/.text0 均为 0 次**（与第 15 轮启动流完全一致，解包工作确定）；
- 之后进程**静默退出**：hook `ExitProcess`/`TerminateProcess`/`RtlExitUserProcess`/
  `NtTerminateProcess`/`ExitThread`、`CreateMutex`/`OpenMutex`/`FindWindow`、
  `OpenSCManager`/`OpenService`/`StartServiceCtrlDispatcher` 均无命中，
  只在早期看到 `GetLastError`、`GetCurrentProcessId`、`CreateEventW(NULL)`、
  `CreateFileW(C:\Windows\Globalization\Sorting\sortdefault.nls)` 这类装载器/CRT 调用。

### 19.3 结论

- 停掉真实服务后 standalone 实例仍未进入解密后的 CODE，说明退出原因不是单实例锁，
  更可能是 stub 检测到“不是由 SCM 启动”（父进程/服务上下文/命令行）或解包后走了
  非服务模式的退出分支；具体判定点还需要更底层的跟踪（syscall/异常/PEB 检查）。
- 本轮的负结果不影响第十六～十八轮的结论：磁盘打包版 → 启动 stub 解密 CODE/.text0 →
  stage2 就是解包后的载荷镜像，这条链已经被零页、入口、寄存器写目标、文件布局四方证据支持。

### 19.4 环境恢复

- 实验后 `sc start Smsvc` 重启服务，并通过 frida 从 Student 进程读回 `sc query Smsvc`：
  **STATE = RUNNING**，服务已恢复。
- spawn 的临时进程均已 kill；真实 Smonitor（服务实例）与 Student.exe 正常。

产物：`analysis/tmp/fr_standalone_run.py`、`fr_standalone_run2.py`、
`fr_standalone_hooks.py`、`fr_svc_state.py`。

## 第二十轮：tmr1 定时器路径线性化与几个负结果

### 20.1 当前服务实例

- `sc queryex Smsvc` 读回：STATE = RUNNING，PID = **10484**；
- 该实例里 lib.dll 基址 = **0x960000**（每次服务重启/进程实例会变，之前见过 0xa90000、0xcb0000 等，
  说明 lib 是 ASLR 重定位加载）。

### 20.2 tmr1 定时器路径

用第 15 轮真实服务采样得到的主线程有序块序列（107 个块）做线性化：

- 产物：`analysis/SMONITOR-TIMER-PATH.md`（表格：块序号/起始地址/区域/末指令/调用目标注释）；
- 工具：`analysis/tmp/timer_linearize.py`；
- 序列特征：一个公共 4 块组合 `0x475cef → 0x47b500 → 0x47b3c0 → 0x478f6f`
  在 2 秒里出现 4 次（positions 16/61/71/102），说明每次定时器 tick 都走同一段混淆链；
  其余块是不同分支（窗口/进程检查、RTL 调用、CODE 侧 TTimer 分发 0x454d9f/0x454da0 等）。
- 局限：只有块起始、没有精确块结束地址，块内容按“从起始反汇编到首个 ret/jmp”近似；
  重采精确 begin/end 事件时 Stalker 事件为空且会话挂起（重启 frida 会话后正常），未能补上。

### 20.3 负结果

1. **lib!KillProc 钩子**：空闲 2.5 秒内 0 命中。taskmgr/perfmon 没在运行时定时器不会调用它，
   与“打开任务管理器才被秒杀”的既有观察一致。
2. **frida spawn 的 taskmgr 秒退**：实为环境问题——同样 spawn notepad.exe、calc.exe 也在 3 秒内退出，
   说明该 Windows guest 里 frida spawn 的 GUI 进程本来就活不下来；因此不能拿它验证 KillProc，
   之前通过 guest 桌面正常启动 taskmgr 被秒杀的结论不受影响。
3. **Stalker call 事件采样**：对真实服务加 `events:{block:true,call:true}` 后 onReceive 解析为空，
   块/call 统计全部 0；单独 block 事件此前可用。本轮未能拿到定时器路径的外部调用目标列表。

### 20.4 环境

- frida-server 正常（enumerate 53 进程）；服务 RUNNING（PID 10484）；Student.exe 在线；
- 没有残留的 spawn 进程。

## 第二十一轮：lib!KillProc 活上下文仿真（任务管理器秒杀机制闭环）

### 21.1 数据准备

- 当前服务实例 PID 10484，lib.dll 基址 **0x960000**；
- 用 frida 从该实例 dump：
  - lib 活镜像 2,301,952 字节（`analysis/tmp/lib_live_10484.bin`，含 426 个导出表）；
  - 进程内 82 个可读堆/数据区间（5.67MB，`analysis/tmp/svc_heap_10484.json`）；
  - 模块基址表与 Toolhelp/进程 API 地址（`svc_mods_10484.json`、`svc_api_addrs2.json`）。
- 注意：第一次 dump 堆区时把“块序号”当字节偏移，造成数据错位；修正后重 dump，
  `cur==lib_live` 逐页一致，才继续仿真。

### 21.2 仿真方法

Unicorn 映射 lib 活镜像 + 全部堆区间 + 系统 DLL 桩区 + 栈/字符串，入口
`KillProc = 0xa09a58`（stdcall，参数在 `[esp+4]`，传 `"taskmgr.exe"`）。
外部 API 用“已知精确清栈 + 未知兜底”的方式模拟：

- RtlEnterCriticalSection / RtlLeaveCriticalSection（1 参，ret 4，返回 0）
- CreateToolhelp32Snapshot（2 参，返回假句柄 0x200）
- Process32First / Process32Next（ANSI 版 0x763491e0 / 0x76347950；First 时构造
  PROCESSENTRY32A：dwSize=296、th32ProcessID=0x1234、**szExeFile 在 +36** = "taskmgr.exe"）
- OpenProcess（3 参，返回假句柄 0x300）
- TerminateProcess（2 参，返回 1）
- CloseHandle（1 参，返回 1）

### 21.3 结果：完整 API 序列

第一次跑（szExeFile 偏移写成 44）返回 0，说明名字没匹配上；修正为 +36 后完整跑通：

    RtlEnterCriticalSection(0xa7b5cc) / RtlLeaveCriticalSection
    CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS=0x2, 0)
    Process32First(0x200, lpProcessEntry32)   ; lp 在栈上 0x201ff9ab
    ... 名字比较（内联代码 + RTL 临界区保护）...
    Process32Next(...) → 返回 0 结束枚举
    CloseHandle(0x200)
    OpenProcess(PROCESS_TERMINATE=0x1, FALSE, pid=0x1234)
    TerminateProcess(0x300, 0)                ; 返回 1
    KillProc 返回 1

结论：**lib!KillProc(name) = 用 Toolhelp32 枚举进程 → 按 szExeFile 匹配名字 →
OpenProcess(PROCESS_TERMINATE) → TerminateProcess 杀掉**；找不到时返回 0。

这正好补上“任务管理器/性能监视器被秒杀”的实现细节：Smonitor 的 tmr1 定时器
（或其他调用点）调 lib!KillProc("taskmgr.exe"/"perfmon.exe")，内部就是上面这条链。

### 21.4 产物

- `analysis/tmp/lib_killproc_emul6.py`：最终仿真脚本（含 API 桩与 PROCESSENTRY32A 构造）
- `analysis/tmp/lib_live_10484.bin`、`svc_heap_10484.json`、`lib_meta_10484.json`、
  `svc_mods_10484.json`、`svc_api_addrs2.json`
- `analysis/tmp/killproc_emul6.json`：完整块链/API 轨迹
- 中间版本 emul1~emul5 记录了两类失败：堆未映射、PROCESSENTRY32A 偏移错误

## 第二十二轮：lib 保护导出批量活上下文仿真

### 22.1 方法

复用第二十一轮的 lib 活镜像（base 0x960000）+ 服务进程堆快照 + 系统 API 桩，做批量仿真：
每个导出单独起一个 Unicorn，按导出约定设置寄存器/栈参数，记录外部 API 调用序列。
本轮修了三个问题：

- 模块前缀解析：`KERNEL32.DLL!Name`、`Name@advapi32.dll` 两种 key 统一取函数名，并按所有模块地址分别映射；
- `GetProcAddress` 动态解析：返回假桩地址并记录 (模块, 函数) 映射，桩被调用时再按名字分发；
- 显式补上 ntdll 的 RtlEnter/LeaveCriticalSection 地址（按模块基址 + RVA 0x400c0/0x3e8c0）。

### 22.2 结果

| 导出 | 完整 API 序列 |
|------|--------------|
| DisableTaskMgr | RegCreateKeyExA(HKCU=0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") → RegSetValueExA("DisableTaskMgr", REG_DWORD, **1**) |
| EnableTaskMgr | 同上 → RegSetValueExA("DisableTaskMgr", REG_DWORD, **0**) |
| DisableUsbStore | RegCreateKeyExA(HKLM=0x80000002, "SYSTEM\\CurrentControlSet\\Services\\UsbStor") → RegSetValueExA("Start", REG_DWORD, **4**) |
| EnableUsbStore | 同上 → RegSetValueExA("Start", REG_DWORD, **3**) |
| DisableSleep | GetModuleHandle/GetProcAddress("SetThreadExecutionState") → SetThreadExecutionState(**0x80000003**)（ES_CONTINUOUS\|ES_SYSTEM_REQUIRED\|ES_DISPLAY_REQUIRED） |
| EnableSleep | 同上 → SetThreadExecutionState(**0x80000000**)（ES_CONTINUOUS） |
| DisableGuest | **WinExec("net user Guest /active:no", 0)** |
| EnableGuest | **WinExec("net user Guest /active:yes", 0)** |
| HideTaskbar | 仿真完整返回 1，但**没有任何外部 API 调用**（只改内部状态/全局标志） |
| ShowTaskbar | 同上（内部状态） |

说明：DisableSleep 日志里的 GetProcAddress 句柄是我们的 GetModuleHandle 桩返回值 0x400000，
实际语义是“取 kernel32 的 SetThreadExecutionState 再调用”；Hide/ShowTaskbar 若最终通过
user32 生效，应该发生在后续由其它代码读取该状态时，而不是函数自身。

### 22.3 产物

- `analysis/tmp/lib_batch_emul_v6.py`：最终批处理仿真脚本（含 GetProcAddress 动态分发）
- `analysis/tmp/lib_batch1.json`：10 个导出的 API 轨迹与 unknown 列表
- 中间版本 v1~v5 记录了模块前缀解析、FAKE 桩分发、Rtl 地址三个修复过程

## 第二十三轮：反虚拟机与重启相关导出的活上下文仿真

### 23.1 新增结果

| 导出 | API 序列 / 行为 |
|------|----------------|
| **ShutWindow(mode)** | LoadLibraryA("ntdll.dll") → GetProcAddress(NtShutdownSystem / RtlAdjustPrivilege / ZwShutdownSystem) → OpenProcessToken(GetCurrentProcess, 0x28) → LookupPrivilegeValueA(NULL,"SeShutdownPrivilege") → AdjustTokenPrivileges → **NtShutdownSystem(mode)**；mode 0/1/2 原样传入 |
| **SeShutdown / SeShutdown2** | 只做提权：OpenProcessToken + LookupPrivilegeValueA("SeShutdownPrivilege") + AdjustTokenPrivileges，然后返回 1（没有直接调用 NtShutdownSystem） |
| **IsRunInVM** | CreateFileA("\\\\.\\PHYSICALDRIVE0", 0xC0000000, share=3) → DeviceIoControl(h, IOCTL 0x4d014, 80 字节输入/输出缓冲) → 返回 **0**（非 VM） |
| **IsAdminRun** | OpenProcessToken(当前线程/进程句柄, 0x8) → GetTokenInformation(TokenElevation=20) → 返回 0 |
| **IsAdminAccount** | OpenProcessToken(...,0x8) → AllocateAndInitializeSid(2 个子授权, Administrators) → GetTokenInformation(TokenGroups=2) → 返回 0 |
| **ChkAdminRun** | 上面两条路径的组合（先 TokenElevation 再 Admin SID 检查）→ 返回 0 |
| **ChkInstance** | 走 CreateMutex/GetLastError 的单实例路径（34 跳），返回 0 |
| **BlackScr(1)** | GetProcAddress("user32","BlockInput") → BlockInput(1) → 调用 user32 内部地址 0x76024d00（位于 SetWindowsHookExAW 与 CliImmSetHotKey 之间、非导出符号），仿真未完成 |

### 23.2 结论

- **ShutWindow(mode) = 提升 SeShutdownPrivilege 后直接 `NtShutdownSystem(mode)`**。
  之前活体验证过教师端远程重启（mode=1）确实让 VM 重启，说明这个构建里
  `NtShutdownSystem(1)` 走的是重启路径（记录为实测行为）。
- **IsRunInVM** 的入口确认：打开 `\\.\PHYSICALDRIVE0` 并下发 IOCTL 0x4d014（80 字节缓冲）。
  用 "QEMU HARDDISK" 与 "VMWARE VIRTUAL DISK" 两种缓冲跑都返回 0，说明字符串匹配发生的
  位置还没定位（可能不在我们填的 in/out 缓冲，或在函数后半段的其它检查）；
  但“QEMU 环境返回 false”的判定入口已经确认。
- IsAdminRun/IsAdminAccount/ChkAdminRun 确认走 token 检查（TokenElevation + Administrators SID），
  我们的桩让它们返回 0（非管理员）。
- BlackScr 确认调用 BlockInput(1) 屏蔽输入，随后进入 user32 内部例程（未完成仿真）。

### 23.3 产物

- `analysis/tmp/lib_batch_emul_v10.py`：27 个用例的批处理仿真器（含 dynproc 动态解析分发）
- `analysis/tmp/lib_batch1.json`：27 个用例的完整 API 轨迹
- 本轮中间版本 v7~v10 记录 DeviceIoControl 缓冲、AllocateAndInitializeSid、GetLastError/FreeSid 映射等修复

## 第二十四轮：IsRunInVM 内部逻辑（反虚拟机检测为什么在 QEMU 不触发）

### 24.1 反汇编结论（lib 活镜像 base 0x960000）

`IsRunInVM = 0xa0e2d8`，逻辑是：

1. `CreateFileA(0xa0e44c, 0xC0000000, 3, 0, 3, 0x8000000, 0)` —— 打开
   `\\\\.\\PHYSICALDRIVE0`；
2. 在栈上构造一个 0x90 字节请求结构（偏移 +0x14 存放“数据缓冲指针”= 结构+0x50），
   然后调用 `DeviceIoControl(h, IOCTL 0x4d014, 请求结构, 0x50, 同一结构, 0x50, &返回字节, NULL)`。
   **0x4d014 = IOCTL_ATA_PASS_THROUGH_DIRECT**（ATA 直通命令，用来读磁盘 IDENTIFY 之类的信息）；
3. 成功后从缓冲区 +0x58 位置取字符串（Delphi PChar → String 赋值），转大小写/大写归一；
4. 依次调用内部 Pos 函数（0x965234）做三次匹配：
   - `Pos("VMWARE")`（字符串 0xa0e468）
   - `Pos("VIRTUAL")`（0xa0e478）
   - `Pos("VBOX")`（0xa0e488）
   任一命中 → 返回 1（在 VM 中）；全不命中 → 返回 0。

### 24.2 为什么 QEMU 里不触发

QEMU 的磁盘标识是 `QEMU HARDDISK`，不包含 `VMWARE`、`VIRTUAL`、`VBOX` 任何子串，
所以三步 Pos 全为 0，函数返回 false —— 与之前实测“qemu 下反虚拟机检测没触发”一致。
换成 VMWARE 虚拟盘（磁盘标识里带 VMWARE）时才会走到返回 1 的分支。

### 24.3 验证尝试与边界

- 直接往 DeviceIoControl 输出缓冲 +0x58 写 `VMWARE...` 会破坏其它栈局部（该位置不是
  真正的数据缓冲，而是结构后面的栈局部），导致后续崩溃；说明 +0x58 的字符串来源依赖
  ATA_PASS_THROUGH_DIRECT 的实际数据缓冲（结构 +0x14 指向的指针），而不是普通 out 缓冲。
- 正确做法是让 DeviceIoControl 桩按 `IOCTL_ATA_PASS_THROUGH_DIRECT` 语义：
  从请求结构 +0x14 读数据缓冲指针，把磁盘 IDENTIFY/标识数据写进去，再让 +0x58 的取串逻辑读到。
  这条留到下轮补完，即可做“VMWARE 数据 → 返回 1”的对照实验。
- 已确认的关键事实：检测字符串就是 `VMWARE/VIRTUAL/VBOX` 三个大写常量，位于
  lib 镜像 0xa0e468/0xa0e478/0xa0e488，引用它们的代码就是 IsRunInVM 本体（0xa0e2d8）。

### 24.4 产物

- `analysis/tmp/scan_vm_strings.py`：字符串与引用扫描
- `analysis/tmp/isruninvm_dis.py`：IsRunInVM 完整反汇编
- `analysis/tmp/lib_batch_emul_v10.py` / `v11`：批量仿真（v11 是 +0x58 注入实验，已证明会破坏栈）

## 第二十五轮：反虚拟机检测对照实验（QEMU 为什么逃过）

### 25.1 IOCTL 语义修正

上一轮把 0x4d014 当成 ATA 直通；本轮按结构字段修正为 **IOCTL_SCSI_PASS_THROUGH_DIRECT**
（请求结构 0x2c 字节：Length=0x2c、CdbLength=0x0c、SenseInfoLength=0x20、DataIn=1、
DataTransferLength=0x40、DataBuffer=P、SenseInfoOffset=0x30、CDB[0]=0x12(INQUIRY)、
CDB[4]=0x40 分配长度）。

SCSI INQUIRY 响应里 **Vendor Identification 在数据偏移 8（8 字节 ASCII）**，
正好对应 IsRunInVM 成功后读取的“缓冲区 +0x58”（结构+0x50 的数据缓冲 + 8）。

DeviceIoControl 桩按此语义实现：从请求结构 +0x14 读数据缓冲指针，写入 64 字节 INQUIRY 响应
（厂商串放在偏移 8），再返回成功。

### 25.2 对照实验结果

| 注入的磁盘厂商串（INQUIRY Vendor ID） | IsRunInVM 返回 |
|---|---|
| `QEMU` | **0**（非虚拟机） |
| `VMWARE` | **0xffffffff / true**（检测到虚拟机） |
| `VBOX` | **true** |
| `VIRTUAL` | **true** |

三条匹配路径（Pos("VMWARE")/Pos("VIRTUAL")/Pos("VBOX")）全部生效。

### 25.3 结论

反虚拟机检测的判定依据是 **磁盘 SCSI INQUIRY 的 Vendor Identification**，只认
VMWARE / VIRTUAL / VBOX 三个关键词。QEMU 默认磁盘厂商串是 `QEMU`（完整标识
"QEMU HARDDISK"），不含这三个词，所以函数返回 false —— 这就是之前 QEMU 环境里
反虚拟机检测“没有触发”的原因。把磁盘厂商串改成 VMWARE/VBOX/VIRTUAL 时函数会立刻返回 true。

### 25.4 产物

- `analysis/tmp/lib_batch_emul_v12.py`：修正 IOCTL 语义后的批量仿真器
- `analysis/tmp/lib_batch1.json`：含 QEMU/VMWARE/VBOX/VIRTUAL 四个变体的返回结果

## 第二十六轮：lib 导出的活体调用回验 + 屏幕保护导出仿真

### 26.1 活体调用（真实 Smonitor，PID 10484）

用 frida 在真实服务进程里直接 `NativeFunction` 调用只读导出：

| 导出 | 实活返回 | 说明 |
|------|---------|------|
| IsRunInVM | 0 | QEMU 磁盘厂商 "QEMU"，不匹配 VMWARE/VIRTUAL/VBOX，与仿真一致 |
| IsAdminRun | -1（true） | 服务以 SYSTEM 运行，TokenElevation 检查为真；仿真里 token 桩模拟的是非管理员，所以仿真返回 0，逻辑本身正确 |
| IsAdminAccount | 1（true） | SYSTEM 在 Administrators 组；同理与仿真差异来自 token 上下文 |
| IsScreenSaverActive | 0 | 与仿真一致（SPI_GETSCREENSAVEACTIVE 返回未激活） |
| IsScreenSaverRunning | 0 | 与仿真一致（SPI 0x72 返回未运行） |
| ChkInstance | 0 | 该函数可能带参数（反汇编里读 [ebp+8]），无参直接调用结果不可靠，仅作记录 |

这次活体调用验证了“IsRunInVM 在 QEMU 返回 false”的最终结论，也解释了 IsAdmin* 仿真/实活差异
（SYSTEM token 注入后应为 true）。

### 26.2 屏幕保护导出仿真

| 导出 | API 序列 |
|------|----------|
| IsScreenSaverActive | SystemParametersInfoA(SPI_GETSCREENSAVEACTIVE=0x10, 0, &buf, 0) → 返回 0 |
| IsScreenSaverRunning | SystemParametersInfoA(0x72, 0, &buf, 0)（SPI_GETSCREENSAVERRUNNING）→ 返回 0 |
| DisableScreenSaver | SystemParametersInfoA(SPI_SETSCREENSAVEACTIVE=0x11, **0**, NULL, 0) → 返回 -1 |
| EnableScreenSaver | SystemParametersInfoA(SPI_SETSCREENSAVEACTIVE=0x11, **1**, NULL, 0) → 返回 -1 |
| RestoreScreenSaver | SystemParametersInfoA(SPI_SETSCREENSAVEACTIVE=0x11, **0**, NULL, 0) → 返回 -1 |

即保护层对屏幕保护的处理就是“用 SPI 关闭/恢复屏保”，没有额外 hook。

### 26.3 产物

- `analysis/tmp/fr_live_calls.py`：活体调用脚本（IsRunInVM/IsAdmin*/屏保/ChkInstance）
- `analysis/tmp/lib_batch_emul_v15.py`：含屏保导出的批量仿真器
- `analysis/tmp/lib_batch1.json`：全部用例 API 轨迹

## 第二十七轮：BlackScr 完整还原（黑屏/锁输入）

### 27.1 反汇编 + 仿真结论

`BlackScr(param) = 0xa0ac54`（stdcall，1 个参数）：

1. 首次调用时动态解析 `BlockInput`：
   `GetModuleHandle/LoadLibrary` + `GetProcAddress(user32,"BlockInput")`，结果存全局 `0xa7c240`；
2. 计算 BlockInput 参数：`cmp ebx,1; sbb eax,eax; inc eax` → param=0 时传 0，param>=1 时传 1；
3. 调用 `BlockInput(flag)`；
4. 再调 `SendMessageA(HWND_BROADCAST=0xFFFF, WM_SYSCOMMAND=0x112, SC_MONITORPOWER=0xF170, v)`：
   - `BlackScr(1)`：v=**2**（关闭显示器）
   - `BlackScr(0)`：v=**-1**（恢复显示器）

仿真（v16 版批量器）：

    BlackScr1:
      GetProcAddress("BlockInput") → dynproc BlockInput(1)
      SendMessageA(0xffff, 0x112, 0xf170, 2)
    BlackScr0:
      GetProcAddress("BlockInput") → dynproc BlockInput(0)
      SendMessageA(0xffff, 0x112, 0xf170, -1)

### 27.2 与保护功能的关系

- 黑屏锁屏：BlockInput 屏蔽键盘鼠标 + 广播 SC_MONITORPOWER 关显示器；
- 解除时恢复输入并重新打开显示器。
- 该动作由 Smonitor 的 U/V 类控制或教师端命令触发（此前静态分析里黑屏/取消黑屏按钮走的就是这条链）。

### 27.3 已还原保护函数清单（累计）

DisableTaskMgr/EnableTaskMgr、DisableUsbStore/EnableUsbStore、DisableGuest/EnableGuest、
DisableSleep/EnableSleep、Hide/ShowTaskbar（内部状态）、IsRunInVM（SCSI INQUIRY 厂商串）、
IsAdminRun/IsAdminAccount/ChkAdminRun、ChkInstance（CreateMutex）、
ShutWindow/SeShutdown/SeShutdown2（SeShutdownPrivilege + NtShutdownSystem）、
KillProc（Toolhelp 枚举 + TerminateProcess）、Is/Disable/Enable/RestoreScreenSaver（SPI）、
BlackScr（BlockInput + SC_MONITORPOWER）。

尚未完成：SetGate（网关控制，WMI 相关）、ChkInstance 的带参语义、Hide/ShowTaskbar 实际生效路径。

### 27.4 产物

- `analysis/tmp/blackscr_dis.py`：BlackScr 反汇编
- `analysis/tmp/lib_batch_emul_v16.py`：含 SendMessageA/W、BlockInput 的批量仿真器
- `analysis/tmp/lib_batch1.json`：全部用例轨迹（BlackScr1/BlackScr0 已包含）

## 第二十八轮：SetGate（上网出口/网关控制）机制还原

### 28.1 函数结构与参数

`SetGate = 0xa63bec`（stdcall，`ret 8`，两个栈参数）：

- 参数1（[ebp+8]）与参数2（[ebp+0xc]）先做 `lstrlen` 校验（为空直接返回）；
- 构造 Delphi 动态数组类型：`[0xa62d80]="StringArray"`、`[0xa62dac]="TIntegerArray"`；
- 用参数1拼 WQL：常量区明文
  `SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = "`
  （0xa63b64），第二参数/数组随后传入助手；
- 调 `0xa63af4` → 内部再调 `0xa63600`（WMI COM 主流程）。

### 28.2 WMI COM 流程（0xa63600 反汇编）

依次出现 COM 接口 vtable 调用（`call dword ptr [eax+0x1c/0x20/0x24/0x3c/0x70/0x74]`）：

1. `CoInitializeEx`（0xa6363f 调 `0xa62c6c`，参数 `[0xa629e0]`）；
2. 创建 WbemLocator（常量 `WbemLocator` 出现在 0xa629a8/0xa62a85/0xa62a98）；
3. `ConnectServer`（vtable +0x1c）；
4. `ExecQuery`（vtable +0x20）执行上面的 WQL；
5. `IEnumWbemClassObject::Next`（+0x24）取结果对象；
6. `IWbemClassObject::Get`（+0x70）读取属性；
7. 继续取方法/参数对象（+0x74 等），把网关写入参数实例；
8. `ExecMethod` 调用 WMI 方法。

### 28.3 关键 UTF-16 字符串（lib 镜像明文）

- `SetGateways`：0xa63a70
- `DefaultIPGateway`：0xa63a8c
- `GatewayCostMetric`：0xa63ab4
- WQL/类名与属性名：`Win32_NetworkAdapterConfiguration`（0xa63b72）、`SettingID`（0xa63b9a）

### 28.4 结论

“控制学生机上网出口”在 lib 层就是 **WMI 调用 Win32_NetworkAdapterConfiguration 的
`SetGateways` 方法，设置 `DefaultIPGateway` 和 `GatewayCostMetric`**，也就是直接改写
网卡默认网关/跃点数，把学生的出网流量导向教师机或无效网关。

这条路径没有额外的内核驱动或持久化保护：停止/禁用 Smsvc 服务（或教师端关闭保护后
服务侧不再执行）后，SetGate 不再被调用；学生端自行把默认网关改回来即可恢复上网。
之前实测的 `sc stop Smsvc` + `taskkill` 绕过对这条同样有效。

### 28.5 产物

- `analysis/tmp/setgate_probe.py` / `setgate_probe2.py` / `setgate_probe3.py`：SetGate 与 WMI 助手反汇编
- `analysis/tmp/setgate_strings.py` / `setgate_strings2.py` / `setgate_strings3.py`：字符串/常量定位

## 第二十九轮：Hide/ShowTaskbar 与 ChkInstance 完整还原

### 29.1 HideTaskbar / ShowTaskbar（0xa0e9c0）

反汇编 + 仿真（v18）确认：

    HideTaskbar（EAX=0）:
      FindWindowA(NULL, "Progman")        -> hwndDesktop
      FindWindowA(NULL, "Shell_TrayWnd")  -> hwndTaskbar
      ShowWindow(hwndTaskbar, SW_HIDE=0)
      ShowWindow(hwndDesktop, SW_HIDE=0)
    ShowTaskbar（EAX=5）:
      ShowWindow(hwndTaskbar, SW_SHOW=5)
      ShowWindow(hwndDesktop, SW_RESTORE=9)

即隐藏任务栏的同时把桌面窗口（Progman）也隐藏，恢复时用 SW_SHOW/SW_RESTORE。
窗口类名明文在 lib 镜像：0xa0ea00="Progman"、0xa0ea08="Shell_TrayWnd"。

### 29.2 ChkInstance（0xa0cb9c，stdcall，1 个字符串参数）

    CreateMutexA(NULL, FALSE, name)
    GetLastError()
    if (ret == 0xB7 /* ERROR_ALREADY_EXISTS */) { CloseHandle(mutex); return -1; }
    return 0;

- 名字由调用方（Student 侧）传入，lib 内没有该名字的明文调用点（导出是给 Student 动态
  LoadLibrary/GetProcAddress 用的，调用点在 Student 里，所以 lib 镜像里搜不到 imm 引用）；
- 之前活体无参直接调用返回 0 也就解释得通：空/garbage 名字下 GetLastError 不会是 183；
- 仿真对照：名字 "SmonitorMutex" + GetLastError=0 → 返回 0；GetLastError=183 → 返回 -1。

### 29.3 清单收尾

此前遗留的三个未完成项里，Hide/ShowTaskbar 实际生效路径与 ChkInstance 带参语义已补完；
仅剩“生产环境里 ChkInstance 实际用的互斥体名”（在 Student 侧决定）与 Student 命令到 lib
调用的映射表没有逐条列出。

### 29.4 产物

- `analysis/tmp/lib_batch_emul_v18.py`：含 FindWindow/ShowWindow/CreateMutex/GetLastError 桩的批量仿真器
- `analysis/tmp/resolve_taskbar.py`：窗口/互斥体 API 地址解析
- `analysis/tmp/taskbar_strings.py`：Progman/Shell_TrayWnd 字符串定位
- `analysis/tmp/chkinstance_callers.py`：ChkInstance 引用扫描（lib 内无直接调用点）
- `analysis/tmp/lib_batch1.json`：全部用例轨迹（含 HideTaskbar2/ShowTaskbar2/ChkInstance_*）

## 第三十轮：ChkInstance 活体验证与生产互斥体名

### 30.1 活体验证（真实 Smonitor，PID 10484）

对同一个名字连续调用两次 lib!ChkInstance：

    ChkInstance("zzx_chk_test_mutex_55")  第 1 次 -> 0
    ChkInstance("zzx_chk_test_mutex_55")  第 2 次 -> -1

同时钩 CreateMutexA 看到两个句柄：
- 第 1 次：CreateMutexA 返回 0x654，GetLastError=0，函数返回 0（句柄保留在进程里，作为实例锁）；
- 第 2 次：CreateMutexA 返回 0x658，GetLastError=183（ERROR_ALREADY_EXISTS），函数内部 CloseHandle(0x658) 后返回 -1。
外部 CloseHandle(0x654)=1、CloseHandle(0x658)=0，与“内部已关闭”一致。
活体语义与仿真完全吻合。

### 30.2 生产互斥体名：Student.exe

用 frida 以挂起方式 spawn 第二个 Student.exe（`C:\Program Files (x86)\gakataka\Student\Student.exe`），
在 resume 前装好 CreateMutexA/W 与 lib!ChkInstance 钩子，抓到：

    lib!ChkInstance 参数 = "Student.exe"
    CreateMutexA 名字     = "Student.exe"

随后该 spawn 实例很快自行退出（与之前 standalone Student 实验一致，属于独立运行模式的退出，
不一定是单实例判定）。

### 30.3 关键负结果：互斥体并未被运行中的 Student 持有

检查命名互斥体 `Student.exe` 是否存在：

- 在 explorer.exe（session 1）里 CreateMutexA("Student.exe") → **GetLastError=0**（新建，说明不存在）；
- 在 Smonitor.exe（session 0）里 CreateMutexA("Student.exe") → **GetLastError=0**（同样不存在）。

也就是说：当前运行的 Student.exe（PID 1512）并没有持有名为 "Student.exe" 的互斥体。
结论：**“先占住互斥体让服务拉起的新 Student 自己退出”这个绕过思路在本构建上不成立**；
第二实例退出的原因更可能是独立运行模式/启动参数（standalone 模式），而不是单实例锁冲突。
之前验证过的自动重启绕过（`sc stop Smsvc`、`taskkill /f /im Student.exe`）仍然是有效路径。

### 30.4 环境与产物

- 测试只创建/关闭了自己的互斥体，没有改配置或注册表；结束后 Student PID 1512、Smonitor PID 10484 均正常运行；
- 产物：`analysis/tmp/fr_chkinstance_live.py`（活体验证）、`fr_spawn_student_mutex2.py`（互斥体名捕获）、
  `fr_mutex_hold.py` / `fr_mutex_check_svc.py`（命名互斥体存在性检查）、`fr_enum_handles*.py`（句柄枚举的失败尝试，记录负结果）

## 第三十一轮：自动重启机制实测（本轮为负结果）

### 31.1 杀 Student 后是否会被自动拉起

在 Smonitor 服务（PID 5652）里挂好 CreateProcessW/A/InternalW、CreateProcessAsUserW、
CreateProcessWithLogonW、CreateProcessWithTokenW、NtCreateUserProcess、WinExec 钩子，
然后 kill 掉 Student（11124），观察 120 秒：

- 钩子事件：**0 个**；
- Student 进程：**120 秒内没有重新出现**。

结论：这个构建里 Smonitor 服务**没有**“检测 Student 不在就拉起”的定时看护逻辑。
之前列表里出现的“0.0 秒又看到同 PID”是 frida enumerate_processes 的短暂陈旧缓存，
不是真的重启。

### 31.2 为什么服务重启能拉起 Student

- `sc qc Smsvc`：TYPE=10 WIN32_OWN_PROCESS，**START_TYPE=2 AUTO_START**，
  ERROR_CONTROL=1 NORMAL，BINARY_PATH_NAME=`C:\Program Files (x86)\gakataka\Student\Smonitor.exe`，
  SERVICE_START_NAME=LocalSystem；
- `sc qfailure Smsvc`：**没有任何失败恢复动作**（RESET_PERIOD=0，无重启命令）；
- 实测 `sc stop Smsvc` + `sc start Smsvc` 后：新 Smonitor PID 2276 + 新 Student PID 10964，
  服务启动时会拉起 Student。

### 31.3 启动项检查

`reg query` 三个 Run 位置（HKLM、HKLM\\WOW6432Node、HKCU 的
`Software\\Microsoft\\Windows\\CurrentVersion\\Run`）全部返回
“系统找不到指定的注册表项或值”——本机没有通过 Run 键自启动 Student/Smonitor。

### 31.4 结论

本构建的“自启动/自恢复”来源是 **Smsvc 服务 AUTO_START**：开机/服务启动时由服务拉起
Smonitor+Student；杀了 Student 本身不会触发重启，也没有配置 SCM 失败恢复动作。
学校环境里“杀了会自己重启”的现象，更可能来自：
- 机器/服务重启（Smsvc 自动启动 → 拉起学生端）；
- 学校镜像上额外配置了服务失败恢复或计划任务（本机没有）；
- 不同构建/不同保护策略（需要学校端 Student.exe/lib.dll/config 哈希对照）。
这一点仍需要学校实际文件来区分。

### 31.5 附带发现

Smonitor 的 **R 命令处理函数**（dispatcher 0x458a6e 分支）引用了 `Student.exe`（0x458b74）
和 `lib.dll`（0x458b80）字符串，并会设置对象 +0xfa 标志；初步看是“启动/检查学生端”类命令，
具体语义留待下轮用 Unicorn 活上下文仿真确认。

### 31.6 环境

恢复后：Smonitor PID 2276、Student PID 10964 正常运行；服务 `sc query` 为 RUNNING；
没有遗留的测试进程。

## 第三十二轮：Smonitor R 命令与 lib!UpdtFile（学生端更新/重启链）

### 32.1 R 命令处理函数（0x458a6e 分支）活上下文仿真

用 Q/T 那套 Unicorn 框架（真实 Smonitor 镜像 + lib + API 桩 + 真实 self 指针）仿真 R 命令，
payload 给安装目录，结果：

    GetFileAttributesA("C:\Program Files (x86)\gakataka\Student\")
    GetModuleFileNameA(...)
    ShellExecuteA(NULL, "rundll32.exe",
        '"C:\Program Files (x86)\gakataka\Student\lib.dll",UpdtFile
         "C:\Program Files (x86)\gakataka\Student\"
         "C:\Program Files (x86)\gakataka\Student\" "Student.exe"',
        NULL, SW_SHOWNORMAL=1)

即 **R 命令 = 用 rundll32 调用 lib!UpdtFile 更新/重启学生端**，参数是（lib 路径、
更新目录、目标目录、要处理的进程名 "Student.exe"）。空 payload 时只做一次 GetFileAttributes("") 就返回。

### 32.2 lib!UpdtFile（0xa0f018）静态流程

rundll32 导出的 stdcall 函数，参数 4 个（lib 路径、目录1、目录2、进程名）：

1. ParamCount>=4 校验，取 ParamStr(2)=目录、ParamStr(3)=目录、ParamStr(4)="Student.exe"；
2. 最多等 5 秒让 ParamStr(4) 进程出现，然后 **KillProc("Student.exe")**（走已还原的 Toolhelp+TerminateProcess 链）；
3. 若 Smsvc 服务在运行 → 调用服务停止 wrapper（0xa0e688）；
4. 最多等 5 秒让 "Smonitor.exe" 出现 → **KillProc("Smonitor.exe")**；
5. 调用 0xa0edd0 / 0xa0ea7c / 0xa0ebb4 做文件复制/更新（更新目录 → 目标目录，含属性/时间处理）；
6. 若 Smsvc 未运行 → 用 Format 构造 "Smonitor.exe" + 目录 + " /INSTALL /SILENT"，经 0x967870（lib .text2 0xa906d8）执行静默安装；
7. StartService(Smsvc)（0xa0e5e8）；
8. 若 Student.exe 还没起来：
   - IsAdminRun 为真 → 0xa0d5c0（提权/runas 启动路径）；
   - 否则 → 0xa09c28(1,0,0,命令) 启动 Student.exe；
9. 返回 0。

字符串证据（lib 镜像明文）："Smsvc"@0xa0f204、"Smonitor.exe"@0xa0f20c/0xa0f224、
" /INSTALL /SILENT"@0xa0f23c。
服务控制 helper：0xa0e4cc（查询状态）、0xa0e688（停止）、0xa0e490（是否在运行）、0xa0e5e8（启动），
内部都经 import thunk 0xa0178c/0xa01794（OpenSCManager/OpenService 一类）。

### 32.3 意义

R 是一条完整的“更新/重启学生端”链：杀 Student → 停 Smsvc → 杀 Smonitor → 复制文件 →
静默安装 Smonitor → 启动服务 → 启动 Student。教师端某些操作（远程执行/更新学生端等）若下发
R 命令，就会触发这条链；它也是“学生端被杀后又被拉起来”的一个可能来源——但需要 R 命令
或服务/文件更新动作触发，不是单纯的存活检测（上一轮已证明没有存活看护）。

### 32.4 环境

本轮中途 Student 再次消失（Smonitor 2276 下），已重启 Smsvc 恢复：Smonitor PID 10288、
Student PID 9468 正常运行。

### 32.5 产物

- `analysis/tmp/smon_uni_r.py` / `r2` / `r3`：R 命令 Unicorn 仿真（逐轮补 GetFileAttributesA、ShellExecuteA 桩）
- `analysis/tmp/api5_trace_R.json`：R_dir/R_dir_noslash/R_empty/R_dot/R_dir_noexe 五组轨迹
- `analysis/tmp/updtfile_dis.py` / `updtfile_dis2.py` / `updt_helpers.py` / `updtfile_strings2.py`：UpdtFile 反汇编与字符串

## 第三十三轮：lib!UpdtFile 完整仿真（R 命令的下半条链）

### 33.1 仿真方法

在 lib 活镜像 + 堆快照 + API 桩的批量仿真器上（v19~v28 迭代）：

- 在 `0x963080`（ParamCount 辅助）入口打补丁，强制返回 5；
- 在 `0x9630e8`（ParamStr 辅助）入口打补丁：按 index 构造 Delphi AnsiString
  （refcount=-1、length、data），ParamStr(2)=安装目录、ParamStr(3)=另一个目录、
  ParamStr(4)="Student.exe"、ParamStr(1)=lib.dll 路径；
- 补 Toolhelp（CreateToolhelp32Snapshot/Process32First/Next A/W）、服务控制
  （OpenSCManager/OpenService/QueryServiceStatus/ControlService/StartService/CloseServiceHandle）、
  文件（CopyFile/GetFileAttributes/SetFileAttributes/GetFileTime/SetFileTime/DeleteFile/MoveFile/
  FindFirstFile/FindNextFile/FindClose/FileTimeToLocalFileTime/FileTimeToDosDateTime）、
  GetFileSecurityA/SetFileSecurityA/GlobalAlloc/GlobalLock、ShellExecute、WinExec、GetUserNameA 等桩；
- 复制/时间/安全属性 helper（0xa0edd0 / 0xa0ea7c / 0xa0ebb4）因为桩模拟下循环，直接跳过
  （静态确认它们内部用 FindFirstFile/FindNextFile + 文件时间 + GetFileSecurity/GlobalAlloc）；
- 管理员判断分支（0xa0de18）直接跳过，走非管理员启动分支。

### 33.2 完整 API 轨迹（最终一轮 v28，进程枚举名故意设为 notepad.exe 以走“启动 Student”分支）

    CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0) → Process32First/Next   ; 等 Student.exe（超时）
    OpenSCManager(NULL,NULL) → OpenService(Smsvc) → QueryServiceStatus      ; Smsvc 在运行
    OpenSCManager → OpenService(Smsvc) → QueryServiceStatus
    ControlService(Smsvc, SERVICE_CONTROL_STOP)                            ; 停服务
    CreateToolhelp32Snapshot → Process32First/Next                          ; 等 Smonitor.exe（超时）
    OpenSCManager → OpenService(Smsvc) → QueryServiceStatus
    OpenSCManager → OpenService(Smsvc) → QueryServiceStatus
    StartService(Smsvc)                                                     ; 启动服务
    CreateToolhelp32Snapshot → Process32First/Next                          ; 再查 Student.exe（未找到）
    ShellExecuteA(NULL, NULL, "C:\Program Files (x86)\gakataka\StudentStudent.exe",
                  NULL, "C:\Program Files (x86)\gakataka\", SW_SHOWNORMAL=1)  ; 启动 Student.exe

（file 名出现 "StudentStudent.exe" 是因为我们补丁里 ParamStr(2) 给的是 "...\\Student" 目录，
真实调用时 ParamStr(2) 是安装根目录，拼出来就是 "...\\Student\\Student.exe"。）

结论：**UpdtFile = 等/杀 Student.exe → 停 Smsvc → 等/杀 Smonitor.exe → 复制/更新时间与安全属性 →
（若服务未运行则执行 Smonitor.exe /INSTALL /SILENT）→ StartService(Smsvc) →
若 Student.exe 不在则 ShellExecute 启动它**。与上轮静态分析完全一致，且补上了实际 API 调用序列。

### 33.3 活体执行尝试（负结果）

想用 frida 挂起启动 `SysWOW64\rundll32.exe lib.dll,UpdtFile ...` 并挂钩子直接观察真实链，
结果：

- System32 的 64 位 rundll32 无法加载 32 位 lib.dll，进程直接退出，0 事件；
- SysWOW64 rundll32 用多种参数形式 spawn 后钩子仍 0 事件、进程立即退出（frida 对 WOW64
  spawn 的钩子不可靠）；其中一次尝试后 Student 消失，但不能归因于这次执行。
- 这条活体路径放弃，改用上面的 Unicorn 仿真。

### 33.4 环境

本轮多次需要恢复 Student（期间发现 Student 会在没有我们干预的情况下消失，疑似 Smonitor
定时器行为，留待下轮排查）。最终恢复：Smonitor PID 10380、Student PID 6068 正常运行。

### 33.5 产物

- `analysis/tmp/lib_batch_emul_v19.py` ~ `v28.py`：逐轮补丁与桩（ParamCount/ParamStr 补丁、服务/文件/安全 API 桩、跳过 helper）
- `analysis/tmp/svc_api_addrs5.json` / `svc_api_addrs6.json`：本轮解析的服务/文件 API 地址
- 轨迹数据在 `analysis/tmp/lib_batch1.json` 的 UpdtFile 用例

## 第三十四轮：U/V 命令还原与 Smonitor 命令字母表补全

### 34.1 U 命令 = U 盘存储开关

用 Smonitor 命令分派器 Unicorn 仿真（真实 Smonitor 镜像 + lib + 真实 self 指针），
命令 `U\\x01` / `U\\x00`：

    U1:
      RegCreateKeyExA(HKLM=0x80000002, "SYSTEM\\CurrentControlSet\\Services\\UsbStor", ...)
      RegSetValueExA(句柄, "Start", REG_DWORD, 3, 4)      ; Start=3 允许 USB 存储
      RegCloseKey
    U0:
      同路径，RegSetValueExA("Start", 4)                  ; Start=4 禁止 USB 存储

即 **U(1)=允许 U 盘存储（Start=3），U(0)=禁止（Start=4）**，和 lib 导出的
DisableUsbStore/EnableUsbStore 是同一注册表位置。

### 34.2 V 命令 = 来宾账户开关

    V1:
      WinExec("net user Guest /active:yes", 0)   ; 启用 Guest
    V0:
      WinExec("net user Guest /active:no", 0)    ; 禁用 Guest

即 **V(1)=启用访客账户，V(0)=禁用访客账户**，与 lib 的 DisableGuest/EnableGuest 对应。

两条命令内部都先经过 RtlEnter/LeaveCriticalSection 保护，U/V 处理函数分别跳到 .text0
里的混淆实现（0x47a71c/0x476a19 与 0x478419/0x4776f1）。

### 34.3 Smonitor 命令字母表（累计）

| 字母 | 语义 |
|------|------|
| Q | 复制用户配置到安装目录 config（含 SetFileSecurity） |
| R | 更新/重启学生端（ShellExecute rundll32 → lib!UpdtFile → 杀 Student/停服务/杀 Smonitor/复制/起服务/起 Student） |
| S | taskmgr 保护标志（self+0xfb） |
| T | 写 install config 的 "ar"（0/1）并 flush |
| U | U 盘存储开关（UsbStor Start=3/4） |
| V | 来宾账户开关（net user Guest /active:yes/no） |
| W | 把命令文本写入 self 字符串缓冲（内存态） |
| X | 设置本地时间（DWORD 8 字节 TDateTime → lib!SetDateTime → SetLocalTime） |

至此 Q/R/S/T/U/V/W/X 八类命令全部还原。

### 34.4 环境与监视

当前 Student PID 6068、Smonitor PID 10380 正常运行。为排查“Student 会自行消失”，
已启动后台监视（frida 钩 Smonitor 的 lib!KillProc、命令分派器、CreateProcess*、TerminateProcess，
并每 2 秒轮询 Student 进程，记录到 `analysis/tmp/monitor59.log`，计划观察 300 秒）。
写文档时监视尚未捕获任何 KillProc/分派/进程变化事件。

### 34.5 产物

- `analysis/tmp/smon_uni_uv.py` / `smon_uni_uv2.py`：U/V 命令 Unicorn 仿真（补注册表/WinExec 桩）
- `analysis/tmp/api5_trace_UV.json`：U1/U0/V1/V0 四组轨迹
- `analysis/tmp/fr_monitor59.py`、`analysis/tmp/monitor59.log`：后台监视脚本与日志

## 第三十五轮：U/V 命令还原、命令表补全与方法论修正

### 35.1 U 命令 = U 盘存储开关

Smonitor 分派器 Unicorn 仿真（真实镜像 + lib + 真实 self 指针），命令 `U\x01`/`U\x00`：

    U1:
      RegCreateKeyExA(HKLM=0x80000002, "SYSTEM\CurrentControlSet\Services\UsbStor", ...)
      RegSetValueExA(句柄, "Start", REG_DWORD, 3, 4)   ; Start=3 允许
    U0:
      同路径，RegSetValueExA("Start", 4)               ; Start=4 禁止

即 **U(1)=允许 U 盘存储，U(0)=禁止**，与 lib!EnableUsbStore/DisableUsbStore 同一注册表位置。

### 35.2 V 命令 = 来宾账户开关

    V1: WinExec("net user Guest /active:yes", 0)   ; 启用 Guest
    V0: WinExec("net user Guest /active:no", 0)    ; 禁用 Guest

即 **V(1)=启用来宾，V(0)=禁用**，与 lib!EnableGuest/DisableGuest 对应。

两条命令都经 RtlEnter/LeaveCriticalSection 保护，处理函数跳到 .text0 混淆实现
（0x47a71c/0x476a19 与 0x478419/0x4776f1）。

### 35.3 Smonitor 命令字母表（Q/R/S/T/U/V/W/X 全部完成）

| 字母 | 语义 |
|------|------|
| Q | 复制用户配置到安装 config（含 SetFileSecurity） |
| R | 更新/重启学生端（rundll32 → lib!UpdtFile：杀 Student/停服务/杀 Smonitor/复制/起服务/起 Student） |
| S | taskmgr 保护标志（self+0xfb） |
| T | 写 install config 的 "ar"（0/1）并 flush |
| U | U 盘存储开关（UsbStor Start=3/4） |
| V | 来宾账户开关（net user Guest /active:yes/no） |
| W | 命令文本写入 self 字符串缓冲（内存态） |
| X | 设置本地时间（8 字节 TDateTime → lib!SetDateTime → SetLocalTime） |

### 35.4 方法论修正：frida enumerate_processes 不可靠

本轮多次发现 `dev.enumerate_processes()` 的结果与真实状态不符（杀掉进程后仍列旧 PID、
恢复后仍报旧 PID 甚至错误 PID）。改用 guest 内 `tasklist` 写文件 + 从 Smonitor 进程读回
得到可靠状态：

- 真实状态：**Student.exe PID 6956，Console 会话 1**；**Smonitor.exe PID 4144，Services 会话 0**；
  Smsvc STATE=RUNNING。
- 因此之前若干“Student 自行消失/被杀”的观察可能只是枚举假象；后台监视脚本
  （analysis/tmp/monitor59.log）也因此不可信，已终止。
- 注意：Smonitor 由 SCM 在 session 0 启动，Student 被放进 Console 会话 1 运行（CreateProcessAsUser 一类）。

### 35.5 同步进行的验证

已启动基于 tasklist 的“杀 Student 是否自动重启”重测（后台任务，
日志 analysis/tmp/restart_test59.log）：先快照、taskkill Student、之后每 10 秒采样一次共 5 分钟。

### 35.6 产物

- `analysis/tmp/smon_uni_uv.py` / `smon_uni_uv2.py`、`api5_trace_UV.json`：U/V 仿真
- `analysis/tmp/fr_tasklist_check2.py` / `fr_restart_test59.py`：可靠状态检查与重测脚本
- `analysis/tmp/restart_test59.log`：自动重启重测日志

### 35.7 自动重启重测结果（tasklist 为准，补充）

05:20:56 用普通 `taskkill /f /im Student.exe` 杀掉 Student（非 frida kill，真实进程终止），
之后每 10 秒用 guest 内 tasklist 采样，直到 05:27:14：

    05:20:56 AFTER-KILL  ["Smonitor.exe 4144 Services 0 ..."]
    05:21:09 ... 05:27:14 每次采样都只有 Smonitor.exe，Student.exe 再未出现

并且到本轮（数小时后）再检查，Student 仍未被拉起——**杀 Student 后 Smonitor 不会自动重启它**，
这个构建的“自启动”仅来自 Smsvc 服务启动时拉起（服务 AUTO_START），与之前的负结果一致。

## 第三十六轮：lib 的 USB/访客导出活体验证 + 环境恢复

### 36.1 活体验证（真实 Smonitor 进程内直接调用 lib 导出）

当前 Smonitor PID 7344，lib.dll 基址 0xa80000，导出：
DisableUsbStore=0xb2f6e8、EnableUsbStore=0xb2f6f8、DisableGuest=0xb2e958、EnableGuest=0xb2e978。

USB 存储（注册表实测，reg query）：

    lib!DisableUsbStore() -> HKLM\SYSTEM\CurrentControlSet\Services\usbstor\Start = 4
    lib!EnableUsbStore()  -> Start = 3

访客账户（net user Guest 实测）：

    lib!DisableGuest() -> "帐户启用  No"
    lib!EnableGuest()  -> "帐户启用  Yes"

与 U/V 命令仿真、和之前对这些导出的 Unicorn 仿真完全一致。
（测试后 USB Start 已回到默认 3；Guest 账户状态恢复为测试前的 Yes。）

### 36.2 命令字符串里的引号坑

用 frida spawn `cmd.exe /c "reg query \"HKLM\\...\" ..."` 时，frida 对 argv 的整体加引号
会破坏内层引号，导致 reg 报“找不到注册表项”。改成不带引号的短路径
（`reg query HKLM\SYSTEM\CurrentControlSet\Services\usbstor /v Start`，路径无空格）即可。
以后所有 guest 命令尽量用无空格路径，避免内嵌引号。

### 36.3 教师按钮 → 命令字母关联实验（受阻）

- 教师 VM 仍在运行（VNC 5902、QMP socket 正常），截图显示教师端 **在线学生 0**；
  最后一条日志停在 02:19（Student 离线）。
- 学生 VM 屏幕之前是黑的（显示器休眠），发 sendkey 唤醒后可见 ZZX 桌面，
  桌面上还留着之前测试用的管理员 cmd 窗口，Student 客户端没有可见窗口/未重新登录上线。
- 因此“点教师端按钮 → 看 Smonitor 收到哪个命令字母”的实验暂时做不了，
  需要先让学生端重新上线（下轮处理：检查 Student 客户端登录状态/网络）。

### 36.4 环境

- 已恢复 Smsvc 服务：Smonitor PID 7344（Services 会话 0）、Student PID 2208（Console 会话 1），
  `sc query Smsvc` RUNNING。
- 已确认：05:20 杀掉 Student 后 6 小时无自动重启（tasklist 实测），本构建无存活看护。
- USB Start=3（默认），Guest 账户启用状态与测试前一致。

### 36.5 产物

- `analysis/tmp/fr_usb_live2.py`：USB Start 切换活体测试
- `analysis/tmp/fr_live_uv_exports.py`：USB/访客导出活体测试与还原
- `analysis/tmp/fr_usb_diag2.py`、`fr_read_back_uv.py`：注册表查询与状态回读
- `analysis/tmp/student60b.png`、`teacher60b.png`：学生/教师 VM 当前截图

## 第三十七轮：Student 客户端未上线的根因（UAC 阻塞）与环境状态

### 37.1 现象链

- 教师端一直显示 **在线学生 0**，日志停在 02:19:09（Student 离线）。
- 用 tasklist 真实状态反复确认：Student 进程缺失；只有 Smonitor 在 Services 会话 0。
- 重启 Smsvc 后，Student 被拉起（Console 会话 1），但：
  - 主窗体 `TfrmMain`（标题“伽卡他卡电子教室学生端”）存在但 **IsWindowVisible=0**；
  - 进程没有任何 TCP/UDP 连接（netstat 按 PID 过滤为空）；
  - 教师端仍 0 在线。

### 37.2 根因：UAC 授权对话框

学生 VM 的 QMP 截图在“主窗体隐藏”时看到的是 **UAC 安全桌面**：

    用户帐户控制
    你要允许来自未知发布者的此应用对你的设备进行更改吗?
    Student.exe   发布者: 未知   文件源: 此计算机上的硬盘驱动器

即：Smsvc 服务用本地登录用户的**过滤令牌**启动 Student（Student 清单要求管理员权限），
于是 Student 卡在 UAC 等待；主窗口不显示、不初始化网络 → 教师端看不到学生。
这解释了这段时间反复出现的“Student 消失/不上线”现象。

### 37.3 UAC 点“是”之后仍然不行

用 VNC 点击“是”后：UAC 消失、桌面恢复，但 Student 进程在数秒内自行退出；
在 Smonitor 里挂钩 lib!KillProc、TerminateProcess、CreateProcessA/W，**没有任何事件**，
说明不是保护层杀的，而是 Student 自己退出。

其它启动方式也失败：

- frida 直接 spawn Student（普通令牌）→ 立刻退出（ERROR_ELEVATION_REQUIRED 类行为）；
- 写 .bat 用 `start "" "…Student.exe"` 从 cmd 启动 → 退出；
- 注入已提权的 cmd.exe（PID 9188），在它内部 CreateProcessA 启动 Student（成功返回 PID 904/628）→ 数秒后退出；
- 先 `sc stop Smsvc` 再启动 Student → 也退出（说明 Student 依赖 Smonitor 服务/本地命令通道）。

推断：Student 以管理员令牌启动后会进入“安装/修复/更新”分支（与 R 命令链类似）然后退出，
或需要 Smsvc 以特定令牌/参数启动；具体原因还需要抓 Student 的退出调用栈/命令行。

### 37.4 新发现：Smonitor 的本地命令 TCP 端口

`netstat -ano` 显示 Smonitor（Session 0）监听 **TCP 0.0.0.0:55686**，
这应该就是 Student→Smonitor 下发 Q/R/S/T/U/V/W/X 命令的本地通道。
后续可以直接连这个端口做命令注入验证（例如 U/V 的注册表/账户效果），不再依赖教师端。

### 37.5 当前环境

- Smsvc 服务 RUNNING；Smonitor PID 10696（Services 会话 0）；**Student 未运行**；
- 教师 VM 正常，教师端在线学生 0；
- 学生 VM 桌面正常（VNC 可操作），无 UAC 挂起；
- 后台 killwatch 任务已停止。

### 37.6 下轮计划

1. 抓 Student 被 Smsvc 启动时的命令行/父进程令牌（可能需要 hook SCM 启动瞬间或读服务代码路径）；
2. 或关闭 UAC（EnableLUA=0）+ 重启学生 VM，让服务拉起的 Student 直接提权运行，再确认上线；
3. 直接连 Smonitor 的 TCP 55686 做命令通道活体验证（U/V 等）。

### 37.7 产物

- `analysis/tmp/fr_student_windows2.py`：Student 窗口枚举（发现 TfrmMain 隐藏）
- `analysis/tmp/fr_student_state61.py` / `fr_student_state61b.py`：窗口/网络状态
- `analysis/tmp/fr_student_nosvc.py` / `fr_create_student_from_cmd.py`：各种启动尝试
- `analysis/tmp/fr_killwatch61b.py` / `killwatch61.log`：Smonitor 杀进程路径监视（无事件）
- 截图：`student61g.png`（UAC 对话框）、`teacher61e.png`（教师端 0 在线）

## 第三十八轮：Student 自退出的动态定位（Delphi RTL 关机路径）

### 38.1 进程创建审计（4688）还原启动链

临时启用进程创建审计（auditpol + ProcessCreationIncludeCmdLine_Enabled），重启 Smsvc 后抓到：

    #1 创建者: Smonitor.exe (SYSTEM 登录 0x3E7, 目标账户 zzx)
       新进程: Student.exe  令牌提升类型: %%1938（受限令牌，mandatory label 8192）
       命令行: "C:\Program Files (x86)\gakataka\Student\Student.exe"
    #2 创建者: Student.exe (PID 0x1630)
       新进程: Student.exe  令牌提升类型: %%1937（提升令牌，mandatory label 12288）
       命令行: "C:\Program Files (x86)\gakataka\Student\Student.exe"

即：Smonitor 用受限令牌拉起 Student → Student 自己再拉起一个管理员令牌的 Student（自提升）。
两个实例随后都消失，教师端离线。

### 38.2 挂起创建 + 钩子：Student 自己调用 ExitProcess

用 frida spawn（挂起创建）Student，先装钩子再恢复运行，捕获到：

    ExitProcess 调用栈: [0x404a28, 0x76356a20, 0x400000]
    → 0x404a28 在 Student 镜像内（RVA 0x4a28），紧接 call ExitProcess 之后
    → 该代码是 Delphi RTL 的关机/收尾路径：0x4049f5~0x404a23 一串 cmp/调用后
      0x404a1d mov eax,[0x58d000]; push eax; call 0x4012c4（ExitProcess 导入）

在此之前 Student 的启动 API 序列（挂起期间钩子，恢复后记录）：

    CreateMutexW ×4（匿名）
    CreateMutexA("Student.exe") -> handle 0x530, GetLastError=0（首次创建成功）
    随后进程退出（无 FindWindow/MessageBox/ShowWindow 调用）

说明：单实例互斥体创建是成功的（不是被已存在实例顶掉），Student 在 GUI/网络初始化之前就
走了 RTL 关机路径；退出码来自全局 0x58d000（尚未抓到具体值）。

### 38.3 不是 Smonitor 杀的

- 在 Smonitor 里挂 lib!KillProc / TerminateProcess / CreateProcessA/W 后观察，无任何事件；
- 先 `sc stop Smsvc`（Smonitor 不存在）再同样挂起创建 Student，仍然秒退。

所以是 Student 自身或 Delphi 运行时主动退出，不是保护层干预。

### 38.4 推断

Student 在创建单实例互斥体后、进入主窗体/网络初始化前判断某个条件不满足，直接 Halt：
候选包括启动参数/父进程/令牌/桌面环境、配置字段缺失、或需要由 Smonitor 以特定方式
（例如先建立本地命令通道）才继续。需要下一轮抓退出码+更早的路径才能确定。

### 38.5 环境还原

- UAC 策略已还原：ConsentPromptBehaviorAdmin=5、PromptOnSecureDesktop=1；
- 进程创建审计已关闭（auditpol success:disable，删除命令行记录策略）；
- Smsvc 服务 RUNNING（Smonitor PID 5064，Services 会话 0）；Student 未运行；
- 教师端在线学生 0；无遗留后台任务。

### 38.6 产物

- `analysis/tmp/fr_suspended_student2.py`：挂起创建+先挂钩后恢复实验
- `analysis/tmp/fr_spawn_full.py`：Student 启动 API 全记录
- `analysis/tmp/spawn_events_61.json`：启动事件数据
- `analysis/tmp/student_exit_dis.py`：ExitProcess 调用点反汇编
- `analysis/tmp/fr_audit4688.py` / `fr_cleanup62.py`：4688 审计与还原

## 第三十九轮：Student 启动早期“正常退出”的动态定位

### 39.1 抓到退出路径

用 frida 挂起创建 Student，先装钩子再恢复，最终捕获：

    RtlExitUserProcess(status=0)
    栈: [0x76356a33, 0x776cdb50, 0x404a28, 0x400000]
      → Student 侧 0x404a28 是 Delphi RTL 关机路径（0x404a23 call ExitProcess 的返回地址）
      → 退出码 0（全局 0x58d000 = 0），是“正常退出”而不是错误码退出

退出前的关键序列（同一进程内）：

    CreateMutexW ×4（匿名）
    CreateMutexA("Student.exe") lasterr=0（首次创建成功）
    SendMessageA(..., msg=0x0A100) ×N（向 shell/托盘窗口发消息）
    FindWindowW("Shell_TrayWnd")
    PostQuitMessage(0)   ← 来自 Student 自身代码 0x48a9e4
       调用链: 0x48a9e4 ← 0x4832cb ← 0x482fab ← 0x48a89c（均是 Student 的混淆层地址）
    DestroyWindow ×N（清理），随后 RTL 关机 → RtlExitUserProcess(0)

即：Student 启动后完成了自己的 UI 初始化，然后在约 1 秒内**自己调用 PostQuitMessage(0) 退出**。

### 39.2 排除了外部因素

- 没有任何异常：Process.setExceptionHandler、RaiseException、UnhandledExceptionFilter 均未触发；
- 没有调用 Halt 的调用点（0x402bfe/0x40dd72），退出码是 0；
- 没有创建子进程（CreateProcessA/W/AsUser/WithToken、ShellExecute、WinExec 全部无调用）；
- Smonitor 里 KillProc/TerminateProcess 钩子无事件；
- 先停掉 Smsvc（Smonitor 不存在）再启动，Student 同样退出。
- 单实例互斥体创建是成功的（lasterr=0），不是被已有实例顶掉。

结论：是 Student 自己的混淆启动逻辑判断某个条件后 **主动 Terminate**（正常退出）。

### 39.3 静态分析的局限与下一步

0x48a9e4 / 0x4832cb / 0x482fab / 0x48a89c 位于 Student 的混淆层，stage2 静态镜像里
这些地址反汇编不可靠（数据/按需解码），所以还需要运行时手段：
- 在 PostQuitMessage 钩子里把“退出前最后若干外部 API/窗口消息”完整记录（已在做）；
- 或运行时 dump 0x48xxxx 区域，用 Stalker 限定在 PostQuit 前窗口跟踪；
- 或直接观察 Student 在 Popup窗口/托盘初始化后是否检测到“已有实例的窗口/消息”而退出。

### 39.4 当前环境

- Smsvc 服务 RUNNING，Smonitor PID 5064（Services 会话 0）；
- Student 未运行（服务拉起后仍会自行退出），教师端在线学生 0；
- 无遗留测试进程；UAC 策略/审计策略保持上轮还原后的值。

### 39.5 产物

- `analysis/tmp/fr_exit_trace63b.py`：RtlExitUserProcess/ExitProcess 抓取
- `analysis/tmp/fr_nt63.py`：ntdll 终止函数钩子（发现 RtlExitUserProcess(0)）
- `analysis/tmp/fr_quit63.py`：PostQuitMessage/窗口消息序列抓取（关键证据）
- `analysis/tmp/fr_spawn_child63.py`：子进程创建检查（无）
- `analysis/tmp/student_quit63.json`、`student_nt63.json`：动态日志
- `analysis/tmp/student_quit_dis.py`：混淆层静态反汇编尝试

## 第四十轮（第 64/65 轮合并）：配置假设排除与混淆层运行时 dump 尝试

### 40.1 配置恢复实验（假设：Q 测试改坏了配置）

- 安装目录 config.cfg 只有 287 字节，而备份（config.cfg.bak / .before-ms / .proxybak / .round23.bak）都是 411 字节；
- 通过 SYSTEM 令牌的 Smonitor 进程把 287B 当前配置另存为 config.cfg.pre63，再把 411B 的
  config.cfg.round23.bak 写回 config.cfg（写入成功，411 字节）；
- 重启 Smsvc 后 Student 仍未运行（tasklist 只有 Smonitor）。**配置不是自退原因**。

### 40.2 混淆层运行时 dump 尝试

- 在 PostQuitMessage 被调用瞬间 dump 0x480000-0x4A0000 的运行内存；
- 与 stage2 静态镜像对比：绝大多数字节不同（运行期已变化），但 0x48a9e4 / 0x4832cb /
  0x482fab / 0x48a89c 等“退出调用栈地址”处反汇编仍是无效指令；
- 说明该层按块解密、执行后加密，抓瞬间快照拿不到解码代码；需要跟踪解码/执行点
  （例如在解密写入处下断或跟踪执行指针）才能还原。

### 40.3 当前环境

- Smsvc 服务 RUNNING，Smonitor PID 6820（Services 会话 0）；
- Student 未运行；教师端在线学生 0；学生 VM 桌面已唤醒，无 UAC 提示；
- 安装配置已改为 411B 备份，原 287B 保存为 config.cfg.pre63（如需还原可写回）。

### 40.4 结论与下轮

Student 自退已确认是“启动后主动 PostQuitMessage（退出码 0）”的正常退出，且与配置、UAC、
Smonitor 存活、单实例互斥体无关；触发条件在混淆层。下轮思路：
1) 在混淆层解密写入点下断（对 0x480000-0x4A0000 设内存写监视/硬件断点）抓解码后的代码；
2) 或从 PostQuitMessage 反向单步：在 VCL Application.Terminate 入口（user32 PostQuitMessage
   调用点附近）读返回地址与调用者，沿调用链回溯到判断点；
3) 另一条线：直接从 Smonitor TCP 55686 命令通道注入 U/V 等命令做活体验证，不依赖 Student 上线。

## 第四十一轮：Student 启动自检逻辑 + 命令通道探测

### 41.1 启动自检代码（从 PostQuitMessage 回溯 + 运行时字节）

在 PostQuitMessage 入口读栈得到返回地址 RVA 0x8A9D4 与调用链，运行时 dump 后反汇编出
Student 启动自检逻辑（位于主 CODE 段，静态镜像可直接反汇编，运行时==静态）：

    0x8A9D4:  call 0x40EECC        ; 某检查
              test al,al
              je   跳过
              push 0
              call 0x407E0C        ; PostQuitMessage(0)  -> 正常退出
    调用者 RVA 0x182C44..0x182D06 顺序检查：
      1) call 0x161850(路径相关参数)       ; 非零 -> 静默退出
      2) call 0x161848("Student.exe")      ; 非零 -> 静默退出
      3) call 0x1618D0("Smsvc")            ; 为零 -> 弹消息 "程序重要文件丢失, 请重新安装" 后退出
      4) call 0x1618D8("Smsvc") / 0x1618E0("Smsvc") / 0x1618C0()
         -> 失败分支弹 "程序服务启动失败, 请重新安装"
            或 "程序服务启动失败, 请开启或重新启动计算机" 后退出
      5) 全部通过 -> 0x182D06 继续正常启动

相关明文字符串（GBK，VA）：
  0x583100 "Student.exe"、0x58310C "Smsvc"、
  0x583114 "程序重要文件丢失, 请重新安装"、0x583134 "伽卡他卡电子教室"、
  0x583148 "程序服务启动失败, 请重新安装"、
  0x583168 "程序服务启动失败, 请开启或重新启动计算机"、
  0x5831A0 "失败, 程序将终止"、0x5831C0 "已经运行学生端, 请注销后再运行"、
  0x5831E8 "/setmods"、0x58322C "PipeStudent"

### 41.2 打补丁强制通过自检（尝试）

把这 5 处条件跳转改成无条件跳到“继续”分支（frida Memory.patchCode，全部成功），
Student 仍然退出，未进入正常启动。可能原因：
- Student 对自身代码有完整性校验（补丁被检测后走另一条静默退出路径）；
- 或退出不经过这组检查（另有更早的退出点）。
该方向暂未定论。

### 41.3 命令通道探测（TCP / 命名管道）

- Smonitor 的 TCP 监听端口**每个服务实例都变**（本轮实例 PID 6820 是 56282，之前实例是 55686）；
- 从 explorer 进程 connect 127.0.0.1:<port> 成功（修正了 sockaddr_in 端口字节序），
  但发送 'U\\x00'、'U\\x01'、长度前缀、0 结尾等几种原始帧，UsbStor Start 均无变化；
- 同时钩住 Smonitor 分派器 0x4589F8，TCP 发送的数据**没有触发分派器**；
- 命名管道 "PipeStudent" 当前不存在（枚举 84 个管道，无 Student 相关）。
结论：TCP 监听端口不是 Q/R/S/T/U/V/W/X 的命令入口（或前置握手未满足）；
命令通道更可能是命名管道 PipeStudent（需 Smonitor 在特定状态才创建/接入）。

### 41.4 环境

Smsvc RUNNING（Smonitor 6820），Student 未运行，教师端在线学生 0；
安装配置为 411B 备份（287B 旧配置保存在 config.cfg.pre63）；USB Start=3。

### 41.5 产物

- `analysis/tmp/fr_postquit_stack66.py` / `postquit_stack66.json`：PostQuit 栈与运行时字节
- `analysis/tmp/analyze_postquit_code.py`、`static_583_dis.py`、`student_checks.py`：自检逻辑反汇编
- `analysis/tmp/fr_checks66.py`、`fr_patch_checks.py`：检查函数钩子与补丁尝试
- `analysis/tmp/fr_probe_tcp_dyn2.py`、`fr_pipe_probe.py`、`fr_dispatch_via_tcp.py`：命令通道探测

## 第四十二轮（第 68/69 轮合并）：VM 恢复、Student 自退根因确认、学生端重新上线

### 42.1 环境恢复

- 两台 VM 在会话中断后已停止（QMP socket 消失）；用 `vm/win10-22h2/run-vm.sh`、
  `vm/win10-teacher-22h2/run-vm.sh` 以 VNC 模式重新启动（后台任务）。
- 锁屏登录：vncdotool 无 typeText/mouseRelease，改用 QEMU HMP `sendkey` 逐键输入；
  两台均登录 ZZX/580356。
- frida-server 恢复：从提权 cmd 启动 `C:\Users\zzx\frida-server64.exe -l 0.0.0.0:27042`。
  只写 `frida-server64.exe`（默认监听 127.0.0.1）时 QEMU hostfwd 到 27042 会挂起，
  必须带 `-l 0.0.0.0:27042`。

### 42.2 Student 自退的根因（长时间问题的结论）

- 单实例检查函数（0x161848）实测语义：调用 `CreateMutexA(name)`，
  若 GetLastError==183（已存在）返回 -1，否则返回 0；即“同名互斥体是否已存在”。
- 旧会话里我们反复启动/挂起 Student，某个长生命周期进程继承了 “Student.exe” 互斥体句柄，
  导致之后每个 Student 都判定“已运行”，走 PostQuitMessage(0) 静默正常退出。
- 重启后从 explorer 用 CreateProcess 启动 Student 前，先在 explorer 里探测
  CreateMutexA("Student.exe")：GetLastError=0（无残留），随后启动 Student（PID 7116）；
  UAC 接受后提权实例 PID 5092 持续运行，不再自退。
- 启动后学生端窗口显示“伽卡他卡电子教室学生端 17.8.24.111 [10.0.2.15,192.168.50.10,
  169.254.83.100]”，随后进入“正在查找教师机”。
- 之前 0x161848 实测返回 -1 的对照、重启后同一调用返回 0，两相对照确认根因是残留互斥体，
  而非配置/UAC/服务/反虚拟机。

### 42.3 启动项检查（确认 Student 不随登录自启）

PowerShell 编码命令查询结果：
- HKCU Run 只有 OneDrive、Edge；HKLM Run 只有 SecurityHealth；WOW6432Node Run 为空；
- 用户/公共启动文件夹为空；计划任务中无 gaka/student/Smonitor/Smsvc 相关项；
- Smsvc 服务为 Automatic 且 RUNNING（Smonitor 进程存在），但服务启动时拉起的 Student
  因旧互斥体残留而退出。
结论：该版本 Student 客户端没有登录自启项，靠服务/手动启动；之前“登录后自动上线”
是当时服务拉起的 Student 恰好成功。

### 42.4 教师端与学生端上线

- 教师端：桌面快捷方式按回车启动 Teacher.exe → UAC 接受 → 教师主界面（17.8）；
- 12:09:54 教师日志：`学生端上线:DESKTOP-S7HAS2J [192.168.50.10]`，在线学生 1；
- 学生端界面曾显示客户端窗口，随后窗口隐藏/minimize，桌面右上角出现红色
  `DESKTOP-S7HAS2J` 字样（待下轮确认来源）；教师端仍显示在线 1。

### 42.5 当前状态

- 学生机：Smsvc RUNNING（Smonitor）、Student.exe 运行（提权，在线）、frida-server64 运行
  （曾出现 enumerate 挂起，需要时重启）；
- 教师机：Teacher.exe 运行，在线学生 1；
- 两台 VM 以后台任务方式运行（学生 bash-ca837179e69449b9，教师 bash-1f0d14878415439c）。

### 42.6 产物

- `analysis/tmp/s68online.png`、`analysis/tmp/t68log.png`：上线证据截图
- `analysis/tmp/fr_launch_student68.py`：explorer 内 CreateProcess 启动 Student + 互斥体探测
- `analysis/tmp/fr_check_api_trace.py`：检查函数 API 追踪（CreateMutexA 语义）
- `analysis/tmp/ps68.py`：启动项/计划任务/服务查询
- `analysis/tmp/start_frida68c.py` 等：frida-server 恢复脚本

## 第四十三轮：教师端按钮 → Student → Smonitor 命令字母的实时关联

### 43.1 实验方法

两端同时挂钩：
- Student（PID 5092）：ws2_32 的 recv/send 全量记录 + 命令分派 0x1833D0；
- Smonitor（PID 2736）：分派器 0x4589F8（base+0x589F8），参数 ECX=缓冲区长度、EDX=缓冲区指针；
然后在教师端依次点击“开启保护”“关闭保护”。

### 43.2 抓到的帧

教师 → Student（TCP，9 字节头 + 负载，magic 52 21 15 52）：

    13 02 00 00 00 52 21 15 52          ; type=0x13 len=2
    0D 01                               ; type=0x0D, 值=1 → 开启保护
    ...
    13 02 00 00 00 52 21 15 52
    0D 00                               ; type=0x0D, 值=0 → 关闭保护

Student → Smonitor（本地 TCP，同样 9 字节头 + magic，type 0x13）：

    开启保护时:
      13 3F 00 00 00 52 21 15 52
      51 43 3A 5C ... 00                ; 'Q' + C:\Users\zzx\AppData\Roaming\gakataka\class\config\config.cfg\0
      13 02 00 00 00 52 21 15 52
      53 01                            ; 'S' + 0x01
    关闭保护时:
      13 3F 00 00 00 52 21 15 52
      51 ...（同一配置文件路径）
      13 02 00 00 00 52 21 15 52
      53 00                            ; 'S' + 0x00

Smonitor 分派器侧同步抓到：
- ECX=0x3F、EDX 指向 Q + C:\Users\...\config.cfg\0（63 字节）
- ECX=0x02、EDX 指向 S 01 / S 00

### 43.3 结论

教师端“开启保护/关闭保护”按钮的链路是：

    教师 → Student（0x0D 01/00 帧）
         → Student 转发 Smonitor：先 Q（把用户配置复制到安装目录，同步保护相关配置）
           再 S 1/0（保护开关标志）

与之前静态/仿真结论一致：Q = 用户配置→安装配置复制 + SetFileSecurity；S = 保护标志
（taskmgr 等相关，标志位于 Smonitor 全局对象 self+0xfb）。
这解释了“开启保护后任务管理器/性能监视器立即关闭”的链路入口：
教师按钮并非直接杀进程，而是下发 S 标志，由 Smonitor 的保护逻辑执行。

### 43.4 产物

- analysis/tmp/teacher_btn70.jsonl：两端钩子全量事件（含时间序）
- analysis/tmp/fr_btn70b.py：双进程挂钩脚本
- analysis/tmp/click_protect70.py：教师按钮点击脚本

### 43.5 当前状态

- Student 在线（教师端在线学生 1，12:09:54 上线记录）；
- Smonitor 2736 运行；frida-server 恢复（50 进程可见）；
- 该关联实验可复用于“远程执行/远程重启/网址控制”等按钮（下一轮继续）。

## 第四十四轮：远程执行 / 远程重启 按钮帧关联与端到端验证

### 44.1 教师端状态与日志

教师端日志（截图 t71state.png）：
- 12:15:41 开启保护
- 12:15:45 关闭保护
- 12:18:16 远程执行: C:\Windows\System32\cmd.exe

### 44.2 远程执行帧（教师 → Student）

    13 80 00 00 00 52 21 15 52          ; type=0x13, len=0x80(128)
    0E 00 43 3A 5C 57 69 6E ... 00     ; 0x0E, sub 0x00, 后面是 NUL 结尾的命令行

本次执行的是教师端列表里遗留的命令（此前实验写入）：

    C:\Windows\System32\cmd.exe /c taskkill /f /im frida-server64.exe & start "" C:\Users\zzx\frida-server64.exe -l 0.0.0.0:27042

这解释了会话中 frida-server 多次被杀/重启的来源（不是软件默认行为，是教师端远程执行
列表里我们早前留下的自愈命令）。

### 44.3 远程重启帧与端到端验证

教师端点“远程重启”并确认后，Student 收到：

    13 04 00 00 00 52 21 15 52          ; type=0x13, len=4
    11 01 30 00                          ; 0x11, sub=0x01, 延时 "0", NUL

随后学生机立即进入重启（QMP 截图黑屏转圈，frida 连接被重置）。说明：
- 教师“远程重启”命令在协议里是 type 0x13 内嵌 0x11 子命令（sub=1、延时参数 "0"），
  与之前静态分析中 0x5833D0 分派 → 0x585404 restart 的链路一致；
- 上一轮我们拦截“0x0A 开头帧”是错误假设，实际重启帧首字节是 0x11，因此本次按计划
  作为真实验证执行了重启；
- 端到端链路：教师按钮 → 0x13/0x11 帧 → Student 分派 → 系统重启。

### 44.4 当前状态

- 学生机正在重启（12:19 左右开始），frida-server 随虚拟机重启丢失；
- 教师机 Teacher.exe 仍在运行；学生重启后需重新登录（ZZX/580356）并启动 Student；
- 之前“钩子 0x0A 拦截”脚本已废弃，正确拦截点应为 payload 首字节 0x11 且 sub=1。

### 44.5 产物

- analysis/tmp/btn71c.jsonl：远程重启帧（type 0x13 + 11 01 30 00）
- analysis/tmp/btn71b.jsonl：远程执行帧（0x0E + 命令行）
- analysis/tmp/t71state.png、analysis/tmp/s71reboot.png：教师对话框与学生重启画面
- analysis/tmp/fr_btn71b.py / fr_btn71c.py：抓帧钩子脚本

## 第四十五轮：远程重启后的恢复与自启观察

### 45.1 恢复过程

- 远程重启后约 30 秒回到锁屏；HMP sendkey 输入 ZZX/580356 登录；
- 登录完成后（12:20 左右）学生端窗口**自动出现**并显示“找到教师机: 192.168.50.1
  [默认教室]”，无需手动启动；
- 教师端日志同步记录：
  - 12:18:43 启用保护（本轮早些时候的按钮点击）
  - 12:19:08 学生端离线:DESKTOP-S7HAS2J [192.168.50.10]（重启）
  - 12:20:36 学生端上线:DESKTOP-S7HAS2J [192.168.50.10]（登录后自动重连）
  - 在线学生 1
- frida-server 通过 Win+R →（沿用队列中的命令）→ UAC 接受后恢复，可枚举 44 进程，
  Student.exe PID 2708。

### 45.2 关于“登录自启”的修正

第一次引导周期（12:02 登录）后 Student 没有自动出现，教师端一直离线，直到手动启动；
第二个周期（12:20 登录）后 Student 自动上线。说明 Smonitor 服务在登录时拉起 Student
存在时序/状态竞争，不能保证每次自启。此前“该版本没有登录自启项”的结论需要修正为：
- 无 Run/启动文件夹/计划任务项；
- 但 Smonitor 服务会在用户登录后尝试拉起 Student，是否成功取决于服务/互斥体状态。

### 45.3 网址控制按钮

点击“网址控制”后教师端未弹出对话框、Student 侧也未收到任何帧（btn72.jsonl 只有 ready）。
该按钮可能需要在学生列表右键菜单或先选中特定对象，留待下轮再试。

### 45.4 当前状态

- 学生机：已登录，Student 在线（PID 2708），frida-server 运行；
- 教师机：Teacher.exe 在线学生 1，日志与上表一致；
- 遗留风险：教师端“远程执行”列表里存有一条会先 taskkill frida-server 再重启它的命令，
  后续实验前应先通过“修改”清空该条参数，避免再次把 frida 打断。

### 45.5 产物

- analysis/tmp/s72desk.png、s72uac2.png：重启后登录与 UAC 画面
- analysis/tmp/t72state.png：教师端离线/上线日志
- analysis/tmp/fr_btn72.py、btn72.jsonl：本轮挂钩脚本与空结果

## 第四十六轮：学生端控制子菜单与重启/关机/开机命令

### 46.1 学生端控制子菜单（右键学生图标）

右键学生图标后“学生端控制”子菜单包含：
开启保护、关闭保护、重启学生端、关闭学生端、启用软件白名单、启用软件黑名单、
禁用软件控制、启用上网白名单、启用上网黑名单、禁用上网控制、设置日期时间。

这解释了工具栏“网址控制”按钮点击无反应：真正的上网控制入口在右键子菜单。

### 46.2 重启学生端

- 教师端确认框：你确定要重启[DESKTOP-S7HAS2J]吗
- 确认后 Student 收到帧：
  13 02 00 00 00 52 21 15 52   ; type=0x13 len=2
  13 00                         ; 0x13, sub=0x00 → 重启学生端（客户端进程）
- 学生端进程重启（PID 2708 → 9992 → 接受 UAC 后 1364），重启后再次弹 UAC；
- 教师端日志：12:23:47 学生端离线 → 12:24:16 学生端上线（在线学生 1，托盘提示上线）；
- 重启后的新 Student 实例向 Smonitor 发送 S 01（恢复保护状态）。

### 46.3 远程关机/重启/开机的命令差异

- 远程重启：13 04 00 00 00 52 21 15 52 + 11 01 30 00（0x11, sub=0x01, 延时 "0"）
- 远程关机：13 04 00 00 00 52 21 15 52 + 11 00 30 00（0x11, sub=0x00, 延时 "0"）
- 两者在钩子里把 payload 首字节 0x11 清零后，学生机既没有重启也没有关机（frida 进程数
  52→保持，客户端在线），验证了拦截点；
- 远程开机：不经过 TCP 命令帧，教师端提示“远程开机完成, 共执行了 1 台”，说明是 WOL
  网络唤醒（提示里列出 BIOS 需开启网卡唤醒、部分网卡需系统允许关机状态唤醒）。

### 46.4 当前状态

- 学生端在线（PID 1364），教师端在线学生 1；
- frida-server 存活，可直接枚举进程；
- 教师端远程执行列表里遗留的 taskkill frida 命令仍存在，后续避免点击“执行”。

### 46.5 产物

- analysis/tmp/t73sub.png、t73menu.png：子菜单与右键菜单
- analysis/tmp/btn73b.jsonl：重启学生端帧与 S 命令
- analysis/tmp/btn73.jsonl：关机帧（11 00 30 00）与被拦截记录
- analysis/tmp/t73after.png、t73online.png：离线/上线日志
## 第四十七轮：关闭学生端命令与恢复流程

### 47.1 关闭学生端

教师端右键 → 学生端控制 → 关闭学生端，确认框“你确定要关闭[DESKTOP-S7HAS2J]吗”，确认后：
- Student 收到帧：13 02 00 00 00 52 21 15 52 + 13 01（0x13, sub=0x01 → 关闭学生端）
- Student 向 Smonitor 发送 13 02 ... + 53 00（S 00，清除保护标志）
- 客户端进程退出；教师端日志 12:25:10 学生端离线，在线学生 0

与重启学生端（13 00，新实例发 S 01 恢复保护）正好相反：关闭走 13 01 + S 00。

### 47.2 恢复流程（已验证）

- frida attach explorer → CreateProcessA(Student.exe)，先探测 CreateMutex(Student.exe) 无残留；
- 弹出 UAC（提权所需），接受；
- 教师端日志 12:25:47 学生端上线，在线学生 1；Student PID 9016。

### 47.3 软件白名单/上网白名单的尝试

通过右键菜单点击与键盘导航（Down×10 → Right → Down×4 → Enter）尝试“启用软件白名单”，
没有产生新的 TCP 帧（btn74.jsonl 只有此前的 13 01 与 S 00）。键盘导航落在“开启保护”附近，
教师端弹出提示“学生端已保护”。子菜单点击坐标/键盘导航的精确位置需要下轮再用截图逐项校准。

### 47.4 当前状态

- 学生端在线（PID 9016），教师端在线学生 1，托盘提示上线；
- 保护标志为开（学生图标提示“学生端已保护”）；
- frida-server 存活；教师端远程执行列表仍存有 taskkill frida 的遗留命令。

### 47.5 产物

- analysis/tmp/btn74.jsonl：关闭学生端帧（13 01 + S 00）
- analysis/tmp/t74close.png：教师端离线日志 12:25:10
- analysis/tmp/t74online.png：恢复后上线日志 12:25:47
- analysis/tmp/nav_swl74.py：菜单键盘导航脚本
## 第四十八轮：软件控制与设置日期时间命令

### 48.1 软件控制系列（type 0x0C）

教师端右键 → 学生端控制下的软件相关项，抓到 Student 收到的帧（均为 9 字节头 + magic）：

- 软件黑名单（已有列表 powershell,cmd）：
  13 11 00 00 00 52 21 15 52
  0C 01 "powershell,cmd" 00
- 软件白名单（空表）：
  13 03 00 00 00 52 21 15 52
  0C 00 00
- 禁用软件控制/应用列表：
  13 22 00 00 00 52 21 15 52
  0C 02 "cmd.exe,powershell.exe,pwsh.exe" 00

每条命令之后 Student 都向 Smonitor 转发 Q + 用户配置路径（config 同步），Smonitor 分派器同步
收到 ECX=0x3F 的 Q 命令。说明软件控制在协议里是 type 0x0C + sub（0 白名单/1 黑名单/2 应用），
负载是逗号分隔的 exe 列表，随后触发配置下发。

### 48.2 设置日期时间（type 0x1A）

点“设置日期时间”后 Student 收到：
  13 03 00 00 00 52 21 15 52
  1A 02 00
随后同样触发 Q 配置同步。该命令与之前静态分析的 Smonitor X 命令（8 字节 TDateTime →
SetLocalTime）对应；本次教师端未填时间，参数为 0。

### 48.3 菜单状态观察

教师端右键子菜单中“启用软件黑名单”在切到白名单模式后变灰（disabled），说明软件控制是
白/黑名单二选一的模式切换；子菜单坐标会随状态轻微变化，后续点选需先截图确认高亮项。

### 48.4 当前状态

- 学生端在线（PID 9016），教师端在线学生 1，保护标志开；
- frida-server 存活；本轮抓帧钩子已停止。

### 48.5 产物

- analysis/tmp/btn75b.jsonl：0x0C 系列与 0x1A 命令帧
- analysis/tmp/t75menu.png：子菜单展开截图（含灰化状态）
- analysis/tmp/t75swbl.png、t75dt.png：教师端界面截图
## 第四十九轮：上网控制与设置日期时间命令

### 49.1 上网控制（type 0x1A）

教师端右键 → 学生端控制下的上网相关项，Student 收到的帧（9 字节头 + magic）：

- 启用上网白名单：13 03 00 00 00 52 21 15 52 + 1A 01 00
- 启用上网黑名单：13 03 00 00 00 52 21 15 52 + 1A 02 00
- 禁用上网控制：  13 03 00 00 00 52 21 15 52 + 1A 00 00

每条命令后 Student 都向 Smonitor 转发 Q + 用户配置路径（config 同步），Smonitor 分派器
收到 ECX=0x3F 的 Q。
注意：子菜单项会随当前模式变灰（选中白名单后黑名单项 disabled、反之亦然），点选坐标会
轻微漂移，本轮用“截图确认高亮项再点击”的方式逐项验证。

### 49.2 设置日期时间（type 0x27 + TDateTime）

菜单最后一项打开对话框（日期选择器 + 时间选择器，默认 2026/11/01 12:29:29）。
点确认后 Student 收到：

  13 0A 00 00 00 52 21 15 52
  27 00 5F 37 BA A7 F0 9E E6 40

负载 = type 0x27、sub 0x00，后接 8 字节 little-endian double，解码为 46327.520474537036，
按 Delphi TDateTime（1899-12-30 起的天数）换算正好是 2026-11-01 12:29:29，与对话框里
选择的日期时间完全一致。
这与之前静态/仿真结论（Smonitor X 命令：8 字节 TDateTime → lib!SetDateTime → SetLocalTime）
对应，说明教师端“设置日期时间”链路是：教师对话框 → Student 0x27 帧 → Student 转 X 给
Smonitor 执行 SetLocalTime。

### 49.3 当前状态

- 学生端在线，教师端在线学生 1；保护标志开；
- 学生机时间被同步为 2026-11-01 12:29:29（与虚拟机宿主时间一致）；
- frida-server 存活；本轮抓帧钩子已停止。

### 49.4 产物

- analysis/tmp/btn76.jsonl：0x1A 系列、0x27 日期时间帧与 Q 同步记录
- analysis/tmp/t76menu.png、t76menu2.png：子菜单状态（含灰化切换）
- analysis/tmp/t76dt.png、t76dt3.png、s76clock.png：日期时间对话框与确认后状态
- analysis/tmp/decode_dt76.py：TDateTime 解码验证脚本
## 第五十轮：清理教师端远程执行遗留命令与输入通道修正

### 50.1 背景

教师端“远程执行”列表里的 cmd.exe 条目存着早前实验留下的一条命令：
  C:\Windows\System32\cmd.exe /c taskkill /f /im frida-server64.exe & start "" C:\Users\zzx\frida-server64.exe -l 0.0.0.0:27042
每次误点“执行”都会杀掉学生机的 frida-server（本会话多次 frida 失联的来源）。

### 50.2 清理过程

- 打开远程执行 → 选中 cmd.exe 条目 → *修改，弹出“添加/修改 程序”对话框（程序名称/程序路径两栏）；
- 清空程序路径后点确定，提示“请输入程序路径”（程序路径不允许为空）；
- 重新输入 `C:\Windows\System32\cmd.exe` 并确定。
- 结果：程序路径字段不再包含 taskkill 命令（最终存成 `C:WindowsSystem32cmd.exe`，反斜杠被
  QEMU sendkey 在编辑框中吞掉，路径无效但无害，不会再杀 frida-server）。

### 50.3 过程中发现的输入通道问题

- analysis/tmp/hmptype.py 默认连接学生机 monitor（QEMU_MON 默认 vm/win10-22h2/monitor.sock）；
  对教师 VM 打字必须显式设置 QEMU_MON=vm/win10-teacher-22h2/monitor.sock，否则按键会发到
  学生机（本轮前几次输入即如此，未造成影响）；
- QEMU HMP sendkey 的 backslash 在 Delphi 编辑框中未生效，导致路径反斜杠丢失；需要精确文本时
  可改用 VNC 直接输入或分字符确认。

### 50.4 当前状态

- 学生端在线（教师端在线学生 1）；frida-server 存活；
- 教师端远程执行列表已不含 taskkill frida-server 命令（遗留风险消除）。

### 50.5 产物

- analysis/tmp/t77rexec.png、t77mod.png、t77mod4.png、t77mod5.png：修改前后对话框
- analysis/tmp/typepath77b.py：带 QEMU_MON 的教师端输入脚本
## 第五十一轮：发送消息命令与课堂控制按钮的空结果

### 51.1 发送消息（type 0x12）

教师端点“发送消息”打开消息窗口（Tahoma 12 号、指定学生 DESKTOP-S7HAS2J），输入文本发送后
Student 收到：

  13 41 00 00 00 52 21 15 52          ; type=0x13, len=0x41(65)
  12 00 "hellofromteacher78" 00 "Tahoma" 00 ... 0C 00 00 00 ...

负载结构：type 0x12、sub 0x00、NUL 结尾的消息正文、NUL 结尾的字体名 "Tahoma"、填充、
末尾 4 字节字号 0x0C(12)。学生端同时弹出“发送消息”窗口显示该文本。

说明：本轮用 HMP sendkey 输入，空格键（spc）在富文本框中未生效，正文里的空格被吞掉，
消息变成 hellofromteacher78；如果用 VNC 直接输入可以保留空格。

### 51.2 黑屏静默/取消黑屏

点击“黑屏静默”后 Student 未收到任何帧，学生机屏幕也没有变黑；教师端界面无变化。
推测该功能需要先进入“屏幕广播/上课”状态，或在独立通道/独立连接上执行，不在
当前 TCP 命令流里（本轮钩子覆盖 ws2_32 recv/send 全进程，仍未捕获）。

### 51.3 当前状态

- 学生端在线，教师端在线学生 1；学生端弹出了消息窗口（可手动关闭）；
- frida-server 存活；抓帧钩子已停止。

### 51.4 产物

- analysis/tmp/btn78.jsonl：发送消息帧（0x12 + 文本 + Tahoma + 字号）
- analysis/tmp/t78msg.png、s78msg.png：教师发送窗口与学生端消息窗口
## 第五十二轮：任务管理器秒关的活体复现与控制实验

### 52.1 保护开启时：Student 亲自杀 taskmgr

学生机保护开启状态下，在学生机按 Ctrl+Shift+Esc 打开任务管理器，1~2 秒内被终止。
同时在 Student(9016) 与 Smonitor(2924) 里挂钩 OpenProcess/TerminateProcess/NtTerminateProcess，
并用 handle→pid 映射表解析目标进程：

  student: TerminateProcess handle=0x5d0 target=7704 code=0
  student: NtTerminateProcess handle=0x5d0 target=7704 status=0
  student: TerminateProcess handle=0x684 target=2068 code=0
  student: NtTerminateProcess handle=0x684 target=2068 status=0

即“秒关任务管理器”是 **Student.exe 自己**执行的：OpenProcess(目标 pid) 后 TerminateProcess(handle,0)。
Smonitor 侧没有对应的终止记录（此前归因 Smonitor 不准确，Smonitor 主要负责保护标志/配置）。

另外观察 Student 的保护循环会周期性枚举全部进程（一轮 40 秒内记录到约 1.8 万次
OpenProcess(access=0x400 PROCESS_QUERY_INFORMATION) 调用），属于“扫进程→匹配名字→杀掉”的看护逻辑。

### 52.2 控制实验：关闭保护后 taskmgr 存活

- 教师端先关闭“发送消息”窗口（它会挡住工具栏按钮），再点“关闭保护”；
- 学生机 Ctrl+Shift+Esc 打开任务管理器后进程列表可见：Taskmgr.exe PID 772 持续存活；
- Student 钩子不再出现新的 Terminate 事件。

结论：任务管理器秒关由保护状态（教师端“开启保护”，Student 向 Smonitor 发 S 1/0 的同一套状态）
控制；关闭保护后不再杀 taskmgr。这回答了“任务管理器/性能监视器清理能不能解开”的问题：
教师端关闭保护即可恢复 taskmgr 使用（但教师会看到该学生被标记为未保护）。

### 52.3 过程教训

- 教师端发送消息窗口是模态的，会覆盖工具栏；后续点工具栏按钮前先关闭它，否则点击被吞
  （本轮第一次“关闭保护”实际点到了消息窗口上）；
- 学生机 Ctrl+Shift+Esc 是可靠的本地开 taskmgr 方式；从 explorer 用 CreateProcessA 启动
  taskmgr 会失败（需要提权）。

### 52.4 当前状态

- 学生端在线，教师端在线学生 1；保护已关闭（教师端点击关闭保护）；
- 学生机 Taskmgr.exe 仍开着（PID 772），可用于继续观察；
- frida-server 存活；本轮钩子脚本已结束。

### 52.5 产物

- analysis/tmp/fr_kill79d.py、kill_trace79d.jsonl：OpenProcess/Terminate 追踪（含 handle→pid 映射）
- analysis/tmp/kill_trace79c.jsonl：Protection 扫描期间约 1.8 万次 OpenProcess 记录
- analysis/tmp/t79off.png、s79off.png：保护关闭后状态
## 第五十三轮：客户端被杀后自动重启（保护开启时）

### 53.1 对照实验

- 保护关闭状态：kill Student(9016) 后 5s/15s 均无新 Student 进程（本轮早些时候验证）；
- 保护开启状态（教师端 12:35:50 启用保护）：kill Student(6200) 后，**3 秒内**出现新
  Student.exe（PID 10164），并持续存活超过 30 秒；教师端 12:36:01 记录离线、
  12:38:07 记录学生端上线（重新连接教师机约 2 分钟）。

结论：自动重启与保护状态绑定——关闭保护时客户端被杀就消失；开启保护时会被看护进程拉起。
这回答了用户“突然结束学生端进程后自动重启”的问题。

### 53.2 重启者的初步排查

- 在 Smonitor(2924) 里挂钩 CreateProcessA/CreateProcessW，杀 Student 前后**没有任何**
  CreateProcess 事件——说明重启不是通过这两个 API 发起的；
- 可能路径：CreateProcessAsUserW / CreateProcessWithTokenW / ShellExecute / WinExec，
  或由 Smsvc 服务通过其他机制（如服务恢复/计划任务）触发；
- 尝试用 wmic 查询 Student 的 ParentProcessId 失败（中文系统 wmic 别名谓词报错），
  下轮改用 PowerShell Get-CimInstance 查询父进程。

### 53.3 当前状态

- Student 在线（PID 10164），教师端在线学生 1，保护开启；
- Smonitor PID 2924 运行；frida-server 存活；
- 本轮钩子脚本已结束。

### 53.4 产物

- analysis/tmp/smon_cp80.log：kill→重启时间线（3s 内 10164）
- analysis/tmp/smon_cp80.jsonl：Smonitor CreateProcess 钩子（无事件）
- analysis/tmp/t80now.png：教师端离线/上线日志（12:36:01 / 12:38:07）
## 第五十四轮：自动重启的执行者 = Smonitor（CreateProcessAsUserA）

### 54.1 钩子证据

在 Smonitor(2924) 里同时挂钩 CreateProcessAsUserA/W、CreateProcessWithTokenW/LogonW、
ShellExecuteA/W、WinExec、NtCreateUserProcess，然后 kill Student，捕获到：

  CreateProcessAsUserA cmd = C:\Program Files (x86)\gakataka\Student\Student.exe
  NtCreateUserProcess ptr = 0x19f2fc（内部实现）

随后 1 秒内出现新 Student（PID 7736）。即保护开启时，**Smonitor 服务会把被杀掉的
Student 重新拉起**。

### 54.2 父进程确认（PowerShell Get-CimInstance）

  Student 7736: ParentProcessId = 2924 (Smonitor), CreationDate = 2026/11/1 13:06:18,
                CommandLine = "C:\Program Files (x86)\gakataka\Student\Student.exe"
  Smonitor 2924: ParentProcessId = 716 (services.exe)

与钩子结果一致：重启由 Smonitor 发起，且用 CreateProcessAsUser 以用户令牌创建（这正好
解释此前 4688 审计里 Smonitor 创建受限令牌 Student、Student 再自提升弹 UAC 的现象）。

### 54.3 结论

“学生端被杀后自动重启”的完整链路：
- 保护开启（S 1）：Smonitor 持续看护 Student；进程消失后 1~3 秒内用 CreateProcessAsUserA
  重新拉起；重连教师机需要额外几秒到两分钟；
- 保护关闭（S 0）：不重启，Student 被杀即消失。

### 54.4 当前状态

- Student 在线（PID 7736，父进程 Smonitor 2924），教师端在线学生 1，保护开启；
- frida-server 存活；钩子脚本已结束。

### 54.5 产物

- analysis/tmp/restarter82.jsonl：CreateProcessAsUserA/NtCreateUserProcess 事件
- analysis/tmp/restarter82.log：kill 后 8 秒内的进程时间线
- analysis/tmp/parent82.py + 输出：Student 父进程 = Smonitor(2924)（CIM 查询）
## 第五十五轮：打开 cmd/PowerShell 是否触发重启的验证

### 55.1 实验

在 Student(7736) 里挂钩关机相关 API：InitiateSystemShutdownExW/A、InitiateSystemShutdownW、
InitiateShutdownW、NtShutdownSystem、NtSetSystemPowerState，以及 WinExec、CreateProcessA/W；
随后通过 explorer 的 CreateProcessA 启动 cmd.exe（多次尝试，含 cmd /k、cmd /c ping 长命令）、
并用 frida spawn cmd 等方式启动，观察 1 分钟。

### 55.2 结果

- 钩子记录：没有任何 InitiateSystemShutdown/InitiateShutdown/NtShutdownSystem/NtSetSystemPowerState
  事件，也没有 WinExec/CreateProcess 的异常调用；
- 学生机没有重启（QMP 画面保持桌面，时间连续），教师端在线状态不变；
- 启动的 cmd 进程未能稳定存活（tasklist 对照里只看到 tasklist 自己的 cmd），但本轮的进程
  检查受 frida enumerate 不可靠与 tasklist 自身 cmd 干扰，cmd 是否被保护逻辑秒杀尚未定论。

结论：在本实验环境（该版本 + 当前配置）中，打开 cmd/PowerShell **不会触发重启**；用户描述的
“开 cmd 就重启”属于学校环境特有配置/行为，可能与教师端策略或另一套保护配置有关，本机未复现。

### 55.3 对照组

- 保护状态在 13:06:48 离线、13:07:46 上线后，教师端 13:09:25 已关闭保护；
- 关闭保护后 taskmgr 可以存活（第五十二轮已证），说明保护关闭确实不再杀进程；
- cmd 的启动/存活判定需要更可靠的启动方式（如学生机开始菜单或 taskmgr 的“运行新任务”），
  下轮改进。

### 55.4 当前状态

- Student 在线（PID 7736），教师端在线学生 1；保护已关闭（13:09:25）；
- frida-server 存活；钩子脚本已结束。

### 55.5 产物

- analysis/tmp/fr_cmdreboot83.py、cmdreboot83.jsonl：关机 API 钩子（无事件）
- analysis/tmp/fr_cmdkill83b.py、cmdkill83b.jsonl：Student/Smonitor 终止追踪
- analysis/tmp/cmd_gt83b.py、t83log.png：cmd 存活对照与教师日志（13:09:25 关闭保护）
## 第五十六轮：cmd/PowerShell 在保护开启下的存活验证（结论修正）

### 56.1 可靠启动方式

前几轮“cmd 秒退”的结论来自不可靠测量（frida get_process 不可靠；tasklist 自身以 cmd.exe 运行，
会污染统计）。本轮改用学生机真实用户路径：VNC 点开始菜单 → HMP 逐键输入 cmd → 回车。

### 56.2 实验结果

- 保护关闭时打开 cmd：命令提示符窗口正常出现并持续存活；
- 教师端 13:11:37 重新启用保护后：
  - 已打开的 cmd 窗口**没有**被关闭；
  - 通过开始菜单再打开一个新的 cmd，同样存活（截图中同时存在两个命令提示符窗口）；
  - 学生机没有重启，教师端在线状态不变；关机相关 API 钩子（前一轮）无任何事件。

### 56.3 结论修正

- 本版本/本配置下，保护机制**不杀 cmd/PowerShell**，两者也不触发重启；
- 保护专门针对 taskmgr（第五十二轮：保护开启时 Student 自己 OpenProcess+TerminateProcess 杀掉
  taskmgr，关闭保护后可存活）；
- 用户描述的“开 cmd 就重启”应是学校环境特有配置/策略（可能来自教师端“学生端控制”里的策略、
  另一套保护配置或第三方脚本），在本地环境未复现。

### 56.4 当前状态

- 学生端在线（PID 7736），教师端在线学生 1；保护开启（13:11:37）；
- 两个 cmd 窗口已通过输入 exit 关闭；frida-server 存活。

### 56.5 产物

- analysis/tmp/s84cmd2.png、s84cmd5.png：保护开启下的两个 cmd 窗口
- analysis/tmp/t84log.png：教师日志（13:09:25 关闭保护 / 13:11:37 启用保护）
- analysis/tmp/start_cmd 相关脚本：analysis/tmp/startmenu_cmd84.py、press_enter84.py
## 第五十七轮：上网出口/网关控制的可观测性尝试

### 57.1 学生机网络现状（ipconfig，GBK 解码）

- 以太网适配器 以太网 2（实验网）：IPv4 192.168.50.10、169.254.83.100，**默认网关为空**；
- 以太网适配器 以太网（QEMU NAT）：IPv4 10.0.2.15，默认网关 fe80::2%9（IPv6）；
- 实验网段没有 IPv4 默认网关，因此“禁用网关/上网出口”在当前环境无法通过网关值变化观察。

### 57.2 教师端“禁用网关/启用网关”点击

- 点击前后 ipconfig 的网关字段完全一致（实验网本来无 IPv4 网关）；
- 在 Student 里挂钩 ws2_32 recv/send 后点击这两个按钮，没有捕获到任何 TCP 帧；
- 说明这两个按钮可能：(a) 需要先选中特定网络适配器/在“系统设置”对话框里配置；
  (b) 走教师端本地或 WMI/服务通道；(c) 我们点击的坐标命中了别的按钮。

### 57.3 结论与限制

“控制学生机上网出口能否强行解除”在本隔离实验网络下无法直接验证：实验网无默认网关、
学生机上网走 QEMU NAT（10.0.2.15），而网关控制大概率针对实验网/校园网适配器。
要验证需要：给实验网配置可路由网关，或直接观察 Student/Smonitor 对 WMI
Win32_NetworkAdapterConfiguration.SetGateways 的调用（此前静态分析已确认 Smonitor 有 SetGate 逻辑）。

### 57.4 当前状态

- 学生端在线（PID 7736），教师端在线学生 1；保护开启；frida-server 存活；
- 网关读取/点击脚本与钩子已结束。

### 57.5 产物

- analysis/tmp/gate85b.py、gate85after.py：ipconfig GBK 解码读取
- analysis/tmp/gateoff85.py、click_gate85.py：教师端按钮点击
- analysis/tmp/fr_gate85.py、gate85.jsonl：Student 收包钩子（无事件）
## 第五十八轮：向 Smonitor 命令通道直接注入 U 命令（失败）

### 58.1 目标

绕过教师端，直接在学生机本地向 Smonitor 的命令通道发送 U 命令（禁用 U 盘存储），
验证是否能强行改变保护状态。

### 58.2 通道与帧格式

- netstat 显示 Smonitor(2924) 监听 0.0.0.0:49671（端口每个实例动态变化）；
- 按之前抓到的 Student→Smonitor 帧格式构造：
  9 字节头 = 0x13 + len(u32 LE) + magic 52 21 15 52，随后是 payload（字母+参数）。

### 58.3 注入尝试

从 explorer 进程建立 TCP 连接并发送以下帧（每帧发送后读 UsbStor Start）：

  payload b'U\\x00'、b'U\\x01'、b'U0'、b'U1'、b'U'、b'S\\x01'

结果：连接成功、send 返回 11/10 字节，但 UsbStor Start 始终为 3（未变化），
说明 Smonitor 没有执行这些命令。

### 58.4 分析

Smonitor 分发器 0x4589F8 只在 Student 正常转发时被调用（此前多轮抓帧已验证）；
直接 TCP 注入未触发，可能原因：
- 只接受来自 Student 进程（或特定源端口/进程校验）的连接；
- 连接后需要额外握手/会话标识（如 PipeStudent 管道名、进程校验）；
- 帧格式还有未捕获的字段（如校验和/序列号）。
下一步可在 Student 里挂钩 send 捕获其真实 socket 句柄，用 Student 自己的 socket 注入，
或静态分析 Smonitor 的 accept/read 循环做协议还原。

### 58.5 当前状态

- 学生端在线（PID 7736），教师端在线学生 1；保护开启；UsbStor Start=3；
- frida-server 存活。

### 58.6 产物

- analysis/tmp/port86.py：Smonitor 动态端口探测
- analysis/tmp/inject86.py：帧构造与 TCP 注入（U/S 命令）
## 第五十九轮：USB 存储与访客账户“强行解开”的持久性验证

### 59.1 Student socket 注入（失败）

捕获 Student→Smonitor 的连接：socket 句柄 1268，peer 端口 49671（与 Smonitor 监听端口一致）。
在 Student 进程内用 WSASend 向该 socket 注入 U\\x00/U\\x01 帧，返回 r=-1、sent=0，
UsbStor Start 未变化。说明直接调用 WSASend 方式不可行（可能需要套接字阻塞/overlapped 参数，
或需从 Student 的真实发送路径插入）。

### 59.2 禁用 U 盘存储能否手动解开（管理员权限）

在保护开启状态下，用管理员命令改 UsbStor 服务 Start 值：

  reg add HKLM\SYSTEM\CurrentControlSet\Services\usbstor /v Start /t REG_DWORD /d 4 /f  （禁用）
  reg add HKLM\SYSTEM\CurrentControlSet\Services\usbstor /v Start /t REG_DWORD /d 3 /f  （启用）

结果：
- initial Start = 3；
- 改为 4 后读取 = 4；
- 改回 3 后立即读取 = 3；5 秒后 = 3；20 秒后 = 3（保护开启状态下没有被改回 4）。

结论：**禁用 U 盘存储可以手动解开**（管理员权限改注册表 Start=3，且不会被实时改回）；
但教师端再次下发“禁用 USB”命令（U0）时会重新设为 4。同理 Smonitor 的 U 命令只在执行时生效，
不是持续强制。

### 59.3 禁用访客账户能否解开

当前 `net user Guest` 显示“帐户启用 = Yes”（此前用管理员命令启用），保护开启状态下保持 Yes，
没有被自动改回 No。结合早前验证（DisableGuest → No、EnableGuest → Yes），说明访客账户禁用
同样可以用管理员命令 `net user Guest /active:yes` 解开，保护不会持续强制。

### 59.4 当前状态

- 学生端在线（PID 7736），教师端在线学生 1；保护开启；
- UsbStor Start=3（启用），Guest 帐户 Yes；frida-server 存活。

### 59.5 产物

- analysis/tmp/sock87b.py：Student→Smonitor socket 句柄捕获
- analysis/tmp/inject87.py：WSASend 注入尝试（失败）
- analysis/tmp/usb_unlock87.py：USB Start 4→3 持久性测试
- analysis/tmp/guest_unlock87.py：Guest 账户状态查询