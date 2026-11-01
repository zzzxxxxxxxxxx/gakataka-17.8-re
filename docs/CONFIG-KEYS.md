# 配置键分析（2026-10-31）

## lab 当前 config.cfg（20 个键）

    md, ms, mt, ar, pi, pa, fn, pt, ps, fs, fc, bd, it, ul, mm, po, stc, stcw, iec, iecw

## 已确认/高置信语义

- md  机器码（32 位十六进制），客户端身份标识
- ms  布尔；非 0 时把内部字符串“未知”写给某全局（推测：隐藏/匿名显示名）
- mt  本地监控端口：Smonitor 启动时随机选端口并写回；Student 按它连接 127.0.0.1
- ar  自动重启开关：T 命令会持久化它；Smsvc 在 ar=1 时拉起被杀的 Student
- pi / pa  加密的教师机地址信息（pi 更像 IP，pa 更像端口/口令字段；无教师环境无法比对）
- fn / fs / fc / bd / it / ul  桌面文字字体：名称/大小/颜色/粗体/斜体/下划线
- pt  教师端端口（默认 230）
- stc 窗口关键字策略模式（实测 2 会关闭命中窗口；0/1/3 未观察到动作）
- stcw 加密的窗口关键字表（运行期解码后用于 CloseWindowCN，例如 #32770 / 任务视图 / Internet 协议属性）
- iec / iecw  IE/网络相关策略开关与关键字表
- ps / po / mm  lab 中为 0/1 的小策略位，具体行为尚未定位

## 代码里存在的完整键集（比 lab 配置多得多）

Student 的保存函数（0x561f0c 一带）会写出 90 多个键，除上面 20 个外还包括：

    rs, pd（教师机 IP 设置，lab 没有）
    chkim, chkvm（输入法/虚拟机检测；反虚拟机提示“禁止学生端在虚拟机环境运行”）
    lock, lockk, black, sdown, resme, smenu, tool（锁定/黑屏/关机/重启/开始菜单/工具栏类）
    proc, pros, prop（进程相关）
    video, audio, vids, vdos, vqaty, cqaty, share, mode, gt, gate
    arecd, brecd, btext, cmsg, cname, dname, fname, fbold, fital, funli, fcolor
    patc, patf, patg, pats, paths, pass, pset, port, pos1-4, nums, rows, cols, color
    time2, times, atime, stime, ftime, wtime, ssize, fsize, fast, autor, bhide, lockk 等

注意：这些额外的键在 Student/Smonitor 里只找到“写”的引用，没有找到按名字“读”的路径；
它们大概率是给教师端/管理工具或旧版本用的字段，学校机器多出来的行不一定改变 Student 行为。

## 本地重启/关机的真实实现

- 分派器：Student 0x5833d0，报文结构里 [esi+4] 是消息类型（0..10）。
- 类型 10 的子命令表（首字节 - 0x0b，取值 0x0b..0x28）中：
  - 子命令 0x11 -> 0x584015
    - 从报文读倒计时秒数，写入全局 [0x5928f0]
    - [报文+1] == 0：调 0x585370（关机流程：确认框“确定要关机吗” -> “%d 秒后将关闭电脑”）
    - [报文+1] != 0：调 0x585404（重启流程：确认框“确定要重启电脑吗” -> “%d 秒后将重启电脑”）
    - 两个流程最终都调 0x5854a4 执行器（参数 1=重启，2=关机）
- 也就是说：重启是“网络报文触发的本地动作”，不是 lib!ShutWindow 的独立路径。

## 待办

- 确认离线时谁给 Student 发 type=10/子命令 0x11 的报文（候选：Smonitor 走本地 TCP 回发）。
  可通过本地代理向 Student 方向注入构造报文验证。
