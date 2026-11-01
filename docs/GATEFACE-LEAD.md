# 学校“违规即重启”的下一层线索：GateFace 组件（2026-10-31 18:25）

## 结论先行

电子教室学生端（Student.exe + lib.dll + Smsvc）在本机同版本上无法本地触发重启；
但同一个安装包还装了整套 **GateFace 门面/公共机房组件**（C:/Users/Public/gakataka/gateface），
它明确包含 protect/violation/USB/policy/restart 逻辑，并带本地数据库与 policy_cache。
学校“打开 CMD/PowerShell、反复杀 Student、插 U 盘都会重启”的行为特征，和这一层的策略式违规处理吻合。

## 证据（来自 analysis/offline-disk/extracted 的安装副本）

| 文件 | 关键字符串计数 |
|---|---|
| dllgftts.dll | Violat 42、Policy 59、Protect 35、USB 9、Reboot 1、ShutDown 6 |
| GFServer.exe | Violat 14、usb 12、Restart 5、ShutDown 1 |
| GFWebServer.exe | Violat 12、usb 12、Restart 4、shutdown 5 |
| StudentManager.exe | Violat 12、Protect 11、shutdown 7、policy_cache |
| Gateface.exe | Violat 12、Protect 9、Restart 4、policy_cache |
| dllstudent.dll | Violat 10、restart 2、shutdown 2 |
| lib.dll（gateface 版） | Usb 2、Protect 1 |

- GateFace 数据目录：GateFace/Data/pool.db（Microsoft Access，非 SQLite）、Data/main.db（SQLite，仅用户表）、Card/Config/Layout。
- 电子教室里的“禁用USB”策略只能通过 lib.dll 导出 DisableUsbStore/EnableUsbStore 设置 USBSTOR，本身不带重启动作；
  这与学校“插入 U 盘立即重启”不是同一路径。

## 尚未证实

- 学校机器实际运行的是哪一层：电子教室学生端、GateFace 门面、还是两者同时（需要现场进程/服务/启动项确认）。
- 重启动作的配置项名称与存放位置（Access 库或 policy_cache），需要学校的 Config/Data 文件才能解出。
- 本机安装是“电子教室模式”，GateFace 未激活（只有 Smsvc 服务与路径注册表值），因此无法直接复现。

## 现场只需做文件/进程检查（无需抓包或调试）

在获得授权的学校终端上，管理员可只读确认：

1. 任务管理器/进程列表里是否有 Gateface.exe、StudentManager.exe、GFServer.exe、GFWebServer.exe、Browser.exe；
2. 服务列表里除 Smsvc 外是否还有 GateFace 相关服务；计划任务/启动项是否指向 C:/Users/Public/gakataka/gateface；
3. 该目录下 Data/pool.db、Config 与 Layout 的文件时间与大小（可复制出来分析）；
4. 电子教室的 config/config.cfg 全文。

把这些文件带回离线分析，就可以定位“违规→重启”的具体策略行，并给出对应的处置点。
