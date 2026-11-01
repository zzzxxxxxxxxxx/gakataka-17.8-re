# 逆向状态总结

## text0

- 指令清单：53718 条（v6，引用不动点后），字节覆盖 85.60%；
- 函数级反编译：约 1523 个入口（rizin 表 1205 + 候选起点 318），输出见 artifacts/；
- 未覆盖 14.4% 字节判定为数据（熵 4.82、无指针表、引用重试解码失败、在线内存无批量解密）。

## text1

- 原始文件中唯一带磁盘原始数据的段（raw 0x1200，大小 0x4AE00）；
- 高熵 7.95，含明文 Delphi 字符串与明文跳板，无标准压缩/加密头；
- 判定为打包器载荷，非可执行代码；编码算法未识别。

## 仓库

- deob-repo/：docs（分析文档）、artifacts（清单/反编译/函数表/状态）、scripts（分析脚本）；
- 提交历史记录了覆盖扩展过程（61.79% → 85.60%）。

## 复现

- 反编译：rizin + rz-ghidra（见 README）；
- 动态：Unicorn 仿真（scripts/text01_dyn*.py）、frida 探测（scripts/stalker_smon*.py、text1_live_*.py）；
- 覆盖统计：scripts/text01_union_v*.py。