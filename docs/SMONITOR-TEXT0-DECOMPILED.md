# Smonitor .text0 全函数反编译（rizin + rz-ghidra 批量）

## 方法

- rizin 0.8.2 + rz-ghidra 插件（pdg）；
- aaa 全量分析得到函数表（analysis/tmp/rizin_aflj.json：全镜像 3602 个函数，text0 内 1213 个）；
- 批量模式：每个地址执行 s addr; af; pdg（不重复 aaa，约 3 个函数/秒）；
- text0 全部 1213 个函数分 16 批反编译，输出 1.8 MB C 伪代码。

## 关于“8 个失败函数”的核查结论

之前批次统计里的 8 个“失败”是统计口径问题，不是 pdg 失败。逐个地址复核（带标记的批量运行）结果：

- 共享会话模式（af + pdg，100 地址/批）：1213 个地址没有 fail，924 个精确匹配，289 个地址被解析为相邻/包含函数；
- 单会话 aaa 后 pdg @ addr 模式：1038 个精确匹配，175 个解析为包含该地址的函数，0 个 fail。

即：所有 1213 个函数入口都产出了可读的 C 代码；289/175 个地址是因为 rizin 函数表存在重叠
（同一段代码被多次识别为函数），pdg 选择了包含该地址的另一个函数。逐地址状态见
analysis/tmp/pdg_status.json 与 analysis/tmp/pdg_aaa_status.json，原始输出见 analysis/tmp/pdg_aaa_out.txt。

## 产物

- analysis/SMONITOR-TEXT0-DECOMPILED-FULL.txt：全量 pdg 反编译输出（约 1.8 MB）
- analysis/SMONITOR-TEXT01-INSN-FULL.txt：并集指令清单（13413 条）
- analysis/tmp/rizin_aflj.json：rizin 函数表
- analysis/tmp/pdg_status.json、pdg_aaa_status.json、pdg_aaa_out.txt：逐函数状态与 aaa 会话原始输出

## 覆盖与限制

- text0 字节覆盖 66.26%（并集）；
- pdg 输出普遍带 unaff_* 与栈帧警告，源于 pushal/pushfd/ret imm 跳板；
- 未覆盖的 text0 字节无函数入口，按数据/VM 载荷处理。
## 候选起点扩展（第 3 轮补充）

- 从 text0 已解码但不在 rizin 函数表中的地址里，按间隔 >=0x80 取候选函数起点 384 个；
- 批量 `s addr; af; pdg`：318 个成功成为独立函数并产出 C 代码，49 个被解析为包含函数，17 个失败；
- 输出：analysis/SMONITOR-TEXT0-CAND-FUNCS.txt（724 KB，318 个新函数）；
- 加上此前 rizin 表的 1205 个函数，text0 函数级反编译累计约 1523 个入口。

备注：候选起点来自静态遍历结果，函数边界由 rizin af 估计，未逐一验证语义。