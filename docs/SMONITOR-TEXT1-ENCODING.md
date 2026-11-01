# Smonitor .text1 编码格式分析

## 结论（先给判断）

text1 不是标准压缩流、不是可执行代码、也不是单一加密流；它是**打包器/混淆器载荷**：
大量高熵字节中保留明文 Delphi/Windows 字符串与明文跳板桩，运行期只做小字节补丁，未观察到整页解密。
具体编码算法（压缩或加密方案）未识别，无标准头、无可检测的周期密钥、无有效 PE/DFM 结构。

## 证据

### 1. 它是原始文件里唯一带磁盘数据的段

原始 Smonitor.exe（analysis/tmp/Smonitor-packed.exe，311,808 字节，与磁盘提取版、学生端版本 md5 一致）：

- CODE/DATA/.idata/.text0 等段的 SizeOfRawData 均为 0（磁盘上无数据）；
- .text1 raw 指针 0x1200、raw 大小 0x4AE00（307,200 字节），是文件里唯一的大块原始数据；
- 文件布局：0x400 头 + 0xE00 + 307200 字节载荷 + 0x200 reloc。

### 2. 内存 text1 等于磁盘载荷，仅少量运行期补丁

- stage2 内存转储的 text1 与原始 .text1 载荷逐字节比较：99.99% 相同；
- text1 在内存中还有第二份拷贝（0x54F000 起，位于第二个 .reloc 段内），与 text1 相差 40 字节，
  分成 12 组 3 字节差异，形态与运行期跳板打桩一致；
- frida 读取当前进程内存逐页校验和：75 页中 8 页与磁盘载荷不同，每页仅 1~15 字节差异，
  页熵/可打印率基本不变，说明只是补丁而不是解密。

### 3. 内容特征

| 指标 | 值 |
|---|---|
| 大小 | 307,200 字节 |
| 熵 | 7.947（接近随机上界 8） |
| 可打印字符比例 | 41.5% |
| ASCII 串 >=8 字符 | 151 条（随机期望约 68 条） |
| 0 字节比例 | 1.1% |
| 指针样 dword | 0.2% |
| 有效 PE 头 | 无（0x4A8E55 处 MZ 不是有效 PE） |
| TPF0（Delphi DFM） | 0 处 |
| zlib/gzip/xz/zstd/bz2 魔数 | 无；直接解压尝试全部失败 |
| 单字节 XOR/ADD/SUB 变换 | 无提升（最高可打印率 0.443） |
| 周期 <=64 的重复密钥 | 无（按余数分组熵均在 7.90+） |
| base64 字符集比例 | 0.296（不是 base64 文本） |

明文串样例：

    The procedure entry point %s could not be located in the dynamic link library %s
    The ordinal %u could not be located in the dynamic link library %s
    ImageList_SetIconSize

### 4. 代码样结构混在高熵区中

- text1 内部有 867 处 E8/E9 相对目标落在 text1 范围内（随机期望约 0.2 处）；
- 反汇编这些目标，能看到明确的混淆跳板代码，例如 0x4C5C54：

      push 0x23deed22
      pushfd
      pushfd
      mov dword ptr [esp + 8], eax
      push edi
      mov byte ptr [esp + 4], al
      jmp 0x4c6c4c

- 同一区域的普通地址（如 0x47C06E）则解出 call 后跟乱码，说明明文跳板/字符串与高熵数据交织。

### 5. 与“按需解密”现象的关系

- 之前确认 text1 不参与命令分发路径（Q/R/S/T/U/V/W/X 执行 text1 指令数为 0）；
- 现在看 text1 更像“待解包载荷 + 明文跳板/字符串”，解包动作发生在进程启动阶段（我们已拿到解包后的
  CODE/.text0 内存镜像），因此运行期 text1 本身不会再被整体改写，只留下补丁痕迹。

## 未解的问题

- 载荷的压缩/加密算法未识别：没有标准头，且明文串与跳板桩混杂，不像单一算法输出；
- 解包器不在原始文件的可执行段里（CODE raw size 为 0），需要从进程启动过程或注入方式入手；
- 明文串可能是编译器字符串表被原样保留，也可能是压缩流 literal 区，当前证据不足以区分。

## 建议的下一步

1. 用 frida 对 text1 页做内存访问监视（MemoryAccessMonitor），在启动/命令触发时抓写入者，定位解包器；
2. 在真实启动流程（服务启动）中 dump 内存，比较启动前后 text1 页内容，找出被解密的页；
3. 若能拿到解包器代码，再按其算法还原载荷（比盲猜压缩格式可靠）。