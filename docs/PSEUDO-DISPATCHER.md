# Smonitor 分派器与 handler 的高级伪代码（Ghidra 反编译）

方法：Smonitor-stage2.exe 是内存镜像，Ghidra 默认不把 0x4589f8 当函数。把 PE 的
AddressOfEntryPoint 改为 RVA 0x589F8（文件偏移 0x589F8）生成副本
analysis/unpacked-auto/Smonitor-entry-dispatch.exe，Ghidra 以 entry 函数精确定位并反编译出分派器。

## 分派器（entry @ 0x4589f8，Ghidra 输出，节选）

    void entry(int param_1,undefined1 *param_2)
    {
      char cVar1;
      undefined1 *puVar2;
      undefined4 uVar3;
      int iVar4;
      undefined4 *in_FS_OFFSET;
      char *pcStack_3c;
      undefined4 uStack_34;
      undefined1 *puStack_30;
      undefined1 *puStack_2c;
      undefined1 *local_28;
      undefined1 *puStack_24;
      undefined1 *puStack_20;
      undefined *local_10;
      undefined *local_c;
      char *local_8;

      local_8 = param_2 + 1;
      switch(*param_2) {
      case 0x51:
        FUN_00458854(param_1,local_8);
        break;
      case 0x52:
        FUN_004046f8((int *)&local_c,local_8);
        uVar3 = FUN_00408a2c(local_c);
        if ((char)uVar3 == '\0') {
          goto LAB_00458b4a;
        }
        *(undefined1 *)(param_1 + 0xfb) = 0;
        pcStack_3c = local_8;
        FUN_004581b0((int *)&local_10);
        FUN_004049c0(local_10);
        iVar4 = thunk_FUN_004747f4();
        if (iVar4 == 0) {
          *(undefined1 *)(param_1 + 0xfa) = 1;
        }
        break;
      case 0x53:
        *(bool *)(param_1 + 0xfb) = *local_8 == '\x01';
        break;
      case 0x54:
        cVar1 = *local_8;
        *(bool *)(param_1 + 0xf8) = cVar1 == '\x01';
        FUN_004583a4(CONCAT31((int3)((uint)local_8 >> 8),cVar1 == '\x01'));
        break;
      case 0x55:
        if (*local_8 == '\x01') {
          thunk_FUN_004795cc();
        }
        else {
          thunk_FUN_0047a71c();
        }
        break;
      case 0x56:
        if (*local_8 == '\x01') {
          thunk_FUN_00479800();
        }
        else {
          thunk_FUN_004731c9(local_8);
        }
        break;
      case 0x57:
        FUN_004588c4(param_1,local_8);
        break;
      case 0x58:
        pcStack_3c = *(char **)local_8;
        thunk_FUN_0047a85b();
      }
    LAB_00458b4a:
      FUN_00404524((int *)&local_10,2);
      return;
    }

（完整输出含 Delphi SEH 的 try/finally 嵌套，见 analysis/tmp/dispatch_handlers_pseudo.json 与
analysis/PSEUDO-DISPATCHER.md 的生成来源。）

## 从反编译确认的语义（与之前动态/静态结论一致）

- 0x51 Q：FUN_00458854(self, cmd+1)。Q 内部：字符串化路径 → 校验 → 释放 self+0x100 旧字符串 →
  thunk_FUN_004729c5()（真正复制配置的混淆入口）→ FUN_004583a4(self+0xf8) 持久化 ar。
- 0x52 R：路径校验失败直接返回；通过则 self+0xfb = 0（先关 taskmgr 保护），取目录、
  FUN_004581b0/FUN_004049c0 规范化目录，thunk_FUN_004747f4() 检查结果；失败时 self+0xfa = 1。
- 0x53 S：*(bool*)(self+0xfb) = (cmd[1] == 1) —— 任务管理器/性能监视器保护标志。
- 0x54 T：*(bool*)(self+0xf8) = (cmd[1] == 1)，并调用 FUN_004583a4 持久化 ar。
- 0x55 U：cmd[1]==1 ? thunk_FUN_004795cc() : thunk_FUN_0047a71c()（USB 存储启/禁）。
- 0x56 V：cmd[1]==1 ? thunk_FUN_00479800() : thunk_FUN_004731c9(cmd+1)（Guest 启/禁）。
- 0x57 W：FUN_004588c4(self, cmd+1)（命令文本处理）。
- 0x58 X：取 cmd+1 处的 8 字节 TDateTime，thunk_FUN_0047a85b()（设置时间）。

## 非混淆 helper 的伪代码（Ghidra 输出，已可读）

    // Q handler：配置同步
    void FUN_00458854(int self, char *s) {
      FUN_004046f8(&local_8, s);                  // 参数转字符串
      if (FUN_00408a1c(local_8)) {                // 非空校验
        FUN_004049c0(*(void **)(self + 0x100));   // 释放旧配置字符串
        thunk_FUN_004729c5();                     // 混淆入口：复制配置
      }
      FUN_004583a4(*(byte *)(self + 0xf8));       // 持久化 ar 标志
    }

    // R handler 的目录规范化
    void FUN_004581b0(int *out) {
      FUN_00402e64(0, &local_8);                  // 取当前模块路径
      FUN_00408ad8(local_8, out);                 // 取目录部分
    }

## 混淆区 handler 的反编译结果（只能到外壳）

Ghidra 对 0x47xxxx 的 handler 只还原出外壳，例如：

    void FUN_0047a71c(void) { LOCK(); UNLOCK(); FUN_0047ac56(); return; }        // U0
    void FUN_004795cc(void) { LOCK(); UNLOCK(); thunk_FUN_0047b4d1(); FUN_00475bfe(); return; } // U1
    void FUN_00479800(void) { LOCK(); UNLOCK(); FUN_00478245(); thunk_FUN_0047b4d1(); FUN_0047699e(); return; } // V1
    void FUN_0047a85b(void) { thunk_FUN_0047b4d1(); FUN_0047b2a0(); return; }   // X

这是 .text0/.text1“按需解密 + 自修改桩 + 虚拟化分发”的跳板链，Ghidra 无法建立正确 CFG；
需要专用 lifter（基于 Unicorn 具体执行轨迹）继续提升。

## 产物

- analysis/unpacked-auto/Smonitor-entry-dispatch.exe（入口改为 0x4589f8 的分析副本）
- analysis/tmp/make_entry_dispatch.py（入口补丁脚本）
- analysis/tmp/dispatch_handlers_pseudo.json（9 个 handler 的 Ghidra 原始输出）
