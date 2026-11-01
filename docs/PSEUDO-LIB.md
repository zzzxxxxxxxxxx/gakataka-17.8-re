# lib.dll 关键函数伪代码（REA / Ghidra 反编译）

- 目标：`analysis/unpacked-auto/lib-stage2.dll`（sha256 df13edbba3bf589d725c15e5d1c0409cfdeb123bd3e57c5a7726249ddd6b1861）
- 工具：REA MCP + Ghidra 12.1.2（Borland Delphi x86 profile）
- 地址为镜像内 VA（image base 0x400000）；运行期基址不同，按 RVA 换算

## ShutWindow

```c

int ShutWindow(void)

{
  char cVar1;
  int iVar2;
  undefined4 in_stack_00000004;
  int in_stack_00000008;
  int in_stack_0000000c;
  
                    /* 0xac9a0  408  ShutWindow */
  if (*DAT_0051a898 == 2) {
    iVar2 = -1;
    FUN_004ac3a8();
    if (((in_stack_0000000c == 0) || (in_stack_00000008 == 0)) || (DAT_0051c24c == (code *)0x0)) {
      if (((in_stack_00000008 == 0) || (DAT_0051c254 == (code *)0x0)) ||
         (DAT_0051c250 == (code *)0x0)) {
        FUN_004b213c(in_stack_00000004);
        cVar1 = FUN_004ac95c();
        iVar2 = -(uint)(cVar1 != '\0');
      }
      else {
        cVar1 = FUN_004b213c(in_stack_00000004);
        if (cVar1 == '\0') {
          (*DAT_0051c254)();
          (*DAT_0051c250)();
        }
        else if (cVar1 == '\x01') {
          (*DAT_0051c254)();
          (*DAT_0051c250)();
        }
        else {
          (*DAT_0051c254)();
          (*DAT_0051c250)();
        }
      }
    }
    else {
      SeShutdown();
      FUN_004b213c(in_stack_00000004);
      (*DAT_0051c24c)();
    }
  }
  else {
    FUN_004b213c(in_stack_00000004);
    cVar1 = FUN_004ac95c();
    iVar2 = -(uint)(cVar1 != '\0');
  }
  return iVar2;
}


```

## SeShutdown

```c

void SeShutdown(void)

{
                    /* 0xac928  410  SeShutdown */
  SeShutdown2();
  return;
}


```

## SeShutdown2

```c

void SeShutdown2(void)

{
                    /* 0xac930  409  SeShutdown2 */
  SetPrivilege();
  return;
}


```

## KillProc

```c

undefined4 KillProc(void)

{
  int iVar1;
  undefined4 uVar2;
  
                    /* 0xa9a58  272  KillProc */
  iVar1 = GetProcId();
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = TermProc();
  }
  return uVar2;
}


```

## RunUpdt

```c

void RunUpdt(void)

{
  undefined1 *puVar1;
  char cVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_00000004;
  undefined4 in_stack_00000008;
  undefined4 in_stack_0000000c;
  undefined4 in_stack_00000010;
  undefined4 uStack_4c;
  undefined1 *puStack_48;
  undefined1 *puStack_44;
  undefined4 local_38;
  undefined1 local_34;
  undefined4 local_30;
  undefined1 local_2c;
  undefined4 local_28;
  undefined1 local_24;
  undefined4 local_20;
  undefined1 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
                    /* 0xaf250  424  RunUpdt */
  puStack_44 = &stack0xfffffffc;
  local_18 = 0;
  local_14 = 0;
  local_10 = 0;
  local_8 = 0;
  local_c = 0;
  puStack_48 = &LAB_004af34a;
  uStack_4c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_4c;
  FUN_00404e28(&local_10,in_stack_0000000c);
  cVar2 = FUN_0040a038(local_10);
  if (cVar2 == '\0') {
    FUN_00404e28(&local_14,in_stack_00000004);
    FUN_0040a47c(local_14,&local_c);
  }
  else {
    FUN_00404e28(&local_c,in_stack_0000000c);
  }
  FUN_00404e28(&local_8,in_stack_00000004);
  iVar3 = FUN_00405234(&DAT_004af364,local_8);
  if (iVar3 < 1) {
    FUN_00404f3c(&local_8,local_c,local_8);
  }
  local_38 = local_8;
  local_34 = 0xb;
  local_30 = in_stack_00000008;
  local_2c = 6;
  local_28 = local_c;
  local_24 = 0xb;
  local_20 = in_stack_00000010;
  local_1c = 6;
  FUN_0040aff8(s___s__UpdtFile___s____s____s__004af370,&local_38,3,&local_18);
  FUN_004050f0(local_18);
  FUN_004a9cac();
  puVar1 = puStack_44;
  *in_FS_OFFSET = uStack_4c;
  puStack_44 = &LAB_004af351;
  puStack_48 = (undefined1 *)0x4af349;
  FUN_00404c54(&local_18,5,puVar1);
  return;
}


```

## SetGate

```c

void SetGate(void)

{
  undefined4 uVar1;
  undefined1 *puVar2;
  int iVar3;
  uint uVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_00000004;
  undefined1 *in_stack_00000008;
  undefined4 uStack_28;
  undefined1 *puStack_24;
  undefined1 *puStack_20;
  undefined1 *local_14;
  undefined4 *local_10;
  undefined4 local_c;
  undefined1 *local_8;
  
                    /* 0x103bec  223  SetGate */
  puStack_20 = &stack0xfffffffc;
  local_c = 0;
  local_10 = (undefined4 *)0x0;
  local_14 = (undefined1 *)0x0;
  puStack_24 = &LAB_00503d17;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  local_8 = (undefined1 *)0x0;
  iVar3 = thunk_FUN_0054cf06();
  if (0 < iVar3) {
    puStack_20 = in_stack_00000008;
    puStack_24 = (undefined1 *)0x503c23;
    iVar3 = thunk_FUN_0054cf06();
    if (0 < iVar3) {
      uVar1 = *in_FS_OFFSET;
      *in_FS_OFFSET = &stack0xffffffe4;
      puStack_20 = (undefined1 *)0x1;
      puStack_24 = (undefined1 *)0x503c4d;
      local_14 = &stack0xfffffffc;
      FUN_0040612c(&local_c,DAT_00502d80,1);
      puStack_20 = (undefined1 *)0x1;
      puStack_24 = (undefined1 *)0x503c65;
      FUN_0040612c(&local_10,DAT_00502dac,1);
      puStack_20 = (undefined1 *)0x503c72;
      FUN_00404e28(local_c,in_stack_00000008);
      *local_10 = 0x14;
      puStack_20 = (undefined1 *)0x503c85;
      FUN_00404e28(&local_14,in_stack_00000004);
      puStack_20 = (undefined1 *)0x503c93;
      uVar4 = FUN_00503af4(local_14,local_c,local_10);
      local_8 = (undefined1 *)-(uint)(uVar4 < 2);
      *in_FS_OFFSET = uVar1;
      local_14 = (undefined1 *)0x503ce5;
      FUN_0040612c(&local_c,DAT_00502d80,1);
      FUN_0040612c(&local_10,DAT_00502dac,1);
      return;
    }
  }
  puVar2 = local_8;
  *in_FS_OFFSET = local_10;
  local_8 = &LAB_00503d1e;
  local_c = 0x503cfa;
  FUN_00404c30(&local_14,local_10,puVar2);
  local_c = 0x503d08;
  FUN_00406258(&local_10,DAT_00502dac);
  local_c = 0x503d16;
  FUN_00406258(&local_c,DAT_00502d80);
  return;
}


```

## IsRunInVM

```c

/* WARNING: Restarted to delay deadcode elimination for space: stack */

void IsRunInVM(void)

{
  undefined1 *puVar1;
  int iVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 *in_FS_OFFSET;
  undefined1 *puStack_b4;
  undefined1 *puStack_b0;
  undefined1 *puStack_ac;
  undefined1 local_a4 [4];
  undefined1 local_a0 [8];
  undefined1 *local_98;
  undefined1 local_94 [4];
  undefined4 local_90;
  undefined1 local_8c;
  undefined1 local_88;
  undefined4 local_84;
  undefined1 *local_80;
  undefined1 local_7c;
  undefined1 local_78;
  undefined1 local_74;
  undefined1 auStack_44 [8];
  undefined1 auStack_3c [56];
  
                    /* 0xae2d8  341  IsRunInVM */
  puStack_ac = &stack0xfffffffc;
  puStack_b0 = &LAB_004ae43c;
  puStack_b4 = (undefined1 *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_b4;
  thunk_FUN_005288a1();
  FUN_004036d4(local_94,0x90,0);
  local_98 = (undefined1 *)0x0;
  local_94[0] = 0x2c;
  local_90 = 0x200c0000;
  local_8c = 1;
  local_88 = 0x40;
  local_84 = 0x1a5e0;
  local_7c = 0x30;
  local_78 = 0x12;
  local_74 = 0x40;
  local_80 = auStack_44;
  iVar2 = thunk_FUN_0052be97(local_94,extraout_EDX,extraout_ECX);
  if (iVar2 != 0) {
    local_98 = auStack_3c;
  }
  thunk_FUN_0052d185(iVar2);
  FUN_00404e28(local_a4,local_98);
  FUN_004094b8(0,local_a0);
  iVar2 = FUN_00405234(s_VMWARE_004ae468,0);
  if ((iVar2 < 1) && (iVar2 = FUN_00405234(s_VIRTUAL_004ae478,0), iVar2 < 1)) {
    FUN_00405234(&DAT_004ae488,0);
  }
  puVar1 = puStack_b4;
  *in_FS_OFFSET = 0x8000000;
  puStack_b4 = &LAB_004ae443;
  FUN_00404c54(local_a4,2,puVar1);
  return;
}


```

## DisableGuest

```c

void DisableGuest(void)

{
                    /* 0xae958  317  DisableGuest */
  FUN_004ae780(s_Guest_004ae970,0);
  return;
}


```

## EnableGuest

```c

void EnableGuest(void)

{
                    /* 0xae978  316  EnableGuest */
  FUN_004ae780(s_Guest_004ae990,1);
  return;
}


```

## DisableUsbStore

```c

int DisableUsbStore(void)

{
  char cVar1;
  
                    /* 0xaf6e8  327  DisableUsbStore */
  cVar1 = FUN_004af69c(4);
  return -(uint)(cVar1 != '\0');
}


```

## EnableUsbStore

```c

int EnableUsbStore(void)

{
  char cVar1;
  
                    /* 0xaf6f8  326  EnableUsbStore */
  cVar1 = FUN_004af69c(3);
  return -(uint)(cVar1 != '\0');
}


```

## HideTaskbar

```c

void HideTaskbar(void)

{
                    /* 0xaea24  356  HideTaskbar */
  FUN_004ae9c0(0);
  return;
}


```

## ShowTaskbar

```c

void ShowTaskbar(void)

{
                    /* 0xaea18  357  ShowTaskbar */
  FUN_004ae9c0(5);
  return;
}


```
