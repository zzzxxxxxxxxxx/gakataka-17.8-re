# 混淆层结构化伪代码（lifter v10：条件语义 + 重复折叠 + 跳板链折叠）

由执行轨迹的控制转移序列生成：带标签、条件跳转、循环回边、跳板链折叠与外部 API 进入点。

## Q 命令（43 次控制转移）

  L_458a38: goto CODE+0x58a5f
  L_458a64: call Q_Handler
  L_458872: call CODE+0x46f8
  L_404715: goto CODE+0x46ff   /* 回边：循环 */   (重复 15 次)
  L_404706: if (相等) goto CODE+0x4719   /* 未跳转，继续 CODE+0x471f */
  L_40471f: goto CODE+0x45f0   /* 回边：循环 */
  L_4045fb: call CODE+0x45c4
  L_4045d0: call CODE+0x2a38
  L_402a42: call CODE+0x23e4
  L_4023f4: if (不相等) goto CODE+0x23ff   /* 未跳转，继续 CODE+0x2405 */
  L_402405: if (小于等于(有符号)) goto CODE+0x2411   /* 未跳转，继续 CODE+0x242d */
  L_40242d: call CODE+0x1368
  0x401368: /* 跳板链折叠 */ CODE+0x1368 -> text0+0x3bec -> text0+0xa6a2
  0x4786ae: /* 跳板链折叠 */ text0+0xa6ae -> text0+0x82ff
  L_4762ff: call text0+0x7cea
  L_475cea: goto VM_dispatch
  L_47b4fb: call text0+0xd3b4
  L_47b3bb: goto text0+0xaf52   /* 回边：循环 */
  L_478f6c: return -> text0+0x8304
  L_476305: call text0+0xa320
  L_478337: return -> RtlEnterCriticalSection
  /* 进入 RtlEnterCriticalSection */
  L_40243b: if (大于等于(有符号)) goto CODE+0x2442   /* 未跳转，继续 CODE+0x2452 */
  L_402452: if (非负) goto CODE+0x2457   /* 未跳转，继续 CODE+0x246b */
  L_40246b: if (相等) goto CODE+0x24fa   /* 未跳转，继续 CODE+0x250f */
  L_40250f: if (大于等于(有符号)) goto CODE+0x251e   /* 未跳转，继续 CODE+0x254e */
  L_40254e: call CODE+0x3f1c
  L_403f2c: call 0x201ffbb1

- 回边数量：17

## S1 命令（9 次控制转移）

  L_458a38: goto CODE+0x58aca
  L_458ad9: goto CODE+0x58b36
  L_458b3e: goto CODE+0x58b4a
  L_458b5f: call CODE+0x4524
  L_40452e: if (相等) goto CODE+0x454a   /* 未跳转，继续 CODE+0x454e */
  L_40454e: if (不相等) goto CODE+0x452a   /* 未跳转，继续 CODE+0x452e */
  L_40452e: if (相等) goto CODE+0x454a   /* 未跳转，继续 CODE+0x4552 */
  L_404552: return -> CODE+0x58b64
  L_458b64: return -> CODE+0x58b6c

- 回边数量：0

## S0 命令（9 次控制转移）

  L_458a38: goto CODE+0x58aca
  L_458ad9: goto CODE+0x58b36
  L_458b3e: goto CODE+0x58b4a
  L_458b5f: call CODE+0x4524
  L_40452e: if (相等) goto CODE+0x454a   /* 未跳转，继续 CODE+0x454e */
  L_40454e: if (不相等) goto CODE+0x452a   /* 未跳转，继续 CODE+0x452e */
  L_40452e: if (相等) goto CODE+0x454a   /* 未跳转，继续 CODE+0x4552 */
  L_404552: return -> CODE+0x58b64
  L_458b64: return -> CODE+0x58b6c

- 回边数量：0

## T1 命令（75 次控制转移）

  L_458a38: goto CODE+0x58adb
  L_458aea: call PersistAr
  L_4583c1: call CODE+0x581fc
  L_458215: call R_DirHelper
  L_4581cb: call CODE+0x2e64
  L_402e72: call CODE+0x4500
  L_404504: if (相等) goto CODE+0x4522   /* 标志满足，走跳转分支 */
  L_404522: return -> CODE+0x2e77
  L_402e87: call CODE+0x126c
  0x40126c: /* 跳板链折叠 */ CODE+0x126c -> text0+0xb9cf
  L_4799cf: call text0+0x96c3
  L_4776d5: call text0+0x7cea
  L_475cea: goto VM_dispatch
  L_47b4fb: call text0+0xd3b4
  L_47b3bb: goto text0+0xaf52   /* 回边：循环 */
  L_478f6c: return -> text0+0x96da
  L_4776da: call text0+0xb8ea
  L_4798ea: call text0+0xb888
  L_47988b: call text0+0x8677
  L_476685: return -> GetModuleFileNameA
  /* 进入 GetModuleFileNameA */
  L_402e94: call CODE+0x45f0
  L_4045fb: call CODE+0x45c4
  L_4045d0: call CODE+0x2a38
  L_402a42: call CODE+0x23e4
  L_4023f4: if (不相等) goto CODE+0x23ff   /* 未跳转，继续 CODE+0x2405 */
  L_402405: if (小于等于(有符号)) goto CODE+0x2411   /* 未跳转，继续 CODE+0x242d */
  L_40242d: call CODE+0x1368
  0x401368: /* 跳板链折叠 */ CODE+0x1368 -> text0+0x3bec -> text0+0xa6a2
  0x4786ae: /* 跳板链折叠 */ text0+0xa6ae -> text0+0x82ff
  L_4762ff: call text0+0x7cea
  L_475cea: goto VM_dispatch
  L_47b4fb: call text0+0xd3b4
  L_47b3bb: goto text0+0xaf52   /* 回边：循环 */
  L_478f6c: return -> text0+0x8304
  L_476305: call text0+0xa320
  L_478337: return -> RtlEnterCriticalSection
  /* 进入 RtlEnterCriticalSection */
  L_40243b: if (大于等于(有符号)) goto CODE+0x2442   /* 未跳转，继续 CODE+0x2448 */
  L_402448: if (大于(有符号)) goto CODE+0x24fa   /* 未跳转，继续 CODE+0x2500 */
  L_402500: if (大于(有符号)) goto CODE+0x2555   /* 未跳转，继续 CODE+0x2557 */
  L_402557: call CODE+0x229c
  L_4022e7: if (大于(有符号)) goto CODE+0x22db   /* 未跳转，继续 CODE+0x22f2 */
  L_4022f2: if (相等) goto CODE+0x22fa   /* 未跳转，继续 CODE+0x2300 */
  L_402300: if (大于(有符号)) goto CODE+0x2310   /* 未跳转，继续 CODE+0x2312 */
  L_402312: call CODE+0x2204
  L_40220f: call CODE+0x1908
  L_40192b: goto CODE+0x196e
  L_401970: if (不相等) goto CODE+0x192d   /* 未跳转，继续 CODE+0x1932 */
  L_401932: if (大于(有符号)) goto CODE+0x1968   /* 未跳转，继续 CODE+0x1976 */
  L_401976: call CODE+0x15e8
  L_4015f5: if (大于等于(有符号)) goto CODE+0x15fe   /* 未跳转，继续 CODE+0x1617 */
  L_401617: call CODE+0x1350
  0x401350: /* 跳板链折叠 */ CODE+0x1350 -> text0+0x967f
  L_47767f: call text0+0x2a8c
  L_470a8c: call text0+0xc6a2
  L_47a6a2: call text0+0xbdf3
  L_479df3: goto text0+0x7a0e   /* 回边：循环 */
  L_475a21: call text0+0xcfbf
  L_47afc3: call text0+0x7cea
  L_475cea: goto VM_dispatch
  L_47b4fb: call text0+0xd3b4
  L_47b3bb: goto text0+0xaf52   /* 回边：循环 */
  L_478f6c: return -> text0+0xcfc8
  L_47afd6: return -> VirtualAlloc
  /* 进入 VirtualAlloc */
  L_40162b: call CODE+0x140c
  L_401415: call CODE+0x1380
  L_40138c: if (不相等) goto CODE+0x13e7   /* 未跳转，继续 CODE+0x1403 */
  L_401403: return -> CODE+0x141a
  L_401423: if (不相等) goto CODE+0x1429   /* 未跳转，继续 CODE+0x1467 */
  L_401467: return -> CODE+0x1630
  L_401632: if (不相等) goto CODE+0x1647   /* 未跳转，继续 CODE+0x164a */
  L_40164a: return -> 0x1

- 回边数量：4

## W 命令（31 次控制转移）

  L_458a38: goto CODE+0x58b1d
  L_458b22: call W_Handler
  L_4588ee: call CODE+0x46f8
  L_404715: goto CODE+0x46ff   /* 回边：循环 */   (重复 3 次)
  L_404710: if (相等) goto CODE+0x4717   /* 未跳转，继续 CODE+0x471f */
  L_40471f: goto CODE+0x45f0   /* 回边：循环 */
  L_4045fb: call CODE+0x45c4
  L_4045d0: call CODE+0x2a38
  L_402a42: call CODE+0x23e4
  L_4023f4: if (不相等) goto CODE+0x23ff   /* 未跳转，继续 CODE+0x2405 */
  L_402405: if (小于等于(有符号)) goto CODE+0x2411   /* 未跳转，继续 CODE+0x242d */
  L_40242d: call CODE+0x1368
  0x401368: /* 跳板链折叠 */ CODE+0x1368 -> text0+0x3bec -> text0+0xa6a2
  0x4786ae: /* 跳板链折叠 */ text0+0xa6ae -> text0+0x82ff
  L_4762ff: call text0+0x7cea
  L_475cea: goto VM_dispatch
  L_47b4fb: call text0+0xd3b4
  L_47b3bb: goto text0+0xaf52   /* 回边：循环 */
  L_478f6c: return -> text0+0x8304
  L_476305: call text0+0xa320
  L_478337: return -> RtlEnterCriticalSection
  /* 进入 RtlEnterCriticalSection */
  L_40243b: if (大于等于(有符号)) goto CODE+0x2442   /* 未跳转，继续 CODE+0x2452 */
  L_402452: if (非负) goto CODE+0x2457   /* 未跳转，继续 CODE+0x246b */
  L_40246b: if (相等) goto CODE+0x24fa   /* 未跳转，继续 CODE+0x250f */
  L_40250f: if (大于等于(有符号)) goto CODE+0x251e   /* 未跳转，继续 CODE+0x254e */
  L_40254e: call CODE+0x3f1c
  L_403f2c: call 0x201ffb91

- 回边数量：5

## X 命令（80 次控制转移）

  L_458a38: goto CODE+0x58b29
  L_458b31: call CODE+0x57fb8
  0x457fb8: /* 跳板链折叠 */ CODE+0x57fb8 -> text0+0x604e -> X_entry
  L_47a87a: call text0+0x7cea
  L_475cea: goto VM_dispatch
  L_47b4fb: call text0+0xd3b4
  L_47b3bb: goto text0+0xaf52   /* 回边：循环 */
  L_478f6c: return -> text0+0xc87f
  L_47a881: goto text0+0xd2a0
  L_47b2b0: return -> lib!SetDateTime
  L_b3dc5b: call lib!+0xbc54
  L_a9bc6c: call lib!+0xbae4
  L_a9bb01: call lib!+0xb858
  L_a9b874: if (非负) goto lib!+0xb887   /* 未跳转，继续 lib!+0xb899 */
  L_a9b899: return -> lib!+0xbb06
  L_a9bb0b: if (大于(有符号)) goto lib!+0xbb31   /* 未跳转，继续 lib!+0xbb5d */
  L_a9bb5d: if (大于等于(有符号)) goto lib!+0xbb4c   /* 未跳转，继续 lib!+0xbb5d */   (重复 2 次)
  L_a9bb5d: if (大于等于(有符号)) goto lib!+0xbb4c   /* 未跳转，继续 lib!+0xbb6b */
  L_a9bb6b: call lib!+0x9440
  L_a99459: return -> lib!+0xbb70
  L_a9bb75: if (不相等) goto lib!+0xbb81   /* 未跳转，继续 lib!+0xbb98 */
  L_a9bb98: call lib!+0x9440
  L_a99459: return -> lib!+0xbb9d
  L_a9bbb6: call lib!+0x9440
  L_a99459: return -> lib!+0xbbbb
  L_a9bbc0: if (不相等) goto lib!+0xbbcc   /* 未跳转，继续 lib!+0xbbd2 */
  L_a9bbd2: call lib!+0xb9a8
  L_a9b9b4: if (不相等) goto lib!+0xb9d7   /* 未跳转，继续 lib!+0xb9db */
  L_a9b9db: return -> lib!+0xbbd7
  L_a9bc10: goto lib!+0xbbee   /* 回边：循环 */   (重复 11 次)
  L_a9bc05: if (低于(无符号)) goto lib!+0xbc12   /* 未跳转，继续 lib!+0xbc30 */
  L_a9bc30: return -> lib!+0xbc71
  L_a9bc88: call lib!+0xb94c
  L_a9b968: call lib!+0xb858
  L_a9b874: if (非负) goto lib!+0xb887   /* 未跳转，继续 lib!+0xb899 */
  L_a9b899: return -> lib!+0xb96d
  L_a9b977: call lib!+0x9440
  L_a99459: return -> lib!+0xb97c
  L_a9b987: call lib!+0x9440
  L_a99459: return -> lib!+0xb98c
  L_a9b99a: call lib!+0x9440
  L_a99459: return -> lib!+0xb99f
  L_a9b9a5: return -> lib!+0xbc8d
  L_a9bc8f: return -> lib!+0xadc60
  L_b3dc64: call lib!+0x7808
  0xa97808: /* 跳板链折叠 */ lib!+0x7808 -> lib!+0x126e1b -> lib!+0x1269ba
  L_bb69c7: call lib!+0x129238
  L_bb923e: goto lib!+0x127055   /* 回边：循环 */
  L_bb705b: call lib!+0x134648
  L_bc4649: call lib!+0x14ce33
  L_bdce4a: goto lib!+0x14ccca   /* 回边：循环 */
  L_bdccdc: goto lib!+0x127d7e   /* 回边：循环 */
  L_bb7d81: call lib!+0x144e6a
  L_bd4e6a: goto lib!+0x150269
  L_be0270: goto lib!+0x15151f
  L_be1534: goto lib!+0x132a73   /* 回边：循环 */
  L_bc2a8b: return -> lib!+0x127060
  L_bb706e: return -> SetLocalTime
  /* 进入 SetLocalTime */
  L_b3dc6c: return -> CODE+0x58b36
  L_458b3e: goto CODE+0x58b4a
  L_458b5f: call CODE+0x4524
  L_40452e: if (相等) goto CODE+0x454a   /* 未跳转，继续 CODE+0x454e */
  L_40454e: if (不相等) goto CODE+0x452a   /* 未跳转，继续 CODE+0x452e */
  L_40452e: if (相等) goto CODE+0x454a   /* 未跳转，继续 CODE+0x4552 */
  L_404552: return -> CODE+0x58b64
  L_458b64: return -> CODE+0x58b6c

- 回边数量：16