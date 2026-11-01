# 混淆层伪代码（lifter v8：控制转移 + 直线语句 + lib/API 注解）

数据：Unicorn 具体执行轨迹 jumps 链（真实控制转移）与 ext 表（间接/外部调用解析）。
相邻转移之间的直线指令被展开为语句；混淆填充指令（pushfd/pushal/ret imm 等）被过滤。

## Q 命令轨迹（43 次控制转移）

  0x458a38: jmp  [eax*4 + 0x458a3f] -> CODE+0x58a5f
      edx = [ebp - 4]
      eax = ebx
  0x458a64: CALL Q_Handler
      esi = edx
      ebx = eax
      eax = 0
      eax = [ebp - 4]
      edx = esi
  0x458872: CALL CODE+0x46f8
      ecx = 0
      TEST(edx, edx)
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
  0x404706: je   0x404719 -> CODE+0x4719
      edx inc
      ecx = edx
      ecx sub= edx
  0x40471f: jmp  0x4045f0 -> CODE+0x45f0
      ebx = eax
      esi = edx
      edi = ecx
      eax = edi
  0x4045fb: CALL CODE+0x45c4
      TEST(eax, eax)
      eax add= 0xa
      eax and= 0xfffffffe
  0x4045d0: CALL CODE+0x2a38
      ebx = eax
      TEST(ebx, ebx)
      eax = ebx
  0x402a42: CALL (间接->CODE+0x23e4)
      ebx = eax
      CMP(DAT_0045b5c0, 0)
  0x4023f4: jne  0x4023ff -> CODE+0x23ff
      CMP(ebx, 0x7ffffff8)
  0x402405: jle  0x402411 -> CODE+0x2411
      edx = 0
      CMP(DAT_0045b049, 0)
  0x40242d: CALL CODE+0x1368
  0x401368: jmp  0x471bec -> text0+0x3bec
  0x471bec: jmp  0x4786a2 -> text0+0xa6a2
      eax = local_20e5ba63
      eax = DAT_0045c15c
  0x4786ae: jmp  0x4762ff -> text0+0x82ff
  0x4762ff: CALL text0+0x7cea
  0x475cea: jmp  0x47b4d1 -> VM_dispatch
      CMP(sp, sp)
      eax sub= 0x12e405f0
      bt eax, 2
      bswap eax
      TEST(ebp, 0x1f3b35de)
      eax add= 0x970ad3b9
  0x47b4fb: CALL text0+0xd3b4
      eax xor= 0xa4c553d3
  0x47b3bb: jmp  0x478f52 -> text0+0xaf52
  0x478f6c: RET -> text0+0x8304
  0x476305: CALL text0+0xa320
  0x478337: RET -> RtlEnterCriticalSection
  // 0x776b00c0: 进入 RtlEnterCriticalSection ; 下一跳 CODE+0x2432
  0x40243b: jge  0x402442 -> CODE+0x2442
      CMP(ebx, 0x1000)
      eax = ebx
      TEST(eax, eax)
  0x402452: jns  0x402457 -> CODE+0x2457
      sar eax, 2
      edx = DAT_0045b620
      edx = [edx + eax*4 - 0xc]
      [ebp - 8] = edx
      CMP([ebp - 8], 0)
  0x40246b: je   0x4024fa -> CODE+0x24fa
      CMP(ebx, DAT_0045b618)
      DAT_0045b618 sub= ebx
      CMP(DAT_0045b618, 0xc)
  0x40250f: jge  0x40251e -> CODE+0x251e
      eax = DAT_0045b61c
      local_14 = eax
      DAT_0045b61c add= ebx
      eax = ebx
      eax or= 2
      edx = local_14
      [edx] = eax
      eax = local_14
      eax add= 4
      [ebp - 4] = eax
      DAT_0045b5b0 inc
      ebx sub= 4
      DAT_0045b5b4 add= ebx
  0x40254e: CALL CODE+0x3f1c
      edx = 0
      ecx add= 5
  0x403f2c: CALL 0x201ffbb1

## S1 命令轨迹（9 次控制转移）

  0x458a38: jmp  [eax*4 + 0x458a3f] -> CODE+0x58aca
      eax = [ebp - 4]
      CMP([eax], 1)
      sete al
      [ebx + 0xfb] = al
  0x458ad9: jmp  0x458b36 -> CODE+0x58b36
      eax = 0
  0x458b3e: jmp  0x458b4a -> CODE+0x58b4a
      eax = 0
      eax = local_c
      edx = 2
  0x458b5f: CALL CODE+0x4524
      ebx = eax
      esi = edx
      edx = [ebx]
      TEST(edx, edx)
  0x40452e: je   0x40454a -> CODE+0x454a
      ebx add= 4
      esi dec
  0x40454e: jne  0x40452a -> CODE+0x452a
      edx = [ebx]
      TEST(edx, edx)
  0x40452e: je   0x40454a -> CODE+0x454a
      ebx add= 4
      esi dec
  0x404552: RET -> CODE+0x58b64
  0x458b64: RET -> CODE+0x58b6c

## S0 命令轨迹（9 次控制转移）

  0x458a38: jmp  [eax*4 + 0x458a3f] -> CODE+0x58aca
      eax = [ebp - 4]
      CMP([eax], 1)
      sete al
      [ebx + 0xfb] = al
  0x458ad9: jmp  0x458b36 -> CODE+0x58b36
      eax = 0
  0x458b3e: jmp  0x458b4a -> CODE+0x58b4a
      eax = 0
      eax = local_c
      edx = 2
  0x458b5f: CALL CODE+0x4524
      ebx = eax
      esi = edx
      edx = [ebx]
      TEST(edx, edx)
  0x40452e: je   0x40454a -> CODE+0x454a
      ebx add= 4
      esi dec
  0x40454e: jne  0x40452a -> CODE+0x452a
      edx = [ebx]
      TEST(edx, edx)
  0x40452e: je   0x40454a -> CODE+0x454a
      ebx add= 4
      esi dec
  0x404552: RET -> CODE+0x58b64
  0x458b64: RET -> CODE+0x58b6c

## T1 命令轨迹（75 次控制转移）

  0x458a38: jmp  [eax*4 + 0x458a3f] -> CODE+0x58adb
      eax = [ebp - 4]
      CMP([eax], 1)
      sete al
      [ebx + 0xf8] = al
  0x458aea: CALL PersistAr
      ebx = eax
      eax = 0
      eax = [ebp - 8]
  0x4583c1: CALL CODE+0x581fc
      ebx = eax
      eax = 0
      eax = [ebp - 4]
  0x458215: CALL R_DirHelper
      ebx = eax
      eax = 0
      edx = [ebp - 4]
      eax = 0
  0x4581cb: CALL CODE+0x2e64
      ebx = edx
      esi = eax
      eax = ebx
  0x402e72: CALL CODE+0x4500
      edx = [eax]
      TEST(edx, edx)
  0x404504: je   0x404522 -> CODE+0x4522
  0x404522: RET -> CODE+0x2e77
      TEST(esi, esi)
  0x402e87: CALL CODE+0x126c
  0x40126c: jmp  0x4799cf -> text0+0xb9cf
  0x4799cf: CALL text0+0x96c3
      al not
      eax = DAT_0045c1ac
  0x4776d5: CALL text0+0x7cea
  0x475cea: jmp  0x47b4d1 -> VM_dispatch
      CMP(sp, sp)
      eax sub= 0x12e405f0
      bt eax, 2
      bswap eax
      TEST(ebp, 0x1f3b35de)
      eax add= 0x970ad3b9
  0x47b4fb: CALL text0+0xd3b4
      eax xor= 0xa4c553d3
  0x47b3bb: jmp  0x478f52 -> text0+0xaf52
  0x478f6c: RET -> text0+0x96da
  0x4776da: CALL text0+0xb8ea
  0x4798ea: CALL text0+0xb888
  0x47988b: CALL text0+0x8677
  0x476685: RET -> GetModuleFileNameA
  // 0x763510d0: 进入 GetModuleFileNameA ; 下一跳 CODE+0x2e8c
  0x402e94: CALL CODE+0x45f0
      ebx = eax
      esi = edx
      edi = ecx
      eax = edi
  0x4045fb: CALL CODE+0x45c4
      TEST(eax, eax)
      eax add= 0xa
      eax and= 0xfffffffe
  0x4045d0: CALL CODE+0x2a38
      ebx = eax
      TEST(ebx, ebx)
      eax = ebx
  0x402a42: CALL (间接->CODE+0x23e4)
      ebx = eax
      CMP(DAT_0045b5c0, 0)
  0x4023f4: jne  0x4023ff -> CODE+0x23ff
      CMP(ebx, 0x7ffffff8)
  0x402405: jle  0x402411 -> CODE+0x2411
      edx = 0
      CMP(DAT_0045b049, 0)
  0x40242d: CALL CODE+0x1368
  0x401368: jmp  0x471bec -> text0+0x3bec
  0x471bec: jmp  0x4786a2 -> text0+0xa6a2
      eax = local_20e5ba63
      eax = DAT_0045c15c
  0x4786ae: jmp  0x4762ff -> text0+0x82ff
  0x4762ff: CALL text0+0x7cea
  0x475cea: jmp  0x47b4d1 -> VM_dispatch
      CMP(sp, sp)
      eax sub= 0x12e405f0
      bt eax, 2
      bswap eax
      TEST(ebp, 0x1f3b35de)
      eax add= 0x970ad3b9
  0x47b4fb: CALL text0+0xd3b4
      eax xor= 0xa4c553d3
  0x47b3bb: jmp  0x478f52 -> text0+0xaf52
  0x478f6c: RET -> text0+0x8304
  0x476305: CALL text0+0xa320
  0x478337: RET -> RtlEnterCriticalSection
  // 0x776b00c0: 进入 RtlEnterCriticalSection ; 下一跳 CODE+0x2432
  0x40243b: jge  0x402442 -> CODE+0x2442
      CMP(ebx, 0x1000)
  0x402448: jg   0x4024fa -> CODE+0x24fa
      CMP(ebx, DAT_0045b618)
  0x402500: jg   0x402555 -> CODE+0x2555
      eax = ebx
  0x402557: CALL CODE+0x229c
      ebx = eax
      edi = 0x45b614
      ebp = 0x45b618
      eax = DAT_0045b60c
      [esi] = eax
      eax = [esi]
      CMP(ebx, [eax + 8])
      eax = [edi]
      [esi] = eax
      eax = [esi]
      eax = [eax + 8]
      CMP(ebx, eax)
      edx = [esi]
      [edx + 8] = ebx
      edx = [esi]
      edx = [edx + 4]
      [esi] = edx
      edx = [esi]
      CMP(ebx, [edx + 8])
  0x4022e7: jg   0x4022db -> CODE+0x22db
      edx = [esi]
      edx = [edx + 4]
      [esi] = edx
      edx = [esi]
      CMP(ebx, [edx + 8])
      edx = [edi]
      [edx + 8] = eax
      eax = [esi]
      CMP(eax, [edi])
  0x4022f2: je   0x4022fa -> CODE+0x22fa
      CMP(ebx, 0x1000)
  0x402300: jg   0x402310 -> CODE+0x2310
      eax = ebx
  0x402312: CALL CODE+0x2204
      ebx = eax
      eax = [ebx + 4]
  0x40220f: CALL CODE+0x1908
      ebx = edx
      esi = eax
      ebp = 0x45b5f8
      esi add= 0x3fff
      esi and= 0xffffc000
      eax = [ebp]
      [edi] = eax
  0x40192b: jmp  0x40196e -> CODE+0x196e
      CMP(ebp, [edi])
  0x401970: jne  0x40192d -> CODE+0x192d
      eax = [edi]
      CMP(esi, [eax + 0xc])
  0x401932: jg   0x401968 -> CODE+0x1968
      eax = [edi]
      eax = [eax]
      [edi] = eax
      CMP(ebp, [edi])
      edx = ebx
      eax = esi
  0x401976: CALL CODE+0x15e8
      ebx = edx
      esi = eax
      CMP(esi, 0x100000)
  0x4015f5: jge  0x4015fe -> CODE+0x15fe
      esi add= 0xffff
      esi and= 0xffff0000
      [ebx + 4] = esi
  0x401617: CALL CODE+0x1350
  0x401350: jmp  0x47767f -> text0+0x967f
  0x47767f: CALL text0+0x2a8c
  0x470a8c: CALL text0+0xc6a2
  0x47a6a2: CALL text0+0xbdf3
  0x479df3: jmp  0x475a0e -> text0+0x7a0e
      movsx ax, dl
      eax = DAT_0045c168
  0x475a21: CALL text0+0xcfbf
  0x47afc3: CALL text0+0x7cea
  0x475cea: jmp  0x47b4d1 -> VM_dispatch
      CMP(sp, sp)
      eax sub= 0x12e405f0
      bt eax, 2
      bswap eax
      TEST(ebp, 0x1f3b35de)
      eax add= 0x970ad3b9
  0x47b4fb: CALL text0+0xd3b4
      eax xor= 0xa4c553d3
  0x47b3bb: jmp  0x478f52 -> text0+0xaf52
  0x478f6c: RET -> text0+0xcfc8
  0x47afd6: RET -> VirtualAlloc
  // 0x7634f660: 进入 VirtualAlloc ; 下一跳 CODE+0x161c
  0x40162b: CALL CODE+0x140c
      esi = edx
      ebx = eax
  0x401415: CALL CODE+0x1380
      ebx = 0x45b5e4
      CMP([ebx], 0)
  0x40138c: jne  0x4013e7 -> CODE+0x13e7
      eax = [ebx]
      eax = [eax]
      [ebx] = eax
  0x401403: RET -> CODE+0x141a
  0x401423: jne  0x401429 -> CODE+0x1429
      eax = [esi]
      [edx + 8] = eax
      eax = [esi + 4]
      [edx + 0xc] = eax
      eax = [ebx]
      [eax] = edx
      [eax + 4] = ebx
      [eax + 4] = edx
      [ebx] = eax
      al = 1
  0x401467: RET -> CODE+0x1630
      TEST(al, al)
  0x401632: jne  0x401647 -> CODE+0x1647
  0x40164a: RET -> 0x1

## W 命令轨迹（31 次控制转移）

  0x458a38: jmp  [eax*4 + 0x458a3f] -> CODE+0x58b1d
      edx = [ebp - 4]
      eax = ebx
  0x458b22: CALL W_Handler
      ecx = 0
      local_c = ecx
      local_28 = ecx
      [ebp - 4] = ecx
      [ebp - 8] = ecx
      ebx = edx
      eax = 0
      eax = [ebp - 4]
      edx = ebx
  0x4588ee: CALL CODE+0x46f8
      ecx = 0
      TEST(edx, edx)
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
  0x404715: jmp  0x4046ff -> CODE+0x46ff
      CMP(cl, [edx])
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
  0x404710: je   0x404717 -> CODE+0x4717
      edx inc
      edx inc
      edx inc
      ecx = edx
      ecx sub= edx
  0x40471f: jmp  0x4045f0 -> CODE+0x45f0
      ebx = eax
      esi = edx
      edi = ecx
      eax = edi
  0x4045fb: CALL CODE+0x45c4
      TEST(eax, eax)
      eax add= 0xa
      eax and= 0xfffffffe
  0x4045d0: CALL CODE+0x2a38
      ebx = eax
      TEST(ebx, ebx)
      eax = ebx
  0x402a42: CALL (间接->CODE+0x23e4)
      ebx = eax
      CMP(DAT_0045b5c0, 0)
  0x4023f4: jne  0x4023ff -> CODE+0x23ff
      CMP(ebx, 0x7ffffff8)
  0x402405: jle  0x402411 -> CODE+0x2411
      edx = 0
      CMP(DAT_0045b049, 0)
  0x40242d: CALL CODE+0x1368
  0x401368: jmp  0x471bec -> text0+0x3bec
  0x471bec: jmp  0x4786a2 -> text0+0xa6a2
      eax = local_20e5ba63
      eax = DAT_0045c15c
  0x4786ae: jmp  0x4762ff -> text0+0x82ff
  0x4762ff: CALL text0+0x7cea
  0x475cea: jmp  0x47b4d1 -> VM_dispatch
      CMP(sp, sp)
      eax sub= 0x12e405f0
      bt eax, 2
      bswap eax
      TEST(ebp, 0x1f3b35de)
      eax add= 0x970ad3b9
  0x47b4fb: CALL text0+0xd3b4
      eax xor= 0xa4c553d3
  0x47b3bb: jmp  0x478f52 -> text0+0xaf52
  0x478f6c: RET -> text0+0x8304
  0x476305: CALL text0+0xa320
  0x478337: RET -> RtlEnterCriticalSection
  // 0x776b00c0: 进入 RtlEnterCriticalSection ; 下一跳 CODE+0x2432
  0x40243b: jge  0x402442 -> CODE+0x2442
      CMP(ebx, 0x1000)
      eax = ebx
      TEST(eax, eax)
  0x402452: jns  0x402457 -> CODE+0x2457
      sar eax, 2
      edx = DAT_0045b620
      edx = [edx + eax*4 - 0xc]
      [ebp - 8] = edx
      CMP([ebp - 8], 0)
  0x40246b: je   0x4024fa -> CODE+0x24fa
      CMP(ebx, DAT_0045b618)
      DAT_0045b618 sub= ebx
      CMP(DAT_0045b618, 0xc)
  0x40250f: jge  0x40251e -> CODE+0x251e
      eax = DAT_0045b61c
      local_14 = eax
      DAT_0045b61c add= ebx
      eax = ebx
      eax or= 2
      edx = local_14
      [edx] = eax
      eax = local_14
      eax add= 4
      [ebp - 4] = eax
      DAT_0045b5b0 inc
      ebx sub= 4
      DAT_0045b5b4 add= ebx
  0x40254e: CALL CODE+0x3f1c
      edx = 0
      ecx add= 5
  0x403f2c: CALL 0x201ffb91

## X 命令轨迹（80 次控制转移）

  0x458a38: jmp  [eax*4 + 0x458a3f] -> CODE+0x58b29
      eax = [ebp - 4]
  0x458b31: CALL CODE+0x57fb8
  0x457fb8: jmp  0x47404e -> text0+0x604e
  0x47404e: jmp  0x47a85b -> X_entry
      eax = [edx - 0x630a365c]
      cwde 
      eax = [edx - 0x7e0d2ad9]
      eax = DAT_0045c814
  0x47a87a: CALL text0+0x7cea
  0x475cea: jmp  0x47b4d1 -> VM_dispatch
      CMP(sp, sp)
      eax sub= 0x12e405f0
      bt eax, 2
      bswap eax
      TEST(ebp, 0x1f3b35de)
      eax add= 0x970ad3b9
  0x47b4fb: CALL text0+0xd3b4
      eax xor= 0xa4c553d3
  0x47b3bb: jmp  0x478f52 -> text0+0xaf52
  0x478f6c: RET -> text0+0xc87f
  0x47a881: jmp  0x47b2a0 -> text0+0xd2a0
  0x47b2b0: RET -> lib!SetDateTime
      eax = local_10
  0xb3dc5b: CALL lib!+0xbc54
      ebx = eax
      eax = [ebx + 4]
      ecx = [ebx + 6]
      edx = [ebx + 2]
      eax = ebx
  0xa9bc6c: CALL lib!+0xbae4
      local_c = ecx
      [ebp - 8] = edx
      [ebp - 4] = eax
      ebx = [ebp + 8]
      eax = local_1c
  0xa9bb01: CALL lib!+0xb858
      ebx = 0
      ecx = eax
      fld q[ebp + 8]
      fmul [ebx + 0x510190]
      edx or= edx
  0xa9b874: jns  0xa9b887 -> lib!+0xb887
      div [ebx + 0x510194]
      eax add= 0xa955a
      [ecx] = edx
      [ecx + 4] = eax
  0xa9b899: RET -> lib!+0xbb06
      ecx = local_18
      TEST(ecx, ecx)
  0xa9bb0b: jg   0xa9bb31 -> lib!+0xbb31
      eax = ecx
      esi = 7
      cdq 
      idiv esi
      edx inc
      [ebx] = dx
      ecx dec
      bx = 1
      CMP(ecx, 0x23ab1)
      ecx sub= 0x23ab1
      bx add= 0x190
      CMP(ecx, 0x23ab1)
  0xa9bb5d: jge  0xa9bb4c -> lib!+0xbb4c
      ecx sub= 0x23ab1
      bx add= 0x190
      CMP(ecx, 0x23ab1)
  0xa9bb5d: jge  0xa9bb4c -> lib!+0xbb4c
      ecx sub= 0x23ab1
      bx add= 0x190
      CMP(ecx, 0x23ab1)
  0xa9bb5d: jge  0xa9bb4c -> lib!+0xbb4c
      ecx sub= 0x23ab1
      bx add= 0x190
      CMP(ecx, 0x23ab1)
      eax = local_e
      eax = local_10
      dx = 0x8eac
      xchg ecx, eax
  0xa9bb6b: CALL lib!+0x9440
      ebx = edx
      edx = eax
      edx shr= 0x10
      div bx
      ebx = [ebp + 8]
      [ecx] = ax
      [ebx] = dx
  0xa99459: RET -> lib!+0xbb70
      CMP(local_10, 4)
  0xa9bb75: jne  0xa9bb81 -> lib!+0xbb81
      imul ax, local_10, 0x64
      bx add= ax
      eax = local_e
      ecx = local_10
      movzx eax, local_e
      dx = 0x5b5
  0xa9bb98: CALL lib!+0x9440
      ebx = edx
      edx = eax
      edx shr= 0x10
      div bx
      ebx = [ebp + 8]
      [ecx] = ax
      [ebx] = dx
  0xa99459: RET -> lib!+0xbb9d
      ax = local_10
      eax shl= 2
      bx add= ax
      eax = local_e
      ecx = local_10
      movzx eax, local_e
      dx = 0x16d
  0xa9bbb6: CALL lib!+0x9440
      ebx = edx
      edx = eax
      edx shr= 0x10
      div bx
      ebx = [ebp + 8]
      [ecx] = ax
      [ebx] = dx
  0xa99459: RET -> lib!+0xbbbb
      CMP(local_10, 4)
  0xa9bbc0: jne  0xa9bbcc -> lib!+0xbbcc
      bx add= local_10
      eax = ebx
  0xa9bbd2: CALL lib!+0xb9a8
      ecx = eax
      movzx eax, cx
      eax and= 3
      TEST(eax, eax)
  0xa9b9b4: jne  0xa9b9d7 -> lib!+0xb9d7
      eax = 0
  0xa9b9db: RET -> lib!+0xbbd7
      edx = eax
      eax = 0
      al = dl
      eax = [eax + eax*2]
      eax = [eax*8 + 0x5100f4]
      local_14 = eax
      ax = 1
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
      cx = local_10
      local_e sub= cx
      eax inc
  0xa9bc10: jmp  0xa9bbee -> lib!+0xbbee
      movzx ecx, ax
      esi = local_14
      cx = [esi + ecx*2 - 2]
      local_10 = cx
      cx = local_e
      CMP(cx, local_10)
  0xa9bc05: jb   0xa9bc12 -> lib!+0xbc12
      ecx = [ebp - 4]
      [ecx] = bx
      ecx = [ebp - 8]
      [ecx] = ax
      ax = local_e
      eax inc
      ecx = local_c
      [ecx] = ax
      eax = edx
  0xa9bc30: RET -> lib!+0xbc71
      [ebx + 4] dec
      eax = [ebx + 0xe]
      ecx = [ebx + 0xc]
      edx = [ebx + 0xa]
      eax = [ebx + 8]
  0xa9bc88: CALL lib!+0xb94c
      edi = ecx
      esi = edx
      ebx = eax
      eax = [ebp - 4]
      eax = local_c
  0xa9b968: CALL lib!+0xb858
      ebx = 0
      ecx = eax
      fld q[ebp + 8]
      fmul [ebx + 0x510190]
      edx or= edx
  0xa9b874: jns  0xa9b887 -> lib!+0xb887
      div [ebx + 0x510194]
      eax add= 0xa955a
      [ecx] = edx
      [ecx + 4] = eax
  0xa9b899: RET -> lib!+0xb96d
      eax = local_c
      ecx = [ebp - 2]
      dx = 0xea60
  0xa9b977: CALL lib!+0x9440
      ebx = edx
      edx = eax
      edx shr= 0x10
      div bx
      ebx = [ebp + 8]
      [ecx] = ax
      [ebx] = dx
  0xa99459: RET -> lib!+0xb97c
      ecx = ebx
      movzx eax, [ebp - 2]
      dx = 0x3c
  0xa9b987: CALL lib!+0x9440
      ebx = edx
      edx = eax
      edx shr= 0x10
      div bx
      ebx = [ebp + 8]
      [ecx] = ax
      [ebx] = dx
  0xa99459: RET -> lib!+0xb98c
      eax = [ebp + 8]
      ecx = edi
      movzx eax, [ebp - 4]
      dx = 0x3e8
  0xa9b99a: CALL lib!+0x9440
      ebx = edx
      edx = eax
      edx shr= 0x10
      div bx
      ebx = [ebp + 8]
      [ecx] = ax
      [ebx] = dx
  0xa99459: RET -> lib!+0xb99f
  0xa9b9a5: RET -> lib!+0xbc8d
  0xa9bc8f: RET -> lib!+0xadc60
      eax = local_10
  0xb3dc64: CALL lib!+0x7808
  0xa97808: jmp  0xbb6e1b -> lib!+0x126e1b
  0xbb6e1b: jmp  0xbb69ba -> lib!+0x1269ba
  0xbb69c7: CALL lib!+0x129238
      eax = DAT_00bad3b4
  0xbb923e: jmp  0xbb7055 -> lib!+0x127055
  0xbb705b: CALL lib!+0x134648
  0xbc4649: CALL lib!+0x14ce33
      CMP(ch, ah)
      bswap eax
      eax not
      CMP(cl, cl)
  0xbdce4a: jmp  0xbdccca -> lib!+0x14ccca
      CMP(bl, dl)
      eax neg
      CMP(ax, 0x3eaf)
      eax xor= 0x2566e2a
  0xbdccdc: jmp  0xbb7d7e -> lib!+0x127d7e
      rol eax, 7
  0xbb7d81: CALL lib!+0x144e6a
  0xbd4e6a: jmp  0xbe0269 -> lib!+0x150269
      eax inc
      eax neg
  0xbe0270: jmp  0xbe151f -> lib!+0x15151f
      rol eax, 0x13
      TEST(esi, 0x46f93f49)
  0xbe1534: jmp  0xbc2a73 -> lib!+0x132a73
  0xbc2a8b: RET -> lib!+0x127060
  0xbb706e: RET -> SetLocalTime
  // 0x76366f80: 进入 SetLocalTime ; 下一跳 lib!+0xadc69
  0xb3dc6c: RET -> CODE+0x58b36
      eax = 0
  0x458b3e: jmp  0x458b4a -> CODE+0x58b4a
      eax = 0
      eax = local_c
      edx = 2
  0x458b5f: CALL CODE+0x4524
      ebx = eax
      esi = edx
      edx = [ebx]
      TEST(edx, edx)
  0x40452e: je   0x40454a -> CODE+0x454a
      ebx add= 4
      esi dec
  0x40454e: jne  0x40452a -> CODE+0x452a
      edx = [ebx]
      TEST(edx, edx)
  0x40452e: je   0x40454a -> CODE+0x454a
      ebx add= 4
      esi dec
  0x404552: RET -> CODE+0x58b64
  0x458b64: RET -> CODE+0x58b6c
## 已知限制

- 只覆盖实际执行路径，未执行分支不出现；
- 直线语句来自运行期镜像（Smonitor 活镜像 + lib 文件镜像）上相邻控制转移之间的字节，混淆填充已过滤；
- API 调用以“进入 API”注解（RtlEnterCriticalSection/GetModuleFileNameA/VirtualAlloc/SetLocalTime 等）；
- 语句仍是寄存器级，未做变量命名/类型推断，也未恢复 if/while 结构；
- 间接调用优先用 ext 表解析，未解析到的标 (间接->地址)；
- 生成脚本：analysis/tmp/pseudo_lift8.py（输入 analysis/tmp/live2_trace_*.json、smon_live_map.json、smon_api_table.json）。