# 混淆层函数体级伪代码（lifter v16：字段访问 + 带参效果注解 + 表达式合并）

## Q 命令执行路径

局部变量：local_20e5ba63=v0, local_14=v1

goto CODE+0x58a5f
  edx = [ebp - 4]
  eax = ebx
call Q_Handler   /* 预计返回 0x458a69 */
    esi = edx
    ebx = eax
    eax = 0
    eax = [ebp - 4]
    edx = esi
  call CODE+0x46f8   /* 预计返回 0x458877 */
      ecx = 0
      TEST(edx, edx)
      CMP(cl, *edx)
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
    goto CODE+0x46ff   /* 回边：循环 */
    /* 以上转移序列重复 15 次 */
      CMP(cl, *edx)
      CMP(cl, [edx + 1])
    if (相等) goto CODE+0x4719   /* 本次未跳转，继续 CODE+0x471f */
      edx inc
      ecx = edx
      ecx sub= edx
    goto CODE+0x45f0   /* 回边：循环 */
      ebx = eax
      esi = edx
      edi = ecx
      eax = edi
    call CODE+0x45c4   /* 预计返回 0x404600 */
        TEST(eax, eax)
        eax add= 0xa
        eax and= 0xfffffffe
      call CODE+0x2a38   /* 预计返回 0x4045d5 */
          ebx = eax
          TEST(ebx, ebx)
          eax = ebx
        call CODE+0x23e4   /* 预计返回 0x402a48 */
            ebx = eax
            CMP(DAT_0045b5c0, 0)
          if (不相等) goto CODE+0x23ff   /* 本次未跳转，继续 CODE+0x2405 */
            CMP(ebx, 0x7ffffff8)
          if (小于等于) goto CODE+0x2411   /* 本次未跳转，继续 CODE+0x242d */
            edx = 0
            CMP(DAT_0045b049, 0)
          call CODE+0x1368   /* 预计返回 0x402432 */
            goto text0+0x3bec
            goto text0+0xa6a2
              eax = v0
              eax = DAT_0045c15c
            goto text0+0x82ff   /* 回边：循环 */
            call text0+0x7cea   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：配置同步 CopyFileA(user_cfg -> install_cfg) + SetFileSecurityA + WritePrivateProfileStringA(config,ar,1) */
            goto VM_dispatch
              CMP(sp, sp)
              eax sub= 0x12e405f0
              bt eax, 2
              TEST(ebp, 0x1f3b35de)
              eax add= 0x970ad3b9
            call text0+0xd3b4   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：配置同步 CopyFileA(user_cfg -> install_cfg) + SetFileSecurityA + WritePrivateProfileStringA(config,ar,1) */
              eax xor= 0xa4c553d3
            goto text0+0xaf52   /* 回边：循环 */
            return -> text0+0x8304
            call text0+0xa320   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：配置同步 CopyFileA(user_cfg -> install_cfg) + SetFileSecurityA + WritePrivateProfileStringA(config,ar,1) */
            return -> RtlEnterCriticalSection
            /* 进入 RtlEnterCriticalSection */
              ebx add= 7
              ebx and= 0xfffffffc
              CMP(ebx, 0xc)
            if (大于等于) goto CODE+0x2442   /* 本次未跳转，继续 CODE+0x2452 */
              CMP(ebx, 0x1000)
              eax = ebx
              TEST(eax, eax)
            if (非负) goto CODE+0x2457   /* 本次未跳转，继续 CODE+0x246b */
              sar eax, 2
              edx = DAT_0045b620
              edx = [edx + eax*4 - 0xc]
              [ebp - 8] = edx
              CMP([ebp - 8], 0)
            if (相等) goto CODE+0x24fa   /* 本次未跳转，继续 CODE+0x250f */
              CMP(ebx, DAT_0045b618)
              DAT_0045b618 sub= ebx
              CMP(DAT_0045b618, 0xc)
            if (大于等于) goto CODE+0x251e   /* 本次未跳转，继续 CODE+0x254e */
              eax = DAT_0045b61c
              v1 = eax
              DAT_0045b61c add= ebx
              eax = ebx
              eax or= 2
              edx = v1
              *edx = eax
              eax = v1
              eax add= 4
              [ebp - 4] = eax
              DAT_0045b5b0 inc
              ebx sub= 4
              DAT_0045b5b4 add= ebx
            call CODE+0x3f1c   /* 预计返回 0x402553 */
                edx = 0
                ecx add= 5
              call 0x201ffbb1   /* 预计返回 0x403f2e */
/* 表达式合并：0 处 */

- 调用 11，返回 2，匹配 0（其中 tail-jump 0），未闭合帧 8

## S1 命令执行路径

局部变量：local_c=v0

goto CODE+0x58aca
  eax = [ebp - 4]
  CMP(*eax, 1)
  sete al
  ebx->ffb = al
goto CODE+0x58b36
  eax = 0
goto CODE+0x58b4a
  eax = 0
  eax = v0
  edx = 2
call CODE+0x4524   /* 预计返回 0x458b64 */
    ebx = eax
    esi = edx
    edx = *ebx
    TEST(edx, edx)
  if (相等) goto CODE+0x454a   /* 本次未跳转，继续 CODE+0x454e */
    ebx add= 4
    esi dec
  if (不相等) goto CODE+0x452a   /* 本次未跳转，继续 CODE+0x452e */
    edx = *ebx
    TEST(edx, edx)
  if (相等) goto CODE+0x454a   /* 本次未跳转，继续 CODE+0x4552 */
    ebx add= 4
    esi dec
  return   /* 回到 0x458b64 */
return -> CODE+0x58b6c
/* 表达式合并：0 处 */

- 调用 1，返回 2，匹配 1（其中 tail-jump 0），未闭合帧 0

## S0 命令执行路径

局部变量：local_c=v0

goto CODE+0x58aca
  eax = [ebp - 4]
  CMP(*eax, 1)
  sete al
  ebx->ffb = al
goto CODE+0x58b36
  eax = 0
goto CODE+0x58b4a
  eax = 0
  eax = v0
  edx = 2
call CODE+0x4524   /* 预计返回 0x458b64 */
    ebx = eax
    esi = edx
    edx = *ebx
    TEST(edx, edx)
  if (相等) goto CODE+0x454a   /* 本次未跳转，继续 CODE+0x454e */
    ebx add= 4
    esi dec
  if (不相等) goto CODE+0x452a   /* 本次未跳转，继续 CODE+0x452e */
    edx = *ebx
    TEST(edx, edx)
  if (相等) goto CODE+0x454a   /* 本次未跳转，继续 CODE+0x4552 */
    ebx add= 4
    esi dec
  return   /* 回到 0x458b64 */
return -> CODE+0x58b6c
/* 表达式合并：0 处 */

- 调用 1，返回 2，匹配 1（其中 tail-jump 0），未闭合帧 0

## T1 命令执行路径

局部变量：local_20e5ba63=v0

goto CODE+0x58adb
  eax = [ebp - 4]
  CMP(*eax, 1)
  sete al
  ebx->ff8 = al
call PersistAr   /* 预计返回 0x458aef */
    ebx = eax
    eax = 0
    eax = [ebp - 8]
  call CODE+0x581fc   /* 预计返回 0x4583c6 */
      ebx = eax
      eax = 0
      eax = [ebp - 4]
    call R_DirHelper   /* 预计返回 0x45821a */
        ebx = eax
        eax = 0
        edx = [ebp - 4]
        eax = 0
      call CODE+0x2e64   /* 预计返回 0x4581d0 */
          ebx = edx
          esi = eax
          eax = ebx
        call CODE+0x4500   /* 预计返回 0x402e77 */
            edx = *eax
            TEST(edx, edx)
          if (相等) goto CODE+0x4522   /* 本次走跳转分支 */
          return   /* 回到 0x402e77 */
          TEST(esi, esi)
        call CODE+0x126c   /* 预计返回 0x402e8c */
          goto text0+0xb9cf
          call text0+0x96c3   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
            al not
            eax = DAT_0045c1ac
          call text0+0x7cea   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
          goto VM_dispatch
            CMP(sp, sp)
            eax sub= 0x12e405f0
            bt eax, 2
            TEST(ebp, 0x1f3b35de)
            eax add= 0x970ad3b9
          call text0+0xd3b4   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
            eax xor= 0xa4c553d3
          goto text0+0xaf52   /* 回边：循环 */
          return -> text0+0x96da
          call text0+0xb8ea   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
          call text0+0xb888   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
          call text0+0x8677   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
          return -> GetModuleFileNameA
          /* 进入 GetModuleFileNameA */
            ecx = eax
            eax = ebx
          call CODE+0x45f0   /* 预计返回 0x402e99 */
              ebx = eax
              esi = edx
              edi = ecx
              eax = edi
            call CODE+0x45c4   /* 预计返回 0x404600 */
                TEST(eax, eax)
                eax add= 0xa
                eax and= 0xfffffffe
              call CODE+0x2a38   /* 预计返回 0x4045d5 */
                  ebx = eax
                  TEST(ebx, ebx)
                  eax = ebx
                call CODE+0x23e4   /* 预计返回 0x402a48 */
                    ebx = eax
                    CMP(DAT_0045b5c0, 0)
                  if (不相等) goto CODE+0x23ff   /* 本次未跳转，继续 CODE+0x2405 */
                    CMP(ebx, 0x7ffffff8)
                  if (小于等于) goto CODE+0x2411   /* 本次未跳转，继续 CODE+0x242d */
                    edx = 0
                    CMP(DAT_0045b049, 0)
                  call CODE+0x1368   /* 预计返回 0x402432 */
                    goto text0+0x3bec
                    goto text0+0xa6a2
                      eax = v0
                      eax = DAT_0045c15c
                    goto text0+0x82ff   /* 回边：循环 */
                    call text0+0x7cea   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                    goto VM_dispatch
                      CMP(sp, sp)
                      eax sub= 0x12e405f0
                      bt eax, 2
                      TEST(ebp, 0x1f3b35de)
                      eax add= 0x970ad3b9
                    call text0+0xd3b4   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                      eax xor= 0xa4c553d3
                    goto text0+0xaf52   /* 回边：循环 */
                    return -> text0+0x8304
                    call text0+0xa320   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                    return -> RtlEnterCriticalSection
                    /* 进入 RtlEnterCriticalSection */
                      ebx add= 7
                      ebx and= 0xfffffffc
                      CMP(ebx, 0xc)
                    if (大于等于) goto CODE+0x2442   /* 本次未跳转，继续 CODE+0x2448 */
                      CMP(ebx, 0x1000)
                    if (大于) goto CODE+0x24fa   /* 本次未跳转，继续 CODE+0x2500 */
                      CMP(ebx, DAT_0045b618)
                    if (大于) goto CODE+0x2555   /* 本次未跳转，继续 CODE+0x2557 */
                      eax = ebx
                    call CODE+0x229c   /* 预计返回 0x40255c */
                        ebx = eax
                        edi = 0x45b614
                        ebp = 0x45b618
                        eax = DAT_0045b60c
                        *esi = eax
                        eax = *esi
                        CMP(ebx, [eax + 8])
                        eax = *edi
                        *esi = eax
                        eax = *esi
                        eax = [eax + 8]
                        CMP(ebx, eax)
                        edx = *esi
                        [edx + 8] = ebx
                        edx = *esi
                        edx = [edx + 4]
                        *esi = edx
                        edx = *esi
                        CMP(ebx, [edx + 8])
                      if (大于) goto CODE+0x22db   /* 本次未跳转，继续 CODE+0x22f2 */
                        edx = *esi
                        edx = [edx + 4]
                        *esi = edx
                        edx = *esi
                        CMP(ebx, [edx + 8])
                        edx = *edi
                        [edx + 8] = eax
                        eax = *esi
                        CMP(eax, *edi)
                      if (相等) goto CODE+0x22fa   /* 本次未跳转，继续 CODE+0x2300 */
                        CMP(ebx, 0x1000)
                      if (大于) goto CODE+0x2310   /* 本次未跳转，继续 CODE+0x2312 */
                        eax = ebx
                      call CODE+0x2204   /* 预计返回 0x402317 */
                          ebx = eax
                          eax = [ebx + 4]
                        call CODE+0x1908   /* 预计返回 0x402214 */
                            ebx = edx
                            esi = eax
                            ebp = 0x45b5f8
                            esi add= 0x3fff
                            esi and= 0xffffc000
                            eax = *ebp
                            *edi = eax
                          goto CODE+0x196e
                            CMP(ebp, *edi)
                          if (不相等) goto CODE+0x192d   /* 本次未跳转，继续 CODE+0x1932 */
                            eax = *edi
                            CMP(esi, eax->fc)
                          if (大于) goto CODE+0x1968   /* 本次未跳转，继续 CODE+0x1976 */
                            eax = *edi
                            eax = *eax
                            *edi = eax
                            CMP(ebp, *edi)
                            edx = ebx
                            eax = esi
                          call CODE+0x15e8   /* 预计返回 0x40197b */
                              ebx = edx
                              esi = eax
                              CMP(esi, 0x100000)
                            if (大于等于) goto CODE+0x15fe   /* 本次未跳转，继续 CODE+0x1617 */
                              esi add= 0xffff
                              esi and= 0xffff0000
                              [ebx + 4] = esi
                            call CODE+0x1350   /* 预计返回 0x40161c */
                              goto text0+0x967f
                              call text0+0x2a8c   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                              call text0+0xc6a2   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                              call text0+0xbdf3   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                              goto text0+0x7a0e   /* 回边：循环 */
                                movsx ax, dl
                                eax = DAT_0045c168
                              call text0+0xcfbf   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                              call text0+0x7cea   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                              goto VM_dispatch
                                CMP(sp, sp)
                                eax sub= 0x12e405f0
                                bt eax, 2
                                TEST(ebp, 0x1f3b35de)
                                eax add= 0x970ad3b9
                              call text0+0xd3b4   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：WritePrivateProfileStringA(config, ar, enable) + flush */
                                eax xor= 0xa4c553d3
                              goto text0+0xaf52   /* 回边：循环 */
                              return -> text0+0xcfc8
                              return -> VirtualAlloc
                              /* 进入 VirtualAlloc */
                                edi = eax
                                *ebx = edi
                                TEST(edi, edi)
                                edx = ebx
                                eax = 0x45b5e8
                              call CODE+0x140c   /* 预计返回 0x401630 */
                                  esi = edx
                                  ebx = eax
                                call CODE+0x1380   /* 预计返回 0x40141a */
                                    ebx = 0x45b5e4
                                    CMP(*ebx, 0)
                                  if (不相等) goto CODE+0x13e7   /* 本次未跳转，继续 CODE+0x1403 */
                                    eax = *ebx
                                    eax = *eax
                                    *ebx = eax
                                  return   /* 回到 0x40141a */
                                if (不相等) goto CODE+0x1429   /* 本次未跳转，继续 CODE+0x1467 */
                                  eax = *esi
                                  [edx + 8] = eax
                                  eax = [esi + 4]
                                  edx->fc = eax
                                  eax = *ebx
                                  *eax = edx
                                  [eax + 4] = ebx
                                  [eax + 4] = edx
                                  *ebx = eax
                                  al = 1
                                return   /* 回到 0x401630 */
                                TEST(al, al)
                              if (不相等) goto CODE+0x1647   /* 本次未跳转，继续 CODE+0x164a */
                              return -> 0x1
/* 表达式合并：0 处 */

- 调用 33，返回 10，匹配 3（其中 tail-jump 0），未闭合帧 15

## W 命令执行路径

局部变量：local_c=v0, local_28=v1, local_20e5ba63=v2, local_14=v3

goto CODE+0x58b1d
  edx = [ebp - 4]
  eax = ebx
call W_Handler   /* 预计返回 0x458b27 */
    ecx = 0
    v0 = ecx
    v1 = ecx
    [ebp - 4] = ecx
    [ebp - 8] = ecx
    ebx = edx
    eax = 0
    eax = [ebp - 4]
    edx = ebx
  call CODE+0x46f8   /* 预计返回 0x4588f3 */
      ecx = 0
      TEST(edx, edx)
      CMP(cl, *edx)
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
      edx add= 4
    goto CODE+0x46ff   /* 回边：循环 */
    /* 以上转移序列重复 3 次 */
      CMP(cl, *edx)
      CMP(cl, [edx + 1])
      CMP(cl, [edx + 2])
      CMP(cl, [edx + 3])
    if (相等) goto CODE+0x4717   /* 本次未跳转，继续 CODE+0x471f */
      edx inc
      edx inc
      edx inc
      ecx = edx
      ecx sub= edx
    goto CODE+0x45f0   /* 回边：循环 */
      ebx = eax
      esi = edx
      edi = ecx
      eax = edi
    call CODE+0x45c4   /* 预计返回 0x404600 */
        TEST(eax, eax)
        eax add= 0xa
        eax and= 0xfffffffe
      call CODE+0x2a38   /* 预计返回 0x4045d5 */
          ebx = eax
          TEST(ebx, ebx)
          eax = ebx
        call CODE+0x23e4   /* 预计返回 0x402a48 */
            ebx = eax
            CMP(DAT_0045b5c0, 0)
          if (不相等) goto CODE+0x23ff   /* 本次未跳转，继续 CODE+0x2405 */
            CMP(ebx, 0x7ffffff8)
          if (小于等于) goto CODE+0x2411   /* 本次未跳转，继续 CODE+0x242d */
            edx = 0
            CMP(DAT_0045b049, 0)
          call CODE+0x1368   /* 预计返回 0x402432 */
            goto text0+0x3bec
            goto text0+0xa6a2
              eax = v2
              eax = DAT_0045c15c
            goto text0+0x82ff   /* 回边：循环 */
            call text0+0x7cea   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：strcpy(self+0x13d36ac, text)（仅内存） */
            goto VM_dispatch
              CMP(sp, sp)
              eax sub= 0x12e405f0
              bt eax, 2
              TEST(ebp, 0x1f3b35de)
              eax add= 0x970ad3b9
            call text0+0xd3b4   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：strcpy(self+0x13d36ac, text)（仅内存） */
              eax xor= 0xa4c553d3
            goto text0+0xaf52   /* 回边：循环 */
            return -> text0+0x8304
            call text0+0xa320   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：strcpy(self+0x13d36ac, text)（仅内存） */
            return -> RtlEnterCriticalSection
            /* 进入 RtlEnterCriticalSection */
              ebx add= 7
              ebx and= 0xfffffffc
              CMP(ebx, 0xc)
            if (大于等于) goto CODE+0x2442   /* 本次未跳转，继续 CODE+0x2452 */
              CMP(ebx, 0x1000)
              eax = ebx
              TEST(eax, eax)
            if (非负) goto CODE+0x2457   /* 本次未跳转，继续 CODE+0x246b */
              sar eax, 2
              edx = DAT_0045b620
              edx = [edx + eax*4 - 0xc]
              [ebp - 8] = edx
              CMP([ebp - 8], 0)
            if (相等) goto CODE+0x24fa   /* 本次未跳转，继续 CODE+0x250f */
              CMP(ebx, DAT_0045b618)
              DAT_0045b618 sub= ebx
              CMP(DAT_0045b618, 0xc)
            if (大于等于) goto CODE+0x251e   /* 本次未跳转，继续 CODE+0x254e */
              eax = DAT_0045b61c
              v3 = eax
              DAT_0045b61c add= ebx
              eax = ebx
              eax or= 2
              edx = v3
              *edx = eax
              eax = v3
              eax add= 4
              [ebp - 4] = eax
              DAT_0045b5b0 inc
              ebx sub= 4
              DAT_0045b5b4 add= ebx
            call CODE+0x3f1c   /* 预计返回 0x402553 */
                edx = 0
                ecx add= 5
              call 0x201ffb91   /* 预计返回 0x403f2e */
/* 表达式合并：0 处 */

- 调用 11，返回 2，匹配 0（其中 tail-jump 0），未闭合帧 8

## X 命令执行路径

局部变量：local_10=v0, local_c=v1, local_1c=v2, local_18=v3, local_e=v4, local_14=v5

goto CODE+0x58b29
  eax = [ebp - 4]
call CODE+0x57fb8   /* 预计返回 0x458b36 */
  goto text0+0x604e
  goto X_entry
    eax = [edx - 0x630a365c]
    cwde 
    eax = [edx - 0x7e0d2ad9]
    eax = DAT_0045c814
  call text0+0x7cea   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
  goto VM_dispatch
    CMP(sp, sp)
    eax sub= 0x12e405f0
    bt eax, 2
    TEST(ebp, 0x1f3b35de)
    eax add= 0x970ad3b9
  call text0+0xd3b4   /* 混淆层入口，按 tail 语义不展开 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
    eax xor= 0xa4c553d3
  goto text0+0xaf52   /* 回边：循环 */
  return -> text0+0xc87f
  goto text0+0xd2a0
  return -> lib!SetDateTime
    eax = v0
  call lib!+0xbc54   /* 预计返回 0xb3dc60 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
      ebx = eax
      eax = [ebx + 4]
      ecx = [ebx + 6]
      edx = [ebx + 2]
      eax = ebx
    call lib!+0xbae4   /* 预计返回 0xa9bc71 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
        v1 = ecx
        [ebp - 8] = edx
        [ebp - 4] = eax
        ebx = [ebp + 8]
        eax = v2
      call lib!+0xb858   /* 预计返回 0xa9bb06 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ebx = 0
          ecx = eax
          fld q[ebp + 8]
          fmul ebx->f510190
          edx or= edx
        if (非负) goto lib!+0xb887   /* 本次未跳转，继续 lib!+0xb899 */
          div ebx->f510194
          eax add= 0xa955a
          *ecx = edx
          [ecx + 4] = eax
        return   /* 回到 0xa9bb06 */
        ecx = v3
        TEST(ecx, ecx)
      if (大于) goto lib!+0xbb31   /* 本次未跳转，继续 lib!+0xbb5d */
        eax = ecx
        esi = 7
        cdq 
        idiv esi
        edx inc
        *ebx = dx
        ecx dec
        bx = 1
        CMP(ecx, 0x23ab1)
        ecx sub= 0x23ab1
        bx add= 0x190
        CMP(ecx, 0x23ab1)
      if (大于等于) goto lib!+0xbb4c   /* 本次未跳转，继续 lib!+0xbb5d */
      /* 以上转移序列重复 3 次 */
        ecx sub= 0x23ab1
        bx add= 0x190
        CMP(ecx, 0x23ab1)
        eax = v4
        eax = v0
        dx = 0x8eac
        xchg ecx, eax
      call lib!+0x9440   /* 预计返回 0xa9bb70 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ebx = edx
          edx = eax
          edx shr= 0x10
          div bx
          ebx = [ebp + 8]
          *ecx = ax
          *ebx = dx
        return   /* 回到 0xa9bb70 */
        CMP(v0, 4)
      if (不相等) goto lib!+0xbb81   /* 本次未跳转，继续 lib!+0xbb98 */
        imul ax, v0, 0x64
        bx add= ax
        eax = v4
        ecx = v0
        movzx eax, v4
        dx = 0x5b5
      call lib!+0x9440   /* 预计返回 0xa9bb9d */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ebx = edx
          edx = eax
          edx shr= 0x10
          div bx
          ebx = [ebp + 8]
          *ecx = ax
          *ebx = dx
        return   /* 回到 0xa9bb9d */
        ax = v0
        eax shl= 2
        bx add= ax
        eax = v4
        ecx = v0
        movzx eax, v4
        dx = 0x16d
      call lib!+0x9440   /* 预计返回 0xa9bbbb */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ebx = edx
          edx = eax
          edx shr= 0x10
          div bx
          ebx = [ebp + 8]
          *ecx = ax
          *ebx = dx
        return   /* 回到 0xa9bbbb */
        CMP(v0, 4)
      if (不相等) goto lib!+0xbbcc   /* 本次未跳转，继续 lib!+0xbbd2 */
        bx add= v0
        eax = ebx
      call lib!+0xb9a8   /* 预计返回 0xa9bbd7 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ecx = eax
          movzx eax, cx
          eax and= 3
          TEST(eax, eax)
        if (不相等) goto lib!+0xb9d7   /* 本次未跳转，继续 lib!+0xb9db */
          eax = 0
        return   /* 回到 0xa9bbd7 */
        edx = eax
        eax = 0
        al = dl
        eax = [eax + eax*2]
        eax = [eax*8 + 0x5100f4]
        v5 = eax
        ax = 1
        movzx ecx, ax
        esi = v5
        cx = [esi + ecx*2 - 2]
        v0 = cx
        cx = v4
        CMP(cx, v0)
        cx = v0
        v4 sub= cx
        eax inc
      goto lib!+0xbbee   /* 回边：循环 */
      /* 以上转移序列重复 11 次 */
        movzx ecx, ax
        esi = v5
        cx = [esi + ecx*2 - 2]
        v0 = cx
        cx = v4
        CMP(cx, v0)
      if (低于) goto lib!+0xbc12   /* 本次未跳转，继续 lib!+0xbc30 */
        ecx = [ebp - 4]
        *ecx = bx
        ecx = [ebp - 8]
        *ecx = ax
        ax = v4
        eax inc
        ecx = v1
        *ecx = ax
        eax = edx
      return   /* 回到 0xa9bc71 */
      [ebx + 4] dec
      eax = ebx->fe
      ecx = ebx->fc
      edx = ebx->fa
      eax = [ebx + 8]
    call lib!+0xb94c   /* 预计返回 0xa9bc8d */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
        edi = ecx
        esi = edx
        ebx = eax
        eax = [ebp - 4]
        eax = v1
      call lib!+0xb858   /* 预计返回 0xa9b96d */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ebx = 0
          ecx = eax
          fld q[ebp + 8]
          fmul ebx->f510190
          edx or= edx
        if (非负) goto lib!+0xb887   /* 本次未跳转，继续 lib!+0xb899 */
          div ebx->f510194
          eax add= 0xa955a
          *ecx = edx
          [ecx + 4] = eax
        return   /* 回到 0xa9b96d */
        eax = v1
        ecx = [ebp - 2]
        dx = 0xea60
      call lib!+0x9440   /* 预计返回 0xa9b97c */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ebx = edx
          edx = eax
          edx shr= 0x10
          div bx
          ebx = [ebp + 8]
          *ecx = ax
          *ebx = dx
        return   /* 回到 0xa9b97c */
        ecx = ebx
        movzx eax, [ebp - 2]
        dx = 0x3c
      call lib!+0x9440   /* 预计返回 0xa9b98c */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ebx = edx
          edx = eax
          edx shr= 0x10
          div bx
          ebx = [ebp + 8]
          *ecx = ax
          *ebx = dx
        return   /* 回到 0xa9b98c */
        eax = [ebp + 8]
        ecx = edi
        movzx eax, [ebp - 4]
        dx = 0x3e8
      call lib!+0x9440   /* 预计返回 0xa9b99f */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
          ebx = edx
          edx = eax
          edx shr= 0x10
          div bx
          ebx = [ebp + 8]
          *ecx = ax
          *ebx = dx
        return   /* 回到 0xa9b99f */
      return   /* 回到 0xa9bc8d */
    return   /* 回到 0xb3dc60 */
    eax = v0
  call lib!+0x7808   /* 预计返回 0xb3dc69 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
    goto lib!+0x126e1b
    goto lib!+0x1269ba   /* 回边：循环 */
    call lib!+0x129238   /* 预计返回 0xbb69cc */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
        eax = DAT_00bad3b4
      goto lib!+0x127055   /* 回边：循环 */
      call lib!+0x134648   /* 预计返回 0xbb7060 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
        call lib!+0x14ce33   /* 预计返回 0xbc464e */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
            CMP(ch, ah)
            eax not
            CMP(cl, cl)
          goto lib!+0x14ccca   /* 回边：循环 */
            CMP(bl, dl)
            eax neg
            CMP(ax, 0x3eaf)
            eax xor= 0x2566e2a
          goto lib!+0x127d7e   /* 回边：循环 */
            rol eax, 7
          call lib!+0x144e6a   /* 预计返回 0xbb7d86 */   /* 混淆层调用，本命令效果：SetLocalTime(Delphi TDateTime -> SYSTEMTIME) */
            goto lib!+0x150269
              eax inc
              eax neg
            goto lib!+0x15151f
              rol eax, 0x13
              TEST(esi, 0x46f93f49)
            goto lib!+0x132a73   /* 回边：循环 */
            return   /* 回到 0xbb7060 */
      return -> SetLocalTime
      /* 进入 SetLocalTime */
      return   /* 回到 0x458b36 */
  eax = 0
goto CODE+0x58b4a
  eax = 0
  eax = v1
  edx = 2
call CODE+0x4524   /* 预计返回 0x458b64 */
    ebx = eax
    esi = edx
    edx = *ebx
    TEST(edx, edx)
  if (相等) goto CODE+0x454a   /* 本次未跳转，继续 CODE+0x454e */
    ebx add= 4
    esi dec
  if (不相等) goto CODE+0x452a   /* 本次未跳转，继续 CODE+0x452e */
    edx = *ebx
    TEST(edx, edx)
  if (相等) goto CODE+0x454a   /* 本次未跳转，继续 CODE+0x4552 */
    ebx add= 4
    esi dec
  return   /* 回到 0x458b64 */
return -> CODE+0x58b6c
/* 表达式合并：0 处 */

- 调用 21，返回 19，匹配 15（其中 tail-jump 0），未闭合帧 0

## 已知限制与说明

- 混淆层调用注解已带 API 参数（SetLocalTime / RegSetValueExA(Start) / WinExec(net user Guest) / ShellExecuteA 命令行等），但来自同命令的 Unicorn API 轨迹，不保证一一对应到具体调用点；
- 表达式合并规则（自增/自减、mem +/-= K）在本批轨迹命中 0 处；
- 字段访问（ebx->ffb）是寄存器+偏移的机械标注；
- 生成脚本：analysis/tmp/pseudo_funcs12.py。
