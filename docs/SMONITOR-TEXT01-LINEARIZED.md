# Smonitor .text0/.text1 线性化清单（活上下文轨迹反汇编）

由 Unicorn 活镜像具体执行轨迹还原：按真实执行顺序列出每个基本块，并标注调用目标
（lib 导出 / 外部 API / 混淆层块）。

### 轨迹 live2_trace_X.json（81 块，结束 eip=0xdeadbeef）

**块 001  0x4589f8-0x458a38  Smonitor 命令分派器**  
```
  0x4589f8  push     ebp                     
  0x4589f9  mov      ebp, esp                
  0x4589fb  push     0                       
  0x4589fd  push     0                       
  0x4589ff  push     0                       
  0x458a01  push     ebx                     
  0x458a02  push     esi                     
  0x458a03  push     edi                     
  0x458a04  mov      ebx, eax                
  0x458a06  xor      eax, eax                
  0x458a08  push     ebp                     
  0x458a09  push     0x458b65                
  0x458a0e  push     dword ptr fs:[eax]      
  0x458a11  mov      dword ptr fs:[eax], esp 
  0x458a14  xor      ecx, ecx                
  0x458a16  push     ebp                     
  0x458a17  push     0x458b40                
  0x458a1c  push     dword ptr fs:[ecx]      
  0x458a1f  mov      dword ptr fs:[ecx], esp 
  0x458a22  mov      dword ptr [ebp - 4], edx
  0x458a25  inc      dword ptr [ebp - 4]     
  0x458a28  xor      eax, eax                
  0x458a2a  mov      al, byte ptr [edx]      
  0x458a2c  add      eax, -0x51              
  0x458a2f  cmp      eax, 7                  
  0x458a32  ja       0x458b36                
  0x458a38  jmp      dword ptr [eax*4 + 0x458a3f]
```

**块 002  0x458b29-0x458b31  CODE+0x58b29**  
```
  0x458b29  mov      eax, dword ptr [ebp - 4]
  0x458b2c  push     dword ptr [eax + 4]     
  0x458b2f  push     dword ptr [eax]         
  0x458b31  call     0x457fb8                   ; X 混淆入口跳板
```

**块 003  0x457fb8-0x457fb8  X 混淆入口跳板**  
```
  0x457fb8  jmp      0x47404e                   ; X 混淆层入口
```

**块 004  0x47404e-0x47404e  X 混淆层入口**  
```
  0x47404e  jmp      0x47a85b                   ; X 真实处理块
```

**块 005  0x47a85b-0x47a87a  X 真实处理块**  
```
  0x47a85b  push     eax                     
  0x47a85c  lea      eax, [edx - 0x630a365c] 
  0x47a862  cwde                             
  0x47a863  lea      eax, [edx - 0x7e0d2ad9] 
  0x47a869  mov      eax, dword ptr [0x45c814]
  0x47a86e  pushal                           
  0x47a86f  push     dword ptr [esp]         
  0x47a872  mov      byte ptr [esp], 4       
  0x47a876  lea      esp, [esp + 0x24]       
  0x47a87a  call     0x475cea                   ; text0+0x7cea
```

**块 006  0x475cea-0x475cea  text0+0x7cea**  
```
  0x475cea  jmp      0x47b4d1                   ; text0+0xd4d1
```

**块 007  0x47b4d1-0x47b4fb  text0+0xd4d1**  
```
  0x47b4d1  pushfd                           
  0x47b4d2  pushal                           
  0x47b4d3  pushfd                           
  0x47b4d4  pop      dword ptr [esp + 0x20]  
  0x47b4d8  pushal                           
  0x47b4d9  cmp      sp, sp                  
  0x47b4dc  mov      word ptr [esp], si      
  0x47b4e0  sub      eax, 0x12e405f0         
  0x47b4e5  pushfd                           
  0x47b4e6  stc                              
  0x47b4e7  clc                              
  0x47b4e8  bt       eax, 2                  
  0x47b4ec  bswap    eax                     
  0x47b4ee  test     ebp, 0x1f3b35de         
  0x47b4f4  clc                              
  0x47b4f5  add      eax, 0x970ad3b9         
  0x47b4fa  cmc                              
  0x47b4fb  call     0x47b3b4                   ; text0+0xd3b4
```

**块 008  0x47b3b4-0x47b3bb  text0+0xd3b4**  
```
  0x47b3b4  pushfd                           
  0x47b3b5  xor      eax, 0xa4c553d3         
  0x47b3ba  clc                              
  0x47b3bb  jmp      0x478f52                   ; text0+0xaf52
```

**块 009  0x478f52-0x478f6c  text0+0xaf52**  
```
  0x478f52  pushfd                           
  0x478f53  push     dword ptr [esp + 0x50]  
  0x478f57  popfd                            
  0x478f58  mov      byte ptr [esp + 0xc], 0x89
  0x478f5d  mov      byte ptr [esp], 0x3d    
  0x478f61  mov      byte ptr [esp], dl      
  0x478f64  mov      byte ptr [esp + 4], dl  
  0x478f68  push     dword ptr [esp + 0x54]  
  0x478f6c  ret      0x58                    
```

**块 010  0x47a87f-0x47a881  text0+0xc87f**  
```
  0x47a87f  pushfd                           
  0x47a880  pushal                           
  0x47a881  jmp      0x47b2a0                   ; 返回地址 pivot 块
```

**块 011  0x47b2a0-0x47b2b0  返回地址 pivot 块**  
```
  0x47b2a0  xchg     dword ptr [esp + 0x24], eax
  0x47b2a4  mov      byte ptr [esp], cl      
  0x47b2a7  mov      byte ptr [esp + 0x10], 0x6f
  0x47b2ac  push     dword ptr [esp + 0x24]  
  0x47b2b0  ret      0x28                    
```

**块 012  0xb3dc4c-0xb3dc5b  lib!SetDateTime**  
```
  0xb3dc4c  push     ebp                     
  0xb3dc4d  mov      ebp, esp                
  0xb3dc4f  add      esp, -0x10              
  0xb3dc52  push     dword ptr [ebp + 0xc]   
  0xb3dc55  push     dword ptr [ebp + 8]     
  0xb3dc58  lea      eax, [ebp - 0x10]       
  0xb3dc5b  call     0xa9bc54                   ; lib+0xbc54
```

**块 013  0xa9bc54-0xa9bc6c  lib+0xbc54**  
```
  0xa9bc54  push     ebp                     
  0xa9bc55  mov      ebp, esp                
  0xa9bc57  push     ebx                     
  0xa9bc58  mov      ebx, eax                
  0xa9bc5a  push     dword ptr [ebp + 0xc]   
  0xa9bc5d  push     dword ptr [ebp + 8]     
  0xa9bc60  lea      eax, [ebx + 4]          
  0xa9bc63  push     eax                     
  0xa9bc64  lea      ecx, [ebx + 6]          
  0xa9bc67  lea      edx, [ebx + 2]          
  0xa9bc6a  mov      eax, ebx                
  0xa9bc6c  call     0xa9bae4                   ; lib+0xbae4
```

**块 014  0xa9bae4-0xa9bb01  lib+0xbae4**  
```
  0xa9bae4  push     ebp                     
  0xa9bae5  mov      ebp, esp                
  0xa9bae7  add      esp, -0x1c              
  0xa9baea  push     ebx                     
  0xa9baeb  push     esi                     
  0xa9baec  mov      dword ptr [ebp - 0xc], ecx
  0xa9baef  mov      dword ptr [ebp - 8], edx
  0xa9baf2  mov      dword ptr [ebp - 4], eax
  0xa9baf5  mov      ebx, dword ptr [ebp + 8]
  0xa9baf8  push     dword ptr [ebp + 0x10]  
  0xa9bafb  push     dword ptr [ebp + 0xc]   
  0xa9bafe  lea      eax, [ebp - 0x1c]       
  0xa9bb01  call     0xa9b858                   ; lib+0xb858
```

**块 015  0xa9b858-0xa9b874  lib+0xb858**  
```
  0xa9b858  push     ebp                     
  0xa9b859  mov      ebp, esp                
  0xa9b85b  push     ebx                     
  0xa9b85c  xor      ebx, ebx                
  0xa9b85e  mov      ecx, eax                
  0xa9b860  fld      qword ptr [ebp + 8]     
  0xa9b863  fmul     dword ptr [ebx + 0xba0190]
  0xa9b869  sub      esp, 8                  
  0xa9b86c  fistp    qword ptr [esp]         
  0xa9b86f  wait                             
  0xa9b870  pop      eax                     
  0xa9b871  pop      edx                     
  0xa9b872  or       edx, edx                
  0xa9b874  jns      0xa9b887                
```

**块 016  0xa9b887-0xa9b899  lib+0xb887**  
```
  0xa9b887  div      dword ptr [ebx + 0xba0194]
  0xa9b88d  add      eax, 0xa955a            
  0xa9b892  mov      dword ptr [ecx], edx    
  0xa9b894  mov      dword ptr [ecx + 4], eax
  0xa9b897  pop      ebx                     
  0xa9b898  pop      ebp                     
  0xa9b899  ret      8                       
```

**块 017  0xa9bb06-0xa9bb0b  lib+0xbb06**  
```
  0xa9bb06  mov      ecx, dword ptr [ebp - 0x18]
  0xa9bb09  test     ecx, ecx                
  0xa9bb0b  jg       0xa9bb31                
```

**块 018  0xa9bb31-0xa9bb5d  lib+0xbb31**  
```
  0xa9bb31  mov      eax, ecx                
  0xa9bb33  mov      esi, 7                  
  0xa9bb38  cdq                              
  0xa9bb39  idiv     esi                     
  0xa9bb3b  inc      edx                     
  0xa9bb3c  mov      word ptr [ebx], dx      
  0xa9bb3f  dec      ecx                     
  0xa9bb40  mov      bx, 1                   
  0xa9bb44  cmp      ecx, 0x23ab1            
  0xa9bb4a  jl       0xa9bb5f                
  0xa9bb4c  sub      ecx, 0x23ab1            
  0xa9bb52  add      bx, 0x190               
  0xa9bb57  cmp      ecx, 0x23ab1            
  0xa9bb5d  jge      0xa9bb4c                
```

**块 019  0xa9bb4c-0xa9bb5d  lib+0xbb4c**  
```
  0xa9bb4c  sub      ecx, 0x23ab1            
  0xa9bb52  add      bx, 0x190               
  0xa9bb57  cmp      ecx, 0x23ab1            
  0xa9bb5d  jge      0xa9bb4c                
```

**块 020  0xa9bb4c-0xa9bb5d  lib+0xbb4c**  
```
  0xa9bb4c  sub      ecx, 0x23ab1            
  0xa9bb52  add      bx, 0x190               
  0xa9bb57  cmp      ecx, 0x23ab1            
  0xa9bb5d  jge      0xa9bb4c                
```

**块 021  0xa9bb4c-0xa9bb6b  lib+0xbb4c**  
```
  0xa9bb4c  sub      ecx, 0x23ab1            
  0xa9bb52  add      bx, 0x190               
  0xa9bb57  cmp      ecx, 0x23ab1            
  0xa9bb5d  jge      0xa9bb4c                
  0xa9bb5f  lea      eax, [ebp - 0xe]        
  0xa9bb62  push     eax                     
  0xa9bb63  lea      eax, [ebp - 0x10]       
  0xa9bb66  mov      dx, 0x8eac              
  0xa9bb6a  xchg     ecx, eax                
  0xa9bb6b  call     0xa99440                   ; lib+0x9440
```

**块 022  0xa99440-0xa99459  lib+0x9440**  
```
  0xa99440  push     ebp                     
  0xa99441  mov      ebp, esp                
  0xa99443  push     ebx                     
  0xa99444  mov      ebx, edx                
  0xa99446  mov      edx, eax                
  0xa99448  shr      edx, 0x10               
  0xa9944b  div      bx                      
  0xa9944e  mov      ebx, dword ptr [ebp + 8]
  0xa99451  mov      word ptr [ecx], ax      
  0xa99454  mov      word ptr [ebx], dx      
  0xa99457  pop      ebx                     
  0xa99458  pop      ebp                     
  0xa99459  ret      4                       
```

**块 023  0xa9bb70-0xa9bb75  lib+0xbb70**  
```
  0xa9bb70  cmp      word ptr [ebp - 0x10], 4
  0xa9bb75  jne      0xa9bb81                
```

**块 024  0xa9bb81-0xa9bb98  lib+0xbb81**  
```
  0xa9bb81  imul     ax, word ptr [ebp - 0x10], 0x64
  0xa9bb86  add      bx, ax                  
  0xa9bb89  lea      eax, [ebp - 0xe]        
  0xa9bb8c  push     eax                     
  0xa9bb8d  lea      ecx, [ebp - 0x10]       
  0xa9bb90  movzx    eax, word ptr [ebp - 0xe]
  0xa9bb94  mov      dx, 0x5b5               
  0xa9bb98  call     0xa99440                   ; lib+0x9440
```

**块 025  0xa99440-0xa99459  lib+0x9440**  
```
  0xa99440  push     ebp                     
  0xa99441  mov      ebp, esp                
  0xa99443  push     ebx                     
  0xa99444  mov      ebx, edx                
  0xa99446  mov      edx, eax                
  0xa99448  shr      edx, 0x10               
  0xa9944b  div      bx                      
  0xa9944e  mov      ebx, dword ptr [ebp + 8]
  0xa99451  mov      word ptr [ecx], ax      
  0xa99454  mov      word ptr [ebx], dx      
  0xa99457  pop      ebx                     
  0xa99458  pop      ebp                     
  0xa99459  ret      4                       
```

**块 026  0xa9bb9d-0xa9bbb6  lib+0xbb9d**  
```
  0xa9bb9d  mov      ax, word ptr [ebp - 0x10]
  0xa9bba1  shl      eax, 2                  
  0xa9bba4  add      bx, ax                  
  0xa9bba7  lea      eax, [ebp - 0xe]        
  0xa9bbaa  push     eax                     
  0xa9bbab  lea      ecx, [ebp - 0x10]       
  0xa9bbae  movzx    eax, word ptr [ebp - 0xe]
  0xa9bbb2  mov      dx, 0x16d               
  0xa9bbb6  call     0xa99440                   ; lib+0x9440
```

**块 027  0xa99440-0xa99459  lib+0x9440**  
```
  0xa99440  push     ebp                     
  0xa99441  mov      ebp, esp                
  0xa99443  push     ebx                     
  0xa99444  mov      ebx, edx                
  0xa99446  mov      edx, eax                
  0xa99448  shr      edx, 0x10               
  0xa9944b  div      bx                      
  0xa9944e  mov      ebx, dword ptr [ebp + 8]
  0xa99451  mov      word ptr [ecx], ax      
  0xa99454  mov      word ptr [ebx], dx      
  0xa99457  pop      ebx                     
  0xa99458  pop      ebp                     
  0xa99459  ret      4                       
```

**块 028  0xa9bbbb-0xa9bbc0  lib+0xbbbb**  
```
  0xa9bbbb  cmp      word ptr [ebp - 0x10], 4
  0xa9bbc0  jne      0xa9bbcc                
```

**块 029  0xa9bbcc-0xa9bbd2  lib+0xbbcc**  
```
  0xa9bbcc  add      bx, word ptr [ebp - 0x10]
  0xa9bbd0  mov      eax, ebx                
  0xa9bbd2  call     0xa9b9a8                   ; lib+0xb9a8
```

**块 030  0xa9b9a8-0xa9b9b4  lib+0xb9a8**  
```
  0xa9b9a8  push     ebx                     
  0xa9b9a9  push     esi                     
  0xa9b9aa  mov      ecx, eax                
  0xa9b9ac  movzx    eax, cx                 
  0xa9b9af  and      eax, 3                  
  0xa9b9b2  test     eax, eax                
  0xa9b9b4  jne      0xa9b9d7                
```

**块 031  0xa9b9d7-0xa9b9db  lib+0xb9d7**  
```
  0xa9b9d7  xor      eax, eax                
  0xa9b9d9  pop      esi                     
  0xa9b9da  pop      ebx                     
  0xa9b9db  ret                              
```

**块 032  0xa9bbd7-0xa9bc10  lib+0xbbd7**  
```
  0xa9bbd7  mov      edx, eax                
  0xa9bbd9  xor      eax, eax                
  0xa9bbdb  mov      al, dl                  
  0xa9bbdd  lea      eax, [eax + eax*2]      
  0xa9bbe0  lea      eax, [eax*8 + 0xba00f4] 
  0xa9bbe7  mov      dword ptr [ebp - 0x14], eax
  0xa9bbea  mov      ax, 1                   
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 033  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 034  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 035  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 036  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 037  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 038  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 039  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 040  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 041  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 042  0xa9bbee-0xa9bc10  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
  0xa9bc07  mov      cx, word ptr [ebp - 0x10]
  0xa9bc0b  sub      word ptr [ebp - 0xe], cx
  0xa9bc0f  inc      eax                     
  0xa9bc10  jmp      0xa9bbee                   ; lib+0xbbee
```

**块 043  0xa9bbee-0xa9bc05  lib+0xbbee**  
```
  0xa9bbee  movzx    ecx, ax                 
  0xa9bbf1  mov      esi, dword ptr [ebp - 0x14]
  0xa9bbf4  mov      cx, word ptr [esi + ecx*2 - 2]
  0xa9bbf9  mov      word ptr [ebp - 0x10], cx
  0xa9bbfd  mov      cx, word ptr [ebp - 0xe]
  0xa9bc01  cmp      cx, word ptr [ebp - 0x10]
  0xa9bc05  jb       0xa9bc12                
```

**块 044  0xa9bc12-0xa9bc30  lib+0xbc12**  
```
  0xa9bc12  mov      ecx, dword ptr [ebp - 4]
  0xa9bc15  mov      word ptr [ecx], bx      
  0xa9bc18  mov      ecx, dword ptr [ebp - 8]
  0xa9bc1b  mov      word ptr [ecx], ax      
  0xa9bc1e  mov      ax, word ptr [ebp - 0xe]
  0xa9bc22  inc      eax                     
  0xa9bc23  mov      ecx, dword ptr [ebp - 0xc]
  0xa9bc26  mov      word ptr [ecx], ax      
  0xa9bc29  mov      eax, edx                
  0xa9bc2b  pop      esi                     
  0xa9bc2c  pop      ebx                     
  0xa9bc2d  mov      esp, ebp                
  0xa9bc2f  pop      ebp                     
  0xa9bc30  ret      0xc                     
```

**块 045  0xa9bc71-0xa9bc88  lib+0xbc71**  
```
  0xa9bc71  dec      word ptr [ebx + 4]      
  0xa9bc75  push     dword ptr [ebp + 0xc]   
  0xa9bc78  push     dword ptr [ebp + 8]     
  0xa9bc7b  lea      eax, [ebx + 0xe]        
  0xa9bc7e  push     eax                     
  0xa9bc7f  lea      ecx, [ebx + 0xc]        
  0xa9bc82  lea      edx, [ebx + 0xa]        
  0xa9bc85  lea      eax, [ebx + 8]          
  0xa9bc88  call     0xa9b94c                   ; lib+0xb94c
```

**块 046  0xa9b94c-0xa9b968  lib+0xb94c**  
```
  0xa9b94c  push     ebp                     
  0xa9b94d  mov      ebp, esp                
  0xa9b94f  add      esp, -0xc               
  0xa9b952  push     ebx                     
  0xa9b953  push     esi                     
  0xa9b954  push     edi                     
  0xa9b955  mov      edi, ecx                
  0xa9b957  mov      esi, edx                
  0xa9b959  mov      ebx, eax                
  0xa9b95b  lea      eax, [ebp - 4]          
  0xa9b95e  push     eax                     
  0xa9b95f  push     dword ptr [ebp + 0x10]  
  0xa9b962  push     dword ptr [ebp + 0xc]   
  0xa9b965  lea      eax, [ebp - 0xc]        
  0xa9b968  call     0xa9b858                   ; lib+0xb858
```

**块 047  0xa9b858-0xa9b874  lib+0xb858**  
```
  0xa9b858  push     ebp                     
  0xa9b859  mov      ebp, esp                
  0xa9b85b  push     ebx                     
  0xa9b85c  xor      ebx, ebx                
  0xa9b85e  mov      ecx, eax                
  0xa9b860  fld      qword ptr [ebp + 8]     
  0xa9b863  fmul     dword ptr [ebx + 0xba0190]
  0xa9b869  sub      esp, 8                  
  0xa9b86c  fistp    qword ptr [esp]         
  0xa9b86f  wait                             
  0xa9b870  pop      eax                     
  0xa9b871  pop      edx                     
  0xa9b872  or       edx, edx                
  0xa9b874  jns      0xa9b887                
```

**块 048  0xa9b887-0xa9b899  lib+0xb887**  
```
  0xa9b887  div      dword ptr [ebx + 0xba0194]
  0xa9b88d  add      eax, 0xa955a            
  0xa9b892  mov      dword ptr [ecx], edx    
  0xa9b894  mov      dword ptr [ecx + 4], eax
  0xa9b897  pop      ebx                     
  0xa9b898  pop      ebp                     
  0xa9b899  ret      8                       
```

**块 049  0xa9b96d-0xa9b977  lib+0xb96d**  
```
  0xa9b96d  mov      eax, dword ptr [ebp - 0xc]
  0xa9b970  lea      ecx, [ebp - 2]          
  0xa9b973  mov      dx, 0xea60              
  0xa9b977  call     0xa99440                   ; lib+0x9440
```

**块 050  0xa99440-0xa99459  lib+0x9440**  
```
  0xa99440  push     ebp                     
  0xa99441  mov      ebp, esp                
  0xa99443  push     ebx                     
  0xa99444  mov      ebx, edx                
  0xa99446  mov      edx, eax                
  0xa99448  shr      edx, 0x10               
  0xa9944b  div      bx                      
  0xa9944e  mov      ebx, dword ptr [ebp + 8]
  0xa99451  mov      word ptr [ecx], ax      
  0xa99454  mov      word ptr [ebx], dx      
  0xa99457  pop      ebx                     
  0xa99458  pop      ebp                     
  0xa99459  ret      4                       
```

**块 051  0xa9b97c-0xa9b987  lib+0xb97c**  
```
  0xa9b97c  push     esi                     
  0xa9b97d  mov      ecx, ebx                
  0xa9b97f  movzx    eax, word ptr [ebp - 2] 
  0xa9b983  mov      dx, 0x3c                
  0xa9b987  call     0xa99440                   ; lib+0x9440
```

**块 052  0xa99440-0xa99459  lib+0x9440**  
```
  0xa99440  push     ebp                     
  0xa99441  mov      ebp, esp                
  0xa99443  push     ebx                     
  0xa99444  mov      ebx, edx                
  0xa99446  mov      edx, eax                
  0xa99448  shr      edx, 0x10               
  0xa9944b  div      bx                      
  0xa9944e  mov      ebx, dword ptr [ebp + 8]
  0xa99451  mov      word ptr [ecx], ax      
  0xa99454  mov      word ptr [ebx], dx      
  0xa99457  pop      ebx                     
  0xa99458  pop      ebp                     
  0xa99459  ret      4                       
```

**块 053  0xa9b98c-0xa9b99a  lib+0xb98c**  
```
  0xa9b98c  mov      eax, dword ptr [ebp + 8]
  0xa9b98f  push     eax                     
  0xa9b990  mov      ecx, edi                
  0xa9b992  movzx    eax, word ptr [ebp - 4] 
  0xa9b996  mov      dx, 0x3e8               
  0xa9b99a  call     0xa99440                   ; lib+0x9440
```

**块 054  0xa99440-0xa99459  lib+0x9440**  
```
  0xa99440  push     ebp                     
  0xa99441  mov      ebp, esp                
  0xa99443  push     ebx                     
  0xa99444  mov      ebx, edx                
  0xa99446  mov      edx, eax                
  0xa99448  shr      edx, 0x10               
  0xa9944b  div      bx                      
  0xa9944e  mov      ebx, dword ptr [ebp + 8]
  0xa99451  mov      word ptr [ecx], ax      
  0xa99454  mov      word ptr [ebx], dx      
  0xa99457  pop      ebx                     
  0xa99458  pop      ebp                     
  0xa99459  ret      4                       
```

**块 055  0xa9b99f-0xa9b9a5  lib+0xb99f**  
```
  0xa9b99f  pop      edi                     
  0xa9b9a0  pop      esi                     
  0xa9b9a1  pop      ebx                     
  0xa9b9a2  mov      esp, ebp                
  0xa9b9a4  pop      ebp                     
  0xa9b9a5  ret      0xc                     
```

**块 056  0xa9bc8d-0xa9bc8f  lib+0xbc8d**  
```
  0xa9bc8d  pop      ebx                     
  0xa9bc8e  pop      ebp                     
  0xa9bc8f  ret      8                       
```

**块 057  0xb3dc60-0xb3dc64  lib+0xadc60**  
```
  0xb3dc60  lea      eax, [ebp - 0x10]       
  0xb3dc63  push     eax                     
  0xb3dc64  call     0xa97808                   ; lib+0x7808
```

**块 058  0xa97808-0xa97808  lib+0x7808**  
```
  0xa97808  jmp      0xbb6e1b                   ; lib+0x126e1b
```

**块 059  0xbb6e1b-0xbb6e1b  lib+0x126e1b**  
```
  0xbb6e1b  jmp      0xbb69ba                   ; lib+0x1269ba
```

**块 060  0xbb69ba-0xbb69c7  lib+0x1269ba**  
```
  0xbb69ba  pushfd                           
  0xbb69bb  pushfd                           
  0xbb69bc  xchg     dword ptr [esp + 4], eax
  0xbb69c0  lea      eax, [esp - 0x3d54c5f2] 
  0xbb69c7  call     0xbb9238                   ; lib+0x129238
```

**块 061  0xbb9238-0xbb923e  lib+0x129238**  
```
  0xbb9238  mov      eax, dword ptr [0xbad3b4]
  0xbb923d  pushal                           
  0xbb923e  jmp      0xbb7055                   ; lib+0x127055
```

**块 062  0xbb7055-0xbb705b  lib+0x127055**  
```
  0xbb7055  push     ecx                     
  0xbb7056  pushfd                           
  0xbb7057  lea      esp, [esp + 0x30]       
  0xbb705b  call     0xbc4648                   ; lib+0x134648
```

**块 063  0xbc4648-0xbc4649  lib+0x134648**  
```
  0xbc4648  pushal                           
  0xbc4649  call     0xbdce33                   ; lib+0x14ce33
```

**块 064  0xbdce33-0xbdce4a  lib+0x14ce33**  
```
  0xbdce33  pushal                           
  0xbdce34  pushfd                           
  0xbdce35  pushfd                           
  0xbdce36  pop      dword ptr [esp + 0x44]  
  0xbdce3a  clc                              
  0xbdce3b  cmp      ch, ah                  
  0xbdce3d  bswap    eax                     
  0xbdce3f  stc                              
  0xbdce40  push     0xcc2099b1              
  0xbdce45  stc                              
  0xbdce46  not      eax                     
  0xbdce48  cmp      cl, cl                  
  0xbdce4a  jmp      0xbdccca                   ; lib+0x14ccca
```

**块 065  0xbdccca-0xbdccdc  lib+0x14ccca**  
```
  0xbdccca  cmp      bl, dl                  
  0xbdcccc  neg      eax                     
  0xbdccce  cmp      ax, 0x3eaf              
  0xbdccd2  mov      byte ptr [esp + 4], dl  
  0xbdccd6  xor      eax, 0x2566e2a          
  0xbdccdb  stc                              
  0xbdccdc  jmp      0xbb7d7e                   ; lib+0x127d7e
```

**块 066  0xbb7d7e-0xbb7d81  lib+0x127d7e**  
```
  0xbb7d7e  rol      eax, 7                  
  0xbb7d81  call     0xbd4e6a                   ; lib+0x144e6a
```

**块 067  0xbd4e6a-0xbd4e6a  lib+0x144e6a**  
```
  0xbd4e6a  jmp      0xbe0269                   ; lib+0x150269
```

**块 068  0xbe0269-0xbe0270  lib+0x150269**  
```
  0xbe0269  push     edx                     
  0xbe026a  inc      eax                     
  0xbe026b  mov      dword ptr [esp], esi    
  0xbe026e  neg      eax                     
  0xbe0270  jmp      0xbe151f                   ; lib+0x15151f
```

**块 069  0xbe151f-0xbe1534  lib+0x15151f**  
```
  0xbe151f  mov      word ptr [esp], 0xd5e7  
  0xbe1525  cmc                              
  0xbe1526  rol      eax, 0x13               
  0xbe1529  mov      byte ptr [esp + 8], 0x42
  0xbe152e  test     esi, 0x46f93f49         
  0xbe1534  jmp      0xbc2a73                   ; lib+0x132a73
```

**块 070  0xbc2a73-0xbc2a8b  lib+0x132a73**  
```
  0xbc2a73  push     dword ptr [esp + 0x50]  
  0xbc2a77  popfd                            
  0xbc2a78  mov      word ptr [esp + 8], di  
  0xbc2a7d  mov      byte ptr [esp], bl      
  0xbc2a80  mov      byte ptr [esp + 0x14], dl
  0xbc2a84  mov      byte ptr [esp], ch      
  0xbc2a87  push     dword ptr [esp + 0x54]  
  0xbc2a8b  ret      0x58                    
```

**块 071  0xbb7060-0xbb706e  lib+0x127060**  
```
  0xbb7060  push     0xa78c6806              
  0xbb7065  xchg     dword ptr [esp + 4], eax
  0xbb7069  pushal                           
  0xbb706a  push     dword ptr [esp + 0x24]  
  0xbb706e  ret      0x28                    
```

**块 072  0x76366f80-0x76366f80  API:SetLocalTime**  

(无法反汇编)


**块 073  0xb3dc69-0xb3dc6c  lib+0xadc69**  
```
  0xb3dc69  mov      esp, ebp                
  0xb3dc6b  pop      ebp                     
  0xb3dc6c  ret      8                       
```

**块 074  0x458b36-0x458b3e  CODE+0x58b36**  
```
  0x458b36  xor      eax, eax                
  0x458b38  pop      edx                     
  0x458b39  pop      ecx                     
  0x458b3a  pop      ecx                     
  0x458b3b  mov      dword ptr fs:[eax], edx 
  0x458b3e  jmp      0x458b4a                   ; CODE+0x58b4a
```

**块 075  0x458b4a-0x458b5f  CODE+0x58b4a**  
```
  0x458b4a  xor      eax, eax                
  0x458b4c  pop      edx                     
  0x458b4d  pop      ecx                     
  0x458b4e  pop      ecx                     
  0x458b4f  mov      dword ptr fs:[eax], edx 
  0x458b52  push     0x458b6c                
  0x458b57  lea      eax, [ebp - 0xc]        
  0x458b5a  mov      edx, 2                  
  0x458b5f  call     0x404524                   ; CODE+0x4524
```

**块 076  0x404524-0x40452e  CODE+0x4524**  
```
  0x404524  push     ebx                     
  0x404525  push     esi                     
  0x404526  mov      ebx, eax                
  0x404528  mov      esi, edx                
  0x40452a  mov      edx, dword ptr [ebx]    
  0x40452c  test     edx, edx                
  0x40452e  je       0x40454a                
```

**块 077  0x40454a-0x40454e  CODE+0x454a**  
```
  0x40454a  add      ebx, 4                  
  0x40454d  dec      esi                     
  0x40454e  jne      0x40452a                
```

**块 078  0x40452a-0x40452e  CODE+0x452a**  
```
  0x40452a  mov      edx, dword ptr [ebx]    
  0x40452c  test     edx, edx                
  0x40452e  je       0x40454a                
```

**块 079  0x40454a-0x404552  CODE+0x454a**  
```
  0x40454a  add      ebx, 4                  
  0x40454d  dec      esi                     
  0x40454e  jne      0x40452a                
  0x404550  pop      esi                     
  0x404551  pop      ebx                     
  0x404552  ret                              
```

**块 080  0x458b64-0x458b64  CODE+0x58b64**  
```
  0x458b64  ret                              
```

**块 081  0x458b6c-0xdeadbeef  CODE+0x58b6c**  
```
  0x458b6c  pop      edi                     
  0x458b6d  pop      esi                     
  0x458b6e  pop      ebx                     
  0x458b6f  mov      esp, ebp                
  0x458b71  pop      ebp                     
  0x458b72  ret                              
  0x458b73  add      byte ptr [ebx + 0x74], dl
  0x458b76  jne      0x458bdc                
  0x458b78  outsb    dx, byte ptr gs:[esi]   
  0x458b7a  je       0x458baa                
  0x458b7c  js       0x458be4                
  0x458b7f  add      byte ptr [ecx + ebp*2 + 0x62], ch
  0x458b83  insb     byte ptr es:[edi], dx   
  0x458b86  insb     byte ptr es:[edi], dx   
  0x458b87  add      byte ptr [ebp - 0x75], dl
  0x458b8a  in       al, dx                  
  0x458b8b  xor      eax, eax                
  0x458b8d  push     ebp                     
  0x458b8e  push     0x458bad                
  0x458b93  push     dword ptr fs:[eax]      
  0x458b96  mov      dword ptr fs:[eax], esp 
  0x458b99  inc      dword ptr [0x45bc14]    
  0x458b9f  xor      eax, eax                
  0x458ba1  pop      edx                     
  0x458ba2  pop      ecx                     
  0x458ba3  pop      ecx                     
  0x458ba4  mov      dword ptr fs:[eax], edx 
  0x458ba7  push     0x458bb4                
  0x458bac  ret                              
  0x458bad  jmp      0x403e38                   ; CODE+0x3e38
  0x458bb2  jmp      0x458bac                   ; CODE+0x58bac
  0x458bb4  pop      ebp                     
  0x458bb5  ret                              
  0x458bb6  mov      eax, eax                
  0x458bb8  sub      dword ptr [0x45bc14], 1 
  0x458bbf  ret                              
  0x458bc0  push     ebp                     
  0x458bc1  mov      ebp, esp                
  0x458bc3  xor      eax, eax                
  0x458bc5  push     ebp                     
  0x458bc6  push     0x458bdf                
  0x458bcb  push     dword ptr fs:[eax]      
  0x458bce  mov      dword ptr fs:[eax], esp 
  0x458bd1  xor      eax, eax                
  0x458bd3  pop      edx                     
  0x458bd4  pop      ecx                     
  0x458bd5  pop      ecx                     
  0x458bd6  mov      dword ptr fs:[eax], edx 
  0x458bd9  push     0x458be6                
  0x458bde  ret                              
  0x458bdf  jmp      0x403e38                   ; CODE+0x3e38
  0x458be4  jmp      0x458bde                   ; CODE+0x58bde
  0x458be6  pop      ebp                     
  0x458be7  ret                              
  0x458be8  add      byte ptr ds:[eax], al   
  0x458beb  add      al, dh                  
  0x458bed  mov      eax, dword ptr [ebp]    
  0x458bf0  js       0x458c56                
  0x458bf2  inc      eax                     
  0x458bf3  add      byte ptr [eax + 0x64], cl
  0x458bf6  inc      eax                     
  0x458bf7  add      byte ptr [edx + 0x40], dl
  0x458bfb  add      byte ptr [eax], al      
  0x458bfd  bound    eax, qword ptr [eax]    
```


---

### 轨迹 api3_trace_W.json（140 块，结束 eip=0xdeadbeef）

**块 001  0x4589f8-0x458a38  Smonitor 命令分派器**  
```
  0x4589f8  push     ebp                     
  0x4589f9  mov      ebp, esp                
  0x4589fb  push     0                       
  0x4589fd  push     0                       
  0x4589ff  push     0                       
  0x458a01  push     ebx                     
  0x458a02  push     esi                     
  0x458a03  push     edi                     
  0x458a04  mov      ebx, eax                
  0x458a06  xor      eax, eax                
  0x458a08  push     ebp                     
  0x458a09  push     0x458b65                
  0x458a0e  push     dword ptr fs:[eax]      
  0x458a11  mov      dword ptr fs:[eax], esp 
  0x458a14  xor      ecx, ecx                
  0x458a16  push     ebp                     
  0x458a17  push     0x458b40                
  0x458a1c  push     dword ptr fs:[ecx]      
  0x458a1f  mov      dword ptr fs:[ecx], esp 
  0x458a22  mov      dword ptr [ebp - 4], edx
  0x458a25  inc      dword ptr [ebp - 4]     
  0x458a28  xor      eax, eax                
  0x458a2a  mov      al, byte ptr [edx]      
  0x458a2c  add      eax, -0x51              
  0x458a2f  cmp      eax, 7                  
  0x458a32  ja       0x458b36                
  0x458a38  jmp      dword ptr [eax*4 + 0x458a3f]
```

**块 002  0x458b1d-0x458b22  CODE+0x58b1d**  
```
  0x458b1d  mov      edx, dword ptr [ebp - 4]
  0x458b20  mov      eax, ebx                
  0x458b22  call     0x4588c4                   ; W 处理器
```

**块 003  0x4588c4-0x4588ee  W 处理器**  
```
  0x4588c4  push     ebp                     
  0x4588c5  mov      ebp, esp                
  0x4588c7  add      esp, -0x28              
  0x4588ca  push     ebx                     
  0x4588cb  xor      ecx, ecx                
  0x4588cd  mov      dword ptr [ebp - 0xc], ecx
  0x4588d0  mov      dword ptr [ebp - 0x28], ecx
  0x4588d3  mov      dword ptr [ebp - 4], ecx
  0x4588d6  mov      dword ptr [ebp - 8], ecx
  0x4588d9  mov      ebx, edx                
  0x4588db  xor      eax, eax                
  0x4588dd  push     ebp                     
  0x4588de  push     0x4589c6                
  0x4588e3  push     dword ptr fs:[eax]      
  0x4588e6  mov      dword ptr fs:[eax], esp 
  0x4588e9  lea      eax, [ebp - 4]          
  0x4588ec  mov      edx, ebx                
  0x4588ee  call     0x4046f8                   ; CODE+0x46f8
```

**块 004  0x4046f8-0x404715  CODE+0x46f8**  
```
  0x4046f8  xor      ecx, ecx                
  0x4046fa  test     edx, edx                
  0x4046fc  je       0x40471f                
  0x4046fe  push     edx                     
  0x4046ff  cmp      cl, byte ptr [edx]      
  0x404701  je       0x40471a                
  0x404703  cmp      cl, byte ptr [edx + 1]  
  0x404706  je       0x404719                
  0x404708  cmp      cl, byte ptr [edx + 2]  
  0x40470b  je       0x404718                
  0x40470d  cmp      cl, byte ptr [edx + 3]  
  0x404710  je       0x404717                
  0x404712  add      edx, 4                  
  0x404715  jmp      0x4046ff                   ; CODE+0x46ff
```

**块 005  0x4046ff-0x404715  CODE+0x46ff**  
```
  0x4046ff  cmp      cl, byte ptr [edx]      
  0x404701  je       0x40471a                
  0x404703  cmp      cl, byte ptr [edx + 1]  
  0x404706  je       0x404719                
  0x404708  cmp      cl, byte ptr [edx + 2]  
  0x40470b  je       0x404718                
  0x40470d  cmp      cl, byte ptr [edx + 3]  
  0x404710  je       0x404717                
  0x404712  add      edx, 4                  
  0x404715  jmp      0x4046ff                   ; CODE+0x46ff
```

**块 006  0x4046ff-0x404715  CODE+0x46ff**  
```
  0x4046ff  cmp      cl, byte ptr [edx]      
  0x404701  je       0x40471a                
  0x404703  cmp      cl, byte ptr [edx + 1]  
  0x404706  je       0x404719                
  0x404708  cmp      cl, byte ptr [edx + 2]  
  0x40470b  je       0x404718                
  0x40470d  cmp      cl, byte ptr [edx + 3]  
  0x404710  je       0x404717                
  0x404712  add      edx, 4                  
  0x404715  jmp      0x4046ff                   ; CODE+0x46ff
```

**块 007  0x4046ff-0x404710  CODE+0x46ff**  
```
  0x4046ff  cmp      cl, byte ptr [edx]      
  0x404701  je       0x40471a                
  0x404703  cmp      cl, byte ptr [edx + 1]  
  0x404706  je       0x404719                
  0x404708  cmp      cl, byte ptr [edx + 2]  
  0x40470b  je       0x404718                
  0x40470d  cmp      cl, byte ptr [edx + 3]  
  0x404710  je       0x404717                
```

**块 008  0x404717-0x40471f  CODE+0x4717**  
```
  0x404717  inc      edx                     
  0x404718  inc      edx                     
  0x404719  inc      edx                     
  0x40471a  mov      ecx, edx                
  0x40471c  pop      edx                     
  0x40471d  sub      ecx, edx                
  0x40471f  jmp      0x4045f0                   ; CODE+0x45f0
```

**块 009  0x4045f0-0x4045fb  CODE+0x45f0**  
```
  0x4045f0  push     ebx                     
  0x4045f1  push     esi                     
  0x4045f2  push     edi                     
  0x4045f3  mov      ebx, eax                
  0x4045f5  mov      esi, edx                
  0x4045f7  mov      edi, ecx                
  0x4045f9  mov      eax, edi                
  0x4045fb  call     0x4045c4                   ; CODE+0x45c4
```

**块 010  0x4045c4-0x4045d0  CODE+0x45c4**  
```
  0x4045c4  test     eax, eax                
  0x4045c6  jle      0x4045ec                
  0x4045c8  push     eax                     
  0x4045c9  add      eax, 0xa                
  0x4045cc  and      eax, 0xfffffffe         
  0x4045cf  push     eax                     
  0x4045d0  call     0x402a38                   ; CODE+0x2a38
```

**块 011  0x402a38-0x402a42  CODE+0x2a38**  
```
  0x402a38  push     ebx                     
  0x402a39  push     ecx                     
  0x402a3a  mov      ebx, eax                
  0x402a3c  test     ebx, ebx                
  0x402a3e  jle      0x402a5a                
  0x402a40  mov      eax, ebx                
  0x402a42  call     dword ptr [0x45903c]    
```

**块 012  0x4023e4-0x4023f4  CODE+0x23e4**  
```
  0x4023e4  push     ebp                     
  0x4023e5  mov      ebp, esp                
  0x4023e7  add      esp, -0x14              
  0x4023ea  push     ebx                     
  0x4023eb  mov      ebx, eax                
  0x4023ed  cmp      byte ptr [0x45b5c0], 0  
  0x4023f4  jne      0x4023ff                
```

**块 013  0x4023ff-0x402405  CODE+0x23ff**  
```
  0x4023ff  cmp      ebx, 0x7ffffff8         
  0x402405  jle      0x402411                
```

**块 014  0x402411-0x40242d  CODE+0x2411**  
```
  0x402411  xor      edx, edx                
  0x402413  push     ebp                     
  0x402414  push     0x402580                
  0x402419  push     dword ptr fs:[edx]      
  0x40241c  mov      dword ptr fs:[edx], esp 
  0x40241f  cmp      byte ptr [0x45b049], 0  
  0x402426  je       0x402432                
  0x402428  push     0x45b5c8                
  0x40242d  call     0x401368                   ; CODE+0x1368
```

**块 015  0x401368-0x401368  CODE+0x1368**  
```
  0x401368  jmp      0x471bec                   ; Q/W 混淆链入口
```

**块 016  0x471bec-0x471bec  Q/W 混淆链入口**  
```
  0x471bec  jmp      0x4786a2                   ; text0+0xa6a2
```

**块 017  0x4786a2-0x4786ae  text0+0xa6a2**  
```
  0x4786a2  push     eax                     
  0x4786a3  lea      eax, [ebp - 0x20e5ba63] 
  0x4786a9  mov      eax, dword ptr [0x45c15c]
  0x4786ae  jmp      0x4762ff                   ; text0+0x82ff
```

**块 018  0x4762ff-0x4762ff  text0+0x82ff**  
```
  0x4762ff  call     0x475cea                   ; text0+0x7cea
```

**块 019  0x475cea-0x475cea  text0+0x7cea**  
```
  0x475cea  jmp      0x47b4d1                   ; text0+0xd4d1
```

**块 020  0x47b4d1-0x47b4fb  text0+0xd4d1**  
```
  0x47b4d1  pushfd                           
  0x47b4d2  pushal                           
  0x47b4d3  pushfd                           
  0x47b4d4  pop      dword ptr [esp + 0x20]  
  0x47b4d8  pushal                           
  0x47b4d9  cmp      sp, sp                  
  0x47b4dc  mov      word ptr [esp], si      
  0x47b4e0  sub      eax, 0x12e405f0         
  0x47b4e5  pushfd                           
  0x47b4e6  stc                              
  0x47b4e7  clc                              
  0x47b4e8  bt       eax, 2                  
  0x47b4ec  bswap    eax                     
  0x47b4ee  test     ebp, 0x1f3b35de         
  0x47b4f4  clc                              
  0x47b4f5  add      eax, 0x970ad3b9         
  0x47b4fa  cmc                              
  0x47b4fb  call     0x47b3b4                   ; text0+0xd3b4
```

**块 021  0x47b3b4-0x47b3bb  text0+0xd3b4**  
```
  0x47b3b4  pushfd                           
  0x47b3b5  xor      eax, 0xa4c553d3         
  0x47b3ba  clc                              
  0x47b3bb  jmp      0x478f52                   ; text0+0xaf52
```

**块 022  0x478f52-0x478f6c  text0+0xaf52**  
```
  0x478f52  pushfd                           
  0x478f53  push     dword ptr [esp + 0x50]  
  0x478f57  popfd                            
  0x478f58  mov      byte ptr [esp + 0xc], 0x89
  0x478f5d  mov      byte ptr [esp], 0x3d    
  0x478f61  mov      byte ptr [esp], dl      
  0x478f64  mov      byte ptr [esp + 4], dl  
  0x478f68  push     dword ptr [esp + 0x54]  
  0x478f6c  ret      0x58                    
```

**块 023  0x476304-0x476305  text0+0x8304**  
```
  0x476304  push     esi                     
  0x476305  call     0x478320                   ; text0+0xa320
```

**块 024  0x478320-0x478337  text0+0xa320**  
```
  0x478320  push     0x238c010a              
  0x478325  mov      byte ptr [esp], 0x22    
  0x478329  xchg     dword ptr [esp + 0xc], eax
  0x47832d  pushal                           
  0x47832e  mov      byte ptr [esp + 4], 0x52
  0x478333  push     dword ptr [esp + 0x2c]  
  0x478337  ret      0x30                    
```

**块 025  0x776b00c0-0x402432  API:RtlEnterCriticalSection**  

(无法反汇编)


**块 026  0x402432-0x40243b  CODE+0x2432**  
```
  0x402432  add      ebx, 7                  
  0x402435  and      ebx, 0xfffffffc         
  0x402438  cmp      ebx, 0xc                
  0x40243b  jge      0x402442                
```

**块 027  0x402442-0x402452  CODE+0x2442**  
```
  0x402442  cmp      ebx, 0x1000             
  0x402448  jg       0x4024fa                
  0x40244e  mov      eax, ebx                
  0x402450  test     eax, eax                
  0x402452  jns      0x402457                
```

**块 028  0x402457-0x40246b  CODE+0x2457**  
```
  0x402457  sar      eax, 2                  
  0x40245a  mov      edx, dword ptr [0x45b620]
  0x402460  mov      edx, dword ptr [edx + eax*4 - 0xc]
  0x402464  mov      dword ptr [ebp - 8], edx
  0x402467  cmp      dword ptr [ebp - 8], 0  
  0x40246b  je       0x4024fa                
```

**块 029  0x4024fa-0x40250f  CODE+0x24fa**  
```
  0x4024fa  cmp      ebx, dword ptr [0x45b618]
  0x402500  jg       0x402555                
  0x402502  sub      dword ptr [0x45b618], ebx
  0x402508  cmp      dword ptr [0x45b618], 0xc
  0x40250f  jge      0x40251e                
```

**块 030  0x40251e-0x40254e  CODE+0x251e**  
```
  0x40251e  mov      eax, dword ptr [0x45b61c]
  0x402523  mov      dword ptr [ebp - 0x14], eax
  0x402526  add      dword ptr [0x45b61c], ebx
  0x40252c  mov      eax, ebx                
  0x40252e  or       eax, 2                  
  0x402531  mov      edx, dword ptr [ebp - 0x14]
  0x402534  mov      dword ptr [edx], eax    
  0x402536  mov      eax, dword ptr [ebp - 0x14]
  0x402539  add      eax, 4                  
  0x40253c  mov      dword ptr [ebp - 4], eax
  0x40253f  inc      dword ptr [0x45b5b0]    
  0x402545  sub      ebx, 4                  
  0x402548  add      dword ptr [0x45b5b4], ebx
  0x40254e  call     0x403f1c                   ; CODE+0x3f1c
```

**块 031  0x403f1c-0x403f2c  CODE+0x3f1c**  
```
  0x403f1c  xor      edx, edx                
  0x403f1e  mov      ecx, dword ptr [esp + 8]
  0x403f22  mov      eax, dword ptr [esp + 4]
  0x403f26  add      ecx, 5                  
  0x403f29  mov      dword ptr fs:[edx], eax 
  0x403f2c  call     ecx                     
```

**块 032  0x402585-0x402585  CODE+0x2585**  
```
  0x402585  jmp      0x40256c                   ; CODE+0x256c
```

**块 033  0x40256c-0x40257a  CODE+0x256c**  
```
  0x40256c  cmp      byte ptr [0x45b049], 0  
  0x402573  je       0x40257f                
  0x402575  push     0x45b5c8                
  0x40257a  call     0x401370                   ; CODE+0x1370
```

**块 034  0x401370-0x401370  CODE+0x1370**  
```
  0x401370  jmp      0x4745c3                   ; text0+0x65c3
```

**块 035  0x4745c3-0x4745c3  text0+0x65c3**  
```
  0x4745c3  jmp      0x4706ab                   ; text0+0x26ab
```

**块 036  0x4706ab-0x4706ba  text0+0x26ab**  
```
  0x4706ab  push     eax                     
  0x4706ac  mov      ah, bl                  
  0x4706ae  not      eax                     
  0x4706b0  mov      eax, dword ptr [0x45c158]
  0x4706b5  pushfd                           
  0x4706b6  lea      esp, [esp + 4]          
  0x4706ba  call     0x475cea                   ; text0+0x7cea
```

**块 037  0x475cea-0x475cea  text0+0x7cea**  
```
  0x475cea  jmp      0x47b4d1                   ; text0+0xd4d1
```

**块 038  0x47b4d1-0x47b4fb  text0+0xd4d1**  
```
  0x47b4d1  pushfd                           
  0x47b4d2  pushal                           
  0x47b4d3  pushfd                           
  0x47b4d4  pop      dword ptr [esp + 0x20]  
  0x47b4d8  pushal                           
  0x47b4d9  cmp      sp, sp                  
  0x47b4dc  mov      word ptr [esp], si      
  0x47b4e0  sub      eax, 0x12e405f0         
  0x47b4e5  pushfd                           
  0x47b4e6  stc                              
  0x47b4e7  clc                              
  0x47b4e8  bt       eax, 2                  
  0x47b4ec  bswap    eax                     
  0x47b4ee  test     ebp, 0x1f3b35de         
  0x47b4f4  clc                              
  0x47b4f5  add      eax, 0x970ad3b9         
  0x47b4fa  cmc                              
  0x47b4fb  call     0x47b3b4                   ; text0+0xd3b4
```

**块 039  0x47b3b4-0x47b3bb  text0+0xd3b4**  
```
  0x47b3b4  pushfd                           
  0x47b3b5  xor      eax, 0xa4c553d3         
  0x47b3ba  clc                              
  0x47b3bb  jmp      0x478f52                   ; text0+0xaf52
```

**块 040  0x478f52-0x478f6c  text0+0xaf52**  
```
  0x478f52  pushfd                           
  0x478f53  push     dword ptr [esp + 0x50]  
  0x478f57  popfd                            
  0x478f58  mov      byte ptr [esp + 0xc], 0x89
  0x478f5d  mov      byte ptr [esp], 0x3d    
  0x478f61  mov      byte ptr [esp], dl      
  0x478f64  mov      byte ptr [esp + 4], dl  
  0x478f68  push     dword ptr [esp + 0x54]  
  0x478f6c  ret      0x58                    
```

**块 041  0x4706bf-0x4706bf  text0+0x26bf**  
```
  0x4706bf  call     0x471ef1                   ; text0+0x3ef1
```

**块 042  0x471ef1-0x471f01  text0+0x3ef1**  
```
  0x471ef1  xchg     dword ptr [esp + 4], eax
  0x471ef5  mov      byte ptr [esp], al      
  0x471ef8  mov      byte ptr [esp], 0xbc    
  0x471efc  pushal                           
  0x471efd  push     dword ptr [esp + 0x24]  
  0x471f01  ret      0x28                    
```

**块 043  0x776ae8c0-0x40257f  API:RtlLeaveCriticalSection**  

(无法反汇编)


**块 044  0x40257f-0x40257f  CODE+0x257f**  
```
  0x40257f  ret                              
```

**块 045  0x403f2e-0x403f2e  CODE+0x3f2e**  
```
  0x403f2e  ret      0xc                     
```

**块 046  0x402553-0x402553  CODE+0x2553**  
```
  0x402553  jmp      0x402587                   ; CODE+0x2587
```

**块 047  0x402587-0x40258e  CODE+0x2587**  
```
  0x402587  mov      eax, dword ptr [ebp - 4]
  0x40258a  pop      ebx                     
  0x40258b  mov      esp, ebp                
  0x40258d  pop      ebp                     
  0x40258e  ret                              
```

**块 048  0x402a48-0x402a4f  CODE+0x2a48**  
```
  0x402a48  mov      dword ptr [esp], eax    
  0x402a4b  cmp      dword ptr [esp], 0      
  0x402a4f  jne      0x402a5f                
```

**块 049  0x402a5f-0x402a64  CODE+0x2a5f**  
```
  0x402a5f  mov      eax, dword ptr [esp]    
  0x402a62  pop      edx                     
  0x402a63  pop      ebx                     
  0x402a64  ret                              
```

**块 050  0x4045d5-0x4045eb  CODE+0x45d5**  
```
  0x4045d5  pop      edx                     
  0x4045d6  mov      word ptr [edx + eax - 2], 0
  0x4045dd  add      eax, 8                  
  0x4045e0  pop      edx                     
  0x4045e1  mov      dword ptr [eax - 4], edx
  0x4045e4  mov      dword ptr [eax - 8], 1  
  0x4045eb  ret                              
```

**块 051  0x404600-0x40460c  CODE+0x4600**  
```
  0x404600  mov      ecx, edi                
  0x404602  mov      edi, eax                
  0x404604  test     esi, esi                
  0x404606  je       0x404611                
  0x404608  mov      edx, eax                
  0x40460a  mov      eax, esi                
  0x40460c  call     0x402c58                   ; CODE+0x2c58
```

**块 052  0x402c58-0x402c6b  CODE+0x2c58**  
```
  0x402c58  push     esi                     
  0x402c59  push     edi                     
  0x402c5a  mov      esi, eax                
  0x402c5c  mov      edi, edx                
  0x402c5e  mov      eax, ecx                
  0x402c60  cmp      edi, esi                
  0x402c62  ja       0x402c77                
  0x402c64  je       0x402c95                
  0x402c66  sar      ecx, 2                  
  0x402c69  js       0x402c95                
  0x402c6b  rep movsd dword ptr es:[edi], dword ptr [esi]
```

**块 053  0x402c6b-0x402c6b  CODE+0x2c6b**  
```
  0x402c6b  rep movsd dword ptr es:[edi], dword ptr [esi]
```

**块 054  0x402c6b-0x402c6b  CODE+0x2c6b**  
```
  0x402c6b  rep movsd dword ptr es:[edi], dword ptr [esi]
```

**块 055  0x402c6b-0x402c72  CODE+0x2c6b**  
```
  0x402c6b  rep movsd dword ptr es:[edi], dword ptr [esi]
  0x402c6d  mov      ecx, eax                
  0x402c6f  and      ecx, 3                  
  0x402c72  rep movsb byte ptr es:[edi], byte ptr [esi]
```

**块 056  0x402c72-0x402c72  CODE+0x2c72**  
```
  0x402c72  rep movsb byte ptr es:[edi], byte ptr [esi]
```

**块 057  0x402c72-0x402c72  CODE+0x2c72**  
```
  0x402c72  rep movsb byte ptr es:[edi], byte ptr [esi]
```

**块 058  0x402c72-0x402c76  CODE+0x2c72**  
```
  0x402c72  rep movsb byte ptr es:[edi], byte ptr [esi]
  0x402c74  pop      edi                     
  0x402c75  pop      esi                     
  0x402c76  ret                              
```

**块 059  0x404611-0x404613  CODE+0x4611**  
```
  0x404611  mov      eax, ebx                
  0x404613  call     0x404500                   ; CODE+0x4500
```

**块 060  0x404500-0x404504  CODE+0x4500**  
```
  0x404500  mov      edx, dword ptr [eax]    
  0x404502  test     edx, edx                
  0x404504  je       0x404522                
```

**块 061  0x404522-0x404522  CODE+0x4522**  
```
  0x404522  ret                              
```

**块 062  0x404618-0x40461d  CODE+0x4618**  
```
  0x404618  mov      dword ptr [ebx], edi    
  0x40461a  pop      edi                     
  0x40461b  pop      esi                     
  0x40461c  pop      ebx                     
  0x40461d  ret                              
```

**块 063  0x4588f3-0x4588fb  CODE+0x588f3**  
```
  0x4588f3  mov      edx, dword ptr [ebp - 4]
  0x4588f6  mov      eax, 0x4589dc           
  0x4588fb  call     0x404b04                   ; CODE+0x4b04
```

**块 064  0x404b04-0x404b24  CODE+0x4b04**  
```
  0x404b04  test     eax, eax                
  0x404b06  je       0x404b48                
  0x404b08  test     edx, edx                
  0x404b0a  je       0x404b3d                
  0x404b0c  push     ebx                     
  0x404b0d  push     esi                     
  0x404b0e  push     edi                     
  0x404b0f  mov      esi, eax                
  0x404b11  mov      edi, edx                
  0x404b13  mov      ecx, dword ptr [edi - 4]
  0x404b16  push     edi                     
  0x404b17  mov      edx, dword ptr [esi - 4]
  0x404b1a  dec      edx                     
  0x404b1b  js       0x404b38                
  0x404b1d  mov      al, byte ptr [esi]      
  0x404b1f  inc      esi                     
  0x404b20  sub      ecx, edx                
  0x404b22  jle      0x404b38                
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 065  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 066  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 067  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 068  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 069  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 070  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 071  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 072  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 073  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 074  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 075  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 076  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 077  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 078  0x404b24-0x404b24  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
```

**块 079  0x404b24-0x404b26  CODE+0x4b24**  
```
  0x404b24  repne scasb al, byte ptr es:[edi]   
  0x404b26  jne      0x404b38                
```

**块 080  0x404b38-0x404b3b  CODE+0x4b38**  
```
  0x404b38  pop      edx                     
  0x404b39  xor      eax, eax                
  0x404b3b  jmp      0x404b45                   ; CODE+0x4b45
```

**块 081  0x404b45-0x404b48  CODE+0x4b45**  
```
  0x404b45  pop      edi                     
  0x404b46  pop      esi                     
  0x404b47  pop      ebx                     
  0x404b48  ret                              
```

**块 082  0x458900-0x458905  CODE+0x58900**  
```
  0x458900  mov      ebx, eax                
  0x458902  cmp      ebx, 1                  
  0x458905  jl       0x4589a3                
```

**块 083  0x4589a3-0x4589b3  CODE+0x589a3**  
```
  0x4589a3  xor      eax, eax                
  0x4589a5  pop      edx                     
  0x4589a6  pop      ecx                     
  0x4589a7  pop      ecx                     
  0x4589a8  mov      dword ptr fs:[eax], edx 
  0x4589ab  push     0x4589cd                
  0x4589b0  lea      eax, [ebp - 0x28]       
  0x4589b3  call     0x404500                   ; CODE+0x4500
```

**块 084  0x404500-0x404504  CODE+0x4500**  
```
  0x404500  mov      edx, dword ptr [eax]    
  0x404502  test     edx, edx                
  0x404504  je       0x404522                
```

**块 085  0x404522-0x404522  CODE+0x4522**  
```
  0x404522  ret                              
```

**块 086  0x4589b8-0x4589c0  CODE+0x589b8**  
```
  0x4589b8  lea      eax, [ebp - 0xc]        
  0x4589bb  mov      edx, 3                  
  0x4589c0  call     0x404524                   ; CODE+0x4524
```

**块 087  0x404524-0x40452e  CODE+0x4524**  
```
  0x404524  push     ebx                     
  0x404525  push     esi                     
  0x404526  mov      ebx, eax                
  0x404528  mov      esi, edx                
  0x40452a  mov      edx, dword ptr [ebx]    
  0x40452c  test     edx, edx                
  0x40452e  je       0x40454a                
```

**块 088  0x40454a-0x40454e  CODE+0x454a**  
```
  0x40454a  add      ebx, 4                  
  0x40454d  dec      esi                     
  0x40454e  jne      0x40452a                
```

**块 089  0x40452a-0x40452e  CODE+0x452a**  
```
  0x40452a  mov      edx, dword ptr [ebx]    
  0x40452c  test     edx, edx                
  0x40452e  je       0x40454a                
```

**块 090  0x40454a-0x40454e  CODE+0x454a**  
```
  0x40454a  add      ebx, 4                  
  0x40454d  dec      esi                     
  0x40454e  jne      0x40452a                
```

**块 091  0x40452a-0x404545  CODE+0x452a**  
```
  0x40452a  mov      edx, dword ptr [ebx]    
  0x40452c  test     edx, edx                
  0x40452e  je       0x40454a                
  0x404530  mov      dword ptr [ebx], 0      
  0x404536  mov      ecx, dword ptr [edx - 8]
  0x404539  dec      ecx                     
  0x40453a  jl       0x40454a                
  0x40453c  lock dec dword ptr [edx - 8]     
  0x404540  jne      0x40454a                
  0x404542  lea      eax, [edx - 8]          
  0x404545  call     0x402a68                   ; CODE+0x2a68
```

**块 092  0x402a68-0x402a6d  CODE+0x2a68**  
```
  0x402a68  push     ebx                     
  0x402a69  test     eax, eax                
  0x402a6b  je       0x402a82                
  0x402a6d  call     dword ptr [0x459040]    
```

**块 093  0x402590-0x4025a7  CODE+0x2590**  
```
  0x402590  push     ebp                     
  0x402591  mov      ebp, esp                
  0x402593  add      esp, -0x10              
  0x402596  push     ebx                     
  0x402597  mov      ebx, eax                
  0x402599  xor      eax, eax                
  0x40259b  mov      dword ptr [0x45b5c4], eax
  0x4025a0  cmp      byte ptr [0x45b5c0], 0  
  0x4025a7  jne      0x4025c8                
```

**块 094  0x4025c8-0x4025e4  CODE+0x25c8**  
```
  0x4025c8  xor      edx, edx                
  0x4025ca  push     ebp                     
  0x4025cb  push     0x402757                
  0x4025d0  push     dword ptr fs:[edx]      
  0x4025d3  mov      dword ptr fs:[edx], esp 
  0x4025d6  cmp      byte ptr [0x45b049], 0  
  0x4025dd  je       0x4025e9                
  0x4025df  push     0x45b5c8                
  0x4025e4  call     0x401368                   ; CODE+0x1368
```

**块 095  0x401368-0x401368  CODE+0x1368**  
```
  0x401368  jmp      0x471bec                   ; Q/W 混淆链入口
```

**块 096  0x471bec-0x471bec  Q/W 混淆链入口**  
```
  0x471bec  jmp      0x4786a2                   ; text0+0xa6a2
```

**块 097  0x4786a2-0x4786ae  text0+0xa6a2**  
```
  0x4786a2  push     eax                     
  0x4786a3  lea      eax, [ebp - 0x20e5ba63] 
  0x4786a9  mov      eax, dword ptr [0x45c15c]
  0x4786ae  jmp      0x4762ff                   ; text0+0x82ff
```

**块 098  0x4762ff-0x4762ff  text0+0x82ff**  
```
  0x4762ff  call     0x475cea                   ; text0+0x7cea
```

**块 099  0x475cea-0x475cea  text0+0x7cea**  
```
  0x475cea  jmp      0x47b4d1                   ; text0+0xd4d1
```

**块 100  0x47b4d1-0x47b4fb  text0+0xd4d1**  
```
  0x47b4d1  pushfd                           
  0x47b4d2  pushal                           
  0x47b4d3  pushfd                           
  0x47b4d4  pop      dword ptr [esp + 0x20]  
  0x47b4d8  pushal                           
  0x47b4d9  cmp      sp, sp                  
  0x47b4dc  mov      word ptr [esp], si      
  0x47b4e0  sub      eax, 0x12e405f0         
  0x47b4e5  pushfd                           
  0x47b4e6  stc                              
  0x47b4e7  clc                              
  0x47b4e8  bt       eax, 2                  
  0x47b4ec  bswap    eax                     
  0x47b4ee  test     ebp, 0x1f3b35de         
  0x47b4f4  clc                              
  0x47b4f5  add      eax, 0x970ad3b9         
  0x47b4fa  cmc                              
  0x47b4fb  call     0x47b3b4                   ; text0+0xd3b4
```

**块 101  0x47b3b4-0x47b3bb  text0+0xd3b4**  
```
  0x47b3b4  pushfd                           
  0x47b3b5  xor      eax, 0xa4c553d3         
  0x47b3ba  clc                              
  0x47b3bb  jmp      0x478f52                   ; text0+0xaf52
```

**块 102  0x478f52-0x478f6c  text0+0xaf52**  
```
  0x478f52  pushfd                           
  0x478f53  push     dword ptr [esp + 0x50]  
  0x478f57  popfd                            
  0x478f58  mov      byte ptr [esp + 0xc], 0x89
  0x478f5d  mov      byte ptr [esp], 0x3d    
  0x478f61  mov      byte ptr [esp], dl      
  0x478f64  mov      byte ptr [esp + 4], dl  
  0x478f68  push     dword ptr [esp + 0x54]  
  0x478f6c  ret      0x58                    
```

**块 103  0x476304-0x476305  text0+0x8304**  
```
  0x476304  push     esi                     
  0x476305  call     0x478320                   ; text0+0xa320
```

**块 104  0x478320-0x478337  text0+0xa320**  
```
  0x478320  push     0x238c010a              
  0x478325  mov      byte ptr [esp], 0x22    
  0x478329  xchg     dword ptr [esp + 0xc], eax
  0x47832d  pushal                           
  0x47832e  mov      byte ptr [esp + 4], 0x52
  0x478333  push     dword ptr [esp + 0x2c]  
  0x478337  ret      0x30                    
```

**块 105  0x776b00c0-0x4025e9  API:RtlEnterCriticalSection**  

(无法反汇编)


**块 106  0x4025e9-0x4025fd  CODE+0x25e9**  
```
  0x4025e9  mov      dword ptr [ebp - 8], ebx
  0x4025ec  mov      eax, dword ptr [ebp - 8]
  0x4025ef  sub      eax, 4                  
  0x4025f2  mov      dword ptr [ebp - 8], eax
  0x4025f5  mov      eax, dword ptr [ebp - 8]
  0x4025f8  mov      ebx, dword ptr [eax]    
  0x4025fa  test     bl, 2                   
  0x4025fd  jne      0x40260e                
```

**块 107  0x40260e-0x402627  CODE+0x260e**  
```
  0x40260e  dec      dword ptr [0x45b5b0]    
  0x402614  mov      eax, ebx                
  0x402616  and      eax, 0x7ffffffc         
  0x40261b  sub      eax, 4                  
  0x40261e  sub      dword ptr [0x45b5b4], eax
  0x402624  test     bl, 1                   
  0x402627  je       0x40267c                
```

**块 108  0x40267c-0x4026ab  CODE+0x267c**  
```
  0x40267c  and      ebx, 0x7ffffffc         
  0x402682  mov      eax, dword ptr [ebp - 8]
  0x402685  add      eax, ebx                
  0x402687  mov      dword ptr [ebp - 0xc], eax
  0x40268a  mov      eax, dword ptr [ebp - 0xc]
  0x40268d  cmp      eax, dword ptr [0x45b61c]
  0x402693  jne      0x4026c1                
  0x402695  sub      dword ptr [0x45b61c], ebx
  0x40269b  add      dword ptr [0x45b618], ebx
  0x4026a1  cmp      dword ptr [0x45b618], 0x3c00
  0x4026ab  jle      0x4026b2                
```

**块 109  0x4026b2-0x4026b7  CODE+0x26b2**  
```
  0x4026b2  xor      eax, eax                
  0x4026b4  mov      dword ptr [ebp - 4], eax
  0x4026b7  call     0x403f1c                   ; CODE+0x3f1c
```

**块 110  0x403f1c-0x403f2c  CODE+0x3f1c**  
```
  0x403f1c  xor      edx, edx                
  0x403f1e  mov      ecx, dword ptr [esp + 8]
  0x403f22  mov      eax, dword ptr [esp + 4]
  0x403f26  add      ecx, 5                  
  0x403f29  mov      dword ptr fs:[edx], eax 
  0x403f2c  call     ecx                     
```

**块 111  0x40275c-0x40275c  CODE+0x275c**  
```
  0x40275c  jmp      0x402743                   ; CODE+0x2743
```

**块 112  0x402743-0x402751  CODE+0x2743**  
```
  0x402743  cmp      byte ptr [0x45b049], 0  
  0x40274a  je       0x402756                
  0x40274c  push     0x45b5c8                
  0x402751  call     0x401370                   ; CODE+0x1370
```

**块 113  0x401370-0x401370  CODE+0x1370**  
```
  0x401370  jmp      0x4745c3                   ; text0+0x65c3
```

**块 114  0x4745c3-0x4745c3  text0+0x65c3**  
```
  0x4745c3  jmp      0x4706ab                   ; text0+0x26ab
```

**块 115  0x4706ab-0x4706ba  text0+0x26ab**  
```
  0x4706ab  push     eax                     
  0x4706ac  mov      ah, bl                  
  0x4706ae  not      eax                     
  0x4706b0  mov      eax, dword ptr [0x45c158]
  0x4706b5  pushfd                           
  0x4706b6  lea      esp, [esp + 4]          
  0x4706ba  call     0x475cea                   ; text0+0x7cea
```

**块 116  0x475cea-0x475cea  text0+0x7cea**  
```
  0x475cea  jmp      0x47b4d1                   ; text0+0xd4d1
```

**块 117  0x47b4d1-0x47b4fb  text0+0xd4d1**  
```
  0x47b4d1  pushfd                           
  0x47b4d2  pushal                           
  0x47b4d3  pushfd                           
  0x47b4d4  pop      dword ptr [esp + 0x20]  
  0x47b4d8  pushal                           
  0x47b4d9  cmp      sp, sp                  
  0x47b4dc  mov      word ptr [esp], si      
  0x47b4e0  sub      eax, 0x12e405f0         
  0x47b4e5  pushfd                           
  0x47b4e6  stc                              
  0x47b4e7  clc                              
  0x47b4e8  bt       eax, 2                  
  0x47b4ec  bswap    eax                     
  0x47b4ee  test     ebp, 0x1f3b35de         
  0x47b4f4  clc                              
  0x47b4f5  add      eax, 0x970ad3b9         
  0x47b4fa  cmc                              
  0x47b4fb  call     0x47b3b4                   ; text0+0xd3b4
```

**块 118  0x47b3b4-0x47b3bb  text0+0xd3b4**  
```
  0x47b3b4  pushfd                           
  0x47b3b5  xor      eax, 0xa4c553d3         
  0x47b3ba  clc                              
  0x47b3bb  jmp      0x478f52                   ; text0+0xaf52
```

**块 119  0x478f52-0x478f6c  text0+0xaf52**  
```
  0x478f52  pushfd                           
  0x478f53  push     dword ptr [esp + 0x50]  
  0x478f57  popfd                            
  0x478f58  mov      byte ptr [esp + 0xc], 0x89
  0x478f5d  mov      byte ptr [esp], 0x3d    
  0x478f61  mov      byte ptr [esp], dl      
  0x478f64  mov      byte ptr [esp + 4], dl  
  0x478f68  push     dword ptr [esp + 0x54]  
  0x478f6c  ret      0x58                    
```

**块 120  0x4706bf-0x4706bf  text0+0x26bf**  
```
  0x4706bf  call     0x471ef1                   ; text0+0x3ef1
```

...（共 140 块，其余略）


---

### 紧凑块链 api4_trace_T1.json（1246 块）

| # | 起始 | 结束 | 末指令 | 注释 |
|---|------|------|--------|------|
| 1 | 0x4589f8 | 0x458a38 | jmp dword ptr [eax*4 + 0x458a3f] |  |
| 2 | 0x458adb | 0x458aea | call 0x4583a4 | persist ar |
| 3 | 0x4583a4 | 0x4583c1 | call 0x4581fc | CODE+0x581fc |
| 4 | 0x4581fc | 0x458215 | call 0x4581b0 | CODE+0x581b0 |
| 5 | 0x4581b0 | 0x4581cb | call 0x402e64 | CODE+0x2e64 |
| 6 | 0x402e64 | 0x402e72 | call 0x404500 | CODE+0x4500 |
| 7 | 0x404500 | 0x404504 | je 0x404522 |  |
| 8 | 0x404522 | 0x404522 | ret |  |
| 9 | 0x402e77 | 0x402e87 | call 0x40126c | CODE+0x126c |
| 10 | 0x40126c | 0x40126c | jmp 0x4799cf | text0+0xb9cf |
| 11 | 0x4799cf | 0x4799cf | call 0x4776c3 | text0+0x96c3 |
| 12 | 0x4776c3 | 0x4776d5 | call 0x475cea | text0+0x7cea |
| 13 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 14 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 15 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 16 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 17 | 0x4776da | 0x4776da | call 0x4798ea | text0+0xb8ea |
| 18 | 0x4798ea | 0x4798ea | call 0x479888 | text0+0xb888 |
| 19 | 0x479888 | 0x47988b | call 0x476677 | text0+0x8677 |
| 20 | 0x476677 | 0x476685 | ret 0x38 |  |
| 21 | 0x763510d0 | 0x402e8c | ? |  |
| 22 | 0x402e8c | 0x402e94 | call 0x4045f0 | CODE+0x45f0 |
| 23 | 0x4045f0 | 0x4045fb | call 0x4045c4 | CODE+0x45c4 |
| 24 | 0x4045c4 | 0x4045d0 | call 0x402a38 | CODE+0x2a38 |
| 25 | 0x402a38 | 0x402a42 | call dword ptr [0x45903c] |  |
| 26 | 0x4023e4 | 0x4023f4 | jne 0x4023ff |  |
| 27 | 0x4023ff | 0x402405 | jle 0x402411 |  |
| 28 | 0x402411 | 0x40242d | call 0x401368 | CODE+0x1368 |
| 29 | 0x401368 | 0x401368 | jmp 0x471bec | Q/W 混淆链入口 |
| 30 | 0x471bec | 0x471bec | jmp 0x4786a2 | text0+0xa6a2 |
| 31 | 0x4786a2 | 0x4786ae | jmp 0x4762ff | text0+0x82ff |
| 32 | 0x4762ff | 0x4762ff | call 0x475cea | text0+0x7cea |
| 33 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 34 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 35 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 36 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 37 | 0x476304 | 0x476305 | call 0x478320 | text0+0xa320 |
| 38 | 0x478320 | 0x478337 | ret 0x30 |  |
| 39 | 0x776b00c0 | 0x402432 | ? |  |
| 40 | 0x402432 | 0x40243b | jge 0x402442 |  |
| 41 | 0x402442 | 0x402452 | jns 0x402457 |  |
| 42 | 0x402457 | 0x40249c | jmp 0x4024c4 | CODE+0x24c4 |
| 43 | 0x4024c4 | 0x4024f0 | call 0x403f1c | CODE+0x3f1c |
| 44 | 0x403f1c | 0x403f2c | call ecx |  |
| 45 | 0x402585 | 0x402585 | jmp 0x40256c | CODE+0x256c |
| 46 | 0x40256c | 0x40257a | call 0x401370 | CODE+0x1370 |
| 47 | 0x401370 | 0x401370 | jmp 0x4745c3 | text0+0x65c3 |
| 48 | 0x4745c3 | 0x4745c3 | jmp 0x4706ab | text0+0x26ab |
| 49 | 0x4706ab | 0x4706ba | call 0x475cea | text0+0x7cea |
| 50 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 51 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 52 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 53 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 54 | 0x4706bf | 0x4706bf | call 0x471ef1 | text0+0x3ef1 |
| 55 | 0x471ef1 | 0x471f01 | ret 0x28 |  |
| 56 | 0x776ae8c0 | 0x40257f | ? |  |
| 57 | 0x40257f | 0x40257f | ret |  |
| 58 | 0x403f2e | 0x403f2e | ret 0xc |  |
| 59 | 0x4024f5 | 0x4024f5 | jmp 0x402587 | CODE+0x2587 |
| 60 | 0x402587 | 0x40258e | ret |  |
| 61 | 0x402a48 | 0x402a4f | jne 0x402a5f |  |
| 62 | 0x402a5f | 0x402a64 | ret |  |
| 63 | 0x4045d5 | 0x4045eb | ret |  |
| 64 | 0x404600 | 0x40460c | call 0x402c58 | CODE+0x2c58 |
| 65 | 0x402c58 | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 66 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 67 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 68 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 69 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 70 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 71 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 72 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 73 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 74 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 75 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 76 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 77 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 78 | 0x402c6b | 0x402c76 | ret |  |
| 79 | 0x404611 | 0x404613 | call 0x404500 | CODE+0x4500 |
| 80 | 0x404500 | 0x404504 | je 0x404522 |  |
| 81 | 0x404522 | 0x404522 | ret |  |
| 82 | 0x404618 | 0x40461d | ret |  |
| 83 | 0x402e99 | 0x402e99 | jmp 0x402ebc | CODE+0x2ebc |
| 84 | 0x402ebc | 0x402ec4 | ret |  |
| 85 | 0x4581d0 | 0x4581d5 | call 0x408ad8 | CODE+0x8ad8 |
| 86 | 0x408ad8 | 0x408ae6 | call 0x408a88 | CODE+0x8a88 |
| 87 | 0x408a88 | 0x408a92 | call 0x4047c0 | CODE+0x47c0 |
| 88 | 0x4047c0 | 0x4047c7 | ret |  |
| 89 | 0x408a97 | 0x408a9b | call 0x4049c0 | CODE+0x49c0 |
| 90 | 0x4049c0 | 0x4049c4 | ret |  |
| 91 | 0x408aa0 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 92 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 93 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 94 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 95 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 96 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 97 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 98 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 99 | 0x408e23 | 0x408e26 | ret |  |
| 100 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 101 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 102 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 103 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 104 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 105 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 106 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 107 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 108 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 109 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 110 | 0x408e23 | 0x408e26 | ret |  |
| 111 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 112 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 113 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 114 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 115 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 116 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 117 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 118 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 119 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 120 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 121 | 0x408e23 | 0x408e26 | ret |  |
| 122 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 123 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 124 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 125 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 126 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 127 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 128 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 129 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 130 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 131 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 132 | 0x408e23 | 0x408e26 | ret |  |
| 133 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 134 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 135 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 136 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 137 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 138 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 139 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 140 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 141 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 142 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 143 | 0x408e23 | 0x408e26 | ret |  |
| 144 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 145 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 146 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 147 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 148 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 149 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 150 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 151 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 152 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 153 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 154 | 0x408e23 | 0x408e26 | ret |  |
| 155 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 156 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 157 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 158 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 159 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 160 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 161 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 162 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 163 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 164 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 165 | 0x408e23 | 0x408e26 | ret |  |
| 166 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 167 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 168 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 169 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 170 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 171 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 172 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 173 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 174 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 175 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 176 | 0x408e23 | 0x408e26 | ret |  |
| 177 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 178 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 179 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 180 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 181 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 182 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 183 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 184 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 185 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 186 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 187 | 0x408e23 | 0x408e26 | ret |  |
| 188 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 189 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 190 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 191 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 192 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 193 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 194 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 195 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 196 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 197 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 198 | 0x408e23 | 0x408e26 | ret |  |
| 199 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 200 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 201 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 202 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 203 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 204 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 205 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 206 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 207 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 208 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 209 | 0x408e23 | 0x408e26 | ret |  |
| 210 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 211 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 212 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 213 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 214 | 0x408e1b | 0x408e21 | jne 0x408e0f |  |
| 215 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 216 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 217 | 0x408e0f | 0x408e11 | jne 0x408e19 |  |
| 218 | 0x408e19 | 0x408e21 | jne 0x408e0f |  |
| 219 | 0x408e0f | 0x408e17 | jmp 0x408e23 | CODE+0x8e23 |
| 220 | 0x408e23 | 0x408e26 | ret |  |
| 221 | 0x408ab9 | 0x408abb | je 0x408acb |  |
| 222 | 0x408acb | 0x408ace | jg 0x408aa7 |  |
| 223 | 0x408aa7 | 0x408ab4 | call 0x408e08 | CODE+0x8e08 |
| 224 | 0x408e08 | 0x408e0d | jmp 0x408e1b | CODE+0x8e1b |
| 225 | 0x408e1b | 0x408e26 | ret |  |
| 226 | 0x408ab9 | 0x408ac1 | call 0x40c750 | CODE+0xc750 |
| 227 | 0x40c750 | 0x40c763 | call 0x4049c0 | CODE+0x49c0 |
| 228 | 0x4049c0 | 0x4049c4 | ret |  |
| 229 | 0x40c768 | 0x40c76b | call 0x40c6d8 | CODE+0xc6d8 |
| 230 | 0x40c6d8 | 0x40c6ea | jne 0x40c700 |  |
| 231 | 0x40c700 | 0x40c703 | jmp 0x40c706 | CODE+0xc706 |
| 232 | 0x40c706 | 0x40c726 | jns 0x40c72d |  |
| 233 | 0x40c72d | 0x40c72f | jne 0x40c735 |  |
| 234 | 0x40c735 | 0x40c744 | jae 0x40c748 |  |
| 235 | 0x40c748 | 0x40c74c | ret |  |
| 236 | 0x40c770 | 0x40c772 | ret |  |
| 237 | 0x408ac6 | 0x408ac8 | jne 0x408ad0 |  |
| 238 | 0x408ad0 | 0x408ad6 | ret |  |
| 239 | 0x408aeb | 0x408af7 | call 0x404a20 | CODE+0x4a20 |
| 240 | 0x404a20 | 0x404a43 | call 0x4045f0 | CODE+0x45f0 |
| 241 | 0x4045f0 | 0x4045fb | call 0x4045c4 | CODE+0x45c4 |
| 242 | 0x4045c4 | 0x4045d0 | call 0x402a38 | CODE+0x2a38 |
| 243 | 0x402a38 | 0x402a42 | call dword ptr [0x45903c] |  |
| 244 | 0x4023e4 | 0x4023f4 | jne 0x4023ff |  |
| 245 | 0x4023ff | 0x402405 | jle 0x402411 |  |
| 246 | 0x402411 | 0x40242d | call 0x401368 | CODE+0x1368 |
| 247 | 0x401368 | 0x401368 | jmp 0x471bec | Q/W 混淆链入口 |
| 248 | 0x471bec | 0x471bec | jmp 0x4786a2 | text0+0xa6a2 |
| 249 | 0x4786a2 | 0x4786ae | jmp 0x4762ff | text0+0x82ff |
| 250 | 0x4762ff | 0x4762ff | call 0x475cea | text0+0x7cea |
| 251 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 252 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 253 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 254 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 255 | 0x476304 | 0x476305 | call 0x478320 | text0+0xa320 |
| 256 | 0x478320 | 0x478337 | ret 0x30 |  |
| 257 | 0x776b00c0 | 0x402432 | ? |  |
| 258 | 0x402432 | 0x40243b | jge 0x402442 |  |
| 259 | 0x402442 | 0x402452 | jns 0x402457 |  |
| 260 | 0x402457 | 0x40249c | jmp 0x4024c4 | CODE+0x24c4 |
| 261 | 0x4024c4 | 0x4024f0 | call 0x403f1c | CODE+0x3f1c |
| 262 | 0x403f1c | 0x403f2c | call ecx |  |
| 263 | 0x402585 | 0x402585 | jmp 0x40256c | CODE+0x256c |
| 264 | 0x40256c | 0x40257a | call 0x401370 | CODE+0x1370 |
| 265 | 0x401370 | 0x401370 | jmp 0x4745c3 | text0+0x65c3 |
| 266 | 0x4745c3 | 0x4745c3 | jmp 0x4706ab | text0+0x26ab |
| 267 | 0x4706ab | 0x4706ba | call 0x475cea | text0+0x7cea |
| 268 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 269 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 270 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 271 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 272 | 0x4706bf | 0x4706bf | call 0x471ef1 | text0+0x3ef1 |
| 273 | 0x471ef1 | 0x471f01 | ret 0x28 |  |
| 274 | 0x776ae8c0 | 0x40257f | ? |  |
| 275 | 0x40257f | 0x40257f | ret |  |
| 276 | 0x403f2e | 0x403f2e | ret 0xc |  |
| 277 | 0x4024f5 | 0x4024f5 | jmp 0x402587 | CODE+0x2587 |
| 278 | 0x402587 | 0x40258e | ret |  |
| 279 | 0x402a48 | 0x402a4f | jne 0x402a5f |  |
| 280 | 0x402a5f | 0x402a64 | ret |  |
| 281 | 0x4045d5 | 0x4045eb | ret |  |
| 282 | 0x404600 | 0x40460c | call 0x402c58 | CODE+0x2c58 |
| 283 | 0x402c58 | 0x402c62 | ja 0x402c77 |  |
| 284 | 0x402c77 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 285 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 286 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 287 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 288 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 289 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 290 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 291 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 292 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 293 | 0x402c85 | 0x402c85 | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 294 | 0x402c85 | 0x402c97 | ret |  |
| 295 | 0x404611 | 0x404613 | call 0x404500 | CODE+0x4500 |
| 296 | 0x404500 | 0x404504 | je 0x404522 |  |
| 297 | 0x404522 | 0x404522 | ret |  |
| 298 | 0x404618 | 0x40461d | ret |  |
| 299 | 0x404a48 | 0x404a48 | jmp 0x404a5b | CODE+0x4a5b |
| 300 | 0x404a5b | 0x404a5c | ret 4 |  |
| ... | | | 共 1246 块 | |


---

### 紧凑块链 api5_trace_Q.json（3685 块）

| # | 起始 | 结束 | 末指令 | 注释 |
|---|------|------|--------|------|
| 1 | 0x4589f8 | 0x458a38 | jmp dword ptr [eax*4 + 0x458a3f] |  |
| 2 | 0x458a5f | 0x458a64 | call 0x458854 | Q 处理器 |
| 3 | 0x458854 | 0x458872 | call 0x4046f8 | CODE+0x46f8 |
| 4 | 0x4046f8 | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 5 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 6 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 7 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 8 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 9 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 10 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 11 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 12 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 13 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 14 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 15 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 16 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 17 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 18 | 0x4046ff | 0x404715 | jmp 0x4046ff | CODE+0x46ff |
| 19 | 0x4046ff | 0x404706 | je 0x404719 |  |
| 20 | 0x404719 | 0x40471f | jmp 0x4045f0 | CODE+0x45f0 |
| 21 | 0x4045f0 | 0x4045fb | call 0x4045c4 | CODE+0x45c4 |
| 22 | 0x4045c4 | 0x4045d0 | call 0x402a38 | CODE+0x2a38 |
| 23 | 0x402a38 | 0x402a42 | call dword ptr [0x45903c] |  |
| 24 | 0x4023e4 | 0x4023f4 | jne 0x4023ff |  |
| 25 | 0x4023ff | 0x402405 | jle 0x402411 |  |
| 26 | 0x402411 | 0x40242d | call 0x401368 | CODE+0x1368 |
| 27 | 0x401368 | 0x401368 | jmp 0x471bec | Q/W 混淆链入口 |
| 28 | 0x471bec | 0x471bec | jmp 0x4786a2 | text0+0xa6a2 |
| 29 | 0x4786a2 | 0x4786ae | jmp 0x4762ff | text0+0x82ff |
| 30 | 0x4762ff | 0x4762ff | call 0x475cea | text0+0x7cea |
| 31 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 32 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 33 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 34 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 35 | 0x476304 | 0x476305 | call 0x478320 | text0+0xa320 |
| 36 | 0x478320 | 0x478337 | ret 0x30 |  |
| 37 | 0x776b00c0 | 0x402432 | ? |  |
| 38 | 0x402432 | 0x40243b | jge 0x402442 |  |
| 39 | 0x402442 | 0x402452 | jns 0x402457 |  |
| 40 | 0x402457 | 0x40246b | je 0x4024fa |  |
| 41 | 0x4024fa | 0x40250f | jge 0x40251e |  |
| 42 | 0x40251e | 0x40254e | call 0x403f1c | CODE+0x3f1c |
| 43 | 0x403f1c | 0x403f2c | call ecx |  |
| 44 | 0x402585 | 0x402585 | jmp 0x40256c | CODE+0x256c |
| 45 | 0x40256c | 0x40257a | call 0x401370 | CODE+0x1370 |
| 46 | 0x401370 | 0x401370 | jmp 0x4745c3 | text0+0x65c3 |
| 47 | 0x4745c3 | 0x4745c3 | jmp 0x4706ab | text0+0x26ab |
| 48 | 0x4706ab | 0x4706ba | call 0x475cea | text0+0x7cea |
| 49 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 50 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 51 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 52 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 53 | 0x4706bf | 0x4706bf | call 0x471ef1 | text0+0x3ef1 |
| 54 | 0x471ef1 | 0x471f01 | ret 0x28 |  |
| 55 | 0x776ae8c0 | 0x40257f | ? |  |
| 56 | 0x40257f | 0x40257f | ret |  |
| 57 | 0x403f2e | 0x403f2e | ret 0xc |  |
| 58 | 0x402553 | 0x402553 | jmp 0x402587 | CODE+0x2587 |
| 59 | 0x402587 | 0x40258e | ret |  |
| 60 | 0x402a48 | 0x402a4f | jne 0x402a5f |  |
| 61 | 0x402a5f | 0x402a64 | ret |  |
| 62 | 0x4045d5 | 0x4045eb | ret |  |
| 63 | 0x404600 | 0x40460c | call 0x402c58 | CODE+0x2c58 |
| 64 | 0x402c58 | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 65 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 66 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 67 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 68 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 69 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 70 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 71 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 72 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 73 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 74 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 75 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 76 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 77 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 78 | 0x402c6b | 0x402c6b | rep movsd dword ptr es:[edi], dword ptr [esi] |  |
| 79 | 0x402c6b | 0x402c72 | rep movsb byte ptr es:[edi], byte ptr [esi] |  |
| 80 | 0x402c72 | 0x402c76 | ret |  |
| 81 | 0x404611 | 0x404613 | call 0x404500 | CODE+0x4500 |
| 82 | 0x404500 | 0x404504 | je 0x404522 |  |
| 83 | 0x404522 | 0x404522 | ret |  |
| 84 | 0x404618 | 0x40461d | ret |  |
| 85 | 0x458877 | 0x45887a | call 0x408a1c | CODE+0x8a1c |
| 86 | 0x408a1c | 0x408a21 | call 0x4089b4 | CODE+0x89b4 |
| 87 | 0x4089b4 | 0x4089c9 | call 0x4049c0 | CODE+0x49c0 |
| 88 | 0x4049c0 | 0x4049c4 | ret |  |
| 89 | 0x4089ce | 0x4089cf | call 0x40664c | CODE+0x664c |
| 90 | 0x40664c | 0x40664c | jmp 0x4777b2 | text0+0x97b2 |
| 91 | 0x4777b2 | 0x4777ca | jmp 0x471725 | text0+0x3725 |
| 92 | 0x471725 | 0x47172a | call 0x475cea | text0+0x7cea |
| 93 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 94 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 95 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 96 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 97 | 0x47172f | 0x471742 | ret 0x34 |  |
| 98 | 0x76353450 | 0x4089d4 | ? |  |
| 99 | 0x4089d4 | 0x4089da | call 0x406644 | CODE+0x6644 |
| 100 | 0x406644 | 0x406644 | jmp 0x47a709 | text0+0xc709 |
| 101 | 0x47a709 | 0x47a709 | call 0x4721b1 | text0+0x41b1 |
| 102 | 0x4721b1 | 0x4721b1 | call 0x47201d | text0+0x401d |
| 103 | 0x47201d | 0x472022 | jmp 0x471e78 | text0+0x3e78 |
| 104 | 0x471e78 | 0x471e86 | call 0x473239 | text0+0x5239 |
| 105 | 0x473239 | 0x473241 | call 0x475cea | text0+0x7cea |
| 106 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 107 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 108 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 109 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 110 | 0x473246 | 0x473246 | call 0x4785b1 | text0+0xa5b1 |
| 111 | 0x4785b1 | 0x4785c8 | ret 0x30 |  |
| 112 | 0x76353410 | 0x4089df | ? |  |
| 113 | 0x4089df | 0x4089f3 | call 0x40663c | CODE+0x663c |
| 114 | 0x40663c | 0x40663c | jmp 0x47ac89 | text0+0xcc89 |
| 115 | 0x47ac89 | 0x47ac96 | jmp 0x476636 | text0+0x8636 |
| 116 | 0x476636 | 0x47663b | call 0x479eb4 | text0+0xbeb4 |
| 117 | 0x479eb4 | 0x479eb4 | jmp 0x477396 | text0+0x9396 |
| 118 | 0x477396 | 0x47739f | call 0x475cea | text0+0x7cea |
| 119 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 120 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 121 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 122 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 123 | 0x4773a4 | 0x4773a5 | jmp 0x4719d5 | text0+0x39d5 |
| 124 | 0x4719d5 | 0x4719e1 | ret 0x50 |  |
| 125 | 0x76353400 | 0x4089f8 | ? |  |
| 126 | 0x4089f8 | 0x408a04 | call 0x406634 | CODE+0x6634 |
| 127 | 0x406634 | 0x406634 | jmp 0x4787bf | text0+0xa7bf |
| 128 | 0x4787bf | 0x4787cf | call 0x4716e9 | text0+0x36e9 |
| 129 | 0x4716e9 | 0x4716e9 | jmp 0x4796ec | text0+0xb6ec |
| 130 | 0x4796ec | 0x4796fa | call 0x475cea | text0+0x7cea |
| 131 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 132 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 133 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 134 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 135 | 0x4796ff | 0x479720 | ret 0x2c |  |
| 136 | 0x7634be20 | 0x408a09 | ? |  |
| 137 | 0x408a09 | 0x408a0b | jne 0x408a14 |  |
| 138 | 0x408a14 | 0x408a1b | ret |  |
| 139 | 0x408a26 | 0x408a2b | ret |  |
| 140 | 0x45887f | 0x458889 | call 0x4049c0 | CODE+0x49c0 |
| 141 | 0x4049c0 | 0x4049c4 | ret |  |
| 142 | 0x45888e | 0x458890 | call 0x457fa8 | CODE+0x57fa8 |
| 143 | 0x457fa8 | 0x457fa8 | jmp 0x4729c5 | text0+0x49c5 |
| 144 | 0x4729c5 | 0x4729e0 | call 0x476487 | text0+0x8487 |
| 145 | 0x476487 | 0x47648c | call 0x475cea | text0+0x7cea |
| 146 | 0x475cea | 0x475cea | jmp 0x47b4d1 | text0+0xd4d1 |
| 147 | 0x47b4d1 | 0x47b4fb | call 0x47b3b4 | text0+0xd3b4 |
| 148 | 0x47b3b4 | 0x47b3bb | jmp 0x478f52 | text0+0xaf52 |
| 149 | 0x478f52 | 0x478f6c | ret 0x58 |  |
| 150 | 0x476491 | 0x476491 | call 0x475f73 | text0+0x7f73 |
| 151 | 0x475f73 | 0x475f73 | call 0x4787d9 | text0+0xa7d9 |
| 152 | 0x4787d9 | 0x4787e2 | ret 0x2c |  |
| 153 | 0xb3daf4 | 0xb3db02 | call 0xa974b8 | lib+0x74b8 |
| 154 | 0xa974b8 | 0xa974b8 | jmp 0xbd7f75 | lib+0x147f75 |
| 155 | 0xbd7f75 | 0xbd7f82 | call 0xbbabcf | lib+0x12abcf |
| 156 | 0xbbabcf | 0xbbabdc | call 0xbc4648 | lib+0x134648 |
| 157 | 0xbc4648 | 0xbc4649 | call 0xbdce33 | lib+0x14ce33 |
| 158 | 0xbdce33 | 0xbdce4a | jmp 0xbdccca | lib+0x14ccca |
| 159 | 0xbdccca | 0xbdccdc | jmp 0xbb7d7e | lib+0x127d7e |
| 160 | 0xbb7d7e | 0xbb7d81 | call 0xbd4e6a | lib+0x144e6a |
| 161 | 0xbd4e6a | 0xbd4e6a | jmp 0xbe0269 | lib+0x150269 |
| 162 | 0xbe0269 | 0xbe0270 | jmp 0xbe151f | lib+0x15151f |
| 163 | 0xbe151f | 0xbe1534 | jmp 0xbc2a73 | lib+0x132a73 |
| 164 | 0xbc2a73 | 0xbc2a8b | ret 0x58 |  |
| 165 | 0xbbabe1 | 0xbbabe6 | jmp 0xbc0617 | lib+0x130617 |
| 166 | 0xbc0617 | 0xbc0621 | ret 0x2c |  |
| 167 | 0x76348b60 | 0xb3db07 | ? |  |
| 168 | 0xb3db07 | 0xb3db0c | call 0xb3eaf8 | lib!SetFileSecParent |
| 169 | 0xb3eaf8 | 0xb3eb19 | call 0xa94e28 | lib+0x4e28 |
| 170 | 0xa94e28 | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 171 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 172 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 173 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 174 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 175 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 176 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 177 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 178 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 179 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 180 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 181 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 182 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 183 | 0xa94e2f | 0xa94e45 | jmp 0xa94e2f | lib+0x4e2f |
| 184 | 0xa94e2f | 0xa94e36 | je 0xa94e49 |  |
| 185 | 0xa94e49 | 0xa94e4f | jmp 0xa94d20 | lib+0x4d20 |
| 186 | 0xa94d20 | 0xa94d2b | call 0xa94cf4 | lib+0x4cf4 |
| 187 | 0xa94cf4 | 0xa94d00 | call 0xa92b70 | lib+0x2b70 |
| 188 | 0xa92b70 | 0xa92b7a | call dword ptr [0xba0044] |  |
| 189 | 0xa9251c | 0xa9252c | jne 0xa92537 |  |
| 190 | 0xa92537 | 0xa9253d | jle 0xa92549 |  |
| 191 | 0xa92549 | 0xa92565 | call 0xa914a0 | lib+0x14a0 |
| 192 | 0xa914a0 | 0xa914a0 | jmp 0xbdcf81 | lib+0x14cf81 |
| 193 | 0xbdcf81 | 0xbdcf88 | call 0xbc361f | lib+0x13361f |
| 194 | 0xbc361f | 0xbc3631 | jmp 0xbc4a88 | lib+0x134a88 |
| 195 | 0xbc4a88 | 0xbc4a8c | call 0xbc4648 | lib+0x134648 |
| 196 | 0xbc4648 | 0xbc4649 | call 0xbdce33 | lib+0x14ce33 |
| 197 | 0xbdce33 | 0xbdce4a | jmp 0xbdccca | lib+0x14ccca |
| 198 | 0xbdccca | 0xbdccdc | jmp 0xbb7d7e | lib+0x127d7e |
| 199 | 0xbb7d7e | 0xbb7d81 | call 0xbd4e6a | lib+0x144e6a |
| 200 | 0xbd4e6a | 0xbd4e6a | jmp 0xbe0269 | lib+0x150269 |
| 201 | 0xbe0269 | 0xbe0270 | jmp 0xbe151f | lib+0x15151f |
| 202 | 0xbe151f | 0xbe1534 | jmp 0xbc2a73 | lib+0x132a73 |
| 203 | 0xbc2a73 | 0xbc2a8b | ret 0x58 |  |
| 204 | 0xbc4a91 | 0xbc4a91 | jmp 0xbc21f6 | lib+0x1321f6 |
| 205 | 0xbc21f6 | 0xbc21ff | ret 0xc |  |
| 206 | 0x776b00c0 | 0xa9256a | ? |  |
| 207 | 0xa9256a | 0xa92573 | jge 0xa9257a |  |
| 208 | 0xa9257a | 0xa9258a | jns 0xa9258f |  |
| 209 | 0xa9258f | 0xa925a3 | je 0xa92632 |  |
| 210 | 0xa92632 | 0xa92638 | jg 0xa9268d |  |
| 211 | 0xa9268d | 0xa9268f | call 0xa923d4 | lib+0x23d4 |
| 212 | 0xa923d4 | 0xa9242a | je 0xa92432 |  |
| 213 | 0xa92432 | 0xa9243c | call 0xa9239c | lib+0x239c |
| 214 | 0xa9239c | 0xa923a5 | jns 0xa923aa |  |
| 215 | 0xa923aa | 0xa923cb | jne 0xa923b4 |  |
| 216 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 217 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 218 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 219 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 220 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 221 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 222 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 223 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 224 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 225 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 226 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 227 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 228 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 229 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 230 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 231 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 232 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 233 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 234 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 235 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 236 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 237 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 238 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 239 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 240 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 241 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 242 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 243 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 244 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 245 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 246 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 247 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 248 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 249 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 250 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 251 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 252 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 253 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 254 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 255 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 256 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 257 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 258 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 259 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 260 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 261 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 262 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 263 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 264 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 265 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 266 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 267 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 268 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 269 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 270 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 271 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 272 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 273 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 274 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 275 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 276 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 277 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 278 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 279 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 280 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 281 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 282 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 283 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 284 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 285 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 286 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 287 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 288 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 289 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 290 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 291 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 292 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 293 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 294 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 295 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 296 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 297 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 298 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 299 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 300 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 301 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 302 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 303 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 304 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 305 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 306 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 307 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 308 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 309 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 310 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 311 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 312 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 313 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 314 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 315 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 316 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 317 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 318 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 319 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 320 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 321 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 322 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 323 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 324 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 325 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 326 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 327 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 328 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 329 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 330 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 331 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 332 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 333 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 334 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 335 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 336 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 337 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 338 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 339 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 340 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 341 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 342 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 343 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 344 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 345 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 346 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 347 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 348 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 349 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 350 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 351 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 352 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 353 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 354 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 355 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 356 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 357 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 358 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 359 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 360 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 361 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 362 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 363 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 364 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 365 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 366 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 367 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 368 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 369 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 370 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 371 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 372 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 373 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 374 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 375 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 376 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 377 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 378 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 379 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 380 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 381 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 382 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 383 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 384 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 385 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 386 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 387 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 388 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 389 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 390 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 391 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 392 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 393 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 394 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 395 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 396 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 397 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 398 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 399 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| 400 | 0xa923b4 | 0xa923cb | jne 0xa923b4 |  |
| ... | | | 共 3685 块 | |
