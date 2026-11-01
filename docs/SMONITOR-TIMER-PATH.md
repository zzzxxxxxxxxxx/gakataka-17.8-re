# Smonitor tmr1 定时器路径线性化

数据来源：真实服务进程 Stalker 2 秒 block 采样（第 15 轮）中主线程 tid 8180 的有序块序列，共 107 个块。
每块从起始地址反汇编到首个控制转移指令，并标注直接调用目标。

| # | 块起始 | 区域 | 末指令 | 注释 |
|---|--------|------|--------|------|
| 1 | 0x454d9f | CODE | ret |  |
| 2 | 0x404530 | CODE | ret |  |
| 3 | 0x404550 | CODE | ret |  |
| 4 | 0x404530 | CODE | ret |  |
| 5 | 0x404550 | CODE | ret |  |
| 6 | 0x404553 | CODE | jmp 0x40457c | CODE+0x457c |
| 7 | 0x454da0 | CODE | jmp 0x403e38 | CODE+0x3e38 |
| 8 | 0x454dae | CODE | ret |  |
| 9 | 0x45440d | CODE | jmp 0x454466 | CODE+0x54466 |
| 10 | 0x457e1c | CODE | ret |  |
| 11 | 0x457e0c | CODE | ret |  |
| 12 | 0x4543fb | CODE | ret |  |
| 13 | 0x45436c | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 14 | 0x406e11 | CODE | jmp 0x4768a5 | text0+0x88a5 |
| 15 | 0x476242 | text0 | ret 0x4c |  |
| 16 | 0x476263 | text0 | ret 0x4c |  |
| 17 | 0x475cef | text0 | jmp 0x47a0f6 | text0+0xc0f6 |
| 18 | 0x47b500 | text0 | ret 0xc |  |
| 19 | 0x47b3c0 | text0 | ret 0x1c |  |
| 20 | 0x478f6f | text0 | jmp 0x471e62 | text0+0x3e62 |
| 21 | 0x476272 | text0 | ret 0x10 |  |
| 22 | 0x454370 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 23 | 0x454378 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 24 | 0x454386 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 25 | 0x45439f | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 26 | 0x4542c8 | CODE | ret |  |
| 27 | 0x4542d4 | CODE | ret |  |
| 28 | 0x43ca97 | CODE | ret |  |
| 29 | 0x43ca9e | CODE | ret |  |
| 30 | 0x43caa9 | CODE | ret |  |
| 31 | 0x43cab1 | CODE | ret |  |
| 32 | 0x43caba | CODE | ret |  |
| 33 | 0x43cac3 | CODE | ret |  |
| 34 | 0x43cacc | CODE | ret |  |
| 35 | 0x43cad7 | CODE | ret |  |
| 36 | 0x43cae8 | CODE | ret |  |
| 37 | 0x43caec | CODE | ret |  |
| 38 | 0x4542d8 | CODE | ret |  |
| 39 | 0x4542e6 | CODE | jmp 0x454345 | CODE+0x54345 |
| 40 | 0x4543a3 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 41 | 0x4543a9 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 42 | 0x4543b2 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 43 | 0x4541bc | CODE | ret |  |
| 44 | 0x4541fa | CODE | jmp 0x454261 | CODE+0x54261 |
| 45 | 0x4543b6 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 46 | 0x4543bf | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 47 | 0x454214 | CODE | jmp 0x454261 | CODE+0x54261 |
| 48 | 0x45421f | CODE | jmp 0x454261 | CODE+0x54261 |
| 49 | 0x4542b4 | CODE | ret |  |
| 50 | 0x4543c3 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 51 | 0x4543cc | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 52 | 0x45419b | CODE | ret |  |
| 53 | 0x4541ac | CODE | ret |  |
| 54 | 0x4543d0 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 55 | 0x4543d6 | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 56 | 0x406f69 | CODE | jmp 0x47725d | text0+0x925d |
| 57 | 0x47a930 | text0 | jmp 0x471390 | text0+0x3390 |
| 58 | 0x477548 | text0 | ret 0x34 |  |
| 59 | 0x4749e7 | text0 | jmp 0x47a97c | text0+0xc97c |
| 60 | 0x47816c | text0 | jmp 0x478f00 | text0+0xaf00 |
| 61 | 0x47a28c | text0 | jmp 0x47b525 | text0+0xd525 |
| 62 | 0x475cef | text0 | jmp 0x47a0f6 | text0+0xc0f6 |
| 63 | 0x47b500 | text0 | ret 0xc |  |
| 64 | 0x47b3c0 | text0 | ret 0x1c |  |
| 65 | 0x478f6f | text0 | jmp 0x471e62 | text0+0x3e62 |
| 66 | 0x47a295 | text0 | ret 0x48 |  |
| 67 | 0x47b53a | text0 | ret 0x34 |  |
| 68 | 0x4543dc | CODE | jmp 0x4543e5 | CODE+0x543e5 |
| 69 | 0x406b31 | CODE | jmp 0x47065a | text0+0x265a |
| 70 | 0x4716cc | text0 | jmp 0x4796ec | text0+0xb6ec |
| 71 | 0x477212 | text0 | jmp 0x479254 | text0+0xb254 |
| 72 | 0x475cef | text0 | jmp 0x47a0f6 | text0+0xc0f6 |
| 73 | 0x47b500 | text0 | ret 0xc |  |
| 74 | 0x47b3c0 | text0 | ret 0x1c |  |
| 75 | 0x478f6f | text0 | jmp 0x471e62 | text0+0x3e62 |
| 76 | 0x477217 | text0 | jmp 0x471792 | text0+0x3792 |
| 77 | 0x47926b | text0 | jmp 0x477673 | text0+0x9673 |
| 78 | 0x41cbb6 | CODE | ret 0x10 |  |
| 79 | 0x42ac8a | CODE | jmp 0x42ace1 | CODE+0x2ace1 |
| 80 | 0x42aca4 | CODE | jmp 0x42ace1 | CODE+0x2ace1 |
| 81 | 0x4038e1 | CODE | jmp esi |  |
| 82 | 0x4038ac | CODE | ret |  |
| 83 | 0x4038b5 | CODE | ret |  |
| 84 | 0x4038c1 | CODE | ret |  |
| 85 | 0x4038d6 | CODE | jmp esi |  |
| 86 | 0x4038e5 | CODE | jmp esi |  |
| 87 | 0x4038e7 | CODE | jmp 0x402f10 | CODE+0x2f10 |
| 88 | 0x42adb4 | CODE | ret |  |
| 89 | 0x42adbe | CODE | ret |  |
| 90 | 0x458794 | CODE | jmp 0x45881b | CODE+0x5881b |
| 91 | 0x45879d | CODE | jmp 0x45881b | CODE+0x5881b |
| 92 | 0x4587a6 | CODE | jmp 0x45881b | CODE+0x5881b |
| 93 | 0x4587af | CODE | jmp 0x45881b | CODE+0x5881b |
| 94 | 0x4587ba | CODE | jmp 0x45881b | CODE+0x5881b |
| 95 | 0x4049c4 | CODE | ret |  |
| 96 | 0x4049c5 | CODE | ret |  |
| 97 | 0x4587c0 | CODE | jmp 0x45881b | CODE+0x5881b |
| 98 | 0x457fb5 | CODE | jmp 0x47acfd | text0+0xccfd |
| 99 | 0x47743c | text0 | jmp 0x473e1c | text0+0x5e1c |
| 100 | 0x479ccd | text0 | jmp 0x47912d | text0+0xb12d |
| 101 | 0x474330 | text0 | jmp 0x4704b1 | text0+0x24b1 |
| 102 | 0x47abbf | text0 | ret 0x18 |  |
| 103 | 0x475cef | text0 | jmp 0x47a0f6 | text0+0xc0f6 |
| 104 | 0x47b500 | text0 | ret 0xc |  |
| 105 | 0x47b3c0 | text0 | ret 0x1c |  |
| 106 | 0x478f6f | text0 | jmp 0x471e62 | text0+0x3e62 |
| 107 | 0x47abd7 | text0 | ret 0x2c |  |