# MiniLCTF2022 WhatAssembly & Lemon Official Writeup

## Lemon | 8 Solves

### Topic Idea

考虑到整体难度偏高，就想出一道签到题平衡一下难度，同时又要让选手在短时间内学到一些东西。结合之前在HITCON2021遇到过 lemon lang 的题，前段时间也稍微研究了一下它的解释器源码，于是就出了这一道运行就送 flag 的题给师傅们随便玩玩。

### Source Code

```
var seed = 0xd33b470;

def next() {
    seed = (seed * 0xdeadbeef + 0xb14cb12d) % 0xffffffff;
    print(seed);
    return seed;
}

class RunMe {
    def __init__(var n) {
        self.enc = [];
        self.flag = [];
        self.res = [2141786733, 76267819, 37219027, 219942343, 755999918, 701306806, 532732060, 334234642, 524809386, 333469062, 160092960, 126810196, 238089888, 301365991, 258515107, 424705310, 1041878913, 618187854, 4680810, 827308967, 66957703, 924471115, 735310319, 541128627, 47689903, 459905620, 495518230, 167708778, 586337393, 521761774, 861166604, 626644061, 1030425184, 665229750, 330150339];
        var i = 0;
        while (i < n) {
            self.enc.append(next());
            i = i + 1;
        }
    }

    def sign(var x, var y) {
        var i = 0;
        while (i < 35) {
            self.flag.append(x[i] ^ y[i]);
            i += 1;
        }
    }
}

print("[+] Starting...");

var my_run = RunMe(35);
my_run.sign(my_run.enc, my_run.res);
print(my_run.flag);

print("[+] Done!");
```

### Bytecode form semantics

import source

```
0: const 25 ; <module 'main'> 
5: module 1 590
11: const 26 ; <module 'src'> 
16: store 0 0
19: const 26 ; <module 'src'> 
24: module 6 590
```

store  global constant

```
30: const 27 ; 221492336 
35: store 0 0
```

function definition

```
38: const 28 ; next 
43: define 0 0 0 0 80
```

class definition

```
83: const 32 ; n 
88: const 33 ; __init__ 
93: define 0 0 1 2 377
...
377: const 33 ; __init__ 
382: const 76 ; x 
387: const 77 ; y 
392: const 78 ; sign 
397: define 0 0 2 3 482
...
487: const 80 ; RunMe 
492: class 4 0
495: store 0 2
```

set array

```
102: array 0
107: self
108: const 34 ; enc 
113: setattr
```

loop and condition statement

```
313: const 72 ; 0 
318: store 0 1
321: load 0 1
324: load 0 0
327: lt
328: jz 371
```

function call

```
333: self
334: const 34 ; enc 
339: getattr
340: const 73 ; append 
345: getattr
346: load 1 1
349: call 0
351: call 1
353: pop
```

bit xor

```
441: load 0 0
444: load 0 2
447: getitem
448: load 0 1
451: load 0 2
454: getitem
455: bxor
```

用 lemon lang 复现逻辑运行即可

### Q & A

- Makefile 对 Windows 64-bit 的解释器没有提供相关编译手段，需要自己改动

- Lemon 语言的 mod 大数运算时的精度问题与类型转换问题

## WhatAssembly | 2 Solves

### Topic Idea

同样来自于前一段时间的学习，结合最近国内比赛比较少涉及到 wasm 相关的逆向，就想到加入一个简化过的 chacha20 让大家对 wasm 有一个初步的认识。

### Source Code

#### HTML Part

核心标签：

```html
<input class="form--block-text"
       id="miniL"
       key="D33.B4T0"
       enc="05779c24d9249e693fa7ac4a10c68dfbd3520083b33f56e90fd84978b6a15c970b976779a8fefe91fb87d2221c9a1f87ed7eaddb8ae6370f9de69e3a7a5c5c488cde79756b0b9f1713e749edd41cff04"
       onerror="alert('Wrong flag!');"
       onsuccess="alert('Correct flag!');">
```

#### C Part

> [Emscripten documentation](https://emscripten.org/index.html)
> 
> [WebAssembly | MDN](https://developer.mozilla.org/zh-CN/docs/WebAssembly)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emscripten.h>

typedef unsigned char u8;

EM_JS(void, setupTag, (), {
    let convertToCArray = (s) => {
      let ptr = Module.allocate(Module.intArrayFromString(s),
                                Module.ALLOC_STACK);
      return ptr;
    };
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
          if (Module._check(flag_arr, key_arr, enc_arr)) {
            eval(flag.getAttribute("onerror"));
          } else {
            eval(flag.getAttribute("onsuccess"));
          }
          Module.stackRestore(stack);
      };
    }
});

void EMSCRIPTEN_KEEPALIVE init() {
  setupTag();
}

#define ROL(a,b) (((a) << (b)) | ((a) >> (8 - (b))))

void qua_rou(u8 *s, int a, int b, int c, int d) {
  s[b] ^= ROL((s[a] + s[d]) & 0xff, 4);
  s[d] ^= ROL((s[c] + s[b]) & 0xff, 2);
  s[c] ^= ROL((s[b] + s[a]) & 0xff, 3);
  s[a] ^= ROL((s[d] + s[c]) & 0xff, 1);
}

int EMSCRIPTEN_KEEPALIVE check(const char* cflag,
                               const char* key,
                               const char* enc) {
  const char table[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  int flaglen = strlen(cflag);
  int keylen = strlen(key);
  int enclen = strlen(enc);
  if (keylen < 8)
    return -1;
  if ((flaglen * 4 <= enclen - 32) || (flaglen * 4 > enclen))
    return -1;

  int padlen = (flaglen + 15) & ~15;
  char *flag = (char*)malloc(padlen);
  memset(flag, 0, padlen);
  memcpy(flag, cflag, flaglen);

  u8 s[16];
  for (int i = 0; i < 8; i++)
    s[i] = key[i];

  int correct = 0;
  for (int i = 0; i < flaglen; i += 8) {
    for (int j = 0; j < 8; j++)
        s[8 + j] = flag[i + j];

    for (int j = 0; j < 42; j++) {
        qua_rou(s, 12, 8, 4, 0);
        qua_rou(s, 13, 9, 5, 1);
        qua_rou(s, 14, 10, 6, 2);
        qua_rou(s, 15, 11, 7, 3);
        qua_rou(s, 15, 10, 5, 0);
        qua_rou(s, 12, 11, 6, 1);
        qua_rou(s, 13, 8, 7, 2);
        qua_rou(s, 14, 9, 4, 3);
    }

    for (int j = 0; j < 16; j++) {
        correct |= (enc[i * 4 + j * 2 + 0] != table[s[j] / 0x10]);
        correct |= (enc[i * 4 + j * 2 + 1] != table[s[j] % 0x10]);
    }
  }

  free(flag);
  return correct;
}
```

- `EM_JS` 在 c/c++ 中内嵌 js 函数

- `EMSCRIPTEN_KEEPALIVE` 导出并防止函数内联

#### Makefile

```makefile
EXPORTS=-s EXPORTED_RUNTIME_METHODS='["intArrayFromString", "allocate", "ALLOC_STACK"]'

all:
    emcc --bind check.c -s WASM=1 -o flag.html $(EXPORTS) -g2
```

### How to Reverse

> [wabt](https://github.com/WebAssembly/wabt)
> 
> [理解WebAssembly文本格式 | MDN](https://developer.mozilla.org/zh-CN/docs/WebAssembly/Understanding_the_text_format)
> 
> [Execution — WebAssembly 2.0](https://webassembly.github.io/spec/core/exec/index.html)

使用 wasm2c 将 wasm 转译为 C ，发现可读性依然很差。此时经典的思路是把 c 编译成 relocatable file，再利用反编译工具帮我们去掉一些语义上的抽象层，从而更好地分析。

不同优化会导致代码结构的变化，自己尝试一下便知。下面其实就没有什么好说的了，wasm 是典型的栈虚拟机，慢慢分析就好了，也不复杂，我也没做什么代码混淆。

#### Check Function

```c
// search js
__int64 __fastcall w2c_check(unsigned int flag_arr, unsigned int key_arr, unsigned int enc_arr)
{
  ......
  if ( ++wasm_rt_call_stack_depth > 0x1F4u )
    wasm_rt_trap(7LL);
  w2c___stack_pointer -= 112;                   // new vm stack frame
  check_sp = w2c___stack_pointer;
  i32_store(&w2c_memory, (unsigned int)w2c___stack_pointer + 104LL, flag_arr);// push parameters to stack
  i32_store(&w2c_memory, check_sp + 100LL, key_arr);
  i32_store(&w2c_memory, check_sp + 96LL, enc_arr);
  v14 = i64_load(&w2c_memory, 1032LL);          // xref to find memory initialization
  i64_store(&w2c_memory, check_sp + 88, v14);   // 8-byte table
  v5 = i64_load(&w2c_memory, 1024LL);
  i64_store(&w2c_memory, check_sp + 80, v5);    // another 8-byte table
  v55 = i32_load(&w2c_memory, check_sp + 104LL);
  v54 = w2c_strlen(v55);
  i32_store(&w2c_memory, check_sp + 76LL, v54); // length of flag_arr
  v53 = i32_load(&w2c_memory, check_sp + 100LL);
  v52 = w2c_strlen(v53);
  i32_store(&w2c_memory, check_sp + 72LL, v52); // length of key_arr
  v51 = i32_load(&w2c_memory, check_sp + 96LL);
  v50 = w2c_strlen(v51);
  i32_store(&w2c_memory, check_sp + 68LL, v50); // length of enc_arr
  if ( (int)i32_load(&w2c_memory, check_sp + 72LL) >= 8// len(key) >= 8
    && (v49 = 4 * i32_load(&w2c_memory, check_sp + 76LL), v49 > (int)(i32_load(&w2c_memory, check_sp + 68LL) - 32))// len(enc) - 32 < 4 * len(flag) <= len(enc)
    && (v48 = 4 * i32_load(&w2c_memory, check_sp + 76LL), v48 <= (int)i32_load(&w2c_memory, check_sp + 68LL)) )
  {
    v47 = (i32_load(&w2c_memory, check_sp + 76LL) + 15) & 0xFFFFFFF0;// mapping the elements of each group to the largest element of that group
    i32_store(&w2c_memory, check_sp + 64LL, v47);
    v46 = i32_load(&w2c_memory, check_sp + 64LL);// padding length
    v45 = w2c_dlmalloc(v46);                    // malloc
    i32_store(&w2c_memory, check_sp + 60LL, v45);
    v44 = i32_load(&w2c_memory, check_sp + 60LL);
    v43 = i32_load(&w2c_memory, check_sp + 64LL);
    w2c_memset(v44, 0LL, v43);                  // memset(ptr, 0, padlen)
    v42 = i32_load(&w2c_memory, check_sp + 60LL);
    v41 = i32_load(&w2c_memory, check_sp + 104LL);
    v6 = i32_load(&w2c_memory, check_sp + 76LL);
    w2c___memcpy(v42, v41, v6);
    i32_store(&w2c_memory, check_sp + 28LL, 0LL);// var i = 0
    while ( (int)i32_load(&w2c_memory, check_sp + 28LL) < 8 )
    {
      v40 = i32_load(&w2c_memory, check_sp + 100LL);
      v39 = v40 + i32_load(&w2c_memory, check_sp + 28LL);// &key_arr[i]
      v38 = i32_load8_u(&w2c_memory, v39);
      v37 = check_sp + 32 + i32_load(&w2c_memory, check_sp + 28LL);// new_space
      i32_store8(&w2c_memory, v37, v38);
      v7 = i32_load(&w2c_memory, check_sp + 28LL) + 1;
      i32_store(&w2c_memory, check_sp + 28LL, v7);// i += 1
    }
    i32_store(&w2c_memory, check_sp + 24LL, 0LL);// isok = 0
    i32_store(&w2c_memory, check_sp + 20LL, 0LL);// var i = 0
    while ( 1 )
    {
      v36 = i32_load(&w2c_memory, check_sp + 20LL);
      if ( v36 >= (int)i32_load(&w2c_memory, check_sp + 76LL) )// i < len(flag_arr)
        break;
      i32_store(&w2c_memory, check_sp + 16LL, 0LL);// var j = 0
      while ( (int)i32_load(&w2c_memory, check_sp + 16LL) < 8 )
      {
        v35 = i32_load(&w2c_memory, check_sp + 60LL);
        v34 = i32_load(&w2c_memory, check_sp + 20LL);
        v33 = v35 + v34 + i32_load(&w2c_memory, check_sp + 16LL);// pad_flag + i + j
        v32 = i32_load8_u(&w2c_memory, v33);
        v31 = check_sp + 32 + i32_load(&w2c_memory, check_sp + 16LL) + 8;// new_space + 8 + j
        i32_store8(&w2c_memory, v31, v32);
        v8 = i32_load(&w2c_memory, check_sp + 16LL) + 1;// j += 1
        i32_store(&w2c_memory, check_sp + 16LL, v8);
      }
      i32_store(&w2c_memory, check_sp + 12LL, 0LL);
      while ( (int)i32_load(&w2c_memory, check_sp + 12LL) < 42 )// 42 rounds encryption
      {
        w2c_qua_rou(check_sp + 32, 12LL, 8LL, 4LL, 0LL);
        w2c_qua_rou(check_sp + 32, 13LL, 9LL, 5LL, 1LL);
        w2c_qua_rou(check_sp + 32, 14LL, 10LL, 6LL, 2LL);
        w2c_qua_rou(check_sp + 32, 15LL, 11LL, 7LL, 3LL);
        w2c_qua_rou(check_sp + 32, 15LL, 10LL, 5LL, 0LL);
        w2c_qua_rou(check_sp + 32, 12LL, 11LL, 6LL, 1LL);
        w2c_qua_rou(check_sp + 32, 13LL, 8LL, 7LL, 2LL);
        w2c_qua_rou(check_sp + 32, 14LL, 9LL, 4LL, 3LL);
        v9 = i32_load(&w2c_memory, check_sp + 12LL) + 1;
        i32_store(&w2c_memory, check_sp + 12LL, v9);
      }
      i32_store(&w2c_memory, check_sp + 8LL, 0LL);
      while ( (int)i32_load(&w2c_memory, check_sp + 8LL) < 16 )// verify hex
      {
        v30 = i32_load(&w2c_memory, check_sp + 96LL);
        v29 = 4 * i32_load(&w2c_memory, check_sp + 20LL);
        v28 = v30 + v29 + 2 * i32_load(&w2c_memory, check_sp + 8LL);
        v27 = i32_load8_u(&w2c_memory, v28);    // enc[4 * i + 2 * j]
        v26 = check_sp + 32 + i32_load(&w2c_memory, check_sp + 8LL);
        v13 = (unsigned __int8)i32_load8_u(&w2c_memory, v26);// new_space[j]
        v25 = i32_load8_u(&w2c_memory, check_sp + 80 + v13 / 16);// table[new_space[j] / 16]
        v24 = i32_load(&w2c_memory, check_sp + 24LL) | (v27 != v25);
        i32_store(&w2c_memory, check_sp + 24LL, v24);
        v23 = i32_load(&w2c_memory, check_sp + 96LL);
        v22 = 4 * i32_load(&w2c_memory, check_sp + 20LL);
        v21 = v22 + 2 * i32_load(&w2c_memory, check_sp + 8LL);
        v20 = i32_load8_u(&w2c_memory, (unsigned int)(v23 + v21 + 1));// enc[4 * i + 2 * j + 1]
        v19 = check_sp + 32 + i32_load(&w2c_memory, check_sp + 8LL);
        v4 = (unsigned __int8)i32_load8_u(&w2c_memory, v19) % 16;
        v18 = i32_load8_u(&w2c_memory, check_sp + 80 + v4);// table[new_space[j] % 16]
        v17 = i32_load(&w2c_memory, check_sp + 24LL) | (v20 != v18);
        i32_store(&w2c_memory, check_sp + 24LL, v17);
        v10 = i32_load(&w2c_memory, check_sp + 8LL) + 1;
        i32_store(&w2c_memory, check_sp + 8LL, v10);
      }
      v11 = i32_load(&w2c_memory, check_sp + 20LL) + 8;// i += 8
      i32_store(&w2c_memory, check_sp + 20LL, v11);
    }
    v16 = i32_load(&w2c_memory, check_sp + 60LL);
    w2c_dlfree(v16);
    v12 = i32_load(&w2c_memory, check_sp + 24LL);
    i32_store(&w2c_memory, check_sp + 108LL, v12);
  }
  else                                          // -1
  {
    i32_store(&w2c_memory, check_sp + 108LL, 0xFFFFFFFFLL);
  }
  v15 = i32_load(&w2c_memory, check_sp + 108LL);
  w2c___stack_pointer = check_sp + 112;         // pop stack frame
  --wasm_rt_call_stack_depth;
  return v15;
}
```

#### Quarou Function

逻辑重叠比较大，xor + 8-bit ROL

```c
_DWORD *__fastcall w2c_qua_rou(unsigned int new_space, unsigned int a, unsigned int b, unsigned int c, unsigned int d)
{
  ......
  if ( ++wasm_rt_call_stack_depth > 0x1F4u )
    wasm_rt_trap(7LL);
  quarou_sp = w2c___stack_pointer - 32;
  i32_store(&w2c_memory, (unsigned int)(w2c___stack_pointer - 32) + 28LL, new_space);
  i32_store(&w2c_memory, quarou_sp + 24LL, a);
  i32_store(&w2c_memory, quarou_sp + 20LL, b);
  i32_store(&w2c_memory, quarou_sp + 16LL, c);
  i32_store(&w2c_memory, quarou_sp + 12LL, d);
  v65 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v64 = v65 + i32_load(&w2c_memory, quarou_sp + 24LL);// ns[a]
  v63 = i32_load8_u(&w2c_memory, v64);
  v62 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v61 = v62 + i32_load(&w2c_memory, quarou_sp + 12LL);// ns[d]
  v60 = i32_load8_u(&w2c_memory, v61);
  v59 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v58 = v59 + i32_load(&w2c_memory, quarou_sp + 24LL);
  v57 = i32_load8_u(&w2c_memory, v58);
  v56 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v55 = v56 + i32_load(&w2c_memory, quarou_sp + 12LL);
  v54 = i32_load8_u(&w2c_memory, v55);
  v53 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v52 = v53 + i32_load(&w2c_memory, quarou_sp + 20LL);// ns[b]
  v51 = (unsigned __int8)i32_load8_u(&w2c_memory, v52) ^ ((16 * (unsigned __int8)(v63 + v60)) | ((int)(unsigned __int8)(v57 + v54) >> 4));
  i32_store8(&w2c_memory, v52, v51);
  v50 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v49 = v50 + i32_load(&w2c_memory, quarou_sp + 16LL);
  v48 = i32_load8_u(&w2c_memory, v49);
  v47 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v46 = v47 + i32_load(&w2c_memory, quarou_sp + 20LL);
  v45 = i32_load8_u(&w2c_memory, v46);
  v44 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v43 = v44 + i32_load(&w2c_memory, quarou_sp + 16LL);
  v42 = i32_load8_u(&w2c_memory, v43);
  v41 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v40 = v41 + i32_load(&w2c_memory, quarou_sp + 20LL);
  v39 = i32_load8_u(&w2c_memory, v40);
  v38 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v37 = v38 + i32_load(&w2c_memory, quarou_sp + 12LL);
  v36 = (unsigned __int8)i32_load8_u(&w2c_memory, v37) ^ ((4 * (unsigned __int8)(v48 + v45)) | ((int)(unsigned __int8)(v42 + v39) >> 6));
  i32_store8(&w2c_memory, v37, v36);
  v35 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v34 = v35 + i32_load(&w2c_memory, quarou_sp + 20LL);
  v33 = i32_load8_u(&w2c_memory, v34);
  v32 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v31 = v32 + i32_load(&w2c_memory, quarou_sp + 24LL);
  v30 = i32_load8_u(&w2c_memory, v31);
  v29 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v28 = v29 + i32_load(&w2c_memory, quarou_sp + 20LL);
  v27 = i32_load8_u(&w2c_memory, v28);
  v26 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v25 = v26 + i32_load(&w2c_memory, quarou_sp + 24LL);
  v24 = i32_load8_u(&w2c_memory, v25);
  v23 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v22 = v23 + i32_load(&w2c_memory, quarou_sp + 16LL);
  v21 = (unsigned __int8)i32_load8_u(&w2c_memory, v22) ^ ((8 * (unsigned __int8)(v33 + v30)) | ((int)(unsigned __int8)(v27 + v24) >> 5));
  i32_store8(&w2c_memory, v22, v21);
  v20 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v19 = v20 + i32_load(&w2c_memory, quarou_sp + 12LL);
  v18 = i32_load8_u(&w2c_memory, v19);
  v17 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v16 = v17 + i32_load(&w2c_memory, quarou_sp + 16LL);
  v15 = i32_load8_u(&w2c_memory, v16);
  v14 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v13 = v14 + i32_load(&w2c_memory, quarou_sp + 12LL);
  v12 = i32_load8_u(&w2c_memory, v13);
  v11 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v10 = v11 + i32_load(&w2c_memory, quarou_sp + 16LL);
  v9 = i32_load8_u(&w2c_memory, v10);
  v8 = i32_load(&w2c_memory, quarou_sp + 28LL);
  v7 = v8 + i32_load(&w2c_memory, quarou_sp + 24LL);
  v6 = (unsigned __int8)i32_load8_u(&w2c_memory, v7) ^ ((2 * (unsigned __int8)(v18 + v15)) | ((int)(unsigned __int8)(v12 + v9) >> 7));
  i32_store8(&w2c_memory, v7, v6);
  result = &wasm_rt_call_stack_depth;
  --wasm_rt_call_stack_depth;
  return result;
}
```

#### Keygen

其实发现 key 只是做一个初始状态的填充，没有实际作用，即一个没有密钥的 chacha20。源码插桩记录每次 state 的变化，依次取后 8-byte 拼接即可：

```python
key = b'D33.B4T0'
enc = bytes.fromhex('05779c24d9249e693fa7ac4a10c68dfbd3520083b33f56e90fd84978b6a15c970b976779a8fefe91fb87d2221c9a1f87ed7eaddb8ae6370f9de69e3a7a5c5c488cde79756b0b9f1713e749edd41cff04')

def ROTL(a, b):
    return ((a<<b) | (a>>(8-b))) & 0xff

def QUAROUrev(s, a, b, c, d):
    s[a] ^= ROTL((s[d] + s[c]) & 0xff, 1)
    s[c] ^= ROTL((s[b] + s[a]) & 0xff, 3)
    s[d] ^= ROTL((s[c] + s[b]) & 0xff, 2)
    s[b] ^= ROTL((s[a] + s[d]) & 0xff, 4)

state = [
    ord('D'), ord('3'), ord('3'), ord('.'),
    ord('B'), ord('4'), ord('T'), ord('0'),
    0, 0, 0, 0,
    0, 0, 0, 0,
]

flag = ""
for j in range(0, len(enc), 16):
    state = list(enc[j : j + 16])
    print(f'\033[0;31m<==============ROUND:{j // 16}==============>\033[0m')
    print(bytes(state))
    for rnd in range(42):
        QUAROUrev(state, 14, 9, 4, 3)
        QUAROUrev(state, 13, 8, 7, 2)
        QUAROUrev(state, 12, 11, 6, 1)
        QUAROUrev(state, 15, 10, 5, 0)
        QUAROUrev(state, 15, 11, 7, 3)
        QUAROUrev(state, 14, 10, 6, 2)
        QUAROUrev(state, 13, 9, 5, 1)
        QUAROUrev(state, 12, 8, 4, 0)
        
    print(bytes(state))
```

# Afterword

愿各位师傅在之后学习的道路上努力追寻自己的兴趣，而不是为了比赛而比赛，多实践多思考，更多的把 CTF 当作学习知识和技术、丰富自己的渠道，做题家不可取捏。
