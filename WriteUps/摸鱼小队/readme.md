# miniLctf 题解

by 摸鱼小队

## twin

是个32位Windows程序，用`main`中的数组异或生成flag，结果是

```plaintext
You_are_too_young_this_is_a_fake_flag!!!
```

结果不对。有几个call+ret垃圾指令，先patch掉。程序正确逻辑在`TlsCallback`里，F5进入，手动解密字符串，分析到的流程为：

* `DLL_PROCESS_ATTACH`：创建文件映射对象，把分配到的内存块用作输入缓冲区
* `DLL_PROCESS_DETACH`：载入程序资源（另一个exe），写到当前目录下的tmp文件中。运行tmp。这个子进程会校验调试器的存在并检验前半个flag，父进程等待子进程结束后检查返回值，然后校验剩下的flag。完成后删除文件。校验用的都是xxtea算法。

值得注意的有两个：

* 父进程写入tmp时，设置了`WriteFile`钩子，它会修改子进程.text段，具体改了xxtea的位移。
* 子进程主动触发异常，父进程收到调试事件后会修改寄存器的值。

```c
// 源码太乱了，略过
```

> miniLctf{cbda59ff59e3e90c91c02e9b40b78b}

## not_rc4

risc-v架构，ida F5分析不出来，于是尝试手动分析汇编，这个是[参考资料](https://shakti.org.in/docs/risc-v-asm-manual.pdf)。

程序是一个简易虚拟机，读入flag当作`QWORD`数组，然后加载`0x2018`处的字节码，最后将`0x20C8`处的运算结果与`0x2030`处的目标值比较。字节码对应的动作为：

| 字节码    | 动作                                                         |
| :-------- | :----------------------------------------------------------- |
| `F1`      | 检验结果，失败退出。                                         |
| `F2 x, y` | 程序跳转到`x`字节前循环`y`次。                               |
| `F3 x`    | 读入`flag[x]`、`flag[x+1]`，把它们分别与`0x0x64627421`、`0x79796473`相加并放入两个寄存器`r1`、`r2`。 |
| `F4 x`    | 如果`x==0xE1`，`r1=0x0x64627421+(((r1^r2)<<(r2&63))|(r1^r2)>>((-r2)&63)))`；否则`r2=0x79796473+(((r1^r2)<<(r1&63))|(r1^r2)>>((-r1)&63)))`。 |
| `F5`      | 把`r1`、`r2`运送到输出缓冲区。                               |
| `FF`      | 退出虚拟机                                                   |

解密代码：

```c
#include <stdio.h>

static void solve(unsigned long long *v)
{
    const unsigned long long magic1 = 0x64627421, magic2 = 0x79796473;
    for (int i = 0; i < 12; ++i)
    {
        int left, right;

        right = v[0] & 63;
        left = 64 - right;
        v[1] -= magic2;
        v[1] = ((v[1] >> right) | (v[1] << left)) ^ v[0];

        right = v[1] & 63;
        left = 64 - right;
        v[0] -= magic1;
        v[0] = ((v[0] >> right) | (v[0] << left)) ^ v[1];
    }
    v[0] -= magic1, v[1] -= magic2;
}

int main()
{
    unsigned long long v[] = {0x4BC21DBB95EF82CA, 0xF57BECAE71B547BE, 0x80A1BDAB15E7F6CD, 0xA3C793D7E1776385};
    solve(v); solve(v + 2);
    printf("%s\n", v);
    return 0;
}
```

> miniLCTF{I_hate_U_r1sc-V!}

## WhatAssembly

是个wasm程序。先把对应文件下载下来，其中html负责展示，wasm加密解析，js是胶水代码。使用wabt工具包还原成c文件，可读性还是很差的，于是使用JEB解析文件。得到下面的：

```c
int check(int flag, int key, int enc_hex) {
    int v0 = __g0 - 112;

    __g0 -= 112;
    *(int*)(v0 + 104) = flag;
    *(int*)(v0 + 100) = key;
    *(int*)(v0 + 96) = enc_hex;
    *(long long*)(v0 + 88) = *(long long*)&hex_map[&gvar_8];
    *(long long*)(v0 + 80) = *(long long*)&hex_map[0];
    int len_flag = strlen(*(int*)(v0 + 104));
    *(int*)(v0 + 76) = len_flag;
    int len_key = strlen(*(int*)(v0 + 100));
    *(int*)(v0 + 72) = len_key;
    int len_enc_hex = strlen(*(int*)(v0 + 96));
    *(int*)(v0 + 68) = len_enc_hex;
    if(*(int*)(v0 + 72) < &gvar_8) {  // key length >= 8
        *(int*)(v0 + 108) = -1;
    }
    else if((unsigned int)(*(int*)(v0 + 68) - 32 >= *(int*)(v0 + 76) * 4) || *(int*)(v0 + 76) * 4 > *(int*)(v0 + 68)) {
        *(int*)(v0 + 108) = -1;  // len_flag>len_enc_hex/4
    }
    else {
        *(int*)(v0 + 64) = (*(int*)(v0 + 76) + 15) & 0xfffffff0;  // group_count
        int v4 = malloc(*(int*)(v0 + 64));
        *(int*)(v0 + 60) = v4;
        __f19(*(int*)(v0 + 64), 0, *(int*)(v0 + 60));
        __f18(*(int*)(v0 + 76), *(int*)(v0 + 104), *(int*)(v0 + 60));
        *(unsigned int*)((int)&gvar_1C + v0) = 0;
        while(*(int*)((int)&gvar_1C + v0) < &gvar_8) {
            *(char*)(*(unsigned int*)((int)&gvar_1C + v0) + v0 + 32) = *(char*)(*(unsigned int*)((int)&gvar_1C + v0) + *(int*)(v0 + 100));
            *(unsigned int*)((int)&gvar_1C + v0) = *(unsigned int*)((int)&gvar_1C + v0) + 1;
        }
        *(unsigned int*)((int)&gvar_18 + v0) = 0;
        *(unsigned int*)((int)&gvar_14 + v0) = 0;
        while(*(int*)((int)&gvar_14 + v0) < *(int*)(v0 + 76)) {
            *(unsigned int*)((int)&gvar_10 + v0) = 0;
            while(*(int*)((int)&gvar_10 + v0) < &gvar_8) {
                *(char*)(*(unsigned int*)((int)&gvar_10 + v0) + v0 + 40) = *(char*)(*(unsigned int*)((int)&gvar_14 + v0) + *(unsigned int*)((int)&gvar_10 + v0) + *(int*)(v0 + 60));
                *(unsigned int*)((int)&gvar_10 + v0) = *(unsigned int*)((int)&gvar_10 + v0) + 1;
            }
            *(unsigned int*)((int)&gvar_C + v0) = 0;
            while(*(int*)((int)&gvar_C + v0) < 42) {
                __f14(0, 4, &gvar_8, &gvar_C, v0 + 32);
                __f14(1, 5, 9, 13, v0 + 32);
                __f14(2, 6, 10, 14, v0 + 32);
                __f14(&gvar_3, 7, 11, 15, v0 + 32);
                __f14(0, 5, 10, 15, v0 + 32);
                __f14(1, 6, 11, &gvar_C, v0 + 32);
                __f14(2, 7, &gvar_8, 13, v0 + 32);
                __f14(&gvar_3, 4, 9, 14, v0 + 32);
                *(unsigned int*)((int)&gvar_C + v0) = *(unsigned int*)((int)&gvar_C + v0) + 1;
            }
            *(unsigned int*)((int)&gvar_8 + v0) = 0;
            while(*(int*)((int)&gvar_8 + v0) < &gvar_10) {
                *(unsigned int*)((int)&gvar_18 + v0) = (unsigned int)((unsigned int)((int)*(char*)(*(unsigned int*)((int)&gvar_14 + v0) * 4 + *(unsigned int*)((int)&gvar_8 + v0) * 2 + *(int*)(v0 + 96)) != (int)*(char*)((unsigned int)*(char*)(*(unsigned int*)((int)&gvar_8 + v0) + v0 + 32) / &gvar_10 + v0 + 80)) | *(unsigned int*)((int)&gvar_18 + v0));
                *(unsigned int*)((int)&gvar_18 + v0) = (unsigned int)((unsigned int)((int)*(char*)(*(unsigned int*)((int)&gvar_14 + v0) * 4 + *(unsigned int*)((int)&gvar_8 + v0) * 2 + (*(int*)(v0 + 96) + 1)) != (int)*(char*)((unsigned int)*(char*)(*(unsigned int*)((int)&gvar_8 + v0) + v0 + 32) % &gvar_10 + v0 + 80)) | *(unsigned int*)((int)&gvar_18 + v0));
                *(unsigned int*)((int)&gvar_8 + v0) = *(unsigned int*)((int)&gvar_8 + v0) + 1;
            }
            *(unsigned int*)((int)&gvar_14 + v0) = *(unsigned int*)((int)&gvar_14 + v0) + &gvar_8;
        }
        free(*(int*)(v0 + 60));
        *(unsigned int*)(v0 + 108) = *(unsigned int*)((int)&gvar_18 + v0);
    }

    int result = *(int*)(v0 + 108);
    __g0 = v0 + 112;
    return result;
}
```

可读性仍然很差，但能看出大概逻辑了。分析发现JEB解析的函数参数顺序全颠倒了，手动修正并还原得：

```c

void qua_rou(char *p, unsigned a0, unsigned a1, unsigned a2, unsigned a3) {
    p[a1] ^= (p[a0] + p[a3]) << 4 | (p[a0] + p[a3]) >> 4;
    p[a3] ^= (p[a2] + p[a1]) << 2 | (p[a2] + p[a1]) >> 6;
    p[a2] ^= (p[a1] + p[a0]) << 3 | (p[a1] + p[a0]) >> 5;
    p[a0] ^= (p[a3] + p[a2]) << 1 | (p[a3] + p[a2]) >> 7;
}

int check(int flag, int key, int enc_hex) {
    char alpha_map[] = "01234567899abcdef"; // 80h~90h
    int len_flag = strlen(flag);
    int len_key = strlen(key);
    int len_enc_hex = strlen(enc_hex);
    if(len_key < 8) {
        result = -1;
    }
    else if(len_enc_hex - 32 >= len_flag * 4 || len_flag * 4 > len_enc_hex) {
        result = -1;
    }
    else {
        int group_count = (len_flag + 15) & 0xfffffff0;
        char *buf = malloc(group_count*16);
        memset(buf, 0, group_count);
        memcpy(buf, flag, len_flag);
        char key1[16]; // 20h~28h
        memmove(key1, key, 8);
        unsigned x = 0;
        while(unsigned j = 0; j < len_flag; j += 8) {
            memmove(key1+8, buf + j, 8); // 28h~30h
            for (unsigned i = 0; i < 42; ++i) {
                qua_rou(key1, 12,  8, 4, 0);
                qua_rou(key1, 13,  9, 5, 1);
                qua_rou(key1, 14, 10, 6, 2);
                qua_rou(key1, 15, 11, 7, 3);
                qua_rou(key1, 15, 10, 5, 0);
                qua_rou(key1, 12, 11, 6, 1);
                qua_rou(key1, 13,  8, 7, 2);
                qua_rou(key1, 14,  9, 4, 3);
            }
            for (unsigned i = 0; i < 16; ++i) {
                x |= enc_hex[j * 4 + i * 2] != alpha_map[key1[i]/16];
                x |= enc_hex[j * 4 + i * 2 + 1] != alpha_map[key1[i]%16];
            }
        }
        free(buf);
        result = x;
    }
    return result;
}
```

解密即可：

```c
#include <stdio.h>
#include <string.h>

static const unsigned char enc[] = {
    0x05,0x77,0x9c,0x24,0xd9,0x24,0x9e,0x69,0x3f,0xa7,0xac,0x4a,0x10,0xc6,0x8d,0xfb,
    0xd3,0x52,0x00,0x83,0xb3,0x3f,0x56,0xe9,0x0f,0xd8,0x49,0x78,0xb6,0xa1,0x5c,0x97,
    0x0b,0x97,0x67,0x79,0xa8,0xfe,0xfe,0x91,0xfb,0x87,0xd2,0x22,0x1c,0x9a,0x1f,0x87,
    0xed,0x7e,0xad,0xdb,0x8a,0xe6,0x37,0x0f,0x9d,0xe6,0x9e,0x3a,0x7a,0x5c,0x5c,0x48,
    0x8c,0xde,0x79,0x75,0x6b,0x0b,0x9f,0x17,0x13,0xe7,0x49,0xed,0xd4,0x1c,0xff,0x04,
};

#define times (sizeof (enc) >> 4)

static void un_qua_rou0(unsigned char *p, unsigned char a0, unsigned char a1, unsigned char a2, unsigned char a3)
{
    p[a0] ^= (unsigned char)(p[a3] + p[a2]) << 1 | (unsigned char)(p[a3] + p[a2]) >> 7;
    p[a2] ^= (unsigned char)(p[a1] + p[a0]) << 3 | (unsigned char)(p[a1] + p[a0]) >> 5;
    p[a3] ^= (unsigned char)(p[a2] + p[a1]) << 2 | (unsigned char)(p[a2] + p[a1]) >> 6;
    p[a1] ^= (unsigned char)(p[a0] + p[a3]) << 4 | (unsigned char)(p[a0] + p[a3]) >> 4;
}

#define un_qua_rou(p, a0, a1, a2, a3) un_qua_rou0(p, a3, a2, a1, a0)

int main()
{
    unsigned char buf[17];

    buf[16] = 0;
    for (unsigned i = 0; i < times; ++i)
    {
        memmove(buf, enc + i * 16, 16);
        for (unsigned j = 0; j < 42; ++j)
        {
            un_qua_rou(buf, 3, 4,  9, 14);
            un_qua_rou(buf, 2, 7,  8, 13);
            un_qua_rou(buf, 1, 6, 11, 12);
            un_qua_rou(buf, 0, 5, 10, 15);
            un_qua_rou(buf, 3, 7, 11, 15);
            un_qua_rou(buf, 2, 6, 10, 14);
            un_qua_rou(buf, 1, 5,  9, 13);
            un_qua_rou(buf, 0, 4,  8, 12);
        }
        printf("%s", buf + 8);
    }
    putchar('\n');
    return 0;
}
```

> miniLctf{0ooo00oh!h3ll0_WASM_h4ck3r!}

## lemon

根据提示最终找到了这里：[lemon-lang/lemon](https://github.com/lemon-lang/lemon)

程序通过线性同余产生伪随机数，并与给定值异或，迭代函数为

```python
lambda x: (x * 0xDEADBEEF + 0xB14CB12D) % 0xFFFFFFFF
```

其中`x0=0xD33B470`。但实际解密时发现除了第一个字符外其他结果均不对，因为这个语言内部计算会把`long long`强制转换为`double`造成误差，所以最后直接用这个语言写解密程序：

```lemon
var a = 0xD33B470;
var f = [0x13ADB1C3,0x27A699B6,0x3D6B0A60,0x2559D45D,0x33545C0C,0x1F1973EE,0x22F2CC71,0x09FF086A,0x1D890216,0x1B699A54,0x02D7B0AF,0x2040F7B3,0x2BD3F1EF,0x371A4F4B,0x03FDB187,0x314FBBA7,0x00476C6A,0x24D8CC4E,0x3E19CF81,0x19507D1E,0x0F68A0A3,0x11F67AE7,0x0E30F6A0,0x078EF854,0x098AD320,0x13E05586,0x1F47F4AA,0x13EC0412,0x1FC0D89C,0x29CD17B6,0x2D0FA4AE,0x0D1C0DC7,0x0237EAD3,0x048BC12B,0x7FA9126D];
for (var i = 0; i < 35; i += 1)
{
    a = (a * 0xDEADBEEF + 0xB14CB12D) % 0xFFFFFFFF;
    print(a ^ f[34 - i]);
};
```

得到的数组再用python转成字符串即可。

> miniLctf{l3m0n_1s_s0_s0urrR77RrrR7}
