# Mini L CTF 2022 writeups-Cryptography

[TOC]

## Double S

### Description: 

> 近来，L-team成员内部流传着一个秘密，而你只能得到少部分成员加密后的密文，你能够拿到这个秘密吗。

### Attachment:

```python
from Crypto.Util.number import *
from secret import flag
import random
import os

assert flag[:9] == b'miniLCTF{'
assert flag[-1:] == b'}'
flag = flag[9:-1]
flag = b'#' + flag + b'#' + os.urandom((64-len(flag)) % 64)

members = [
    ...
]

my_sec = [bytes_to_long(flag[i*4:i*4+4]) for i in range(16)]

n = 32
t = 32

class Sharing:
    def __init__(self,secret):
        self.A = secret
        self.init_func()

    def init_func(self):
        for i in range(n - 16):
            self.A.append(random.randrange(1,1<<32))
    
    def f(self,x):
        ret = 0
        tmp = 1
        for i in range(n):
            ret += self.A[i] * tmp
            tmp *= x
        return ret

def get_msg(name,SS):
    inp = bytes_to_long(name)
    cip = SS.f(inp)
    return name,cip

def main():
    SS = Sharing(my_sec)
    f = open("./outputs",'wb')
    for i in range(t):
        tmp_member = random.choice(members)
        members.remove(tmp_member)
        name , cipher = get_msg(tmp_member.encode(),SS)
        f.write(name + b" " + str(cipher).encode() + b"\n")
    f.close()

main() 
```

### Expected Solution

题目给出Sharing类，计算多项式
$$
f(x)=a_0+a_1x+a_2x^2+...+a_{31}x^{31}
$$
其中 $a_0,a_1$ 等部分系数是flag的内容。并且题目给出t条多项式f(x)和x的值，其中t=n=32。于是可以构造矩阵
$$
\left[\begin{matrix}1&x_0&x_0^2&...&x_0^{31}\\
1&x_1&x_1^2&...&x_1^{31}\\
...&...&...&...&...\\
1&x_{31}&x_{31}^2&...&x_{31}^{31}\\
\end{matrix}\right]\cdot
\left[\begin{matrix}a_0\\
a_1\\
...\\
a_{31}\\
\end{matrix}\right]=
\left[\begin{matrix}c_0\\
c_1\\
...\\
c_{31}\\
\end{matrix}\right]
$$
代入发现左边这个矩阵满秩，即可通过解多项式获得系数的值。

### Unexpected Solution

由于多项式是在整数环下，并且可能某member的id太短辣，以至于可以转换成id的进制，就能直接得到系数 :( 。

## Double SS

### Description:

> 又有一个新的秘密被大家分享了，这次你还能够拿到这个秘密吗？

### Attachment:

```python
from Crypto.Util.number import *
from secret import flag
import random
import os

assert flag[:9] == b'miniLCTF{'
assert flag[-1:] == b'}'
flag = flag[9:-1]
table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz!_@#$%^&"
flag = b'#' + flag + b'#' 
for i in range((64-len(flag)) % 64):
    flag += bytes([random.choice(table)]) 

members = [
	...
]

my_sec = [bytes_to_long(flag[i*4:i*4+4]) for i in range(16)]

n = 32
t = 31

class Sharing:
    def __init__(self,secret):
        self.A = secret
        self.init_func()

    def init_func(self):
        for i in range(n - 16):
            self.A.append(random.randrange(1,1<<32))
    
    def f(self,x):
        ret = 0
        tmp = 1
        for i in range(n):
            ret += self.A[i] * tmp
            tmp *= x
        return ret

def get_msg(name,SS):
    inp = bytes_to_long(name)
    cip = SS.f(inp)
    return name,cip

def main():
    SS = Sharing(my_sec)
    f = open("./outputs",'wb')
    for i in range(t):
        tmp_member = random.choice(members)
        members.remove(tmp_member)
        name , cipher = get_msg(tmp_member.encode(),SS)
        f.write(name + b" " + str(cipher).encode() + b"\n")
    f.close()

main() 
```

### Expected Solution

主函数部分与DoubleS类似，不过由于少给一条多项式，其中t+1=n=32。有两种做法：

1. 由于4个byte一块，第一块已知第一个字符为 # ，并且其中的字符是在table中的，同DoubleS构造爆破 # 后面的三个字符即可， 爆破时间是 O(70^3)。
2. 第一块已知 第一个字符为 #，我们可以通过给他假设加入一条式子，我们让他成为满秩矩阵，解密即可得到近似解。

### Unexpected Solution

由于多项式是在整数环下，和DoubleS相同的非预期 TnT

## Double SS  revenge

### Description:

由于上一道题和Double S 相同的非预期，于是又调整了到了模多项式上。

### Attachment:

```python
...
p = getPrime(256)
...
class Sharing:
    def __init__(self,secret):
        self.A = secret
        self.init_func()

    def init_func(self):
        for i in range(n - 16):
            self.A.append(random.randrange(1,1<<32))
    
    def f(self,x):
        ret = 0
        tmp = 1
        for i in range(n):
            ret += self.A[i] * tmp
            tmp *= x
        return ret % p
...
```

### Expected Solution

题目主要函数同上。只不过改成了%p，并且给出了p。

主要做法也与Double SS的预期解类似。

## factorchal

### Description:

> 这道题看起来好像很容易呢，你能在5min内挑战成功吗

### Attachment:

```python
from Crypto.Util.number import*
from secret import flag
from hashlib import sha256
import socketserver
import signal
import string
import random
table = string.ascii_letters+string.digits

def get_key():
    tmp = random.randrange(1,1<<27)
    while 1:
        tmp += 2
        if isPrime(tmp):
            break
    d = tmp * p
    e = inverse(d,phi)
    return d,e

p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p-1) * (q-1)
d,e = get_key()
msg = getRandomRange(1,1<<400)
c = pow(msg,e,n)

class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b''):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        proof = (''.join([random.choice(table)for _ in range(20)])).encode()
        sha = sha256(proof).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha )
        XXXX = self.recv(prompt = b'[+] Plz Tell Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return sha.decode()

    def handle(self):
        Hash = self.proof_of_work()
        if not Hash:
            self.request.close()
        self.send(b"\nI'll send you my encrypt data.Can you decrypt it in 5mins???")
        self.send(b'e = ' + hex(e).encode())
        self.send(b'n = ' + hex(n).encode())
        self.send(b'c = ' + hex(c).encode())
        signal.alarm(300)
        self.send(b'plz response the msg:')
        sec_m = int(self.recv(),16)
        if sec_m == msg:
            self.send(b'\nYou win!Give you my flag!')
            self.send(flag)
        self.send(b"\nConnection has been closed  =.=  ")
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
```

### Expected Solution

主要漏洞点是题目中的getkey函数，其中d=kp，并且k需要是一个(1<<27)内的素数。

我们选择的r是随意给出的一个数据，但不能是n的因子（那不就分解n了，想什么孽）或者n的倍数
$$
c=m^{e}\mod n,(kp)e=k_i\phi+1\\
r^{kpe}=r\mod n\\
r^{ke\cdot 1}\equiv r \mod n\Rightarrow r^{ke\cdot p}\equiv r \mod p
$$
接下来通过欧拉定理得到
$$
r^{ke}\equiv r \mod p\Rightarrow r^{ke}-r\equiv 0 \mod p
$$
由于k是一个素数，此处k的爆破空间准确来讲范围应该是 2^26。

如果说r不是q的倍数 $GCD(r^{ke}-r,n)=p$ 了，但如果是，那么可能就找不到，并且不是n的倍数，那可能或许你就能够直接分解n（废话。

ps: 此处如果直接用python自带的pow函数，可能速度不够，因为限制时间在5min内。因此调用gmpy2库中的powmod函数（gmpy2 yyds!）。同时爆破k过程中可以使用s2 = 2^{2e}，s1=s1 * s2%p去优化速度。

## Copiano

### Description:

> Block of Piano?

### Attachment:

```python
from Crypto.Util.number import *
import os
from secret import flag

nbit = 2048
p, q = getPrime(nbit // 2), getPrime(nbit // 2)
N = p * q
e = 3
cipher_block_length = nbit // 8
plain_block_length = cipher_block_length // 8

def pad(msg):
    return msg + ((plain_block_length - len(msg) % plain_block_length) % plain_block_length) * b'\x00'

def block_enc(msg):
    m = bytes_to_long(msg)
    x = bytes_to_long(os.urandom(nbit // 8))

    c = long_to_bytes(pow(m ^ x, e, N)).rjust(cipher_block_length,b'\x00')
    t = m & x
    return c , (x,t)

def ecb_mode_enc(msg):
    plain_block = [msg[plain_block_length * i: plain_block_length * (i + 1)] for i in range(len(msg) // plain_block_length)]
    cipher_text = b''
    x_list = []
    t_list = []
    for msg_part in plain_block:
        cipher_part , (x_tmp,t_tmp) = block_enc(msg_part)
        cipher_text += cipher_part
        x_list.append(x_tmp)
        t_list.append(t_tmp)
    return cipher_text , x_list , t_list

cipher , x_list, t_list = ecb_mode_enc(pad(flag))

f = open("./output",'wb')
f.write(b"N =" + str(N).encode() + b'\n')
f.write(b"e =" + str(e).encode() + b'\n')
f.write(b"c =" + cipher + b'\n')
f.write(b"x_list =" +str(x_list).encode() + b'\n')
f.write(b"t_list =" +str(t_list).encode() + b'\n')
f.close()
```

### Expected Solution

题目中加密部分是讲明文分块进行ECB模式的加密。每块加密过程如下
$$
enc(m)=(m\oplus x)^e\mod N
$$
并且给出了 $m\&x$ ，因此我们可以分析得到
$$
m\oplus x = m+x-2m\&x
$$
回代enc(m)，我们发现
$$
(m\oplus x)^3\equiv (m+x-2m\&x)\mod N
$$
其中x与 $m\&x$ 我们都已知，并且m大致是256bit，而N为2048位。因此想到的是使用coppersmith去解决这个问题。

### Unexpected Solution

本题由于e=3很小，并且在调的过程中让x变小，但是没调回去，于是导致了低指数加密攻击......

即可以拿到 $m\oplus x$ ，直接异或回去就拿到了m。TnT...............

## R1ngWin

### Description:

> ERROR ! ERROR ! ERROR !

### Hint:

> Do you know how **Ding Key Exchange** works?

### Attachment:

```python
from bfv.batch_encoder import BatchEncoder
from bfv.bfv_encryptor import BFVEncryptor
from bfv.bfv_key_generator import BFVKeyGenerator
from bfv.bfv_parameters import BFVParameters
from secret import flag
# source of py-fhe:https://github.com/sarojaerabelli/py-fhe/
def main():
    degree = 32 
    plain_modulus = 257
    ciph_modulus = 0x9000000000000

    params = BFVParameters(poly_degree=degree,
                            plain_modulus=plain_modulus,
                            ciph_modulus=ciph_modulus)

    key_generator = BFVKeyGenerator(params,e_times=3)
    f = open("./output",'w')

    public_key1 = key_generator.public_key
    f.write("public_key1 = (" + str(public_key1.p0) + "," + str(public_key1.p1) + ")\n")

    # encrypt part
    encoder = BatchEncoder(params)
    encryptor = BFVEncryptor(params, public_key1)
    message = list(flag)
    plain = encoder.encode(message)
    cipher = encryptor.encrypt(plain)
    f.write("cipher:" + str(cipher))

    f.close()

if __name__ == '__main__':
    main()
```

修改了一点点库函数

```python
class BFVKeyGenerator:
    def __init__(self, params,e_times=1):
        self.generate_secret_key(params)
        self.generate_public_key(params,e_times)
        self.generate_relin_key(params)

    def generate_secret_key(self, params):
        self.secret_key = SecretKey(Polynomial(params.poly_degree,
                                               sample_triangle(params.poly_degree)))

    def generate_public_key(self, params,etimes):
        pk_coeff = Polynomial(params.poly_degree,
                              sample_uniform(0, params.ciph_modulus, params.poly_degree,odd=True))
        pk_error = Polynomial(params.poly_degree,
                              sample_triangle(params.poly_degree)).scalar_multiply(etimes,params.ciph_modulus)
        p0 = pk_error.add(pk_coeff.multiply(
            self.secret_key.s, params.ciph_modulus), params.ciph_modulus).scalar_multiply(
                -1, params.ciph_modulus)
        p1 = pk_coeff
        self.public_key = PublicKey(p0, p1)
```

### Expected Solution

该题是想让选手们了解一下RLWE这个东西，并且本题是通过使用了py-fhe库[4]进行的加密。

这里如果了解一点RLWE中的BFV，我们可以知道它是在不可约多项式f的商环上，该题
$$
f=x^{32}+1
$$
同时 `BFVKeyGenerator(params,e_times=3)` 中可以得知公钥p和私钥s的关系如下
$$
p=(p_0=p_1s+3e,p_1)
$$
并且可以知道多项式私钥s的系数定义域是在 $\{-1,0,1\}$ 中，扰动向量是3的倍数。此处给出一个Hint: Ding Key Exchange。

是由于DKE中有一个"错误消除"的方式，也是该题的出题思路[1]。

DKE中的错误消除方法是 Jintai Ding 在2012年发明的基于LWE和RLWE的类DH密钥交换算法[2]。
$$
k_A=s_Ap_B=as_As_B+2s_Ae_B;k_B=s_Bp_A=as_Bs_A+2s_Be_A;\\
k_A-k_B=a(s_As_B-s_As_B)+2(s_Ae_B-s_Be_A)=2(s_Ae_B-s_Be_A)
$$
可以得知kA以及kB奇偶性相同。于是A和B就可以将自己得到的kA或kB模2之后就能够得到相同的会话密钥了。

这道题是将其模3了我们就可以直接消除掉e，但是好像与DKE的关系可能也不是很大（或许只是引起我这种想法的点吧。

不过shallow和hashhash都说该方法蛮像Nguyen早期攻击GGH的方法，如果有兴趣可以去看看他写的相关paper[3]。

## Postscript:

可能因为第一次给一场比赛出这么多题，而且没有好好测题(🔨🔨🔨)，出了好一些非预期，背大锅，同时最近也没啥出题灵感5555，出得不是很好，但是总归也希望这些题目能给大家带来一些学习以及上升的空间吧。

不过想到一年前也差不多这个时候的Mini L CTF，肝了三天，能ak了crypto(不过就3道的原因吧)，算是我进入L-Team的入场券，同时也是我才一点点摸到CTF的门槛，真快啊，今年就到我们办了。不过过程中拿着admin账号看后台交flag记录，还挺有意思的捏：

比如说企鹅的题 `who is the god of XDSEC` ，Reply:`miniLCTF{rx}`!以及zsky学长的 `You_are_too_younggthis_is_a_fake_flag!!!` ，还有晚安题里的协会人们的黑照，以及彩蛋题之hacked by shallow，甚至Noah的取证题里还有一个`dbt下崽器`(???)

出题人们属实太会整活辣。同时今年的学弟们也很给力捏(ddw)！！！

也十分感谢Merak，0Rays，Vidar和CNSS等校外师傅愿意来赏脸参加 XD

## Reference:

[1] : [基于格RLWE问题的密钥交换协议和原理-知乎](https://zhuanlan.zhihu.com/p/45880224)

[2] : [A Simple Provably Secure Key Exchange Scheme Based on the Learning with Errors Problem](https://eprint.iacr.org/2012/688.pdf)

[3] : [Cryptanalysis of the Goldreich-Goldwasser-Halevi Cryptosystem from Crypto ’97](https://link.springer.com/chapter/10.1007/3-540-48405-1_18)

[4] : [py-fhe](https://github.com/sarojaerabelli/py-fhe/)



