# 含樹イツキの憂鬱 | Disk Forensics
## Download Info
- BaiduNetDiskFastLink: `4784404e0916ae12dfdbe0aceabaa3dc#45b3487f1a0e5c28a98c2a956a13573e#7839472699#xdsec_20220415_01_01.zip`
- BaiduNetDiskLink: https://pan.baidu.com/s/1TyJtMmW-XOh6Qem-2qKswQ (提取码：game) 
- CheckSum: `8ab897f303b93bfea8dff5b856475ea736f36cd5a5794a3ad27a1fbdbebd35d2`



## Description
Uncompress password: `MiniLCTF@2022-AUal+WMtnBuTMvLtPDsAIg==`

含树某天从网上搞到了一个”有意思“的小软件，正当他摩拳擦掌跃跃欲试的时候，突然发现自己的电脑出了点小问题。于是他急忙带着自己的电脑来到了 xdsec 的实验室寻求帮忙。

Warning: 千万不要在物理机上运行镜像中的任何可执行文件！



## Hint
- 据知情人士 cyxq 透露, 含树喜欢把重要的东西记在备忘录里。
- 常用软件都会在桌面上放快捷方式的吧？



## Solve
- 桌面上有一个 `README.txt`, 内容是勒索信息.
- 在 `%USER%/Downloads/` 发现一个叫 "DBT下载器" 的应用程序, 逆一下, 可以发现病毒会释放文本到桌面，并对 `%USER%/Documents/` 目录下的文件进行加密. 在联网时从 `http://101.34.215.191:5555/get_p` 获取 online key,  联网失败时使用 default key. 从程序输出的 `hahaha.log` 中可以看到这次加密使用了 online key.  加密使用简单的异或.
- 访问 `http://101.34.215.191:5555/get_p`  得到一串 base64, 获取并解码几次可以发现长度始终是 16 bytes. 
- 通过分析 `%USER%/Documents/` 中的 `.docx` & `.png` 文件可以得到 16 bytes 的 key(用加密前的文件头与加密后的文件头进行异或).
- 写一个简单脚本对文件进行异或, 恢复原始文件.  `%USER%/Documents/好康的` 中有一个大小为 50MB 的 png 文件数据异常, 结合电脑上安装了 Veracrypt, 这或许是一个 Veracrypt 创建的加密容器.
- 电脑上装有 iTunes, 在 `%APPDATA%/Apple computer/MobileSync/` 目录下可以找到 iphone (ios 10)备份数据.
- 利用工具将备份数据导出为可读格式, 之后在备忘录的数据库 `NoteStore.sqlite` 中可以找到 `Password: dbtyeyyd5`.  数据库中备忘录内容的字段是经过编码后存储的, 需要进行解码. 可以在 GitHub 上找到两个开源项目. 不过两个项目都有点小毛病, 一个 Ruby 写的, 环境不太好配, 而且代码中有 2 处问题, 需要手动修一下; 另一个是 gradle 的, 也是代码有问题, 比上一个更难改. 如果你有专业的自动取证工具或 iOS 备份查看工具可以用的话, 可以当这一步不存在.
- 使用上一步中获取到的密码将 `IMG_20220423_114514` 作为 Veracrypt 加密容器加载. 得到 flag.
- `%SYSTEMROOT%/Temp/` 目录下有一堆缓存文件, 其中包括了 `flag.txt` 的快捷方式并指向了 `z:/flag.txt`. (但为什么只有2解呢)

## Script example
```python
import os  
from base64 import b64decode  
  
file_list = []  
# p = b"watchoutnexttime"  
p = b64decode("mkLPGV3n0DiR5yC+XqN5sg==")  

user_home = os.getenv("HOME") or os.path.expanduser('~')
path_to_enc = os.path.join(user_home, "Documents\\") 
for path, _, files in os.walk(path_to_enc):  
    for filename in files:  
        file_list.append(os.path.join(path, filename))  
  
while file_list:  
    cur = file_list.pop()  
    if cur.split("\\")[-1].split(".")[-1] == "hahaha":  
        with open(cur, "rb") as fin:  
            with open(".".join(cur.split(".")[:-1]), "wb") as fout:  
                m = fin.read()  
                pl = len(p)  
                ml = len(m)  
                k = (ml // pl) * p + p[: ml % pl]  
                for i in range(ml):  
                    textBytes = (k[i] ^ m[i]).to_bytes(1, "big")  
                    fout.write(textBytes)
```

---

# 含樹イツキの溜息 | Memory Forensics
## Download Info
- BaiduNetDiskFastLink: `ff519570fc86a3c89fb5bdc75b007168#cd136b5c89394ac8ee18004a81f3af8b#666559915#WIN-Q0BKD9OJ4S7-20220422-140551.zip`
- BaiduNetDiskLink: https://pan.baidu.com/s/1aIIrJmI6QlYNP4QZ0JVMzA (提取码：game)
- CheckSum: `2545d5397352e12ddce885e140287ec4fdc9540c3ddc3866518b5dfc278bc449`



## Description
Uncompress password:  `MiniLCTF@2022-AUal+WMtnBuTMvLtPDsAIg==`

含树最近在偷偷摸摸搞什么事情。某人悄悄地趁含树上厕所忘记锁屏，从他的虚拟机里提取了内存镜像。所以，含树究竟在偷偷干什么？



## Hint
- 坏掉的苹果把坏掉的部分削掉就能吃了。
- 进程里似乎混进了奇怪的东西。



## Solve
- 查看进程发现 wireshark, bandizip, firefox, cmd 和 xchat
- 查看文件列表, 发现 wireshark 开启了一个 pcap 文件, bandizip 读取了一个 zip 文件
- 查看网络连接, 发现 xchat 连接了一个服务器
- 导出 wireshark 读取的 pcap 文件和 bandizip 读取的 zip 文件
- 其实还可以导出一张图片, 是桌面截图, 可以看到 wireshark 的快捷方式 & Xchat 的对话框 & bandizip 的密码输入框.
- pcap 文件损坏, 无法用 wireshark 全部读取
	- 方案一: 删除其中的重复的 `00`, 多试几次, 可以把大多数流量包读取出来
	- 方案二: 16 进制查看, 可以看到部分 `utf-8` 编码的明文数据
	- 方案三: 使用 [pcapfix]([pcapfix - repair corrupted pcap / pcapng files (f00l.de)](https://f00l.de/pcapfix/)) 进行修复
- 可以看到流量包中 IRC 通讯的数据, HS 从 SomeBody 手里买到了一个 flag, 用一个传输工具通过 tcp 传输. 在交流中提到使用了 HS 熟悉的密码.
- 使用 volatility 的 [mimikatz 插件](https://github.com/volatilityfoundation/community/tree/master/FrancescoPicasso)提取用户密码:  `Hs_w4nt5_4_gf`
- 用用户密码解压 zip 文件
- 得到 flag

---

# にゃにゃにゃにゃにゃん | Steganography
## Description
喵喵 喵喵 喵喵喵喵 喵喵 
喵 喵喵喵喵喵喵喵喵喵喵喵喵喵喵 
喵喵 喵喵喵喵喵喵喵喵喵喵喵喵 
喵 喵喵喵喵喵喵喵喵喵喵喵  



## Hint
- 含树发来了神秘链接：[https://github.com/aliyunav/Finger](https://github.com/aliyunav/Finger)
- 含树在 IDA 里发现了几个有意思的函数，并表示这题简单。MISC 带师洛千表示，这题不用逆。



## Solve
- wav 格式, steghide 提取隐写文件, passphrase 在元数据中 `Nyan!: nyanyanyanya~`.
- 提取到文件,  是一个 shell 脚本, 用 gzexe 压缩过的. 但因为压缩内容是二进制文件所以直接运行脚本会报错.
- 提取文件的后半部分, `1F 8B 08 08 BD` 之后的内容保存为 gz 文件, 使用 gzip 或其它解压应用解压, 得到 `nyanyanya`. binwalk 也可以自动分离.
- 查看文件头, 是一个 elf 文件. 
- 困难做法: 拖进 ida 里. 分析可以发现有一个 `RC4` 解密函数. 动调查看所有被这个函数解密过的数据, 其中一段数据解密之后是一个 shell 脚本.
- 简单做法: dump 内存(`(gdb)dump memory` or `ps -elf | grep nya`).
- 用 Hint 中提到的 finger 可以自动识别常用函数, 发现有 `xsh` , `arc4`, `key` 这几个函数, 丢到搜索引擎搜索可以找到 shc 和 unshc 这两个项目. (然而 unshc 3 年没更新了, 已经不能用了.)
