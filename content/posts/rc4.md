+++
title = "RC4的描述"
date = 2023-04-15
updated = 2025-06-09
[taxonomies]
categories = ["杂项"]
tags = ["杂项", "ctf"]
[extra]
lang = "zh"
toc = true
comment = true
math = true
mermaid = true
+++


### 简介

RC4加密算法是大名鼎鼎的RSA三人组中的头号人物Ronald Rivest在1987年设计的密钥长度可变的流加密算法簇。之所以称其为簇，是由于其核心部分的S-box长度可为任意，但一般为256字节。该算法的速度可以达到DES加密的10倍左右，且具有很高级别的非线性。RC4起初是用于保护商业机密的。但是在1994年9月，它的算法被发布在互联网上，也就不再有什么商业机密了。RC4也被叫做ARC4（Alleged RC4——所谓的RC4），因为RSA从来就没有正式发布过这个算法。

### 算法

该算法较为简单，文字描述有点绕，直接上代码





```
def crypt(data, key):   #data为明文或密文，key为密钥
    """RC4 algorithm"""
    x = 0
    box = range(256)   #初始化S盒
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
        #对称密码，加密解密算法一样
    return ''.join(out)
```

python中Crypto库中有该算法，具体用法如下：





```
from Crypto.Cipher import *
data = "kangel"
key = "key"
cipher = ARC4.new(key)    #加载密钥
m = cipher.decrypt(key)   #用该密钥解密
print m
```

### 扩展

RC4在有些情况下与sha1、base64一起混合使用，如果发现密文是base64编码，需考虑该算法，具体算法如下：





```
import random, base64
from hashlib import sha1
 
def crypt(data, key):
    """RC4 algorithm"""
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
 
    return ''.join(out)
 
 
def tencode(data, key, encode=base64.b64encode, salt_length=16):
    """RC4 encryption with random salt and final encoding"""
    salt = ''
    for n in range(salt_length):
        salt += chr(random.randrange(256))
    data = salt + crypt(data, sha1(key + salt).digest())
    if encode:
        data = encode(data)
    return data
 
 
def tdecode(data, key, decode=base64.b64decode, salt_length=16):
    """RC4 decryption of encoded data"""
    if decode:
        data = decode(data)
        print data
    salt = data[:salt_length]
    print len(salt)
    return crypt(data[salt_length:], sha1(key + salt).digest())
 
 
if __name__ == '__main__':
    # 需要解密的数据
    data = 'UUyFTj8PCzF6geFn6xgBOYSvVTrbpNU4OF9db9wMcPD1yDbaJw=='
    # 密钥
    key = 'welcometoicqedu'
    # 解码
    decoded_data = tdecode(data=data, key=key)
    #decoded_data = crypt(data,m)
    print("明文是：")
    print decoded_data
#bdctf{YOU_CRAKE_THE_RC4}
```

### 逆向题中的体现

前天打了掘安杯，这明明是一道很简单的逆向，可就是得不出flag。

题目如下：程序为64位的ELF文件，用ida打开

![img](https://j-kangel.github.io/2019/04/09/RC4/1.JPG)

当时并不知道这是RC4（主要还是菜），但是RC4算法不难，所以很容易实现。刚开始被那一段`>>31>>24`迷惑了很久，还恶补了一堆东西，例如：

逻辑右移与算术右移（左移都是末尾补0）





```
a = 1011
b = a >> 1
#a为无符号数
b = 0101
#a为有符号数,最高位为符号位，不进行移位运算，补全补符号位
b = 1101
所以：对于整数来说，逻辑右移与算术右移结果相同。
```

上面的代码中先是有符号int（32位）右移31位，然后无符右移24位。因为被以为的数均为正数，所以最终结果都是0。

int_64如何转化为int_8（取最低字节）：模256就行了

然后写着写着就变成了RC4，未经修改的原生态代码，虽然有点乱（额，其实是非常乱），但其实并没有什么问题

可就是答案不对。





```
a = []
for i in range(256):
    a.append(i)
v11 = 0
ch = "Th1sIsTheK3y"
for j in range(256):
    v11 = (v11 + a[j] + ord(ch[j%12]))%256
    v3 = a[j]
    a[j]=a[v11]
    a[v11] = v3
v8 = 0
v9 = 0
b = []
for k in range(24):
    v8 = (v8 +1)%256
    v9 = (v9+a[v8])%256
    b.append(a[(a[v9]+a[v8])%256])

#print(a)
#print(b)
key = [0x1c,0x61,0x97,0x34,0x28,0x69,0xfa,0x54,0xda,0x3a,0x2b,0xbb,0x05,0x09,0x16,0x38,0xf3,0xcf,0xd8,0xa5,0x12,0x7e,0x67,0x44]
print(key)
flag=""
for i in range(24):
    flag+=chr(key[i]^b[i])

print len(b)
print len(key)
print flag
```

后来看了官方wp，说是对key，进行了一次混淆。到了这里，我多说两句关于混淆：





```
为了有效抵抗攻击者对密码体制的攻击，Shannon提出三个基本设计思想--扩散、混淆（混乱）和乘积密码。
扩散：一位明文变化导致多位密文变化
混淆：进行多次加密
```

这里有个puts函数，首先用key对key进行一次RC4，得到的新key再用来加密flag。由于忽略了这一点（主要还是因为菜），所以最终只能是望而却步。看了wp，在ida中alt+t中搜索call sub_400686（RC4函数），果然有两处。

![img](https://j-kangel.github.io/2019/04/09/RC4/2.JPG)

最后上脚本





```
#coding="utf-8"
from Crypto.Cipher import *
data = "\x1c\x61\x97\x34\x28\x69\xfa\x54\xda\x3a\x2b\xbb\x05\x09\x16\x38\xf3\xcf\xd8\xa5\x12\x7e\x67\x44"
key = "Th1sIsTheK3y"
cipher = ARC4.new(key)
m = cipher.decrypt(key)
key_1 = ARC4.new(m)
m = key_1.decrypt(data)
print m
```

### 总结

看似差之毫厘，实际则反映知识的掌握程度和解题的熟练程度。不说了，回炉再造去了。