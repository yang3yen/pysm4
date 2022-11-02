
pysm4
========


### SM4算法

国密SM4(无线局域网SMS4)算法， 一个分组算法， 分组长度为128bit， 密钥长度为128bit，
算法具体内容参照[SM4算法](https://drive.google.com/file/d/0B0o25hRlUdXcbzdjT0hrYkkwUjg/view?usp=sharing)。

### pysm4

pysm4是国密SM4算法的Python实现， 提供了`encrypt`、 `decrypt`、 `encrypt_ecb`、 `decrypt_ecb`、 `encrypt_cbc`、
`decrypt_cbc`等函数用于加密解密， 用法如下：

#### 1. `encrypt`和`decrypt`

```python
>>> from pysm4 import encrypt, decrypt
# 明文
>>> clear_num = 0x0123456789abcdeffedcba9876543210
# 密钥
>>> mk = 0x0123456789abcdeffedcba9876543210
# 加密
>>> cipher_num = encrypt(clear_num, mk)
>>> hex(cipher_num)[2:].replace('L', '')
'681edf34d206965e86b3e94f536e4246'
# 解密
>>> clear_num == decrypt(cipher_num, mk)
True
```

#### 2. `encrypt_ecb`和`decrypt_ecb`

```python
>>> from pysm4 import encrypt_ecb, decrypt_ecb
# 明文
>>> plain_text = 'pysm4是国密SM4算法的Python实现'
# 密钥
>>> key = 'hello, world!'  # 密钥长度小于等于16字节
# 加密
>>> cipher_text = encrypt_ecb(plain_text, key)
>>> cipher_text
'ng3L4ldgvsZciAgx3LhplDvIzrd0+GXiNqNmd1VW0YOlwo+ojtpownOCbnxbq/3y'
# 解密
>>> plain_text == decrypt_ecb(cipher_text, key)
True
```

#### 3. `encrypt_cbc`和`decrypt_cbc`

```python
>>> from pysm4 import encrypt_cbc, decrypt_cbc
# 明文
>>> plain_text = 'pysm4是国密SM4算法的Python实现'
# 密钥
>>> key = 'hello, world!'  # 密钥 长度小于等于16字节
# 初始化向量
>>> iv = '11111111'        # 初始化向量  长度小于等于16字节
# 加密
>>> cipher_text = encrypt_cbc(plain_text, key, iv)
'cTsdKRSH2FqIJf22NHMjX5ZFHghR4ZtJ10wbNwj2//bJSElBXVeMtFycjdlVKP15'
# 解密
>>> plain_text == decrypt_cbc(cipher_text, key, iv)
True
```

pysm4实现了分组密码工作模式中的`ECB`(电子密码本)和`CBC`(密码块链接)模式， 具体内容请参考维基百科的[分组密码工作模式](https://zh.wikipedia.org/wiki/%E5%88%86%E7%BB%84%E5%AF%86%E7%A0%81%E5%B7%A5%E4%BD%9C%E6%A8%A1%E5%BC%8F)。

### 安装

#### GitHub

```bash
$ python setup.py install
```

#### PyPI

```bash
$ pip install pysm4
```

### 兼容

pysm4支持Python2.7和Python3.3以上版本，其他版本没有测试。

### 性能

验证[SM4算法](https://drive.google.com/file/d/0B0o25hRlUdXcbzdjT0hrYkkwUjg/view?usp=sharing)中的实例二：
```
实例二： 利用相同加密密钥对一组明文反复加密1000000次
明文： 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
密钥： 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 
密文： 59 52 98 c7 c6 fd 27 1f 04 02 f8 04 c3 3d 3f 66
```
使用pysm4在我个人电脑验证实例二时，耗时600多秒。性能比使用JAVA或C/C++实现版本差了很多。

