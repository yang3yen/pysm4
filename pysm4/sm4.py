#!/usr/bin/env python
# -*- coding: utf-8 -*-


from sys import version_info

from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify

__all__ = ['encrypt_ecb', 'decrypt_ecb',
           'encrypt_cbc', 'decrypt_cbc',
           'encrypt', 'decrypt']

if version_info[0] == 2:
    # python2
    PY2 = True
    PY3 = False
else:
    # python3
    PY2 = False
    PY3 = True

if PY2:
    _range = xrange
    string_types = (basestring,)
    text_type = unicode
    binary_type = str
else:
    _range = range
    string_types = (str,)
    text_type = str
    binary_type = bytes

E_FMT = 'UTF8'

# S盒
S_BOX = {
    0X00: 0XD6, 0X01: 0X90, 0X02: 0XE9, 0X03: 0XFE, 0X04: 0XCC, 0X05: 0XE1, 0X06: 0X3D, 0X07: 0XB7,
    0X08: 0X16, 0X09: 0XB6, 0X0A: 0X14, 0X0B: 0XC2, 0X0C: 0X28, 0X0D: 0XFB, 0X0E: 0X2C, 0X0F: 0X05,
    0X10: 0X2B, 0X11: 0X67, 0X12: 0X9A, 0X13: 0X76, 0X14: 0X2A, 0X15: 0XBE, 0X16: 0X04, 0X17: 0XC3,
    0X18: 0XAA, 0X19: 0X44, 0X1A: 0X13, 0X1B: 0X26, 0X1C: 0X49, 0X1D: 0X86, 0X1E: 0X06, 0X1F: 0X99,
    0X20: 0X9C, 0X21: 0X42, 0X22: 0X50, 0X23: 0XF4, 0X24: 0X91, 0X25: 0XEF, 0X26: 0X98, 0X27: 0X7A,
    0X28: 0X33, 0X29: 0X54, 0X2A: 0X0B, 0X2B: 0X43, 0X2C: 0XED, 0X2D: 0XCF, 0X2E: 0XAC, 0X2F: 0X62,
    0X30: 0XE4, 0X31: 0XB3, 0X32: 0X1C, 0X33: 0XA9, 0X34: 0XC9, 0X35: 0X08, 0X36: 0XE8, 0X37: 0X95,
    0X38: 0X80, 0X39: 0XDF, 0X3A: 0X94, 0X3B: 0XFA, 0X3C: 0X75, 0X3D: 0X8F, 0X3E: 0X3F, 0X3F: 0XA6,
    0X40: 0X47, 0X41: 0X07, 0X42: 0XA7, 0X43: 0XFC, 0X44: 0XF3, 0X45: 0X73, 0X46: 0X17, 0X47: 0XBA,
    0X48: 0X83, 0X49: 0X59, 0X4A: 0X3C, 0X4B: 0X19, 0X4C: 0XE6, 0X4D: 0X85, 0X4E: 0X4F, 0X4F: 0XA8,
    0X50: 0X68, 0X51: 0X6B, 0X52: 0X81, 0X53: 0XB2, 0X54: 0X71, 0X55: 0X64, 0X56: 0XDA, 0X57: 0X8B,
    0X58: 0XF8, 0X59: 0XEB, 0X5A: 0X0F, 0X5B: 0X4B, 0X5C: 0X70, 0X5D: 0X56, 0X5E: 0X9D, 0X5F: 0X35,
    0X60: 0X1E, 0X61: 0X24, 0X62: 0X0E, 0X63: 0X5E, 0X64: 0X63, 0X65: 0X58, 0X66: 0XD1, 0X67: 0XA2,
    0X68: 0X25, 0X69: 0X22, 0X6A: 0X7C, 0X6B: 0X3B, 0X6C: 0X01, 0X6D: 0X21, 0X6E: 0X78, 0X6F: 0X87,
    0X70: 0XD4, 0X71: 0X00, 0X72: 0X46, 0X73: 0X57, 0X74: 0X9F, 0X75: 0XD3, 0X76: 0X27, 0X77: 0X52,
    0X78: 0X4C, 0X79: 0X36, 0X7A: 0X02, 0X7B: 0XE7, 0X7C: 0XA0, 0X7D: 0XC4, 0X7E: 0XC8, 0X7F: 0X9E,
    0X80: 0XEA, 0X81: 0XBF, 0X82: 0X8A, 0X83: 0XD2, 0X84: 0X40, 0X85: 0XC7, 0X86: 0X38, 0X87: 0XB5,
    0X88: 0XA3, 0X89: 0XF7, 0X8A: 0XF2, 0X8B: 0XCE, 0X8C: 0XF9, 0X8D: 0X61, 0X8E: 0X15, 0X8F: 0XA1,
    0X90: 0XE0, 0X91: 0XAE, 0X92: 0X5D, 0X93: 0XA4, 0X94: 0X9B, 0X95: 0X34, 0X96: 0X1A, 0X97: 0X55,
    0X98: 0XAD, 0X99: 0X93, 0X9A: 0X32, 0X9B: 0X30, 0X9C: 0XF5, 0X9D: 0X8C, 0X9E: 0XB1, 0X9F: 0XE3,
    0XA0: 0X1D, 0XA1: 0XF6, 0XA2: 0XE2, 0XA3: 0X2E, 0XA4: 0X82, 0XA5: 0X66, 0XA6: 0XCA, 0XA7: 0X60,
    0XA8: 0XC0, 0XA9: 0X29, 0XAA: 0X23, 0XAB: 0XAB, 0XAC: 0X0D, 0XAD: 0X53, 0XAE: 0X4E, 0XAF: 0X6F,
    0XB0: 0XD5, 0XB1: 0XDB, 0XB2: 0X37, 0XB3: 0X45, 0XB4: 0XDE, 0XB5: 0XFD, 0XB6: 0X8E, 0XB7: 0X2F,
    0XB8: 0X03, 0XB9: 0XFF, 0XBA: 0X6A, 0XBB: 0X72, 0XBC: 0X6D, 0XBD: 0X6C, 0XBE: 0X5B, 0XBF: 0X51,
    0XC0: 0X8D, 0XC1: 0X1B, 0XC2: 0XAF, 0XC3: 0X92, 0XC4: 0XBB, 0XC5: 0XDD, 0XC6: 0XBC, 0XC7: 0X7F,
    0XC8: 0X11, 0XC9: 0XD9, 0XCA: 0X5C, 0XCB: 0X41, 0XCC: 0X1F, 0XCD: 0X10, 0XCE: 0X5A, 0XCF: 0XD8,
    0XD0: 0X0A, 0XD1: 0XC1, 0XD2: 0X31, 0XD3: 0X88, 0XD4: 0XA5, 0XD5: 0XCD, 0XD6: 0X7B, 0XD7: 0XBD,
    0XD8: 0X2D, 0XD9: 0X74, 0XDA: 0XD0, 0XDB: 0X12, 0XDC: 0XB8, 0XDD: 0XE5, 0XDE: 0XB4, 0XDF: 0XB0,
    0XE0: 0X89, 0XE1: 0X69, 0XE2: 0X97, 0XE3: 0X4A, 0XE4: 0X0C, 0XE5: 0X96, 0XE6: 0X77, 0XE7: 0X7E,
    0XE8: 0X65, 0XE9: 0XB9, 0XEA: 0XF1, 0XEB: 0X09, 0XEC: 0XC5, 0XED: 0X6E, 0XEE: 0XC6, 0XEF: 0X84,
    0XF0: 0X18, 0XF1: 0XF0, 0XF2: 0X7D, 0XF3: 0XEC, 0XF4: 0X3A, 0XF5: 0XDC, 0XF6: 0X4D, 0XF7: 0X20,
    0XF8: 0X79, 0XF9: 0XEE, 0XFA: 0X5F, 0XFB: 0X3E, 0XFC: 0XD7, 0XFD: 0XCB, 0XFE: 0X39, 0XFF: 0X48
}

# 系统参数FK
FK = (0XA3B1BAC6, 0X56AA3350, 0X677D9197, 0XB27022DC)

# 固定参数CK
CK = (0X00070E15, 0X1C232A31, 0X383F464D, 0X545B6269,
      0X70777E85, 0X8C939AA1, 0XA8AFB6BD, 0XC4CBD2D9,
      0XE0E7EEF5, 0XFC030A11, 0X181F262D, 0X343B4249,
      0X50575E65, 0X6C737A81, 0X888F969D, 0XA4ABB2B9,
      0XC0C7CED5, 0XDCE3EAF1, 0XF8FF060D, 0X141B2229,
      0X30373E45, 0X4C535A61, 0X686F767D, 0X848B9299,
      0XA0A7AEB5, 0XBCC3CAD1, 0XD8DFE6ED, 0XF4FB0209,
      0X10171E25, 0X2C333A41, 0X484F565D, 0X646B7279)

# 轮密钥缓存
_rk_cache = {}

# 加密
SM4_ENCRYPT = 1
# 解密
SM4_DECRYPT = 0
# 分组byte数
BLOCK_BYTE = 16
BLOCK_HEX = BLOCK_BYTE * 2


def num2hex(num, width=1):
    """
    整数转为指定长度的十六进制字符串，不足补0
    >>> num2hex(1000, width=4)
    '03e8'
    :param num: 整数
    :param width: 16进制字符串长度， 默认为1
    :return str
    """
    return '{:0>{width}}'.format(hex(num)[2:].replace('L', ''),
                                 width=width)


def _byte_unpack(num, byte_n=4):
    # 分解后元组长度
    _len = 4
    # 步长
    step = (byte_n // _len) * 2
    hex_str = num2hex(num=num, width=byte_n * 2)
    split_v = list(_range(len(hex_str)))[::step] + [len(hex_str)]
    return tuple([int(hex_str[s:e], base=16) for s, e in
                  zip(split_v[:-1], split_v[1:])])


def _byte_pack(byte_array, byte_n=4):
    _len = 4
    # byte_array每一项16进制字符串的长度
    width = (byte_n // _len) * 2
    if len(byte_array) != _len:
        raise ValueError('byte_array length must be 4.')
    return int(''.join([num2hex(num=v, width=width)
                        for v in byte_array]), 16)


def _s_box(byte):
    return S_BOX.get(byte)


def _non_linear_map(byte_array):
    """
    非线性变换, 输入A=(a0, a1, a2, a3)
    (b0, b1, b2, b3) = (Sbox(a0), Sbox(a1), Sbox(a2), Sbox(a3))
    """
    return (_s_box(byte_array[0]), _s_box(byte_array[1]),
            _s_box(byte_array[2]), _s_box(byte_array[3]))


def _linear_map(byte4):
    """
    线性变换L
    L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)
    """
    _left = loop_left_shift
    return byte4 ^ _left(byte4, 2) ^ _left(byte4, 10) ^ _left(byte4, 18) ^ _left(byte4, 24)


def _linear_map_s(byte4):
    """
    线性变换L'
    L'(B) = B ⊕ (B <<< 13) ⊕ (B <<< 23)
    """
    _left = loop_left_shift
    return byte4 ^ _left(byte4, 13) ^ _left(byte4, 23)


def loop_left_shift(num, offset, base=32):
    """
    循环向左移位
    >>> loop_left_shift(0b11010000, 3, base=8)
    >>> 0b10000110
    """
    bin_str = '{:0>{width}}'.format(bin(num)[2:], width=base)
    rem = offset % base
    return int(bin_str[rem:] + bin_str[:rem], 2)


def _rep_t(byte4):
    """合成置换T, 由非线性变换和线性变换L复合而成"""
    # 非线性变换
    b_array = _non_linear_map(_byte_unpack(byte4))
    # 线性变换L
    return _linear_map(_byte_pack(b_array))


def _rep_t_s(byte4):
    """
    合成置换T', 由非线性变换和线性变换L'复合而成
    """
    # 非线性变换
    b_array = _non_linear_map(_byte_unpack(byte4))
    # 线性变换L'
    return _linear_map_s(_byte_pack(b_array))


def _round_keys(mk):
    """
    轮密钥由加密密钥通过密钥扩展算法生成
    加密密钥MK = (MK0, MK1, MK2, MK3)
    轮密钥生成算法:
    (K0, K1, K2, K3) = (MK0 ⊕ FK0, MK1 ⊕ FK1, MK2 ⊕ FK2, MK3 ⊕ FK3)
    rki = Ki+4 = Ki⊕T'(Ki+1 ⊕ Ki+2 ⊕ Ki+3 ⊕ CKi) i=0, 1,...,31
    :param mk: 加密密钥, 16byte, 128bit
    :return list
    """
    # 尝试从轮密钥缓存中获取轮密钥
    # 没有获取到, 根据密钥扩展算法生成
    _rk_keys = _rk_cache.get(mk)
    if _rk_keys is None:
        mk0, mk1, mk2, mk3 = _byte_unpack(mk, byte_n=16)
        keys = [mk0 ^ FK[0], mk1 ^ FK[1], mk2 ^ FK[2], mk3 ^ FK[3]]
        for i in _range(32):
            rk = keys[i] ^ _rep_t_s(keys[i + 1] ^ keys[i + 2] ^ keys[i + 3] ^ CK[i])
            keys.append(rk)
        _rk_keys = keys[4:]
        # 加入轮密钥缓存中
        _rk_cache[mk] = _rk_keys
    return _rk_keys


def _round_f(byte4_array, rk):
    """
    轮函数, F(X0, X1, X2, X3, rk) = X0 ⊕ T(X1 ⊕ X2 ⊕ X3 ⊕ rk)
    :param byte4_array: (X0, X1, X2, X3), 每一项4byte, 32bit
    :param rk: 轮密钥, 4byte, 32bit
    """
    x0, x1, x2, x3 = byte4_array
    return x0 ^ _rep_t(x1 ^ x2 ^ x3 ^ rk)


def _crypt(num, mk, mode=SM4_ENCRYPT):
    """
    SM4加密和解密
    :param num: 密文或明文 16byte
    :param mk:  密钥 16byte
    :param mode: 轮密钥顺序
    """
    x_keys = list(_byte_unpack(num, byte_n=16))
    round_keys = _round_keys(mk)
    if mode == SM4_DECRYPT:
        round_keys = round_keys[::-1]
    for i in _range(32):
        x_keys.append(_round_f(x_keys[i:i + 4], round_keys[i]))
    return _byte_pack(x_keys[-4:][::-1], byte_n=16)


def encrypt(clear_num, mk):
    """
    SM4加密算法由32次迭代运算和1次反序变换R组成.
    明文输入为(X0, X1, X2, X3), 每一项4byte, 密文输出为(Y0, Y1, Y2, Y3), 每一项4byte
    轮密钥为rki, i=0,1,...,32, 4byte, 运算过程如下:
    1). 32次迭代运算: Xi+4 = F(Xi, Xi+1, Xi+2, Xi+3, rki), i=0,1,...,32
    2). 反序变换: (Y0, Y1, Y2, Y3) = (X35, X34, X33, X32)
    :param clear_num: 明文, 16byte
    :param mk: 密钥, 16byte
    """
    return _crypt(num=clear_num, mk=mk)


def decrypt(cipher_num, mk):
    """
    SM4解密算法, 解密变换与加密变换结构相同, 不同的仅是轮密钥的使用顺序.
    解密时轮密钥使用顺序为(rk31,rk30,...,rk0)
    :param cipher_num: 密文, 16byte
    :param mk: 密钥, 16byte
    """
    return _crypt(num=cipher_num, mk=mk, mode=SM4_DECRYPT)


def _padding(text, mode=SM4_ENCRYPT):
    """
    加密填充和解密去填充
    """
    # python2 is (basestring, )
    # python3 is (str, bytes)
    _str_or_bytes = string_types if PY2 else (string_types + (binary_type,))
    if text is None or not isinstance(text, _str_or_bytes):
        return

    # unicode
    if isinstance(text, text_type):
        text = text.encode(encoding=E_FMT)

    if mode == SM4_ENCRYPT:
        # 填充
        p_num = BLOCK_BYTE - (len(text) % BLOCK_BYTE)
        space = '' if PY2 else b''
        pad_s = (chr(p_num) * p_num) if PY2 else (chr(p_num).encode(E_FMT) * p_num)
        res = space.join([text, pad_s])
    else:
        # 去填充
        p_num = ord(text[-1]) if PY2 else text[-1]
        res = text[:-p_num]
    return res


def _key_iv_check(key_iv):
    """
    密钥或初始化向量检测
    """
    # 密钥
    if key_iv is None or not isinstance(key_iv, string_types):
        raise TypeError('Parameter key or iv:{} not a basestring'.format(key_iv))

    if isinstance(key_iv, text_type):
        key_iv = key_iv.encode(encoding=E_FMT)

    if len(key_iv) > BLOCK_BYTE:
        raise ValueError('Parameter key or iv:{} byte greater than {}'.format(key_iv.decode(E_FMT),
                                                                              BLOCK_BYTE))
    return key_iv


def _hex(str_or_bytes):
    # PY2: _hex('北京') --> 'e58c97e4baac'
    # PY3: _hex('北京') --> b'e58c97e4baac'
    if PY2:
        hex_str = hexlify(str_or_bytes)
    else:
        # python3
        if isinstance(str_or_bytes, text_type):
            byte = str_or_bytes.encode(encoding=E_FMT)
        elif isinstance(str_or_bytes, binary_type):
            byte = str_or_bytes
        else:
            byte = b''
        hex_str = hexlify(byte)
    return hex_str


def _unhex(hex_str):
    # PY2: _unhex('e58c97e4baac') --> '\xe5\x8c\x97\xe4\xba\xac'
    # PY3: _unhex('e58c97e4baac') --> b'\xe5\x8c\x97\xe4\xba\xac'
    return unhexlify(hex_str)


# 电子密码本(ECB)
def encrypt_ecb(plain_text, key):
    """
    SM4(ECB)加密
    :param plain_text: 明文
    :param key: 密钥, 小于等于16字节
    """
    plain_text = _padding(plain_text, mode=SM4_ENCRYPT)
    if plain_text is None:
        return

    # 密钥检验
    key = _key_iv_check(key_iv=key)

    plain_hex = _hex(plain_text)
    cipher_hex_list = []
    for i in _range(len(plain_text) // BLOCK_BYTE):
        sub_hex = plain_hex[i * BLOCK_HEX:(i + 1) * BLOCK_HEX]
        cipher = encrypt(clear_num=int(sub_hex, 16),
                         mk=int(_hex(key), 16))
        cipher_hex_list.append(num2hex(num=cipher, width=BLOCK_HEX))

    cipher_text = b64encode(_unhex(''.join(cipher_hex_list)))
    return cipher_text if PY2 else cipher_text.decode(E_FMT)


def decrypt_ecb(cipher_text, key):
    """
    SM4(ECB)解密
    :param cipher_text: 密文
    :param key: 密钥, 小于等于16字节
    """
    cipher_text = b64decode(cipher_text)
    cipher_hex = _hex(cipher_text)

    # 密码检验
    key = _key_iv_check(key_iv=key)
    plain_hex_list = []
    for i in _range(len(cipher_text) // BLOCK_BYTE):
        sub_hex = cipher_hex[i * BLOCK_HEX:(i + 1) * BLOCK_HEX]
        plain = decrypt(cipher_num=int(sub_hex, 16),
                        mk=int(_hex(key), 16))
        plain_hex_list.append(num2hex(num=plain, width=BLOCK_HEX))

    plain_text = _padding(_unhex(''.join(plain_hex_list)),
                          mode=SM4_DECRYPT)
    return plain_text if PY2 else plain_text.decode(E_FMT)


# 密码块链接(CBC)
def encrypt_cbc(plain_text, key, iv):
    """
    SM4(CBC)加密
    :param plain_text: 明文
    :param key: 密钥, 小于等于16字节
    :param iv: 初始化向量, 小于等于16字节
    """
    plain_text = _padding(plain_text, mode=SM4_ENCRYPT)
    if plain_text is None:
        return

    # 密钥检验
    key = _key_iv_check(key_iv=key)
    # 初始化向量监测
    iv = _key_iv_check(key_iv=iv)

    plain_hex = _hex(plain_text)
    ivs = [int(_hex(iv), 16)]
    for i in _range(len(plain_text) // BLOCK_BYTE):
        sub_hex = plain_hex[i * BLOCK_HEX:(i + 1) * BLOCK_HEX]
        cipher = encrypt(clear_num=(int(sub_hex, 16) ^ ivs[i]),
                         mk=int(_hex(key), 16))
        ivs.append(cipher)

    cipher_text = b64encode(_unhex(''.join([num2hex(num=c, width=BLOCK_HEX)
                                            for c in ivs[1:]])))
    return cipher_text if PY2 else cipher_text.decode(E_FMT)


def decrypt_cbc(cipher_text, key, iv):
    """
    SM4(CBC)解密
    :param cipher_text: 密文
    :param key: 密钥 小于等于16字节
    :param iv: 初始化向量 小于等于16字节
    """
    cipher_text = b64decode(cipher_text)
    cipher_hex = _hex(cipher_text)

    # 密钥检测
    key = _key_iv_check(key_iv=key)
    # 初始化向量检测
    iv = _key_iv_check(key_iv=iv)
    ivs = [int(_hex(iv), 16)]
    plain_hex_list = []
    for i in _range(len(cipher_text) // BLOCK_BYTE):
        sub_hex = cipher_hex[i * BLOCK_HEX:(i + 1) * BLOCK_HEX]
        cipher = int(sub_hex, 16)
        plain = (ivs[i] ^ decrypt(cipher_num=cipher,
                                  mk=int(_hex(key), 16)))
        ivs.append(cipher)
        plain_hex_list.append(num2hex(num=plain, width=BLOCK_HEX))

    plain_text = _padding(_unhex(''.join(plain_hex_list)),
                          mode=SM4_DECRYPT)
    return plain_text if PY2 else plain_text.decode(E_FMT)
