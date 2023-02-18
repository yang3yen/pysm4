#!/usr/bin/env python
# -*- coding: utf-8 -*-


import unittest
from pysm4 import *


class TestPySM4(unittest.TestCase):
    # 明文
    clear_num = 0x0123456789abcdeffedcba9876543210
    # 密钥
    mk = 0x0123456789abcdeffedcba9876543210
    # 密文
    cipher_num = 0x681edf34d206965e86b3e94f536e4246

    plain_text = '我冷眼向过去稍稍回顾，只见它曲折灌溉的悲喜，都消失在一片亘古的荒漠，'\
                 '这才知道我的全部努力，不过完成了普通的生活。'
    key = 'hello, world!'
    # 初始化向量
    iv = '11111111'

    def test_encrypt(self):
        # 加密测试
        self.assertEqual(encrypt(self.clear_num, self.mk),
                         self.cipher_num)

    def test_decrypt(self):
        # 解密测试
        self.assertEqual(decrypt(self.cipher_num, self.mk),
                         self.clear_num)

    def test_crypt_ecb(self):
        # SM4 ECB加密解密测试
        self.assertEqual(decrypt_ecb(cipher_text=encrypt_ecb(plain_text=self.plain_text,
                                                             key=self.key),
                                     key=self.key), self.plain_text)

    def test_crypt_cbc(self):
        # SM4 CBC加密解密测试
        self.assertEqual(decrypt_cbc(cipher_text=encrypt_cbc(plain_text=self.plain_text,
                                                             key=self.key,
                                                             iv=self.iv),
                                     key=self.key,
                                     iv=self.iv), self.plain_text)

    def test_bytes_key_iv(self):
        key = b"9HdkinIPmHOn2zg="
        iv = b"837bdd102b15e719"

        self.assertEqual(decrypt_cbc(cipher_text=encrypt_cbc(plain_text=self.plain_text,
                                                             key=key,
                                                             iv=iv),
                                     key=key,
                                     iv=iv), self.plain_text)


if __name__ == '__main__':
    unittest.main()
