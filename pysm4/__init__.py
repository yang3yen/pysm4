# -*- coding: utf-8 -*-


"""
    pysm4
    ~~~~~

    pysm4是国密 SM4算法的Python实现， 提供了`encrypt`、 `decrypt`、 `sm4_encrypt_ecb`、
    `sm4_decrypt_ecb`、 `sm4_encrypt_cbc`、 `sm4_decrypt_cbc`等函数用于加密解密。

    :copyright: (c) 2017 by yang3yen.
    :license: MIT, see LICENSE for more details.
"""
from .sm4 import encrypt, decrypt, sm4_encrypt_ecb, \
    sm4_decrypt_ecb, sm4_encrypt_cbc, sm4_decrypt_cbc


__title__ = 'pysm4'
__version__ = '0.7'
__author__ = 'yang3yen'
__license__ = 'MIT'
__copyright__ = 'Copyright 2017 yang3yen'
__email__ = 'yang3yen@gmail.com'
