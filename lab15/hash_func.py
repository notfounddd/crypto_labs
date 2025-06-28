import struct
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
from datetime import datetime
import json
import socket
import sys

def gcd(x, y):
    a_2 = 1; a_1 = 0
    b_2 = 0; b_1 = 1
    while y != 0:
        q = x // y
        r = x - q * y
        a = a_2 - q * a_1
        b = b_2 - q * b_1
        x = y; y = r
        a_2 = a_1; a_1 = a
        b_2 = b_1; b_1 = b
    m = x; a = a_2; b = b_2
    return m, a, b

def fast_exp_mod(a, n, s):
    x = 1
    while n > 0:
        if n & 1:
            x = (x * a) % s
        a = (a * a) % s
        n = n >> 1
    return x

def generate_prime(k):
    while True:
        p = random.getrandbits(k)
        highest_bit = 1 << (k - 1)
        lowest_bit = 1
        p = (p | highest_bit) | lowest_bit
        p = int(p)
        t = 100
        if p < 2:
            continue
        if p in (2, 3):
            return p
        if p % 2 == 0:
            continue
        s = 0
        r = p - 1
        while r % 2 == 0:
            r //= 2
            s += 1
        for _ in range(t):
            a = random.randint(2, p - 2)
            y = fast_exp_mod(a, r, p)
            if y == 1 or y == p - 1:
                continue
            for _ in range(s - 1):
                y = fast_exp_mod(y, 2, p)
                if y == p - 1:
                    break
            else:
                break
        else:
            return p
