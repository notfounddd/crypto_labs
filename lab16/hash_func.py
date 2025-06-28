import struct
import random
from datetime import datetime,timedelta
import json
import socket
import sys


# Константы для SHA-512
SHA512_INITIAL_HASH = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
]

SHA512_K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]

def rotate_right(x, n, bits=64):
    return (x >> n) | (x << (bits - n)) & ((1 << bits) - 1)

def Ch(x, y, z):
    return (x & y) ^ (~x & z)

def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0_512(x):
    return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39)

def Sigma1_512(x):
    return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41)

def sigma0_512(x):
    return rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7)

def sigma1_512(x):
    return rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6)

def pad_message(message):
    block_size = 1024  # 1024 бит = 128 байт для SHA-512
    length_size = 128  # 128 бит для длины сообщения
    original_length = len(message) * 8  # in bits
    message += b'\x80'  # Append '10000000' bit
    while (len(message) * 8 + length_size) % block_size != 0:
        message += b'\x00'
    message += struct.pack('>QQ', original_length >> 64, original_length & 0xFFFFFFFFFFFFFFFF)
    return message

def sha512(message):
    if isinstance(message, str):
        message = message.encode('utf-8')
    elif not isinstance(message, bytes):
        raise TypeError("Message must be either string or bytes")
    
    message = pad_message(message)
    hash_values = list(SHA512_INITIAL_HASH)
    
    for i in range(0, len(message), 128):  # 128 bytes = 1024 bits
        block = message[i:i + 128]
        words = [int.from_bytes(block[j:j + 8], 'big') for j in range(0, 128, 8)]

        for t in range(16, 80):
            s0 = sigma0_512(words[t - 15])
            s1 = sigma1_512(words[t - 2])
            words.append((words[t - 16] + s0 + words[t - 7] + s1) & 0xFFFFFFFFFFFFFFFF)

        a, b, c, d, e, f, g, h = hash_values

        for t in range(80):
            S1 = Sigma1_512(e)
            ch = Ch(e, f, g)
            temp1 = (h + S1 + ch + SHA512_K[t] + words[t]) & 0xFFFFFFFFFFFFFFFF
            S0 = Sigma0_512(a)
            maj = Maj(a, b, c)
            temp2 = (S0 + maj) & 0xFFFFFFFFFFFFFFFF

            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFFFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

        hash_values = [(hash_values[i] + [a, b, c, d, e, f, g, h][i]) & 0xFFFFFFFFFFFFFFFF for i in range(8)]
    
    return ''.join(format(h, '016x') for h in hash_values)

def generate_session_key(bits=256):
    key_bits = [str(random.randint(0, 1)) for _ in range(bits)]
    return ''.join(key_bits)

def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()



def encrypt_message(message, public_key):
    n, e = public_key
    block_size = (n.bit_length() + 7) // 8 - 11  
    message_bytes = message if isinstance(message, bytes) else message.encode('utf-8')
    
    blocks = [message_bytes[i:i+block_size] for i in range(0, len(message_bytes), block_size)]
    cipher_blocks = []
    for block in blocks:
        m = int.from_bytes(block, byteorder='big')
        c = pow(m, e, n)
        cipher_blocks.append(c)
    
    return cipher_blocks

def decrypt_message(cipher_blocks, private_key):
    # private_key должен быть (n, d) или (p, q, d)
    if len(private_key) == 3:
        p, q, d = private_key
        n = p * q
    else:
        n, d = private_key  # если private_key = (n, d)

    decrypted_blocks = []
    for c in cipher_blocks:
        if c >= n:
            raise ValueError("Зашифрованный блок больше модуля n!")
        m = fast_exp_mod(c, d, n)
        block_size = (n.bit_length() + 7) // 8
        decrypted_block = m.to_bytes(block_size, byteorder='big').lstrip(b'\x00')
        decrypted_blocks.append(decrypted_block)
    return b''.join(decrypted_blocks)

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

def generate_keys(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(2, phi)
    nod, d, _ = gcd(e, phi)
    while nod != 1:
        e = random.randrange(2, phi)
        nod, d, _ = gcd(e, phi)

    d = d % phi
    if d < 0:
        d += phi

    return (n, e), (p, q, d)

def create_utc_timestamp():
    return datetime.utcnow().strftime("%y%m%d%H%M%SZ")

def verify_timestamp(timestamp, max_delay_seconds=30):

    try:
        msg_time = datetime.strptime(timestamp, "%y%m%d%H%M%SZ")
        
        time_diff = datetime.utcnow() - msg_time
        
        return time_diff < timedelta(seconds=max_delay_seconds)
    
    except ValueError as e:
        print(f"[ERROR] Неверный формат временной метки: {timestamp}")
        print(f"Ожидается формат: YYMMDDHHMMSSZ (пример: '231215143000Z')")
        return False