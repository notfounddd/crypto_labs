import json
import struct

# Константы для SHA-256
SHA256_INITIAL_HASH = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

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

# Функции преобразования
def Ch(x, y, z):
    return (x & y) ^ (~x & z)

def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0_256(x):
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)

def Sigma1_256(x):
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)

def sigma0_256(x):
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3)

def sigma1_256(x):
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10)

def Sigma0_512(x):
    return rotate_right(x, 28, 64) ^ rotate_right(x, 34, 64) ^ rotate_right(x, 39, 64)

def Sigma1_512(x):
    return rotate_right(x, 14, 64) ^ rotate_right(x, 18, 64) ^ rotate_right(x, 41, 64)

def sigma0_512(x):
    return rotate_right(x, 1, 64) ^ rotate_right(x, 8, 64) ^ (x >> 7)

def sigma1_512(x):
    return rotate_right(x, 19, 64) ^ rotate_right(x, 61, 64) ^ (x >> 6)

def rotate_right(x, n, bits=32):
    return (x >> n) | (x << (bits - n)) & ((1 << bits) - 1)

# Дополнение сообщения
def pad_message(message, block_size, length_size):
    original_length = len(message) * 8  # in bits
    message += b'\x80'  # Append '1' bit
    while (len(message) * 8 + length_size) % block_size != 0:
        message += b'\x00'
    # Записываем длину сообщения в big-endian формате
    if length_size == 64:
        message += struct.pack('>Q', original_length)
    elif length_size == 128:
        message += struct.pack('>QQ', original_length >> 64, original_length & 0xFFFFFFFFFFFFFFFF)
    return message

# Основная функция хеширования
def sha256(message):
    return sha_generic(message, 32, 64, SHA256_INITIAL_HASH, SHA256_K, 64)

def sha512(message):
    return sha_generic(message, 64, 128, SHA512_INITIAL_HASH, SHA512_K, 80)

def sha_generic(message, word_size, length_size, initial_hash, k_constants, rounds):
    block_size = word_size * 16
    message = pad_message(message, block_size, length_size)
    hash_values = initial_hash.copy()

    for i in range(0, len(message), block_size // 8):
        block = message[i:i + block_size // 8]
        words = [int.from_bytes(block[j:j + word_size // 8], 'big') for j in range(0, block_size // 8, word_size // 8)]

        # Расширение слов
        for t in range(16, rounds):
            s0 = sigma0_256(words[t - 15]) if word_size == 32 else sigma0_512(words[t - 15])
            s1 = sigma1_256(words[t - 2]) if word_size == 32 else sigma1_512(words[t - 2])
            words.append((words[t - 16] + s0 + words[t - 7] + s1) % (1 << word_size))

        a, b, c, d, e, f, g, h = hash_values

        for t in range(rounds):
            S1 = Sigma1_256(e) if word_size == 32 else Sigma1_512(e)
            ch = Ch(e, f, g)
            temp1 = (h + S1 + ch + k_constants[t] + words[t]) % (1 << word_size)
            S0 = Sigma0_256(a) if word_size == 32 else Sigma0_512(a)
            maj = Maj(a, b, c)
            temp2 = (S0 + maj) % (1 << word_size)

            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) % (1 << word_size), c, b, a, (temp1 + temp2) % (1 << word_size)

        hash_values = [(hash_values[i] + [a, b, c, d, e, f, g, h][i]) % (1 << word_size) for i in range(8)]

    return ''.join(format(h, '0' + str(word_size // 4) + 'x') for h in hash_values)

# Главное меню    
def main():
    print("Выберите тип хэша:")
    print("1. SHA-256")
    print("2. SHA-512")
    choice = input("Введите номер (1 или 2): ").strip()

    while choice not in ("1", "2"):
        print("Неверный выбор. Попробуйте снова.")
        choice = input("Введите номер (1 или 2): ").strip()

    print("\nВыберите источник данных:")
    print("1. Ввести текст вручную")
    print("2. Прочитать из файла")
    source = input("Введите номер (1 или 2): ").strip()

    while source not in ("1", "2"):
        print("Неверный выбор. Попробуйте снова.")
        source = input("Введите номер (1 или 2): ").strip()

    if source == "1":
        text = input("Введите текст для хэширования: ")
        message = text.encode('utf-8')
    else:
        path = input("Введите путь к файлу: ")
        try:
            with open(path, 'rb') as f:
                message = f.read()
        except FileNotFoundError:
            print("Файл не найден!")
            return

    if choice == "1":
        result_hash = sha256(message)
        hash_type = "SHA-256"
    else:
        result_hash = sha512(message)
        hash_type = "SHA-512"

    result_data = {
        "Type": hash_type,
        "Hash": result_hash.hex()
    }

    json_filename = input("Введите имя JSON-файла (без расширения): ").strip()
    if not json_filename:
        json_filename = "result"

    json_path = f"{json_filename}.json"

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, indent=4)

    print(f"\nРезультат сохранён в файл: {json_path}")
    print(f"Тип хэша: {hash_type}")
    print(f"Хэш: {result_hash.hex()}")

if __name__ == "__main__":
    main()
