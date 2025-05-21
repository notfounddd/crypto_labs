from lab4 import *
from lab5 import *
import random
import string

__IPAD__ = b'\x36'
__OPAD__ = b'\x5c'

def gen_key(block_size):
    characters = string.ascii_letters + string.digits  # A-Z, a-z, 0-9
    rand_len = random.randint(1, block_size)
    key = ''.join(random.choice(characters) for _ in range(rand_len))

    key_bytes = key.encode('utf-8')
    
    if len(key_bytes) < block_size:
        key_bytes += b'\x00' * (block_size - len(key_bytes))

    return key_bytes

def hmac(message, func):
    if func == 1:
        hash_ = sha256
        block_len = 64
    elif func == 2:
        hash_ = sha512
        block_len = 128
    elif func == 3:
        hash_ = streebog256
        block_len = 128
    elif func == 4:
        hash_ = streebog512
        block_len = 128
    else:
        raise ValueError("Неверный тип хэш-функции")
    
    key = gen_key(block_len)
    
    # Создаем ipad и opad нужной длины
    ipad = __IPAD__ * block_len
    opad = __OPAD__ * block_len
    
    key_ipad = transform_x(key, ipad)
    key_opad = transform_x(key, opad)
    HMAC = hash_(key_opad + bytes.fromhex(hash_(key_ipad + message)))
    
    return HMAC, key

def main():
    print("Выберите тип хэша:")
    print("1. SHA-256")
    print("2. SHA-512")
    print("3. Stribog-256")
    print("4. Stribog-512")
    choice = input("Введите номер (1 - 4): ").strip()

    while choice not in ("1", "2", "3", "4"):
        print("Неверный выбор. Попробуйте снова.")
        choice = input("Введите номер (1 - 4): ").strip()

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
        hash_type = "SHA-256"
        result, key = hmac(message, 1)
    elif choice == "2":
        hash_type = "SHA-512"
        result, key = hmac(message, 2)
    elif choice == "3":
        hash_type = "Stribog-256"
        result, key = hmac(message, 3)
    elif choice == "4":
        hash_type = "Stribog-512"
        result, key = hmac(message, 4)

    result_data = {
        "Func": "HMAC",
        "Type": hash_type,
        "Hash": result,
        "Key": key.decode('utf-8')
    }

    json_filename = input("Введите имя JSON-файла (без расширения): ").strip()
    if not json_filename:
        json_filename = "result"

    json_path = f"{json_filename}.json"

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, indent=4)

    print(f"\nРезультат сохранён в файл: {json_path}")
    print(f"Тип хэша: {hash_type}")
    print(f"Хэш: {result}")

if __name__ == "__main__":
    main()
