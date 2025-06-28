from hash_func import *

HASH_ALGORITHMS = {
    'SHA256': sha256,
    'SHA512': sha512,
    'GOST256': streebog256, 
    'GOST512': streebog512  
}
CONFIG_FILE = "group_config.json"
SIGNATURE_FILE = "timestamped_signature.json"

def select_hash_algorithm():
    """Функция для интерактивного выбора алгоритма хеширования"""
    algorithms = {
        '1': {'name': 'SHA-256', 'value': 'SHA256'},
        '2': {'name': 'SHA-512', 'value': 'SHA512'},
        '3': {'name': 'Streebog 256', 'value': 'GOST256'},
        '4': {'name': 'Streebog 512', 'value': 'GOST512'}
    }
    
    print("\nДоступные алгоритмы хеширования:")
    for key, alg in algorithms.items():
        print(f"{key}. {alg['name']}")
    
    while True:
        choice = input("Введите номер алгоритма (1-4): ").strip()
        if choice in algorithms:
            selected = algorithms[choice]
            print(f"Выбран алгоритм: {selected['name']}")
            return selected['value']
        print("Ошибка: введите число от 1 до 4")

def generate_safe_primes(bit_length=512):
    """Генерация безопасных простых чисел p и q (p = 2q + 1)"""
    while True:
        q = generate_prime(bit_length)
        p = 2 * q + 1
        if isprime(p, 50):
            return p, q

def generate_generator(p, q):
    """Генерация элемента порядка q в мультипликативной группе Zp*"""
    while True:
        h = random.randint(2, p - 2)
        g = fast_exp_mod(h, (p - 1) // q, p)
        if g > 1:
            return g

def generate_group_keys(member_count=2, rsa_bits=1024):
    """Генерация всех ключей для группы"""
    p, q = generate_safe_primes()
    alpha = generate_generator(p, q)
    members = []
    
    for _ in range(member_count):
        private_key = random.randint(1, q - 1)
        public_key = fast_exp_mod(alpha, private_key, p)
        members.append({'private': private_key, 'public': public_key})
        
    leader_private = random.randint(1, q - 1)
    leader_public = fast_exp_mod(alpha, leader_private, p)

    # Генерация RSA ключей для пропусков
    p1 = generate_prime(rsa_bits // 2)
    p2 = generate_prime(rsa_bits // 2)
    n = p1 * p2
    phi = (p1 - 1) * (p2 - 1)
    e = 65537
    d = module_inverse(e, phi)
    
    return {
        "prime_p": p, 
        "prime_q": q, 
        "generator": alpha, 
        "members": members,
        "leader_private": leader_private, 
        "leader_public": leader_public,
        "rsa_public": e, 
        "rsa_private": d, 
        "rsa_modulus": n
    }

def create_group_signature(message, hash_name, config, member_a, member_b):
    """Создание групповой подписи с участием двух членов группы"""
    hash_func = HASH_ALGORITHMS[hash_name]
    message_hash = int(hash_func(message.encode('utf-8')), 16)
    
    p, q, n, d = config['prime_p'], config['prime_q'], config['rsa_modulus'], config['rsa_private']
    alpha = config['generator']
    pub_a, pub_b = config['members'][0]['public'], config['members'][1]['public']
    
    # Вычисляем "пропуски" для участников
    pass_a = fast_exp_mod(message_hash + pub_a, d, n)
    pass_b = fast_exp_mod(message_hash + pub_b, d, n)

    # Обмен данными с участниками группы
    member_a.send(json.dumps({'pass': pass_a}).encode('utf-8'))
    rand_a = json.loads(member_a.recv(8192).decode('utf-8'))['random']
    member_b.send(json.dumps({'pass': pass_b}).encode('utf-8'))
    rand_b = json.loads(member_b.recv(8192).decode('utf-8'))['random']

    # Вычисление компонентов подписи
    term_a = fast_exp_mod(pub_a, pass_a, p)
    term_b = fast_exp_mod(pub_b, pass_b, p)
    U = (term_a * term_b) % p
    
    leader_rand = random.randint(1, q)
    leader_part = fast_exp_mod(alpha, leader_rand, p)
    R = (leader_part * rand_a * rand_b) % p
    
    # Вычисление общего вызова
    hash_input = message.encode('utf-8').hex() + hex(R)[2:] + hex(U)[2:]
    challenge = int(hash_func(hash_input.encode('utf-8')), 16)
    
    # Получение частичных подписей от участников
    member_a.send(json.dumps({'challenge': challenge}).encode('utf-8'))
    sig_a = json.loads(member_a.recv(8192).decode('utf-8'))['signature']
    member_b.send(json.dumps({'challenge': challenge}).encode('utf-8'))
    sig_b = json.loads(member_b.recv(8192).decode('utf-8'))['signature']

    # Проверка частичных подписей
    if fast_exp_mod(alpha, sig_a, p) != (rand_a * fast_exp_mod(pub_a, pass_a * challenge, p)) % p:
        raise ValueError("Проверка подписи участника A не удалась")
    print("Подпись участника A верифицирована.")
    
    if fast_exp_mod(alpha, sig_b, p) != (rand_b * fast_exp_mod(pub_b, pass_b * challenge, p)) % p:
        raise ValueError("Проверка подписи участника B не удалась")
    print("Подпись участника B верифицирована.")

    # Формирование полной подписи
    leader_sig = (leader_rand + config['leader_private'] * challenge) % q
    full_sig = (leader_sig + sig_a + sig_b) % q

    return U, challenge, full_sig, R

def create_signature_structure(message, hash_name, signature):
    """Создание структуры подписи в формате CAdES"""
    U, E, S, R = signature
    return {
        "contentType": "signedData",
        "content": {
            "version": "1",
            "digestAlgorithms": [hash_name],
            "encapContentInfo": {
                "eContentType": "data",
                "eContent": message.encode("utf-8").hex()
            },
            "signerInfos": [{
                "version": "1",
                "sid": "GroupSignature",
                "digestAlgorithm": hash_name,
                "signatureAlgorithm": "GroupDS",
                "signature": {
                    "U": U,
                    "E": E,
                    "S": S,
                    "R": R
                }
            }]
        }
    }

def verify_timestamp(data_with_ts):
    """Проверка подписи сервера времени"""
    try:
        ts_data = data_with_ts['content']['signerInfos'][0]['unsignedAttrs'][0]['values'][0]
        signature = int(ts_data['signature'], 16)
        n = ts_data['tsa_public_key_n']
        e = ts_data['tsa_public_key_e']
        hash_name = ts_data['hash_algorithm']
        imprint = ts_data['message_imprint']
        timestamp = ts_data['timestamp']
        
        decrypted_hash = fast_exp_mod(signature, e, n)
        
        hash_func = HASH_ALGORITHMS[hash_name]
        computed_hash = int(hash_func(f"{imprint}:{timestamp}".encode('utf-8')), 16)
        
        if computed_hash == decrypted_hash:
            print("Подпись сервера времени действительна.")
            return True
        else:
            print("Ошибка: недействительная подпись сервера времени.")
            return False
            
    except (KeyError, IndexError, TypeError) as e:
        print(f"Ошибка проверки метки времени: {e}")
        return False

def main_menu():
    """Главное меню программы лидера"""
    config = None
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        print("Конфигурация группы загружена.")

    while True:
        print("\nМеню лидера группы:")
        print("1. Создать новую конфигурацию группы")
        print("2. Создать групповую подпись с меткой времени")
        print("3. Проверить подпись с меткой времени")
        print("4. Выход")
        
        choice = input("> ").strip()

        if choice == "1":
            print("Генерация новой конфигурации группы...")
            config = generate_group_keys()
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"Конфигурация сохранена в файл {CONFIG_FILE}")

        elif choice == "2":
            if not config:
                print("Ошибка: сначала создайте конфигурацию группы")
                continue
            
            message = input("Введите сообщение для подписи: ").strip()
            hash_name = select_hash_algorithm()

            try:
                print("Подключение к участникам группы...")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as member_a, \
                     socket.socket(socket.AF_INET, socket.SOCK_STREAM) as member_b:
                    
                    member_a.connect(("localhost", 1233))
                    member_b.connect(("localhost", 1234))
                    print("Участники группы подключены.")

                    signature = create_group_signature(message, hash_name, config, member_a, member_b)
                    signature_struct = create_signature_structure(message, hash_name, signature)
                    
                    print("\nГрупповая подпись создана. Отправка на сервер времени...")
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tsa:
                        tsa.connect(("localhost", 12345))
                        tsa.send(json.dumps(signature_struct).encode('utf-8'))
                        
                        response = json.loads(tsa.recv(8192).decode('utf-8'))
                        if response.get('status') == 'ok':
                            print("Метка времени получена. Сохранение...")
                            with open(SIGNATURE_FILE, 'w') as f:
                                json.dump(response['data'], f, indent=4)
                            print(f"Файл подписи {SIGNATURE_FILE} сохранен.")
                        else:
                            print(f"Ошибка сервера времени: {response.get('error', 'неизвестная ошибка')}")

            except ConnectionRefusedError:
                print("Ошибка: не удалось подключиться. Убедитесь, что:")
                print("- Участники группы запущены (user1.py и user2.py)")
                print("- Сервер времени запущен (server.py)")
            except Exception as e:
                print(f"Критическая ошибка: {e}")

        elif choice == "3":
            if not os.path.exists(SIGNATURE_FILE):
                print(f"Ошибка: файл подписи {SIGNATURE_FILE} не найден")
                continue
            with open(SIGNATURE_FILE, 'r') as f:
                data = json.load(f)
            
            print("Проверка подписи сервера времени...")
            verify_timestamp(data)

        elif choice == "4":
            print("Завершение работы...")
            break

        else:
            print("Неверный выбор, попробуйте снова")

if __name__ == "__main__":
    main_menu() 