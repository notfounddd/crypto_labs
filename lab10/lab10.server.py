from hash_func import *


HASH_ALGORITHMS = {
    'SHA256': sha256,
    'SHA512': sha512,
    'GOST256': streebog256,
    'GOST512': streebog512
}

def verify_signature(data):
    """
    Проверка групповой подписи перед добавлением метки:
    1. Извлечение компонентов подписи (U, E, S, R)
    2. Проверка хеша E = hash(message || R || U)
    3. Проверка уравнения подписи alpha^S ≡ R * (U * leader_public)^E mod p
    """
    try:
        with open("group_config.json") as f:
            config = json.load(f)
        
        # Получаем данные из подписи
        message = bytes.fromhex(data['content']['encapContentInfo']['eContent']).decode('utf-8')
        sig = data['content']['signerInfos'][0]['signature']
        U, E, S, R = sig['U'], sig['E'], sig['S'], sig['R']
        
        # Получаем алгоритм хеширования
        hash_alg = data['content']['signerInfos'][0]['digestAlgorithm']
        hash_func = HASH_ALGORITHMS[hash_alg]
        
        # Формируем входные данные для хеширования так же, как на стороне лидера
        # В оригинальном коде лидера: hash_input = message.encode('utf-8').hex() + hex(R)[2:] + hex(U)[2:]
        # Поэтому мы должны делать то же самое на сервере
        message_hex = message.encode('utf-8').hex()
        R_hex = hex(R)[2:]
        U_hex = hex(U)[2:]
        hash_input = (message_hex + R_hex + U_hex).encode('utf-8')
        
        computed_E = int(hash_func(hash_input), 16)
        
        if E != computed_E:
            print(f"Ошибка: несоответствие хеша (ожидалось {E}, получено {computed_E})")
            print(f"Использованные данные для хеширования: {hash_input}")
            return False
            
        # Проверяем саму подпись
        p = config['prime_p']
        alpha = config['generator']
        leader_public = config['leader_public']
        
        left_part = fast_exp_mod(alpha, S, p)
        right_part = (R * fast_exp_mod(U * leader_public, E, p)) % p
        
        if left_part != right_part:
            print(f"Ошибка: подпись недействительна (левая часть {left_part} != правая часть {right_part})")
            return False
            
        return True
        
    except Exception as e:
        print(f"Ошибка при проверке подписи: {e}")
        return False

def run_server():
    """
    Основной цикл сервера:
    1. Принимает подключения от лидера
    2. Проверяет подпись
    3. Генерирует метку времени
    4. Создает RSA подпись для метки
    5. Возвращает подписанную метку времени
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen()
    print("Сервер меток времени запущен на порту 12345")
    
    while True:
        conn, addr = server.accept()
        print(f"Подключение от: {addr}")
        
        try:
            # Получаем данные подписи
            data = conn.recv(8192)
            if not data:
                continue
                
            data = json.loads(data.decode('utf-8'))
            
            # Проверяем подпись
            if not verify_signature(data):
                conn.send(json.dumps({
                    'status': 'error', 
                    'error': 'Недействительная подпись'
                }).encode('utf-8'))
                continue
                
            # Получаем алгоритм хеширования из подписи
            hash_alg = data['content']['signerInfos'][0]['digestAlgorithm']
            hash_func = HASH_ALGORITHMS[hash_alg]
            
            # Генерируем ключи RSA для подписи метки времени
            p = generate_prime(512)
            q = generate_prime(512)
            n = p * q
            e = 65537
            d = module_inverse(e, (p-1)*(q-1))
            
            # Создаем метку времени
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ")
            
            # Создаем отпечаток для подписи
            sig_data = data['content']['signerInfos'][0]['signature']
            imprint = hash_func(json.dumps(sig_data, sort_keys=True).encode('utf-8'))
            
            # Подписываем отпечаток + метку времени
            to_sign = f"{imprint}:{timestamp}".encode('utf-8')
            signature = fast_exp_mod(int(hash_func(to_sign), 16), d, n)
            
            # Формируем токен метки времени
            token = {
                "timestamp": timestamp,
                "signature": hex(signature),
                "tsa_public_key_e": e,
                "tsa_public_key_n": n,
                "hash_algorithm": hash_alg,
                "message_imprint": imprint
            }
            
            # Добавляем метку времени к подписи
            if 'unsignedAttrs' not in data['content']['signerInfos'][0]:
                data['content']['signerInfos'][0]['unsignedAttrs'] = []
                
            data['content']['signerInfos'][0]['unsignedAttrs'].append({
                "attrType": "timestampToken",
                "values": [token]
            })
            
            # Отправляем ответ
            conn.send(json.dumps({
                'status': 'ok', 
                'data': data
            }).encode('utf-8'))
            
            print("Метка времени успешно добавлена")
            
        except Exception as e:
            print(f"Ошибка: {e}")
            conn.send(json.dumps({
                'status': 'error', 
                'error': str(e)
            }).encode('utf-8'))
        finally:
            conn.close()

if __name__ == "__main__":
    run_server()