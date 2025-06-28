from hash_func import *


HOST = 'localhost'
PORT = 65433
PASSWORD = "secure_password"  # Общий пароль между клиентом и сервером

def main():
    # Генерируем простое число p
    p = generate_prime(512)
    print(f"Сгенерировано простое p: {p}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Сервер запущен на {HOST}:{PORT}")
        conn, addr = s.accept()
        
        with conn:
            print(f"Подключен клиент: {addr}")
            
            # Отправляем p клиенту
            conn.sendall(json.dumps({"p": p}).encode('utf-8'))
            
            # Получаем открытый ключ клиента
            data = conn.recv(2048)
            client_data = json.loads(data.decode("utf-8"))
            alpha = client_data.get("alpha")
            print(f"Получен открытый ключ α: {alpha}")
            
            # Вычисляем g = h(w) mod p
            g = int(sha512(PASSWORD), 16) % p
            if g == 0:
                g = 2  # Защита от нулевого значения
            print(f"Вычислено g: {g}")
            
            # Генерация секретного ключа и открытого ключа
            y = random.randint(2, p - 2)
            beta = fast_exp_mod(g, y, p)
            print(f"Секретный ключ y: {y}")
            print(f"Открытый ключ β: {beta}")
            
            # Отправляем открытый ключ клиенту
            conn.sendall(json.dumps({"beta": beta}).encode('utf-8'))
            
            # Вычисляем общий ключ
            k = fast_exp_mod(alpha, y, p)
            print(f"Общий ключ сессии k: {k}")
            
            # Запись параметров сервера
            abonent_B = {
                "p": p,
                "g": g,
                "secret_key_y": y,
                "public_key_beta": beta,
                "received_alpha": alpha,
                "session_key_k": k,
                "password": PASSWORD
            }
            with open("abonent_B.json", "w", encoding="utf-8") as f:
                json.dump(abonent_B, f, indent=4)
            print("Параметры сервера сохранены в abonent_B.json")

if __name__ == "__main__":
    main()