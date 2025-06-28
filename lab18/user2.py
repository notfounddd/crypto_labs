from hash_func import *
import json
import random
import socket

HOST = 'localhost'
PORT = 65433
PASSWORD = "secure_password"  # Общий пароль между клиентом и сервером

def main():
    # Устанавливаем соединение
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        # Получаем p от сервера
        data = s.recv(2048)
        server_data = json.loads(data.decode("utf-8"))
        p = server_data.get("p")
        print(f"Получено p: {p}")
        
        # Вычисляем g = h(w) mod p
        # Преобразуем хеш из hex строки в целое число
        hash_hex = sha512(PASSWORD)
        g = int(hash_hex, 16) % p
        if g == 0:
            g = 2  # Защита от нулевого значения
        
        print(f"Вычислено g: {g}")
        
        # Генерация секретного ключа и открытого ключа
        x = random.randint(2, p - 2)
        alpha = fast_exp_mod(g, x, p)
        print(f"Секретный ключ x: {x}")
        print(f"Открытый ключ α: {alpha}")
        
        # Отправляем открытый ключ серверу
        s.sendall(json.dumps({"alpha": alpha}).encode("utf-8"))
        
        # Получаем открытый ключ сервера
        data = s.recv(2048)
        server_data = json.loads(data.decode("utf-8"))
        beta = server_data.get("beta")
        print(f"Получен открытый ключ β: {beta}")
        
        # Вычисляем общий ключ
        k = fast_exp_mod(beta, x, p)
        print(f"Общий ключ сессии k: {k}")
        
        # Запись параметров клиента
        abonent_A = {
            "p": p,
            "g": g,
            "secret_key_x": x,
            "public_key_alpha": alpha,
            "received_beta": beta,
            "session_key_k": k,
            "password": PASSWORD
        }
        with open("abonent_A.json", "w", encoding="utf-8") as f:
            json.dump(abonent_A, f, indent=4)
        print("Параметры клиента сохранены в abonent_A.json")

if __name__ == "__main__":
    main()