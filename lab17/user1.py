from hash_func import * 

HOST = 'localhost'
PORT = 65433

def main():
    # Генерация параметров Диффи-Хеллмана
    p, g = generate_params(512)
    print(f"Сгенерированы параметры:\np = {p}\ng = {g}")

    x = random.randint(2, p - 2)
    alpha = fast_exp_mod(g, x, p)
    print(f"Секретный ключ x: {x}")
    print(f"Открытый ключ α: {alpha}")

    # Устанавливаем соединение
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Отправка p и g
        s.sendall(json.dumps({"p": p, "g": g}).encode('utf-8'))

        # Получение β от сервера
        data = s.recv(2048)
        server_data = json.loads(data.decode("utf-8"))
        beta = server_data.get("beta")
        print(f"Получен открытый ключ β: {beta}")

        # Отправка α серверу
        s.sendall(json.dumps({"alpha": alpha}).encode("utf-8"))

        # Получение подтверждения
        data = s.recv(1024)
        server_response = json.loads(data.decode("utf-8"))
        print("Ответ от сервера:", server_response)

        # Вычисление общего ключа
        k = fast_exp_mod(beta, x, p)
        print(f"🗝️ Общий ключ сессии k: {k}")

        # Запись параметров клиента (Абонент A) в файл
        abonent_A = {
            "p": p,
            "g": g,
            "secret_key_x": x,
            "public_key_alpha": alpha,
            "received_beta": beta,
            "session_key_k": k
        }
        with open("abonent_A.json", "w", encoding="utf-8") as f:
            json.dump(abonent_A, f, indent=4)
        print("Параметры клиента сохранены в abonent_A.json")

if __name__ == "__main__":
    main()
