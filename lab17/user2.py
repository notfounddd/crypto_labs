from hash_func import * 


HOST = 'localhost'
PORT = 65434

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"✅ Сервер запущен на {HOST}:{PORT}")
        conn, addr = s.accept()
        
        with conn:
            print(f"🔌 Подключен клиент: {addr}")
            try:
                # Получаем параметры p и g
                data = conn.recv(2048)
                client_data = json.loads(data.decode("utf-8"))
                p = client_data.get("p")
                g = client_data.get("g")
                print(f"📥 Получено:\np = {p}\ng = {g}")

                # Генерация секретного ключа и открытого
                y = random.randint(2, p - 2)
                beta = fast_exp_mod(g, y, p)
                print(f"Секретный ключ y: {y}")
                print(f"Открытый ключ β: {beta}")

                # Отправляем открытый ключ клиенту
                conn.sendall(json.dumps({"beta": beta}).encode('utf-8'))

                # Получаем открытый ключ клиента (alpha)
                data = conn.recv(2048)
                client_data = json.loads(data.decode("utf-8"))
                alpha = client_data.get("alpha")
                print(f"Получен открытый ключ α: {alpha}")

                # Вычисляем общий ключ
                k = fast_exp_mod(alpha, y, p)
                print(f"Общий ключ сессии k: {k}")

                # Отправка подтверждения
                conn.sendall(json.dumps({"status": "ok"}).encode('utf-8'))

                # Запись параметров сервера (Абонент B) в файл
                abonent_B = {
                    "p": p,
                    "g": g,
                    "secret_key_y": y,
                    "public_key_beta": beta,
                    "received_alpha": alpha,
                    "session_key_k": k
                }
                with open("abonent_B.json", "w", encoding="utf-8") as f:
                    json.dump(abonent_B, f, indent=4)
                print("Параметры сервера сохранены в abonent_B.json")

            except Exception as e:
                conn.sendall(json.dumps({
                    "status": "error",
                    "message": f"❌ Ошибка: {str(e)}"
                }).encode("utf-8"))
                print("❌ Исключение:", e)

if __name__ == "__main__":
    main()
