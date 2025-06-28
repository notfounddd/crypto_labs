from hash_func import *

IP = 'localhost'
PORT = 55555
IDs = 'server'
IDu = 'user'

def main():
    public_key, private_key = generate_keys(1024)
    n, e = public_key  # Добавьте эту строку
    print(f"[SERVER] Public Key (n, e): {public_key}")
    print(f"[SERVER] Private Key (p, q, d): {private_key}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((IP, PORT))
        s.listen()
        print(f"[SERVER] Ожидание подключения на {IP}:{PORT}...")

        conn, addr = s.accept()
        print(f"[SERVER] Подключен клиент: {addr}")

        send_pub_key = {
            'ID': IDs,
            'n': public_key[0],
            'e': public_key[1]
        }
        
        conn.sendall(json.dumps(send_pub_key).encode('utf-8'))
        print("[SERVER] Отправил открытый ключ клиенту.")

        data = conn.recv(4096).decode('utf-8')
        encrypted_message = json.loads(data)
        print("[SERVER] Получил сообщение от клиента:", encrypted_message)

        decrypted_message = decrypt_message(encrypted_message, private_key)
        print("[SERVER] Расшифрованное сообщение:", decrypted_message)

        try:
            message = json.loads(decrypted_message.decode('utf-8'))
        except json.JSONDecodeError as e:
            print("[SERVER] Ошибка декодирования JSON:", e)
            return

        if message.get('client_id') != IDu:
            print("[SERVER] Ошибка: Неверный ID клиента")
            return

        if not verify_timestamp(message['timestamp']):
            print("[SERVER] Ошибка: Временная метка недействительна или устарела")
            return

        test_signature = {
            'ID': IDs,
            'session_key': message['session_key'],
            'timestamp': message['timestamp']
        }
        sign = sha512(json.dumps(test_signature).encode('utf-8'))

        print(sign)
        print(message['signature'])

        if sign == message['signature']:
            print("[SERVER] Подпись проверена успешно. Сообщение достоверно.")
            print(f"[SERVER] Сеансовый ключ: {message['session_key']}")
        else:
            print(f"[SERVER] Подпись недействительна")


if __name__ == '__main__':
    main()
