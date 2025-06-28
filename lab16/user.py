from hash_func import *

IP = 'localhost'
PORT = 55555
ID = 'user'


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((IP, PORT))
        print(f"[CLIENT] Подключился к серверу {IP}:{PORT}")

        data = s.recv(4096).decode('utf-8')
        pub_key_data = json.loads(data)
        
        n = pub_key_data['n']
        e = pub_key_data['e']
        server_id = pub_key_data['ID']
        
        print(f"[CLIENT] Получил открытый ключ от {server_id}:")
        print(f"  n = {n}")
        print(f"  e = {e}")

        session_key = generate_session_key(256)
        timestamp = create_utc_timestamp()
        
        json_session_key = json.dumps({
            'session_key': session_key,
            'timestamp': timestamp
        }, indent=4)
        
        print(f"[CLIENT] JSON с сеансовым ключом:\n{json_session_key}")
        with open('session_key.json', 'w') as f:
            f.write(json_session_key)

        signature = {
            'ID': server_id,
            'session_key': session_key,
            'timestamp': timestamp
        }
        print("[CLIENT] Сеансовый ключ сохранен в файл session_key.json")
        sign = sha512(json.dumps(signature).encode('utf-8'))
        
        message = {
            'session_key': session_key,
            'timestamp': timestamp,
            'signature': sign,
            'client_id': ID
        }
        
        message_json = json.dumps(message, indent=4)
        encrypt = encrypt_message(message_json, (n, e))
        print("[CLIENT] Зашифровал сообщение с сеансовым ключом и подписью.")
        s.sendall(json.dumps(encrypt).encode('utf-8'))
        print("[CLIENT] Отправил сообщение с сеансовым ключом и подписью на сервер.")
        with open('message.json', 'w') as f:
            f.write(message_json)

if __name__ == '__main__':
    main()