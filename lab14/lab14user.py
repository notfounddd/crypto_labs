import socket
import json
import hash_func


HOST = '127.0.0.1'
PORT = 9090
HASH_COUNT = 20
SECRET_KEY = "secret_key"



def generate_hash_chain(secret: str, count: int, hash_type: str) -> list[str]:
    hashes = []
    if hash_type == "sha256":
        hashes = [hash_func.sha256(secret.encode())]
    elif hash_type == "sha512":
        hashes = [hash_func.sha512(secret.encode())]
    elif hash_type == "stribog256":
        hashes = [hash_func.streebog256(secret.encode())]
    elif hash_type == "stribog512":
        hashes = [hash_func.streebog512(secret.encode())]
    
    for _ in range(1, count):
        prev_hash = hashes[-1]
        if hash_type == "sha256":
            hashes.append(hash_func.sha256(prev_hash.encode()))
        elif hash_type == "sha512":
            hashes.append(hash_func.sha512(prev_hash.encode()))
        elif hash_type == "stribog256":
            hashes.append(hash_func.streebog256(bytes.fromhex(prev_hash)))
        elif hash_type == "stribog512":
            hashes.append(hash_func.streebog512(bytes.fromhex(prev_hash)))
    
    return hashes

def send_to_server(data: dict, host: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(json.dumps(data).encode('utf-8'))
        #print(f"[USER] Отправлено: {data}")

def auth_loop(user_id: str, host: str, port: int, hash_chain: list[str], hash_type: str):
    current_index = 1
    chain_length = len(hash_chain)

    while True:
        choice = input("\n[1] Отправить пароль\n[2] Сменить пользователя\n[другое] Выход\n> ").strip()

        if choice == "1":
            if current_index >= chain_length:
                print("[USER] Цепочка исчерпана, регистрирую пользователя заново...")

                last_hash = hash_chain[-1]
                init_data = {
                    "id": user_id,
                    "i": 1,
                    "hash_type": hash_type,
                    "hash": last_hash
                }
                send_to_server(init_data, host, port)
                current_index = 1
                print("[USER] Регистрация завершена, можно снова отправлять пароль")
                continue

            hash_val = hash_chain[-(current_index + 1)]
            data = {
                "id": user_id,
                "i": current_index,
                "hash_type": hash_type,
                "hash": hash_val
            }
            send_to_server(data, host, port)
            current_index += 1

        elif choice == "2":
            return

        else:
            print("[USER] Завершение работы.")
            exit()

def select_hash_algorithm():
    print("\nВыберите алгоритм хеширования:")
    print("1. SHA-256")
    print("2. SHA-512")
    print("3. Streebog 256")
    print("4. Streebog 512")
    
    while True:
        choice = input("> ").strip()
        if choice == "1":
            return "sha256"
        elif choice == "2":
            return "sha512"
        elif choice == "3":
            return "stribog256"
        elif choice == "4":
            return "stribog512"
        else:
            print("Неверный выбор, попробуйте снова")

def main():


    while True:
        user_id = input("\nВведите ваш ID пользователя: ").strip()
        if not user_id:
            print("[USER] ID не может быть пустым")
            continue

        hash_type = select_hash_algorithm()
        hash_chain = generate_hash_chain(SECRET_KEY, HASH_COUNT, hash_type)
        last_hash = hash_chain[-1]

        init_data = {
            "id": user_id,
            "i": 1,
            "hash_type": hash_type,
            "hash": last_hash
        }
        send_to_server(init_data, HOST, PORT)
        print(f"[USER] Инициализация завершена для пользователя {user_id} с алгоритмом {hash_type}.")

        auth_loop(user_id, HOST, PORT, hash_chain, hash_type)

if __name__ == '__main__':
    main()