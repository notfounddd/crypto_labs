from hash_func import *

IP = 'localhost'
PORT = 55555

IdA = 123784

def main():
    print("Выберите хэш-функцию:")
    print("1. SHA-256")
    print("2. SHA-512")
    print("3. Stribog-256")
    print("4. Stribog-512")
    func_choice = input("Введите номер (1-4): ").strip()

    while func_choice not in ("1", "2", "3", "4"):
        func_choice = input("Неверный выбор. Повторите: ").strip()

    hash_map = {
        "1": ("sha256", sha256),
        "2": ("sha512", sha512),
        "3": ("stribog256", streebog256),
        "4": ("stribog512", streebog512)
    }

    hash_name, hash_func = hash_map[func_choice]

    z = str(generate_prime(512))
    hash_z = hash_func(z.encode())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((IP, PORT))
        print("[A] Connected to server")

        # 1. Receive public key
        pubkey_data = s.recv(4096)
        pub = json.loads(pubkey_data.decode())
        n, e = pub["n"], pub["e"]

        # 2. Encrypt (z || ID_A)
        temp_Data = {
            "z": z,
            "IdA": str(IdA)
        }

        ciphertext = encrypt(json.dumps(temp_Data), n, e)

        # 3. Send data
        data_to_send = {
            "hash_func": hash_name,
            "hash": hash_z,
            "ID_A": str(IdA),
            "cipher": ciphertext
        }
        s.sendall(json.dumps(data_to_send).encode())

        # 4. Receive z back and verify
        response = s.recv(4096)
        if not response:
            print("[A] Ошибка: пустой ответ от сервера.")
            exit(1)

        msg = json.loads(response.decode())
        if "error" in msg:
            print(f"[A] Сервер вернул ошибку: {msg['error']}")
            exit(1)

        z_returned = msg.get("z")
        print(f"[A] Received z: {z_returned}")

        if z_returned == z:
            print("[A] Успех! z совпадает.")
        else:
            print("[A] Ошибка: z не совпадает!")

if __name__ == "__main__":
    main()