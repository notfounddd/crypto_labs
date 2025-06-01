from hash_func import *

__ID__ = "ZaparaAE"
HOST = 'localhost'
PORT = 65432

def generate_fiat_shamir_keys(bit_length=512, s_length=512):
    p = generate_prime(bit_length)
    q = generate_prime(bit_length)
    n = p * q

    a_list = [random.randint(1, n-1) for _ in range(s_length)]
    b_list = [fast_exp_mod(module_inverse(a, n), 2, n) for a in a_list]

    return n, p, q, a_list, b_list

def hash_message(TypeHash, message):
    if TypeHash == "sha256":
        return sha256(message)
    elif TypeHash == "sha512":
        return sha512(message)
    elif TypeHash == "streebog256":
        return streebog256(message)
    elif TypeHash == "streebog512":
        return streebog512(message)
    else:
        raise ValueError("Unsupported hash function")

def fiat_shamir_sign(TypeHash, message: bytes, n, a_list):
    r = random.randint(1, n-1)
    u = fast_exp_mod(r, 2, n)
    h = hash_message(TypeHash, message + str(u).encode())
    s = bin(int(h, 16))[2:].zfill(len(a_list))

    product = 1
    for i in range(len(s)):
        if s[i] == '1':
            product = (product * a_list[i]) % n
    t = (r * product) % n

    return s, t

def fiat_shamir_verify(TypeHash, message, signature, n, b_list):
    s, t = signature
    t = int(t)

    product = 1
    for i in range(len(s)):
        if s[i] == '1':
            product = (product * b_list[i]) % n
    w = (fast_exp_mod(t, 2, n) * product) % n

    h = hash_message(TypeHash, message.encode('utf-8') + str(w).encode())
    s_prime = bin(int(h, 16))[2:].zfill(len(s))

    return s == s_prime

def request_create(TypeHash, Algorithm, message):
    hash_len_map = {"sha256": 256, "streebog256": 256, "sha512": 512, "streebog512": 512}
    s_len = hash_len_map.get(TypeHash, 512)

    n, p, q, a_list, b_list = generate_fiat_shamir_keys(512, s_len)
    s, t = fiat_shamir_sign(TypeHash, message, n, a_list)

    Client_request = {
        "CMSVersion": "1",
        "DigestAlgorithmIdentifiers": TypeHash,
        "EncapsulatedContentInfo": {
            "ContentType": "Data",
            "OCTET_STRING_OPTIONAL": message.decode("utf-8")
        },
        "SignerInfos": {
            "CMSVersion": "1",
            "SignerIdentifier": __ID__,
            "DigestAlgorithmIdentifiers": TypeHash,
            "SignatureAlgorithmIdentifier": Algorithm,
            "SignatureValue": {
                "s": s,
                "t": str(t)
            },
            "SubjectPublicKeyInfo": {
                "n": str(n),
                "b_list": [str(b) for b in b_list]
            }
        }
    }

    with open("client_request.json", "w", encoding="utf-8") as f:
        json.dump(Client_request, f, indent=4)
    print("\u2705 JSON-запрос создан и сохранён в client_request.json")

def verify_server_response(response):
    try:
        server_timestamp = response["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["Timestamp"]
        current_time = datetime.utcnow().strftime("%y%m%d%H%M%SZ")

        time_diff = abs(datetime.strptime(current_time, "%y%m%d%H%M%SZ") - 
                       datetime.strptime(server_timestamp, "%y%m%d%H%M%SZ")).total_seconds()

        if time_diff > 300:
            print(f"❌ Временная метка недействительна (разница: {time_diff} секунд)")
            return False

        server_hash_type = response["SignerInfos"]["UnsignedAttributes"]["ServerHashAlgorithm"]
        message = response["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"]
        signature = (
            response["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["ServerSignatureValue"]["s"],
            response["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["ServerSignatureValue"]["t"]
        )
        pubkey = response["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["ServerPublicKeyInfo"]
        n = int(pubkey["n"])
        b_list = [int(b) for b in pubkey["b_list"]]

        valid = fiat_shamir_verify(server_hash_type, message, signature, n, b_list)
        if not valid:
            print("❌ Подпись сервера недействительна")
            return False

        print("✅ Временная метка и подпись сервера действительны")
        return True

    except Exception as e:
        print(f"❌ Ошибка при проверке ответа сервера: {str(e)}")
        return False

def main():
    print("Выберите тип хэша:")
    print("1. SHA-256")
    print("2. SHA-512")
    print("3. Stribog-256")
    print("4. Stribog-512")
    choice = input("Введите номер (1 - 4): ").strip()

    hash_map = {"1": "sha256", "2": "sha512", "3": "streebog256", "4": "streebog512"}
    hash_type = hash_map.get(choice)

    print("\nВыберите источник данных:")
    print("1. Ввести текст вручную")
    print("2. Прочитать из файла")
    source = input("Введите номер (1 или 2): ").strip()

    if source == "1":
        text = input("Введите текст для хэширования: ")
        message = text.encode('utf-8')
    else:
        path = input("Введите путь к файлу: ")
        try:
            with open(path, 'rb') as f:
                message = f.read()
        except FileNotFoundError:
            print("Файл не найден!")
            return

    request_create(hash_type, "Fiat-Shamir", message)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        with open("client_request.json", "r", encoding="utf-8") as f:
            json_data = f.read()
        s.sendall(json_data.encode('utf-8'))

        data = s.recv(99999999)
        response_all = json.loads(data.decode('utf-8'))

    if response_all["status"] == "success":
        print(response_all["confirmation"])

        if verify_server_response(response_all["response"]):
            with open("server_response.json", "w", encoding="utf-8") as f:
                json.dump(response_all["response"], f, indent=4, ensure_ascii=False)
            print("\u2705 Ответ сервера сохранён в server_response.json")

            confirmation = {
                "status": "confirmed",
                "timestamp": response_all["response"]["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["Timestamp"],
                "client_id": __ID__
            }
            with open("client_confirmation.json", "w", encoding="utf-8") as f:
                json.dump(confirmation, f, indent=4)
            print("\u2705 Подтверждение создано и сохранено в client_confirmation.json")
        else:
            print("❌ Ответ сервера не прошел проверку")
    else:
        print(response_all["message"])

if __name__ == "__main__":
    main()