import socket
import json
from file6 import *
from lab4 import *
from lab5 import *
from datetime import datetime

__ID__ = "ZaparaAE"
HOST = 'localhost'
PORT = 65432

def elgamal_sign(message: bytes, hashfunc, p, a, alpha):
    if hashfunc == "sha256":
        hash_ = sha256
    elif hashfunc == "sha512":
        hash_ = sha512
    elif hashfunc == "streebog256":
        hash_ = streebog256
    elif hashfunc == "streebog512":
        hash_ = streebog512

    h = int(hash_(message), 16)
    while True:
        r = random.randint(1, p - 2)
        temp, _, _ = euclidean_algorithm(r, p - 1)
        if temp == 1:
            break
    
    y = fast_exp_mod(alpha, r, p)
    r_inv = module_inverse(r, p - 1)
    b = (h - a * y) * r_inv % (p - 1)
    
    return (y, b)

def elgamal_verify(message, signature, p, alpha, beta, hashfunc):
    y, b = signature
    if not (0 < y < p and 0 < b < p - 1):
        return False

    if hashfunc == "sha256":
        hash_ = sha256
    elif hashfunc == "sha512":
        hash_ = sha512
    elif hashfunc == "streebog256":
        hash_ = streebog256
    elif hashfunc == "streebog512":
        hash_ = streebog512

    h = int(hash_(message.encode('utf-8')), 16)

    left = (fast_exp_mod(beta, y, p) * fast_exp_mod(y, b, p)) % p
    right = fast_exp_mod(alpha, h, p)

    return left == right

def request_create(TypeHash, Algorithm, message):
    p, alpha, a, beta = generate_elgamal_keys(512)
    y, b = elgamal_sign(message, TypeHash, p, a, alpha)

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
                "y": str(y),
                "b": str(b)
            },
            "SubjectPublicKeyInfo": {
                "p": str(p),
                "alpha": str(alpha),
                "beta": str(beta)
            }
        }
    }

    with open("client_request.json", "w", encoding="utf-8") as f:
        json.dump(Client_request, f, indent=4)

    print("✅ JSON-запрос создан и сохранён в client_request.json")

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

    request_create(hash_type, "ElGamal", message)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        with open("client_request.json", "r", encoding="utf-8") as f:
            json_data = f.read()
        s.sendall(json_data.encode('utf-8'))

        data = s.recv(8192)
        response_all = json.loads(data.decode('utf-8'))

    if response_all["status"] == "success":
        print(response_all["confirmation"])
        
        # Проверяем подпись сервера
        server_response = response_all["response"]
        server_signature = (
            int(server_response["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["ServerSignature"]["y"]),
            int(server_response["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["ServerSignature"]["b"])
        )
        server_pubkey = server_response["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["ServerPublicKeyInfo"]
        server_hash = server_response["SignerInfos"]["UnsignedAttributes"]["DigestAlgorithmServer"]
        
        timestamp = server_response["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["Timestamp"]
        
        valid = elgamal_verify(
            timestamp,
            server_signature,
            int(server_pubkey["p"]),
            int(server_pubkey["alpha"]),
            int(server_pubkey["beta"]),
            server_hash
        )
        
        if valid:
            print("✅ Подпись сервера с временной меткой верна")
            print(f"Временная метка: {timestamp}")
        else:
            print("❌ Подпись сервера недействительна")
        
        with open("server_response.json", "w", encoding="utf-8") as f:
            json.dump(server_response, f, indent=4, ensure_ascii=False)
        print("✅ Ответ сервера сохранён в server_response.json")
    else:
        print(response_all["message"])

if __name__ == "__main__":
    main()