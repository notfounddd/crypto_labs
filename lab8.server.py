import socket
import json
from file6 import *
from lab4 import *
from lab5 import *
from datetime import datetime

HOST = 'localhost'
PORT = 65432

def create_utc_timestamp() -> str:
    now_utc = datetime.utcnow()
    return now_utc.strftime("%y%m%d%H%M%SZ")

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
    b = (h - a *y) * r_inv % (p - 1)
    
    return (y, b)

def offer_create(client_data, server_hash):
    timestamp = create_utc_timestamp()
    
    # Генерируем ключи сервера
    server_p, server_alpha, server_a, server_beta = generate_elgamal_keys(1024)
    server_y, server_b = elgamal_sign(timestamp.encode('utf-8'), server_hash, server_p, server_a, server_alpha)

    Server_offer = {
        "CMSVersion": "1",
        "DigestAlgorithmIdentifiers": client_data["DigestAlgorithmIdentifiers"],
        "EncapsulatedContentInfo": client_data["EncapsulatedContentInfo"],
        "SignerInfos": {
            "CMSVersion": "1",
            "SignerIdentifier": client_data["SignerInfos"]["SignerIdentifier"],
            "DigestAlgorithmIdentifiers": client_data["DigestAlgorithmIdentifiers"],
            "SignatureAlgorithmIdentifier": client_data["SignerInfos"]["SignatureAlgorithmIdentifier"],
            "SignatureValue": client_data["SignerInfos"]["SignatureValue"],
            "SubjectPublicKeyInfo": client_data["SignerInfos"]["SubjectPublicKeyInfo"],
            "UnsignedAttributes": {
                "DigestAlgorithmServer": server_hash,
                "ObjectIdentifier": "signature-time-stamp",
                "SET_OF_AttributeValue": {
                    "Timestamp": timestamp,
                    "ServerSignature": {
                        "y": str(server_y),
                        "b": str(server_b)
                    },
                    "ServerPublicKeyInfo": {
                        "p": str(server_p),
                        "alpha": str(server_alpha),
                        "beta": str(server_beta)
                    }
                }
            }
        }
    }
    return Server_offer

def main():
    hash_options = ["sha256", "sha512", "streebog256", "streebog512"]
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"✅ Сервер запущен на {HOST}:{PORT}")
        conn, addr = s.accept()

        with conn:
            print(f"✅ Подключен клиент: {addr}")
            data = conn.recv(8192)
            try:
                client_data = json.loads(data.decode("utf-8"))
            except Exception as e:
                conn.sendall(json.dumps({
                    "status": "error",
                    "message": "❌ Ошибка при разборе JSON"
                }).encode("utf-8"))
                return

            try:
                TypeHash = client_data["DigestAlgorithmIdentifiers"]
                message = client_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"]
                y = int(client_data["SignerInfos"]["SignatureValue"]["y"])
                b = int(client_data["SignerInfos"]["SignatureValue"]["b"])
                pubkey = client_data["SignerInfos"]["SubjectPublicKeyInfo"]
                p = int(pubkey["p"])
                alpha = int(pubkey["alpha"])
                beta = int(pubkey["beta"])
                user = client_data["SignerInfos"]["SignerIdentifier"]

                valid = elgamal_verify(message, (y, b), p, alpha, beta, TypeHash)
                print(f"Результат проверки подписи: {valid}")

                if valid:
                    # Случайно выбираем хэш-функцию для сервера
                    server_hash = random.choice(hash_options)
                    response = offer_create(client_data, server_hash)
                    
                    conn.sendall(json.dumps({
                        "status": "success",
                        "confirmation": "✅ Подпись верна",
                        "response": response
                    }).encode("utf-8"))
                else:
                    conn.sendall(json.dumps({
                        "status": "error",
                        "message": "❌ Подпись недействительна"
                    }).encode("utf-8"))
            except Exception as e:
                conn.sendall(json.dumps({
                    "status": "error",
                    "message": f"❌ Ошибка обработки запроса: {str(e)}"
                }).encode("utf-8"))

if __name__ == "__main__":
    main()