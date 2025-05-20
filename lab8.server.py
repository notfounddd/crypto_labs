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

def elgamal_verify(message, signature, p, alpha, b, hashfunc):
    r, s = signature
    if not (0 < r < p and 0 < s < p - 1):
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

    v1 = (fast_exp_mod(b, r, p) * fast_exp_mod(r, s, p)) % p
    v2 = fast_exp_mod(alpha, h, p)

    return v1 == v2

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
        k = random.randint(1, p - 2)
        temp,_,_ = euclidean_algorithm(k, p - 1)
        if temp == 1:
            break
    r = fast_exp_mod(alpha, k, p)
    k_inv = module_inverse(k, p - 1)
    s = (k_inv * (h - a * r)) % (p - 1)
    return (r, s)



def offer_create(TypeHash, Algorithm, message, user, signature, pubkey):
    timestamp = create_utc_timestamp()

    server_p, alpha, server_a, server_b = generate_elgamal_keys(1024)
    r, s = elgamal_sign(timestamp.encode('utf-8'), TypeHash, server_p, server_a, alpha)

    Server_offer = {
        "CMSVersion": "1",
        "DigestAlgorithmIdentifiers": TypeHash,
        "EncapsulatedContentInfo": {
            "ContentType": "Data",
            "OCTET_STRING_OPTIONAL": message
        },
        "SignerInfos": {
            "CMSVersion": "1",
            "SignerIdentifier": user,
            "DigestAlgorithmIdentifiers": TypeHash,
            "SignatureAlgorithmIdentifier": Algorithm,
            "SignatureValue": {
                "r": str(signature[0]),
                "s": str(signature[1])
            },
            "SubjectPublicKeyInfo": pubkey,
            "UnsignedAttributes": {
                "ObjectIdentifier": "signature-time-stamp",
                "SET_OF_AttributeValue": {
                    "Timestamp": timestamp,
                    "ServerSignature": {
                        "r": str(r),
                        "s": str(s)
                    },
                    "ServerPublicKeyInfo": {
                        "p": str(server_p),
                        "alpha": str(alpha),
                        "b": str(server_b)
                    }
                }
            }
        }
    }
    return Server_offer


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"✅ Сервер запущен на {HOST}:{PORT}")
        conn, addr = s.accept()

        with conn:
            print(f"✅ Подключен клиент: {addr}")
            data = conn.recv(8192)
            try:
                json_data = json.loads(data.decode("utf-8"))
            except Exception as e:
                conn.sendall("❌ Ошибка при разборе JSON".encode("utf-8"))
                return

            try:
                TypeHash = json_data["DigestAlgorithmIdentifiers"]
                message = json_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"]
                r = int(json_data["SignerInfos"]["SignatureValue"]["r"])
                s_val = int(json_data["SignerInfos"]["SignatureValue"]["s"])
                pubkey = json_data["SignerInfos"]["SubjectPublicKeyInfo"]
                p = int(pubkey["p"])
                alpha = int(pubkey["alpha"])
                b = int(pubkey["b"])
                user = json_data["SignerInfos"]["SignerIdentifier"]

                valid = elgamal_verify(message, (r, s_val), p, alpha, b, TypeHash)
                print(f"Результат проверки подписи: {valid}")

                if valid:
                    response = offer_create(TypeHash, "ElGamal", message, user, (r, s_val), pubkey)
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
