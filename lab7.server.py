import socket
import json
from datetime import datetime
from file4 import *
from lab4 import *
from lab5 import *

HOST = 'localhost'
PORT = 65432

def create_utc_timestamp() -> str:
    now_utc = datetime.utcnow()
    return now_utc.strftime("%y%m%d%H%M%SZ")

def parse_json(json_data: bytes) -> dict:
    try:
        decoded = json_data.decode("utf-8")
        data = json.loads(decoded)
        return data
    except Exception as e:
        print(f"❌ Ошибка при разборе JSON: {e}")
        return {}



def create_signature (message, hashfunc, d, n):
    if hashfunc == "sha256":
        hash_ = sha256
    elif hashfunc == "sha512":
        hash_ = sha512
    elif hashfunc == "streebog256":
        hash_ = streebog256
    elif hashfunc == "streebog512":
        hash_ = streebog512
        
        
    hash_hex = hash_(message.encode('utf-8'))
    hash_int = int(hash_hex, 16)
    signature = fast_exp_mod(hash_int, d, n )
    
    return signature


def check_Signature(SignatureValue, e, n, message, hashfunc):
    
    hash_funcs = {
        "sha256": sha256,
        "sha512": sha512,
        "streebog256": streebog256,
        "streebog512": streebog512
    }
    if hashfunc not in hash_funcs:
        raise ValueError(f"❌ Неподдерживаемая хеш-функция: {hashfunc}")
    
    hash_func = hash_funcs[hashfunc]
    hash_hex = hash_func(message.encode("utf-8"))
    hash_int = int(hash_hex, 16)

    decrypted_signature = fast_exp_mod(SignatureValue, e, n)

    return decrypted_signature == hash_int

# Формирование ответа сервера с временной меткой
def offer_create(TypeHash, Algorithm, message, user, user_Signature, user_E, user_N):
    timestamp = create_utc_timestamp()

    server_pubkey, server_privkey = generate_keys(1024)

    ts_signature = create_signature(timestamp, TypeHash, server_privkey[2], server_pubkey[0])

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
            "SignatureValue": hex(user_Signature),
            "SubjectPublicKeyInfo": {
                "e": str(user_E),
                "n": str(user_N)
            },
            "UnsignedAttributes": {
                "ObjectIdentifier": "signature-time-stamp",
                "SET_OF_AttributeValue": {
                    "Timestamp": timestamp,
                    "ServerSignature": hex(ts_signature),
                    "ServerPublicKeyInfo": {
                        "e": str(server_pubkey[1]),
                        "n": str(server_pubkey[0])
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
            data = conn.recv(4096)
            json_data = parse_json(data)

            if not json_data:
                conn.sendall("❌ Ошибка при разборе JSON".encode('utf-8'))
                return

            try:
                TypeHash = json_data["DigestAlgorithmIdentifiers"]
                message = json_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"]
                e = int(json_data["SignerInfos"]["SubjectPublicKeyInfo"]["e"])
                n = int(json_data["SignerInfos"]["SubjectPublicKeyInfo"]["n"])
                SignatureValue = int(json_data["SignerInfos"]["SignatureValue"], 16)
                user = json_data["SignerInfos"]["SignerIdentifier"]

                result = check_Signature(SignatureValue, e, n, message, TypeHash)

                print(f"Результат проверки подписи: {result}")

                if result:
                    response = offer_create(TypeHash, "RSA", message, user, SignatureValue, e, n)
                    conn.sendall(json.dumps({
                        "status": "success",
                        "confirmation": "✅ Подпись верна",
                        "response": response
                        }).encode("utf-8"))
                else:
                    conn.sendall(json.dumps({
                        "status": "error",
                        "message": "❌ Подпись неверна"
                    }).encode("utf-8"))

            except KeyError as e:
                error_message = f"❌ Ошибка: отсутствует поле {e}"
                print(error_message)
                conn.sendall(error_message.encode("utf-8"))
                
if __name__ == "__main__":
    main()