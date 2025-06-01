from hash_func import *

HOST = 'localhost'
PORT = 65432

def create_utc_timestamp():
    return datetime.utcnow().strftime("%y%m%d%H%M%SZ")

def generate_fiat_shamir_keys(bit_length=512, s_length=256):
    p = generate_prime(bit_length)
    q = generate_prime(bit_length)
    n = p * q
    a_list = [random.randint(1, n - 1) for _ in range(s_length)]
    b_list = [fast_exp_mod(module_inverse(a, n), 2, n) for a in a_list]
    return n, p, q, a_list, b_list

def fiat_shamir_sign(TypeHash, message: bytes, n, a_list):
    r = random.randint(1, n - 1)
    u = fast_exp_mod(r, 2, n)
    h = hash_message(TypeHash, message + str(u).encode())
    s = bin(int(h, 16))[2:].zfill(len(a_list))
    product = 1
    for i in range(len(s)):
        if s[i] == '1':
            product = (product * a_list[i]) % n
    t = (r * product) % n
    return s, t

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

def generate_server_keys_and_signature(message, hash_types):
    server_hash_type = random.choice(hash_types)
    hash_len_map = {
        "sha256": 256,
        "streebog256": 256,
        "sha512": 512,
        "streebog512": 512
    }
    s_len = hash_len_map.get(server_hash_type, 256)
    n, p, q, a_list, b_list = generate_fiat_shamir_keys(512, s_len)
    s, t = fiat_shamir_sign(server_hash_type, message.encode('utf-8'), n, a_list)
    return {
        "ServerHashAlgorithm": server_hash_type,
        "ServerPublicKeyInfo": {
            "n": str(n),
            "b_list": [str(b) for b in b_list]
        },
        "ServerSignatureValue": {
            "s": s,
            "t": str(t)
        }
    }

def offer_create(client_data):
    timestamp = create_utc_timestamp()
    message = client_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"]
    server_data = generate_server_keys_and_signature(message, ["sha256", "sha512", "streebog256", "streebog512"])

    return {
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
                "ObjectIdentifier": "signature-time-stamp",
                "SET_OF_AttributeValue": {
                    "Timestamp": timestamp,
                    "ServerSignatureValue": server_data["ServerSignatureValue"],
                    "ServerPublicKeyInfo": server_data["ServerPublicKeyInfo"],
                },
                "ServerHashAlgorithm": server_data["ServerHashAlgorithm"]
            }
        }
    }

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"✅ Сервер запущен на {HOST}:{PORT}")
        conn, addr = s.accept()

        with conn:
            print(f"✅ Подключен клиент: {addr}")
            data = conn.recv(9999999999)
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
                signature = (
                    client_data["SignerInfos"]["SignatureValue"]["s"],
                    client_data["SignerInfos"]["SignatureValue"]["t"]
                )
                pubkey = client_data["SignerInfos"]["SubjectPublicKeyInfo"]
                n = int(pubkey["n"])
                b_list = [int(b) for b in pubkey["b_list"]]
                user = client_data["SignerInfos"]["SignerIdentifier"]

                valid = fiat_shamir_verify(TypeHash, message, signature, n, b_list)
                print(f"Результат проверки подписи: {valid}")

                if valid:
                    response = offer_create(client_data)
                    
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