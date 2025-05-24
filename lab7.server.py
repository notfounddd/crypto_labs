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
        print(f"❌ Error parsing JSON: {e}")
        return {}

def check_signature(SignatureValue, e, n, message, hashfunc):
    hash_funcs = {
        "sha256": sha256,
        "sha512": sha512,
        "streebog256": streebog256,
        "streebog512": streebog512
    }
    if hashfunc not in hash_funcs:
        raise ValueError(f"❌ Unsupported hash function: {hashfunc}")
    
    hash_func = hash_funcs[hashfunc]
    hash_hex = hash_func(message.encode("utf-8"))
    hash_int = int(hash_hex, 16)

    decrypted_signature = fast_exp_mod(SignatureValue, e, n)

    return decrypted_signature == hash_int

def create_server_signature(message, user_signature, timestamp, hash_func_name, d, n):
    # Concatenate message and user signature
    concat_msg = message + str(user_signature)
    
    # Hash the concatenated string
    hash_func = {
        "sha256": sha256,
        "sha512": sha512,
        "streebog256": streebog256,
        "streebog512": streebog512
    }[hash_func_name]
    
    first_hash = hash_func(concat_msg.encode('utf-8'))
    
    # Concatenate with timestamp and hash again
    concat_with_timestamp = first_hash + timestamp
    final_hash = hash_func(concat_with_timestamp.encode('utf-8'))
    
    # Create signature
    hash_int = int(final_hash, 16)
    signature = fast_exp_mod(hash_int, d, n)
    
    return signature

def offer_create(client_data):
    timestamp = create_utc_timestamp()
    server_pubkey, server_privkey = generate_keys(1024)
    
    # Randomly select server hash function (independent of client's choice)
    server_hash_func = random.choice(["sha256", "sha512", "streebog256", "streebog512"])
    print(f"Server selected hash function: {server_hash_func}")
    
    # Create server signature
    message = client_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"]
    user_signature = int(client_data["SignerInfos"]["SignatureValue"], 16)
    server_signature = create_server_signature(
        message, 
        user_signature, 
        timestamp, 
        server_hash_func, 
        server_privkey[2], 
        server_pubkey[0]
    )
    
    Server_offer = {
        "CMSVersion": "1",
        "DigestAlgorithmIdentifiers": client_data["DigestAlgorithmIdentifiers"],
        "EncapsulatedContentInfo": client_data["EncapsulatedContentInfo"],
        "SignerInfos": {
            "CMSVersion": "1",
            "SignerIdentifier": client_data["SignerInfos"]["SignerIdentifier"],
            "DigestAlgorithmIdentifiers": client_data["DigestAlgorithmIdentifiers"],
            "SignatureAlgorithmIdentifier": "RSA",
            "SignatureValue": client_data["SignerInfos"]["SignatureValue"],
            "SubjectPublicKeyInfo": client_data["SignerInfos"]["SubjectPublicKeyInfo"],
            "UnsignedAttributes": {
                "ObjectIdentifier": "signature-time-stamp",
                "SET_OF_AttributeValue": {
                    "Timestamp": timestamp,
                    "ServerSignature": hex(server_signature),
                    "ServerPublicKeyInfo": {
                        "e": str(server_pubkey[1]),
                        "n": str(server_pubkey[0])
                    },
                    "ServerHashAlgorithm": server_hash_func
                }
            }
        }
    }
    return Server_offer

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"✅ Server started on {HOST}:{PORT}")
        conn, addr = s.accept()
        
        with conn:
            print(f"✅ Client connected: {addr}")
            data = conn.recv(4096)
            json_data = parse_json(data)

            if not json_data:
                conn.sendall("❌ Error parsing JSON".encode('utf-8'))
                return

            try:
                TypeHash = json_data["DigestAlgorithmIdentifiers"]
                message = json_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"]
                e = int(json_data["SignerInfos"]["SubjectPublicKeyInfo"]["e"])
                n = int(json_data["SignerInfos"]["SubjectPublicKeyInfo"]["n"])
                SignatureValue = int(json_data["SignerInfos"]["SignatureValue"], 16)

                result = check_signature(SignatureValue, e, n, message, TypeHash)

                print(f"Signature verification result: {result}")

                if result:
                    response = offer_create(json_data)
                    conn.sendall(json.dumps({
                        "status": "success",
                        "confirmation": "✅ Signature is valid",
                        "response": response
                    }).encode("utf-8"))
                else:
                    conn.sendall(json.dumps({
                        "status": "error",
                        "message": "❌ Invalid signature"
                    }).encode("utf-8"))

            except KeyError as e:
                error_message = f"❌ Error: missing field {e}"
                print(error_message)
                conn.sendall(error_message.encode("utf-8"))
                
if __name__ == "__main__":
    main()

