import socket
from file4 import *
from lab4 import *
from lab5 import *
from datetime import datetime, timedelta


__ID__ = "ZaparaAE"

HOST = 'localhost'
PORT = 65432

def verify_server_timestamp(response_json):
    try:
        attrs = response_json["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]
        timestamp = attrs["Timestamp"]
        server_signature = int(attrs["ServerSignature"], 16)
        server_e = int(attrs["ServerPublicKeyInfo"]["e"])
        server_n = int(attrs["ServerPublicKeyInfo"]["n"])
        server_hash_func = attrs["ServerHashAlgorithm"]
        
        # Get original message and user signature
        message = response_json["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"]
        user_signature = int(response_json["SignerInfos"]["SignatureValue"], 16)
        
        # Recreate server signature
        concat_msg = message + str(user_signature)
        hash_func = {
            "sha256": sha256,
            "sha512": sha512,
            "streebog256": streebog256,
            "streebog512": streebog512
        }[server_hash_func]
        
        first_hash = hash_func(concat_msg.encode('utf-8'))
        concat_with_timestamp = first_hash + timestamp
        expected_hash = hash_func(concat_with_timestamp.encode('utf-8'))
        
        # Verify server signature
        decrypted = fast_exp_mod(server_signature, server_e, server_n)
        is_signature_valid = decrypted == int(expected_hash, 16)

        # Check timestamp validity (±300 seconds)
        timestamp_dt = datetime.strptime(timestamp, "%y%m%d%H%M%SZ")
        now = datetime.utcnow()
        delta = abs((now - timestamp_dt).total_seconds())
        is_time_valid = delta < 300

        return is_signature_valid and is_time_valid

    except Exception as e:
        print(f"❌ Error verifying server timestamp: {e}")
        return False

def create_signature(message, hashfunc, d, n):
    hash_funcs = {
        "sha256": sha256,
        "sha512": sha512,
        "streebog256": streebog256,
        "streebog512": streebog512
    }
    hash_func = hash_funcs[hashfunc]
    hash_hex = hash_func(message)
    hash_int = int(hash_hex, 16)
    signature = fast_exp_mod(hash_int, d, n)
    return signature

def request_create(TypeHash, Algorithm, message):
    public_key, private_key = generate_keys(1024)
    SignatureValue = create_signature(message, TypeHash, private_key[2], public_key[0])
    
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
            "SignatureValue": hex(SignatureValue),
            "SubjectPublicKeyInfo": {
                "e": str(public_key[1]),
                "n": str(public_key[0])
            },
            "UnsignedAttributes": {
                "ObjectIdentifier": "signature-time-stamp",
                "SET_OF_AttributeValue": ""
            }
        }
    }
    
    with open("client_request.json", "w", encoding="utf-8") as f:
        json.dump(Client_request, f, indent=4)

    print("✅ JSON request created and saved to client_request.json")
    return Client_request

def main():
    print("Select hash type:")
    print("1. SHA-256")
    print("2. SHA-512")
    print("3. Stribog-256")
    print("4. Stribog-512")
    choice = input("Enter number (1-4): ").strip()

    while choice not in ("1", "2", "3", "4"):
        print("Invalid choice. Try again.")
        choice = input("Enter number (1-4): ").strip()

    print("\nSelect data source:")
    print("1. Enter text manually")
    print("2. Read from file")
    source = input("Enter number (1 or 2): ").strip()

    while source not in ("1", "2"):
        print("Invalid choice. Try again.")
        source = input("Enter number (1 or 2): ").strip()

    if source == "1":
        text = input("Enter text to hash: ")
        message = text.encode('utf-8')
    else:
        path = input("Enter file path: ")
        try:
            with open(path, 'rb') as f:
                message = f.read()
        except FileNotFoundError:
            print("File not found!")
            return

    hash_types = {
        "1": "sha256",
        "2": "sha512",
        "3": "streebog256",
        "4": "streebog512"
    }
    hash_type = hash_types[choice]
    
    client_request = request_create(hash_type, "RSA", message)
     
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(json.dumps(client_request).encode('utf-8'))

        data = s.recv(8192)
        response_all = json.loads(data.decode('utf-8'))
        
    if response_all["status"] == "success":
        print(response_all["confirmation"])
        response_json = response_all["response"]

        if verify_server_timestamp(response_json):
            print("✅ Server timestamp is valid and signature confirmed")

            with open("server_response.json", "w", encoding="utf-8") as f:
                json.dump(response_json, f, indent=4, ensure_ascii=False)
            print("✅ Server response with timestamp saved to server_response.json")
        else:
            print("❌ Invalid timestamp or signature")
    else:
        print(response_all["message"])

if __name__ == "__main__":
    main()