import socket
from file4 import *
from lab4 import *
from lab5 import *
from datetime import datetime, timedelta

__ID__ = "ZaparaAE"


HOST = 'localhost'
PORT = 65432

def verify_server_timestamp(response_json):
    attrs = response_json["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]
    timestamp = attrs["Timestamp"]
    server_signature = int(attrs["ServerSignature"], 16)
    server_e = int(attrs["ServerPublicKeyInfo"]["e"])
    server_n = int(attrs["ServerPublicKeyInfo"]["n"])

    # проверка временной метки на подлинность
    
    hash_funcs = {
        "sha256": sha256,
        "sha512": sha512,
        "streebog256": streebog256,
        "streebog512": streebog512
    }
    hash_func = hash_funcs.get(response_json["DigestAlgorithmIdentifiers"])
    hash_hex = hash_func(timestamp.encode("utf-8"))
    
    
    hash_int = int(hash_hex, 16)
    # Расшифровка подписи сервера
    decrypted = fast_exp_mod(server_signature, server_e, server_n)

    is_signature_valid = decrypted == hash_int

    # проверка допустимого времени (±300 секунд)
    try:
        
        timestamp_dt = datetime.strptime(timestamp, "%y%m%d%H%M%SZ")
        now = datetime.utcnow()
        delta = abs((now - timestamp_dt).total_seconds())
        is_time_valid = delta < 300
    except Exception as e:
        print(f"❌ Ошибка разбора времени: {e}")
        return False

    return is_signature_valid and is_time_valid



def create_signature (message, hashfunc, d, n):
    if hashfunc == "sha256":
        hash_ = sha256
    elif hashfunc == "sha512":
        hash_ = sha512
    elif hashfunc == "streebog256":
        hash_ = streebog256
    elif hashfunc == "streebog512":
        hash_ = streebog512
        
        
    hash_hex = hash_(message)
    hash_int = int(hash_hex, 16)
    signature = fast_exp_mod(hash_int, d, n )
    
    return signature

def request_create(TypeHash, Algorithm, message):
    
    public_key,private_key = generate_keys(1024)
    SignatureValue = create_signature(message, TypeHash,private_key[2],public_key[0])
    
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

    print("✅ JSON-запрос создан и сохранён в client_request.json")
    
    

def main():
    
    print("Выберите тип хэша:")
    print("1. SHA-256")
    print("2. SHA-512")
    print("3. Stribog-256")
    print("4. Stribog-512")
    choice = input("Введите номер (1 - 4): ").strip()

    while choice not in ("1", "2", "3", "4"):
        print("Неверный выбор. Попробуйте снова.")
        choice = input("Введите номер (1 - 4): ").strip()

    print("\nВыберите источник данных:")
    print("1. Ввести текст вручную")
    print("2. Прочитать из файла")
    source = input("Введите номер (1 или 2): ").strip()

    while source not in ("1", "2"):
        print("Неверный выбор. Попробуйте снова.")
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

    if choice == "1":
        hash_type = "sha256"
    elif choice == "2":
        hash_type = "sha512"
    elif choice == "3":
        hash_type = "streebog256"
    elif choice == "4":
        hash_type = "streebog512"
    
    request_create(hash_type, "RSA", message)
     
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        with open("client_request.json", "r", encoding="utf-8") as f:
            json_data = f.read()
        s.sendall(json_data.encode('utf-8'))

        data = s.recv(8192)
        response_all = json.loads(data.decode('utf-8'))
        
    if response_all["status"] == "success":
        print(response_all["confirmation"])
        response_json = response_all["response"]

        if verify_server_timestamp(response_json):
            print("✅ Временная метка сервера действительна и подтверждена подписью")

            # Сохраняем ответ в файл
            with open("server_response.json", "w", encoding="utf-8") as f:
                json.dump(response_json, f, indent=4, ensure_ascii=False)
            print("✅ Ответ сервера с временной меткой сохранён в server_response.json")

        else:
            print("❌ Временная метка недействительна или неподписана")
    else:
        print(response_all["message"])


















if __name__ == "__main__":
    main()

