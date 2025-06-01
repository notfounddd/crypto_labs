from hash_func import *

ID1 = 123784
ID2 = 543217
IP = "localhost"
SERVER_PORT = 55555  # Port to connect to initially
RESPONSE_PORT = 55556  # Port to listen for response

def tsa_or_rand(choice):
    if choice == '1':
        now_utc = datetime.utcnow()
        padd = now_utc.strftime("%y%m%d%H%M%SZ")
    elif choice == '2':
        padd = generate_prime(512)
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)
    return padd

def socket_send_receive(ip, port, data_to_send):
    # First send the initial data
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        print("Connected to server")
        s.sendall(data_to_send)
        print("Initial data sent")

    # Then wait for response on different port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((IP, RESPONSE_PORT))
        s.listen()
        print(f"Waiting for response on port {RESPONSE_PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"Connection from {addr}")
            response = conn.recv(4096)
            if not response:
                print("No response received")
                return None
            try:
                return json.loads(response.decode('utf-8'))
            except Exception as e:
                print(f"Error decoding response: {e}")
                return None

def main():
    key = gen_rand_bits(128)
    mess1 = input("Enter mess1 (ciphertext): ")
    mess2 = input("Enter mess2 (plaintext): ")
    choice = input("Choose timestamp(1) or gen_rand_prime(2): ")
    value = tsa_or_rand(choice)
    
    temp_Data = {
        "message 1": mess1,
        "ID1": ID1,
        "value": value
    }
    encoded_Data = aes_encrypt(key, json.dumps(temp_Data))
    
    data_to_send = {
        "key": key,
        "open message": mess2,
        "encode message": encoded_Data
    }
    print("\nReceived data:")
    print(f"Key: {key}")
    print(f"Open message: {mess2}")
    print(f"Decrypted message: {mess1}")
    print(f"ID1: {ID1}")
    print(f"Value: {value}")
    response = socket_send_receive(IP, SERVER_PORT, json.dumps(data_to_send).encode('utf-8'))
    if response:
        print("\nReceived response from second user:")
        print(f"Open message: {response['open message4']}")
        
        if 'encode message3' in response:
            decrypted = aes_decrypt(key, response['encode message3'])
            decrypted_data = json.loads(decrypted)
            if decrypted_data['value'] == value:
                if decrypted_data['ID2'] == ID2:
                    print("Decrypted response data:")
                    print(f"Message 3: {decrypted_data['message 3']}")
                    print(f"Sender ID: {decrypted_data['ID2']}")
                    print(f"Value: {decrypted_data['value']}")
                else:
                    print("Invalid ID2")
                    sys.exit(1)
            else:
                print("Invalid value")
                sys.exit(1)

if __name__ == "__main__":
    main()