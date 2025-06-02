from hash_func import *

ID1 = 123784
ID2 = 543217
IP = "localhost"
SERVER_PORT = 55555  # Port to connect to initially
RESPONSE_PORT = 55556  # Port to listen for response


def socket_send(ip, port, data_to_send):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        print("Connected to server")
        s.sendall(data_to_send)
        print("Data sent successfully")

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
    mess1 = input("Enter mess1: ")
    valueA = rand(512)
    print(f"Your valueA: {valueA}")
    Data = {
        "message 1": mess1,
        "key": key,
        "valueA": valueA,
        "ID1": ID1
    }
    response = socket_send_receive(IP, SERVER_PORT, json.dumps(Data).encode('utf-8'))
    
    if response:
        print("\nReceived response from second user:")
        print(f"Open message: {response['open message3']}")
        
        if 'encode message2' in response:
            decrypted = aes_decrypt(key, response['encode message2'])
            decrypted_data = json.loads(decrypted)
            if decrypted_data['valueA'] == valueA:
                if decrypted_data['ID2'] == ID2:
                    print("Decrypted response data:")
                    print(f"Message 2: {decrypted_data['message 2']}")
                    print(f"Sender ID: {decrypted_data['ID2']}")
                    print(f"ValueA: {decrypted_data['valueA']}")
                    print(f"ValueB: {decrypted_data['valueB']}")
                    #send third part
                    mess5 = input("Enter mess5 (plaintext): ")
                    mess4 = input("Enter mess4 (ciphertext): ")
                    temp_data = {
                        "message 4": mess4,
                        "ID1": ID1,
                        "valueA": valueA,
                        "valueB": decrypted_data['valueB']
                    }
                    encoded_Data = aes_encrypt(key, json.dumps(temp_data))
                    data_for_send = {
                        "open message5": mess5,
                        "encode message4": encoded_Data
                    }
                    response = socket_send(IP, SERVER_PORT, json.dumps(data_for_send).encode('utf-8'))

                else:
                    print("Invalid ID2")
                    sys.exit(1)
            else:
                print("Invalid valueA")
                sys.exit(1)

if __name__ == "__main__":
    main()