from hash_func import *
import socket
import json

IP = "localhost"
SERVER_PORT = 55555 
RESPONSE_PORT = 55556 
ID1 = 123784
ID2 = 543217

def main():
    # === Этап 1: Получаем первое сообщение от клиента ===
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((IP, SERVER_PORT))
        s.listen()
        print(f"Server started and listening on {IP}:{SERVER_PORT}")
        
        conn, addr = s.accept()
        with conn:
            print(f"Client connected: {addr}")
            data = conn.recv(4096)
            if not data:
                print("No data received")
                return
            
            try:
                received_data = json.loads(data.decode('utf-8'))
                message1 = received_data['message 1']
                key = received_data['key']
                valueA = received_data['valueA']
                id1 = received_data['ID1']
                print(f"Key: {key}")
                print(f"Open message1: {message1}")
                print(f"ValueA: {valueA}")
                print(f"ID1: {id1}")

                if id1 == ID1:
                    mess2 = input("Enter mess2 (ciphertext): ")
                    mess3 = input("Enter mess3 (plaintext): ")
                    valueB = rand(512) 
                    print(f"Your valueB: {valueB}")
                    temp_data = {
                        "message 2": mess2,
                        "ID2": ID2,
                        "valueA": valueA,
                        "valueB": valueB
                    }     
                    encoded_Data = aes_encrypt(key, json.dumps(temp_data))   
                    data_for_send = {
                        "open message3": mess3,
                        "encode message2": encoded_Data
                    }
                    
                    # Отправляем ответ клиенту
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                        s2.connect((IP, RESPONSE_PORT))
                        s2.sendall(json.dumps(data_for_send).encode('utf-8'))
                        print("Response (mess2, mess3) sent successfully")
                else:
                    print("Invalid ID1")
                    return
            
            except Exception as e:
                print(f"Error processing first part: {e}")
                return

    # === Этап 2: Принимаем ответное сообщение клиента (mess4 + mess5) ===
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((IP, SERVER_PORT))  # слушаем снова на том же порту
        s.listen()
        print(f"Waiting for message 4 and 5 from client on {IP}:{SERVER_PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"Client connected for 2nd message: {addr}")
            data = conn.recv(4096)
            if not data:
                print("No second message received")
                return

            try:
                received_data = json.loads(data.decode('utf-8'))
                mess5 = received_data["open message5"]
                encoded_message4 = received_data["encode message4"]

                decrypted = aes_decrypt(key, encoded_message4)
                decrypted_data = json.loads(decrypted)

                if decrypted_data['valueA'] == valueA and decrypted_data['valueB'] == valueB:
                    if decrypted_data['ID1'] == ID1:
                        print("\nDecrypted response data from second stage:")
                        print(f"Message 4: {decrypted_data['message 4']}")
                        print(f"Message 5 (open): {mess5}")
                        print(f"Sender ID1: {decrypted_data['ID1']}")
                        print(f"ValueA: {decrypted_data['valueA']}")
                        print(f"ValueB: {decrypted_data['valueB']}")
                    else:
                        print("Invalid ID1 in second message")
                else:
                    print("Invalid valueA or valueB in second message")

            except Exception as e:
                print(f"Error processing second part: {e}")
                return

if __name__ == "__main__":
    main()
