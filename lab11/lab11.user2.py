from hash_func import *

IP = "localhost"
SERVER_PORT = 55555 
RESPONSE_PORT = 55556 
ID1 = 123784
ID2 = 543217


def main():
    # First receive the initial data
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
                return None
            
            try:
                received_data = json.loads(data.decode('utf-8'))
                open_message2 = received_data['open message']
                key = received_data['key']
                
                decrypted_data = aes_decrypt(key, received_data['encode message'])
                decrypted_json = json.loads(decrypted_data)
                
                decrypted_message1 = decrypted_json['message 1']
                id1 = decrypted_json['ID1']
                value = decrypted_json['value']
                
                print("\nReceived data:")
                print(f"Key: {key}")
                print(f"Open message: {open_message2}")
                print(f"Decrypted message: {decrypted_message1}")
                print(f"ID1: {id1}")
                print(f"Value: {value}")
                
                # Prepare response
                if id1 == ID1:
                    mess3 = input("Enter mess3 (ciphertext): ")
                    mess4 = input("Enter mess4 (plaintext): ")   
                    temp_data = {
                        "message 3": mess3,
                        "ID2": ID2,
                        "value": value
                    }     
                    encoded_Data = aes_encrypt(key, json.dumps(temp_data))   
                    data_for_send = {
                        "open message4": mess4,
                        "encode message3": encoded_Data
                    }
                    
                    # Send response
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                        s2.connect((IP, RESPONSE_PORT))
                        s2.sendall(json.dumps(data_for_send).encode('utf-8'))
                        print("Response sent successfully")
                    
            except Exception as e:
                print(f"Error processing data: {e}")
                return None

if __name__ == "__main__":
    main()