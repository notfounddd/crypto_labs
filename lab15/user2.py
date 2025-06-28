from hash_func import *
import socket
import json
import random

class Verifier:
    def __init__(self, name):
        self.name = name
        self.n = None
        self.v = None
        self.port = 65433  # Подключение к Prover на порту 65433
        
    def connect_to_prover(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 65433))
            
            data = s.recv(1024)
            self.v = int(json.loads(data.decode())['v'])
            print(f"[BOB] {self.name} получил v = {self.v}")
            
            for i in range(10):
                print(f"\n🔄 Итерация {i+1}")
                
                data = s.recv(1024)
                x = int(json.loads(data.decode())['x'])
                print(f"[BOB] {self.name} получает x = {x}")
                
                c = random.randint(0, 1)
                print(f"[BOB] {self.name} выбирает вызов c = {c}")
                s.sendall(json.dumps({'c': c}).encode())
                
                data = s.recv(1024)
                y = int(json.loads(data.decode())['y'])
                print(f"[BOB] {self.name} получает y = {y}")
                
                left = fast_exp_mod(y, 2, self.n) if self.n else 0
                right = (x * fast_exp_mod(self.v, c, self.n)) % self.n if self.n else 0
                valid = (left == right)
                
                result = "Проверка пройдена" if valid else "Проверка не пройдена"
                print(f"[BOB] {self.name} проверяет: {result}")
                s.sendall(json.dumps({'result': result}).encode())
                
                if not valid:
                    print("❌ Идентификация не удалась!")
                    return
                    
            print("\n✅ Идентификация успешно завершена!")

if __name__ == "__main__":
    bob = Verifier("Bob")
    bob.connect_to_prover()