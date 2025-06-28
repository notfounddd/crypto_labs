from hash_func import *
import socket
import json
import random

class Prover:
    def __init__(self, name):
        self.name = name
        self.n = None
        self.s = None
        self.v = None
        self.port = 65433
        
    def register_with_center(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 65432))  # Подключение к TrustedCenter на порту 65432
            s.sendall(b'get_n')
            data = s.recv(1024)
            response = json.loads(data.decode())
            self.n = int(response['n'])
            
        while True:
            self.s = random.randint(1, self.n-1)
            if gcd(self.s, self.n)[0] == 1:
                break
                
        self.v = pow(self.s, 2, self.n)
        print(f"🔑 {self.name} выбрал секрет s = {self.s}, v = {self.v}")
        
    def start(self):
        self.register_with_center()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', self.port))
            s.listen()
            print(f"[ALICE] {self.name} (доказывающий) запущен")
            
            conn, addr = s.accept()
            with conn:
                print(f"🔗 Подключение проверяющего от {addr}")
                conn.sendall(json.dumps({'v': str(self.v)}).encode())
                
                for i in range(10):
                    print(f"\n🔄 Итерация {i+1}")
                    
                    z = random.randint(1, self.n-1)
                    x = fast_exp_mod(z, 2, self.n)
                    print(f"[ALICE] {self.name} выбирает z = {z}, вычисляет x = {x}")
                    conn.sendall(json.dumps({'x': str(x)}).encode())
                    
                    data = conn.recv(1024)
                    c = json.loads(data.decode())['c']
                    print(f"[ALICE] {self.name} получает вызов c = {c}")
                    
                    y = (z * (self.s ** c)) % self.n
                    print(f"[ALICE] {self.name} вычисляет y = {y}")
                    conn.sendall(json.dumps({'y': str(y)}).encode())
                    
                    data = conn.recv(1024)
                    result = json.loads(data.decode())['result']
                    print(f"[ALICE] {self.name} получает результат: {result}")
                    
                    if "не пройдена" in result:
                        print("\n❌ Идентификация не удалась!")
                        return
                        
                print("\n✅ Идентификация успешно завершена!")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(('localhost', 65432))
                    s.sendall(b'shutdown')
if __name__ == "__main__":
    alice = Prover("Alice")
    alice.start()