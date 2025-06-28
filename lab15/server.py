from hash_func import *
import socket
import json

class TrustedCenter:
    def __init__(self):
        self.p = generate_prime(512)
        self.q = generate_prime(512)
        self.n = self.p * self.q
        self.port = 65432
        self.running = True
        
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', self.port))
            s.listen()
            print(f"🔒 Доверенный центр запущен. n = {self.n}")
            
            while self.running:
                try:
                    conn, addr = s.accept()
                    with conn:
                        print(f"🔗 Подключение от {addr}")
                        data = conn.recv(1024)
                        
                        if data == b'get_n':
                            response = {'n': str(self.n)}
                            conn.sendall(json.dumps(response).encode())
                        elif data == b'shutdown':  # Обработка команды выключения
                            print("🛑 Получена команда на выключение сервера")
                            conn.sendall(b'Server shutting down')
                            self.stop()
                            break  # Выход из цикла для завершения работы
                        else:
                            conn.sendall(b'Unknown command')
                except Exception as e:
                    print(f"⚠️ Ошибка: {e}")
                    self.running = False
                    print("🔴 Сервер остановлен")
                    break

    def stop(self):
        self.running = False
        print("🛑 Сервер завершает работу...")

if __name__ == "__main__":
    tc = TrustedCenter()
    try:
        tc.start()
    except KeyboardInterrupt:
        tc.stop()