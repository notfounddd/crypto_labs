from hash_func import *


class GroupMember:
    def __init__(self):
        self.prime_p = None
        self.prime_q = None
        self.generator = None
        self.private_key = None
        self.public_key = None

    def load_keys(self):
        try:
            with open("group_config.json", 'r') as f:
                config = json.load(f)
                self.prime_p = config['prime_p']
                self.prime_q = config['prime_q']
                self.generator = config['generator']
                self.private_key = config['members'][0]['private']
                self.public_key = config['members'][0]['public']
                print("Keys loaded successfully for member A.")
        except (FileNotFoundError, KeyError, IndexError):
            print("Error: Configuration file not found or invalid.")
            exit()

    def run_service(self):
        """
        Основной цикл участника:
        1. Ожидает подключения лидера
        2. Получает пропуск (pass)
        3. Генерирует случайный компонент R
        4. Получает вызов (challenge)
        5. Вычисляет свою часть подписи
        6. Отправляет результат лидеру
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("localhost", 1233))
        server.listen()
        print("Member A service running on localhost:1233, waiting for leader...")

        conn, addr = server.accept()
        print(f"Leader connected from {addr}")

        try:
            data = json.loads(conn.recv(8192).decode('utf-8'))
            member_pass = data['pass']
            print("Received pass from leader.")

            random_part = random.randint(1, self.prime_q - 1)
            R = fast_exp_mod(self.generator, random_part, self.prime_p)
            conn.send(json.dumps({'random': R}).encode('utf-8'))
            print("Generated and sent random component.")

            data = json.loads(conn.recv(8192).decode('utf-8'))
            challenge = data['challenge']
            print("Received challenge from leader.")

            signature_part = (random_part + self.private_key * member_pass * challenge) % self.prime_q
            conn.send(json.dumps({'signature': signature_part}).encode('utf-8'))
            print("Calculated and sent signature part.")

        except Exception as e:
            print(f"Error during session: {e}")
        finally:
            conn.close()
            server.close()
            print("Connection closed.")

if __name__ == "__main__":
    member = GroupMember()
    member.load_keys()
    member.run_service()