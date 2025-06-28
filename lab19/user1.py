import socket, json
import numpy as np
class User:
    def __init__(self, name: str, user_id: int, personal_poly, field_size: int):
        """
        Инициализация пользователя
        
        :param name: имя пользователя
        :param user_id: публичный ID
        :param personal_poly: персональный многочлен
        :param field_size: размер поля
        """

        self.name = name
        self.id = user_id
        self.personal_poly = personal_poly
        self.field_size = field_size
    def compute_shared_key(self, other_user_id: int) -> int:
        return (np.array(self.personal_poly).T @ np.array(other_user_id))[0][0] % self.field_size
    
def main():
    name = "A"
    socket_A = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_A.connect(('localhost', 5000))

    socket_A.send(name.encode())

    recv = json.loads(socket_A.recv(1024).decode())

    socket_A.close()
    
    alice = User(name, recv["user_id"], recv["personal_poly"], recv["field_size"])

    socket_A = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_A.connect(("localhost", 5001))

    socket_A.send(json.dumps({"user_id_A": alice.id}).encode())

    recv = json.loads(socket_A.recv(1024).decode())

    user_id_B = recv["user_id_B"]

    key = alice.compute_shared_key(user_id_B)

    socket_A.close()

    print("Ключ: ", key)

if __name__ == "__main__":
    main()