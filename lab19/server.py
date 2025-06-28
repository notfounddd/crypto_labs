from os import name
import numpy as np
import random, socket, json

def fast_exp_mod(a, n, s):
    x = 1
    while n > 0:
        if n & 1:
            x = (x * a) % s
        a = (a * a) % s
        n = n >> 1
    return x


def generate_prime(k):
    while True:
        p = random.getrandbits(k)
        highest_bit = 1 << (k - 1)
        lowest_bit = 1
        p = (p | highest_bit) | lowest_bit
        p = int(p)
        t = 100
        if p < 2:
            continue
        if p in (2, 3):
            return p
        if p % 2 == 0:
            continue
        s = 0
        r = p - 1
        while r % 2 == 0:
            r //= 2
            s += 1
        for _ in range(t):
            a = random.randint(2, p - 2)
            y = fast_exp_mod(a, r, p)
            if y == 1 or y == p - 1:
                continue
            for _ in range(s - 1):
                y = fast_exp_mod(y, 2, p)
                if y == p - 1:
                    break
            else:
                break
        else:
            return p



class TrustedCenter:
    def __init__(self, field_size: int, m: int = 1):
        """
        Инициализация доверенного центра
        
        :param field_size: размер поля F (простое число)
        :param m: параметр безопасности (степень многочлена будет 2m)
        """
        self.field_size = field_size
        self.m = m
        self.polynomial = self._generate_symmetric_matrix()
        self.user_ids = {}

    def _generate_symmetric_matrix(self):
        """Генерация симметричного многочлена f(x,y) степени 2m"""
        # Создаем (m+1) x (m+1) матрицу коэффициентов
        poly = [[0] * (self.m + 1) for _ in range(self.m + 1)]
        
        # Заполняем коэффициенты случайными значениями
        for i in range(self.m + 1):
            for j in range(i, self.m + 1):  # Используем симметрию
                poly[i][j] = random.randint(0, self.field_size - 1) % self.field_size
                if i != j:
                    poly[j][i] = poly[i][j]  # Обеспечиваем симметричность
        return np.array(poly)

    def register_user(self, user_name: str):
    
        user_id = [0] * (self.m + 1)
        
        while True:
            for i in range(self.m + 1):
                user_id[i] = random.randint(0, self.field_size - 1)
            if user_id not in self.user_ids.values():
                break
        
        self.user_ids[user_name] = user_id

        user_id = np.array(user_id)[:, None]
        personal_poly = self._calculate_private_keys(user_id)
        return user_id, personal_poly

    def _calculate_private_keys(self, user_id: int):
        """Вычисление персонального многочлена для пользователя"""
        return self.polynomial @ user_id
    

def main():
    # field_size = 17
    field_size = generate_prime(128)
    m = 5
    tc = TrustedCenter(field_size, m)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(2)
    print("Запуск на localhost:5000")

    conn_A, addr_A = server_socket.accept()
    print(f"Соедениени с А {addr_A}")
    conn_B, addr_B = server_socket.accept()
    print(f"Соедениени с B {addr_B}")

    name_A = conn_A.recv(1024).decode()
    name_B = conn_B.recv(1024).decode()

    user_id_A, personal_poly_A = tc.register_user(name_A)
    user_id_B, personal_poly_B = tc.register_user(name_B)

    conn_A.send(json.dumps({
        "user_id": user_id_A.tolist(),
        "personal_poly": personal_poly_A.tolist(),
        "field_size": field_size
    }).encode())
    conn_B.send(json.dumps({
        "user_id": user_id_B.tolist(),
        "personal_poly": personal_poly_B.tolist(),
        "field_size": field_size
    }).encode())

    conn_A.close()
    conn_B.close()
    server_socket.close()

if __name__ == "__main__":
    main()