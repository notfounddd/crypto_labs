import random
from typing import List, Tuple

def fast_exp_mod(a, n, s):
    """Быстрое возведение в степень по модулю (метод квадратов)"""
    x = 1
    while n > 0:
        if n & 1:  # Если младший бит равен 1
            x = (x * a) % s
        a = (a * a) % s
        n = n >> 1  # Сдвиг вправо (деление на 2)
    return x

def generate_prime(k):
    """Генерация простого числа длиной k бит с использованием теста Миллера-Рабина"""
    while True:
        # Генерируем случайное k-битное число
        p = random.getrandbits(k)
        # Устанавливаем старший и младший биты в 1 для гарантии длины и нечетности
        highest_bit = 1 << (k - 1)
        lowest_bit = 1
        p = (p | highest_bit) | lowest_bit
        p = int(p)
        t = 100  # Количество тестов Миллера-Рабина
        
        # Проверка тривиальных случаев
        if p < 2:
            continue
        if p in (2, 3):
            return p
        if p % 2 == 0:
            continue
            
        # Разложение p-1 = r * 2^s
        s = 0
        r = p - 1
        while r % 2 == 0:
            r //= 2
            s += 1
            
        # Тест Миллера-Рабина
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
            return p  # Число прошло все тесты - вероятно простое

# Глобальное простое число для всех операций
__PRIME__ = generate_prime(512)

def generate_polynomial(t: int, secret: int) -> List[int]:
    """Генерация полинома степени t-1 со свободным членом secret"""
    # Коэффициенты: secret (свободный член) + t-1 случайных коэффициентов
    return [secret] + [random.randrange(0, __PRIME__) for _ in range(t - 1)]

def evaluate_polynomial(coeffs: List[int], x: int) -> int:
    """Вычисление значения полинома в точке x (схема Горнера)"""
    y = 0
    for i, a in enumerate(coeffs):
        # y = a0 + a1*x + a2*x^2 + ... + an*x^n mod __PRIME__
        y = (y + a * fast_exp_mod(x, i, __PRIME__)) % __PRIME__
    return y

def generate_shares(n: int, t: int, secret: int) -> List[Tuple[int, int]]:
    """Генерация n долей секрета с порогом t"""
    assert 1 < t <= n, "Должно быть 1 < t <= n"
    # Генерируем полином степени t-1
    coeffs = generate_polynomial(t - 1, secret)
    shares = []
    used_x = set()  # Для уникальных x-координат
    
    for _ in range(n):
        # Генерируем уникальную x-координату
        while True:
            x = random.randint(1, __PRIME__ - 1)
            if x not in used_x:
                used_x.add(x)
                break
        # Вычисляем y-координату (значение полинома в точке x)
        y = evaluate_polynomial(coeffs, x)
        shares.append((x, y))
    return shares

def lagrange_interpolation(x: int, x_s: List[int], y_s: List[int]) -> int:
    """Интерполяция Лагранжа для восстановления значения в точке x"""
    total = 0
    k = len(x_s)
    
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        li = 1  # Базисный полином Лагранжа
        
        for j in range(k):
            if i != j:
                xj = x_s[j]
                # Вычисление числителя и знаменателя
                numerator = (x - xj) % __PRIME__
                denominator = (xi - xj) % __PRIME__
                # Обратный элемент знаменателя (по малой теореме Ферма)
                inv_denominator = fast_exp_mod(denominator, __PRIME__ - 2, __PRIME__)
                li = (li * numerator * inv_denominator) % __PRIME__
                
        total = (total + yi * li) % __PRIME__
    return total

def reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
    """Восстановление секрета по t долям"""
    # Разделяем x и y координаты
    x_s, y_s = zip(*shares)
    # Интерполяция в точке 0 (свободный член полинома)
    return lagrange_interpolation(0, list(x_s), list(y_s))

def main():
    """Основная функция для взаимодействия с пользователем"""
    try:
        # Ввод параметров
        N = int(input("Введите общее количество участников (N): "))
        T = int(input("Введите пороговое значение (T): "))
        assert 1 < T <= N, "Ошибка: должно выполняться 1 < T <= N"
    except (ValueError, AssertionError) as e:
        print(f"❌ Неверный ввод: {e}")
        return

    try:
        Users = int(input("Введите количество доступных пользователей (Users): "))
        if Users > N or Users < 1:
            raise ValueError("Users должен быть в диапазоне от 1 до N")
    except ValueError as e:
        print(f"❌ Неверный ввод: {e}")
        return

    # Генерация случайного секрета
    secret = random.randint(1, __PRIME__ - 1)
    print(f"\n🔐 Секрет сгенерирован: {secret}")

    # Создание долей секрета
    shares = generate_shares(N, T, secret)
    print(f"\n📨 Сгенерированные доли (r_i, s_i):")
    for idx, (r, s) in enumerate(shares, start=1):
        print(f"Участник {idx}: ({r}, {s})")

    if Users < T:
        print(f"\n❌ Недостаточно пользователей для восстановления секрета.")
        print(f"Требуется минимум T = {T}, а доступно только Users = {Users}.")
    else:
        print(f"\n✅ Пользователей достаточно. Восстанавливаем секрет из первых {T} из {Users} доступных.")
        available_shares = shares[:Users]
        selected_shares = random.sample(available_shares, T)
        recovered_secret = reconstruct_secret(selected_shares)
        print(f"\n🔁 Восстановленный секрет: {recovered_secret}")
        print("✔️ Совпадение:", recovered_secret == secret)

if __name__ == "__main__":
    main()