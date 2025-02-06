#help function

import random
# 1
# Обобщенный (расширенный) алгоритм Евклида
def euclidean_algorithm(x, y):
    a_2 = 1; a_1 = 0
    b_2 = 0; b_1 = 1
    while y != 0:
        q = x // y
        r = x - q * y
        a = a_2 - q * a_1
        b = b_2 - q * b_1
        x = y; y = r
        a_2 = a_1; a_1 = a
        b_2 = b_1; b_1 = b
    m = x; a = a_2; b = b_2
    return m, a, b
# 2.1    
# Алгоритм быстрого возведения в степень
def fast_exp(a, n):
    x = 1
    while n > 0:
        if n & 1:
            x = x * a
        a = a * a
        n = n >> 1
    return x
# 2.2
# Алгоритм быстрого возведения в степень по модулю
def fast_exp_mod(a, n, s):
    x = 1
    while n > 0:
        if n & 1:
            x = (x * a) % s
        a = (a * a) % s
        n = n >> 1
    return x
# 3
# Символ Якоби
def jacobi_symbol(a, n):
    if n <= 2 or n % 2 == 0:
        raise ValueError("n must be an odd integer <= 3.")
    if a < 0 or a >= n:
        raise ValueError("a must be in the range [0, n).")
    if a == 0:
        return 0
    if a == 1:
        return 1
    a = a % n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in [3, 5]:
                result = -result 
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a = a % n
    if n == 1:
        return result
    return 0
#4.1
#Тест Ферма
def fermat_test(n, k=5): # k - количество итераций теста
    if n < 5 or n % 2 == 0:
        return "Число n составное"
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return "Число n составное"
    
    return "Число n, вероятно, простое"
#4.2
#Тест Соловэя-Штрассена
def solovay_strassen(n, k=5):
    if n < 2:
        return "Число n составное"
    if n % 2 == 0:
        return "Число n составное"
    if fast_exp_mod(2, n - 1, n) != 1:
        return "Число n составное"
    for _ in range(k):
        a = random.randint(2, n - 2)
        jacobi = jacobi_symbol(a, n)
        if jacobi == 0 or fast_exp_mod(a, (n - 1) // 2, n) != jacobi % n:
            return "Число n составное"
    return "Число n, вероятно, простое" 
#4.3
#Тест Миллера-Рабина
def miller_rabin(n, k=5):
    if n < 5 or n % 2 == 0:
        return "Число n составное"
    r = n - 1
    S = 0
    while r % 2 == 0:
        r //= 2
        S += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        y = fast_exp_mod(a, r, n)
        if y == 1 or y == n - 1:
            continue
        j = 1
        while j <= S - 1:
            y = fast_exp_mod(y, 2, n)
            if y == 1:
                return "Число n составное"
            if y == n - 1:
                break
            j += 1
        else:
            return "Число n составное"
    return "Число n, вероятно, простое"
#6
#Генерация простого числа заданной размерности
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
#7
#Решение сравнения первой степени
def solve_congruence(a, b, m):
    d, a1, b1 = euclidean_algorithm(a, m)
    if b % d != 0:
        return "Решений нет"
    else:
        a1 = a1 % (m // d)
        b1 = b // d
        m1 = m // d
        x0 = (a1 * b1) % m1
        solutions = [x0 + i * m1 for i in range(d)]
        return solutions

#8
#Решение сравнения второй степени
def legendre_symbol (a, p):
    legendre = fast_exp_mod(a, (p-1) // 2, p)
    if legendre == p - 1:
        return -1
    return legendre

def solve_congruence_quadro(a, p):
    if legendre_symbol(a, p) == -1:
        return "Решений нет"
    
    # Разложение p-1 на множители
    h = p - 1
    k = 0
    while h % 2 == 0:
        h //= 2
        k += 1
    N=2
    a1 = fast_exp_mod(a, (h + 1) // 2, p)
    a2 = fast_exp_mod(a, -1, p)
    N1 = fast_exp_mod(N, h, p)
    N2 = 1
    j = 0

    for i in range(k - 1):
        b = (a1 * N2) % p
        c = (a2 * b * b) % p
        d = fast_exp_mod(c, 1 << (k - 2 - i), p)
        if d == p - 1:
            j_i = 1
        else:
            j_i = 0
        N2 = (N2 * fast_exp_mod(N1, 1 << i, p)) % p 
    
    x1 = (a1 * N2) % p
    x2 = (-x1) % p
    return x1, x2

#9
#Решение системы сравнений
def pairwise_coprime(arr):
    for i in range(len(arr)):
        for j in range(i + 1, len(arr)):
            gcd, a , b  = euclidean_algorithm(arr[i], arr[j])
            if gcd != 1:
                return False
    return True

def find_total_module(arr):
    total_module = 1
    for i in range(len(arr)):
        total_module = total_module * arr[i]
    return total_module

def module_inverse(a, p):
    gcd, x, y  = euclidean_algorithm(a, p)
    if gcd != 1:
        return "Обратного элемент не существует"
    return x % p

def solve_system(list_b, list_m):
    if not pairwise_coprime(list_m):
        return "Система сравнений не имеет решения"
    total_module = find_total_module(list_m)
    x = 0
    M = 0
    N = 0
    for i in range(len(list_m)):
        M = total_module // list_m[i]
        N = module_inverse(M , list_m[i])
        x += list_b[i] * M * N
    return x % total_module


#main

## 1
#x = 12
#y = 8
#gcd, a, b = euclidean_algorithm(x, y)
#print(f"Наибольший общий делитель {x} и {y} равен {gcd}, коэффициенты: a = {a}, b = {b} (где {gcd} = {a} * {x} + {b} * {y})\n")

## 2.1
#a = 2
#n = 10
#result = fast_exp(a, n)
#print(f"{a} в степени {n} равно {result}\n")

## 2.2
#a = 2
#n = 10
#s = 100
#result_mod = fast_exp_mod(a, n, s)
#print(f"{a} в степени {n} по модулю {s} равно {result_mod}\n")

##3
#a = -1
#n = 5
#print(f"Символ Якоби ({a}/{n}) = {jacobi_symbol(a, n)}")

##4.1
#n = 1000033
#print("Тест Ферма для : ", n, " - ", fermat_test(n))

##4.2
#n = 9999991
#print("Тест Соловэя-Штрассена для n = ", n, " - ", solovay_strassen(n))

#5
#n = 9999990
#print("Тест Миллера-Рабина для n = ", n, " - ", miller_rabin(n))

#6
#k = 16
#prime_number = generate_prime(k)
#print(f"Сгенерированное простое число размерности {k} бит: {prime_number}")

#7
#a=2
#b=6
#m=8
#print(f"Решение сравнения {a}x ≡ {b} (mod {m}): {solve_congruence(a,b,m)}")

##8
#a=16
#p=17
#N=2
#print(f"Решение сравнения x^2 ≡ {a} (mod {p}): {solve_congruence_quadro(a,p,N)}")

##9
#b_list = [3, 5, 2]
#m_list = [4, 7, 9]
#a = solve_system(b_list, m_list)
#print(f"Решение системы: x = {a}")
