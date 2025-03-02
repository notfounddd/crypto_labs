#pollard p & p-1

from file1 import *
import random
from math import log

def f(x, n):
    return (x**2 + 1) % n

def pollard_rho(n, c):
    a = c
    b = c
    d = 1

    while d == 1:
        a = f(a, n)
        b = f(f(b, n), n)
        d, _, _ = euclidean_algorithm(abs(a - b), n)

    if d == n:
        return None
    else:
        return d  # Нетривиальный делитель

def pollard_rho_minus_1(n):
    B = []
    with open("C:/VsCode/crypto/lab2_input.txt", 'r') as file:
        line = file.readline()
        B = [int(num.strip()) for num in line.split(',')] 

    for _ in range(1000):
        a = random.randint(2, n-2)
        d, _, _ = euclidean_algorithm(a, n)
        if d >= 2: return d

        for p_i in B:
            l = int(log(n) / log(p_i))  # Вычисление l как максимальной степени p_i^l <= B
            a = fast_exp_mod(a, p_i**l, n)
        
        d, _, _ = euclidean_algorithm(a - 1, n)

        if d != 1 and d != n: return d
    return None

# p-метод Полларда
n = 8051
c = random.randint(1, n-1)
divisor = pollard_rho(n, c)

if divisor:
    print(f"Нетривиальный делитель числа {n}: {divisor}")
else:
    print("Делитель не найден")

# (p-1)-метод Полларда
n_p_minus_1 = 83725982673891286235028433

divisor1 = pollard_rho_minus_1(n_p_minus_1)

if divisor1:
    print(f"Нетривиальный делитель числа {n_p_minus_1}: {divisor1}")
else:
    print("Делитель не найден")
