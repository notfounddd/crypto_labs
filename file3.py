#diskret log

from file1 import *

def calc_order(a, p):
    order = 1
    while fast_exp_mod(a, order, p) != 1:
        order += 1
    return order

def pollards_rho(a, b, p, r, max_steps=1000):
    u_c, v_c = 2, 2  
    u_d, v_d = 2, 2  
    c = (fast_exp_mod(a, u_c, p) * fast_exp_mod(b, v_c, p)) % p
    d = c

    for step in range(max_steps):
       
        if c < p // 2:
            c = (a * c) % p
            u_c = (u_c + 1) % r
        else:
            c = (b * c) % p
            v_c = (v_c + 1) % r

        if d < p // 2:
            d = (a * d) % p
            u_d = (u_d + 1) % r
        else:
            d = (b * d) % p
            v_d = (v_d + 1) % r
        
        if d < p // 2:
            d = (a * d) % p
            u_d = (u_d + 1) % r
        else:
            d = (b * d) % p
            v_d = (v_d + 1) % r
        
        # Проверяем на совпадение
        if c == d:
            # Решаем сравнение: u_c + v_c * x ≡ u_d + v_d * x (mod r)
            A = (v_c - v_d) % r
            B = (u_d - u_c) % r
            # Решаем A * x ≡ B (mod r)
            x = solve_congruence(A, B, r)[0]
            if fast_exp_mod(a, x, p) == b % p:
                return x
            else:
                return "no result"

    return "no result"

def write_output(filename, result):
    with open(filename, 'w') as file:
        file.write(str(result))

output_filename = 'output.txt'

input_arr = {}
with open("C:/VsCode/crypto/lab3_input.txt", 'r') as f:
    for line in f:
        key, value = line.strip().split(" = ")
        input_arr[key] = int(value)

p = input_arr.get("p")
a = input_arr.get("a")
b = input_arr.get("b")

r = calc_order(a, p)
result = pollards_rho(a, b, p, r)

write_output(output_filename, result)
