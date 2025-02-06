import random

def generate_polynomial(p, k):
    polynomial = [random.randint(0, p-1) for _ in range(k + 1)]

    if polynomial[0] == 0:
        polynomial[0] = random.randint(1, p-1)
    return polynomial

def polynomial_addition(polynomial1, polynomial2, p):
    max_len = max(len(polynomial1), len(polynomial2))
    result = [0] * max_len

    for i in range(max_len):

        if i < len(polynomial1):
            a = polynomial1[i]
        else:
            a = 0
        if i < len(polynomial2):
            b = polynomial2[i]
        else:
            b = 0

        result[i] = (a + b) % p

    return result

def polynomial_division(dividend, divisor, p):
    while len(dividend) >= len(divisor):
        coeff = dividend[0] // divisor[0]

        for i in range(len(divisor)):
            dividend[i] -= divisor[i] * coeff

        if dividend[0] == 0:
            dividend.pop(0)

    for i in range(len(dividend)):
        if dividend[i] != 0:
            dividend[i] %= p
    return dividend

def polynomial_multiplication(polynomial1, polynomial2, irreducible_poly, p):
    product = [0] * (len(polynomial1) + len(polynomial2) - 1)

    for i in range(len(polynomial1)):
        for j in range(len(polynomial2)):
            product[i + j] += (polynomial1[i] * polynomial2[j]) % p

    while len(product) > len(irreducible_poly) and product[0] == 0:
        while product[0] == 0:
            product.pop(0)

    if len(product) >= len(irreducible_poly):
        product = polynomial_division(product, irreducible_poly, p)
    return product

p = int(input("Enter the field over which the construction is taking place: "))
k = int(input("Enter the degree of construction: "))
irreducible_poly = list(map(int, input("Enter the irreducible polynomial over this field: ").split()))
print(f"Irreducible polynomial: {irreducible_poly}")

polynomial1 = generate_polynomial(p, random.randint(1, k - 1))
print(f"Polynomial 1: {polynomial1}")

polynomial2 = generate_polynomial(p, random.randint(1, k - 1))
print(f"Polynomial 2: {polynomial2}")

print(f"Addition: {polynomial_addition(polynomial1, polynomial2, p)}")
print(f"Multiplication: {polynomial_multiplication(polynomial1, polynomial2, irreducible_poly, p)}")
