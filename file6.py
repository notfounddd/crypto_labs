#el gamal
from file1 import *
import json
import random

def save_parameters(filename, p, a, alpha, b):
    params = {
        "p": p,
        "a": a,
        "alpha": alpha,
        "b": b
    }
    with open(filename, 'w') as file:
        json.dump(params, file, indent=4)

def load_parameters(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def save_encrypted_message(ciphertext, filename):
    encrypted_message = {
        "Version": 0,
        "EncryptedContentInfo": {
            "ContentType": "text",
            "ContentEncryptionAlgorithmIdentifier": "algamalEncryption",
            "encryptedContent": ciphertext,
            "OPTIONAL": {}
        }
    }
    with open(filename, 'w') as file:
        json.dump(encrypted_message, file, indent=4)

def load_encrypted_message(filename):
    with open(filename, 'r') as file:
        encrypted_message = json.load(file)
    return encrypted_message["EncryptedContentInfo"]["encryptedContent"]

def save_decrypted_message(decrypted_text, filename):
    decrypted_message = {
        "DecryptedContent": decrypted_text
    }
    with open(filename, 'w') as file:
        json.dump(decrypted_message, file, indent=4)

def is_primitive_root(alfa, p):
    return fast_exp_mod(alfa, 2, p) != 1 and fast_exp_mod(alfa, 2, p) != -1 and fast_exp_mod(alfa, (p-1)//2, p) != 1

def split_blocks(message, block_size):
    return [message[i:i + block_size] for i in range(0, len(message), block_size)]

def gamal_encrypt_block(message, p, alpha, b):
    r = random.randint(0, p - 2)
    c1 = fast_exp_mod(alpha, r, p)
    c2 = (message * fast_exp_mod(b, r, p)) % p
    return (c1, c2)

def gamal_encrypt(message, p, alpha, b):
    block_size = (p.bit_length() - 1) // 8
    message_bytes = message.encode('utf-8')
    blocks = split_blocks(message_bytes, block_size)

    encrypted_blocks = []
    for block in blocks:
        block_num = int.from_bytes(block, 'big')
        encrypted_block = gamal_encrypt_block(block_num, p, alpha, b)
        encrypted_blocks.append(encrypted_block)
    
    return encrypted_blocks

def gamal_decrypt_block(ciphertext, p, a):
    c1, c2 = ciphertext
    c1_inv = module_inverse(fast_exp_mod(c1, a, p), p)
    return (c2 * c1_inv) % p

def decrypt_blocks(encrypted_blocks, p, a):
    decrypted_message = ""
    for block in encrypted_blocks:
        m = gamal_decrypt_block(block, p, a)
        decrypted_message += m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
    return decrypted_message


print("Select an action:")
print("1. Generate parameters p, a, alpha, and b")
print("2. Encrypt a message")
print("3. Decrypt a message")
choice = input("Enter the action number: ")

if choice == '1':
    bit_length = int(input("Enter the bit length : "))
    p = generate_prime(bit_length)
    a = random.randint(1, p - 2)
    while True:
        alpha = random.randint(2, p - 2)
        if is_primitive_root(alpha, p):
            break
    b = fast_exp_mod(alpha, a, p)
    save_parameters('parameters.json', p, a, alpha, b)
    print("Parameters p, a, alpha, and b have been saved in parameters.json")

elif choice == '2':
    params = load_parameters('parameters.json')
    p, alpha, b = params["p"], params["alpha"], params["b"]
    message = input("Enter the message to encrypt: ")
    c = gamal_encrypt(message, p, alpha, b)
    save_encrypted_message(c, 'ciphertext.json')
    print("Encrypted message has been saved in ciphertext.json")

elif choice == '3':
    params = load_parameters('parameters.json')
    p, a = params["p"], params["a"]
    c = load_encrypted_message("ciphertext.json")
    decrypted_message = decrypt_blocks(c, p, a)
    save_decrypted_message(decrypted_message, 'decrypted_text.json')
    print("Decrypted message has been saved in decrypted_text.json")
