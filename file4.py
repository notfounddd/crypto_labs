#rsa

import random
import json
from file1 import *

def generate_keys(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(2, phi)
    gcd, d, _ = euclidean_algorithm(e, phi)
    while gcd != 1:
        e = random.randrange(2, phi)
        gcd, d, _ = euclidean_algorithm(e, phi)

    d = d % phi
    if d < 0:
        d += phi

    return (n, e), (p, q, d)

def save_public_key(n, e, filename):
    key_data = {
        "SubjectPublicKeyInfo": {
            "publicExponent": e,
            "N": n
        }
    }
    with open(filename, 'w') as file:
        json.dump(key_data, file, indent=4)

def save_private_key(p, q, d, filename):
    key_data = {
        "privateExponent": d,
        "prime1": p,
        "prime2": q
    }
    with open(filename, 'w') as file:
        json.dump(key_data, file, indent=4)

def pkcs7_pad(message, block_size):
    padding_len = block_size - (len(message) % block_size)
    padding = chr(padding_len) * padding_len
    return message + padding

def pkcs7_unpad(message):
    padding_len = ord(message[-1])
    return message[:-padding_len]

def split_blocks(message, block_size):
    return [message[i:i + block_size] for i in range(0, len(message), block_size)]

def encrypt(message, n, e):
    block_size = (len(bin(n)) - 2) // 8 - 1
    padded_message = pkcs7_pad(message, block_size)
    
    #only padded message
    print(padded_message)
    
    #blocked & padded message
    blocks = split_blocks(padded_message, block_size)
    print(blocks)
    
    #blocked & padded message & bytes view
    for block in blocks:
        print(f"Block: {block} Encoded: {block.encode('utf-8')}")
    
    ciphertext = [hex(fast_exp_mod(int.from_bytes(block.encode('utf-8'), byteorder='big'), e, n)) for block in blocks]
    return ciphertext

def decrypt(ciphertext, n, d):
    blocks = []
    for c in ciphertext:
        decrypted_block = fast_exp_mod(int(c, 16), d, n)
        block_size = (decrypted_block.bit_length() + 7) // 8
        #print(decrypted_block.to_bytes(block_size, byteorder='big'))
        blocks.append(decrypted_block.to_bytes(block_size, byteorder='big').decode('utf-8'))
        
    padded_message = ''.join(blocks)
    return pkcs7_unpad(padded_message)

def save_encrypted_message(ciphertext, filename):
    encrypted_message = {
        "Version": 0,
        "EncryptedContentInfo": {
            "ContentType": "text",
            "ContentEncryptionAlgorithmIdentifier": "rsaEncryption",
            "encryptedContent":  ciphertext,
            "OPTIONAL": {}
        }
    }
    with open(filename, 'w') as file:
        json.dump(encrypted_message, file, indent=4)

def load_encrypted_message(filename):
    with open(filename, 'r') as file:
        encrypted_message = json.load(file)
    ciphertext = encrypted_message["EncryptedContentInfo"]["encryptedContent"]
    return ciphertext


def save_decrypted_message(decodetext, filename):
    decrypted_message = {
        "Version": 0,
        "EncryptedContentInfo": {
            "ContentType": "text",
            "ContentEncryptionAlgorithmIdentifier": "rsaEncryption",
            "dencryptedContent":  decodetext,
            "OPTIONAL": {}
        }
    }
    with open(filename, 'w') as file:
        json.dump(decrypted_message, file, indent=4)


print("RSA Implementation")
print("1. Generate Keys")
print("2. Encrypt Message")
print("3. Decrypt Message")
choice = input("Enter your choice: ")

if choice == "1":
    bits = int(input("Enter key size (1024): "))
    public_key, private_key = generate_keys(bits)

    save_public_key(public_key[0], public_key[1], "public_key.json")
    save_private_key(private_key[0], private_key[1], private_key[2], "private_key.json")
    print("Keys generated and saved.")

elif choice == "2":
    with open("public_key.json", 'r') as file:
        public_key = json.load(file)

    n = public_key["SubjectPublicKeyInfo"]["N"]
    e = public_key["SubjectPublicKeyInfo"]["publicExponent"]

    message = input("Enter the message to encrypt: ")
    ciphertext = encrypt(message, n, e)

    save_encrypted_message(ciphertext, "encrypted_message.json")
    print("Message encrypted and saved.")

elif choice == "3":
    with open("private_key.json", 'r') as file:
        private_key = json.load(file)
    n = private_key["prime1"] * private_key["prime2"]
    d = private_key["privateExponent"]

    ciphertext = load_encrypted_message("encrypted_message.json")
    plaintext = decrypt(ciphertext, n, d)
    print("Decrypted message:", plaintext)
    save_decrypted_message(plaintext, "decrypted_message.json")
    print("Message was decoded")
else:
    print("Invalid choice.")
