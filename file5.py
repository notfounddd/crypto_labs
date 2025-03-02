#rabin

from file1 import *
import json
import hashlib

def save_encrypted_message(ciphertext, filename):
    encrypted_message = {
        "Version": 0,
        "EncryptedContentInfo": {
            "ContentType": "text",
            "ContentEncryptionAlgorithmIdentifier": "rabinEncryption",
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

def save_decrypted_message(decoded_text, filename):
    decrypted_message = {
        "Version": 0,
        "EncryptedContentInfo": {
            "ContentType": "text",
            "ContentEncryptionAlgorithmIdentifier": "rabinEncryption",
            "decryptedContent": decoded_text, 
            "OPTIONAL": {}
        }
    }
    with open(filename, 'w') as file:
        json.dump(decrypted_message, file, indent=4)

def split_blocks(message, block_size):
    return [message[i:i + block_size] for i in range(0, len(message), block_size)]

def add_redundancy(block):
    block_bytes = bytes(block)
    hash_obj = hashlib.sha3_256(block_bytes)
    checksum = hash_obj.digest()[:8]
    block.extend(checksum)
    return block

def check_redundancy(block):
    if len(block) < 8:
        return False
    checksum = bytes(block[-8:])
    block_data = block[:-8]
    
    block_bytes = bytes(block_data)
    hash_obj = hashlib.sha3_256(block_bytes)
    computed_checksum = hash_obj.digest()[:8]
    
    return checksum == computed_checksum

def rabin_encrypt(message, n):
    block_size = (n.bit_length() - 1) // 8
    message_bytes = message.encode('utf-8')
    blocks = split_blocks(message_bytes, block_size)

    encrypted_blocks = []
    for block in blocks:
        block_with_redundancy = add_redundancy(list(block))
        block_num = int.from_bytes(block_with_redundancy, 'big')
        encrypted_block = fast_exp_mod(block_num, 2, n)
        encrypted_blocks.append(encrypted_block)

    return encrypted_blocks

def rabin_decrypt_block(chip, p, q):
    n = p * q
    mp = solve_congruence_quadro(chip, p)
    mq = solve_congruence_quadro(chip, q)
    if mp is None or mq is None:
        print(f"Ошибка при решении для c={chip} с p={p} и q={q}")
        return None
    _, yp, yq = euclidean_algorithm(p, q)
    r1 = (yp * p * mq[0] + yq * q * mp[0]) % n
    r2 = n - r1
    r3 = (yp * p * mq[0] - yq * q * mp[0]) % n
    r4 = n - r3
    return r1, r2, r3, r4

def decrypt_blocks(encrypted_blocks, p, q):
    decrypted_message = ""
    for block in encrypted_blocks:
        r1, r2, r3, r4 = rabin_decrypt_block(block, p, q)
        for r in [r1, r2, r3, r4]:
            try:
                block_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
                if check_redundancy(list(block_bytes)):
                    decrypted_message += block_bytes[:-8].decode('utf-8')
                    break
            except Exception as e:
                print(f"Error block incode: {e}")
                continue
    save_decrypted_message(decrypted_message, 'decode.json')
    return decrypted_message


print("Rabin Implementation:")
print("1. Generate Keys")
print("2. Encrypt Message")
print("3. Decrypt Message")
choice = input("Enter your choice: ")

if choice == '1':
    bit_length = int(input("Enter length: "))
    q = generate_prime(bit_length)
    p = generate_prime(bit_length)
    if p % 4 == 3 and q % 4 == 3:
        exit()
    n = p * q
        
    with open('params.json', 'w') as f:
        json.dump({"p": p, "q": q, "n": n}, f, indent=4)
        
    print("Params.json was created with parametrs")

elif choice == '2':
    with open('params.json', 'r') as f:
        params = json.load(f)
    n = params["n"]
        
    message = input("Enter the message to encrypt: ")
        
    c = rabin_encrypt(message, n)
    save_encrypted_message(c, 'ciphertext.json')
    print("Message encrypted and saved on ciphertext.json")

elif choice == '3':
    with open('params.json', 'r') as f:
        params = json.load(f)
    p = params["p"]
    q = params["q"]
       
    c = load_encrypted_message("ciphertext.json")
    possible_messages = decrypt_blocks(c, p, q)
