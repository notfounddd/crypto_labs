base64/base32
import json

def string_to_bits(string):
    return ''.join(format(ord(char), '08b') for char in string)

def bits_to_string(binary_message):
    del_length = len(binary_message) % 8
    if del_length > 0:
        binary_message = binary_message[:-del_length]
    chars = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    ascii_message = ''.join(chr(int(char, 2)) for char in chars)
    return ascii_message

def output_on_file(message, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(message)

def input_from_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return f.read().strip()

def load_encoding_table(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return json.load(file)

def encode_any_base(message, code):
    bit_message = string_to_bits(message)
    
    if code == 32:
        alp = load_encoding_table('base32_alp.json')
        padding = (5 - (len(bit_message) % 5)) % 5
        bit_message += '0' * padding
        chunks = [bit_message[i:i+5] for i in range(0, len(bit_message), 5)]
        res = [alp[chunk] for chunk in chunks]
        
        while len(res) % 8 != 0:
            res.append('=')
        
    elif code == 64:
        alp = load_encoding_table('base64_alp.json')
        padding = (6 - (len(bit_message) % 6)) % 6
        bit_message += '0' * padding
        chunks = [bit_message[i:i+6] for i in range(0, len(bit_message), 6)]
        res = [alp[chunk] for chunk in chunks]
        
        while len(res) % 4 != 0:
            res.append('=')
    else:
        print(f"Incorrect coding type: base{code}")
        return None
        
    return ''.join(res)

def decode_any_base(encoded_text, code):
    if code == 32:
        alp = load_encoding_table('base32_alp.json')
        inverse_alp = {v: k for k, v in alp.items()}
        encoded_text = encoded_text.rstrip('=')
        bit_message = ''.join(inverse_alp[char] for char in encoded_text)
    
    elif code == 64:
        alp = load_encoding_table('base64_alp.json')
        inverse_alp = {v: k for k, v in alp.items()}
        encoded_text = encoded_text.rstrip('=')
        bit_message = ''.join(inverse_alp[char] for char in encoded_text)
    
    else:
        print(f"Incorrect coding type: base{code}")
        return None
    
    return bits_to_string(bit_message)

print("Select an action:")
print("1. Encrypt a message")
print("2. Decrypt a message")
choice1 = input("Enter the action number: ")

if choice1 == '1':
    print("Select encoding method:")
    print("1. Base64")
    print("2. Base32")
    choice2 = input("Enter the method number: ")
    encoding_type = 64 if choice2 == '1' else 32 if choice2 == '2' else None
    
    if encoding_type:
        print("Select input method:")
        print("1. Keyboard")
        print("2. File")
        input_choice = input("Enter the method number: ")
        
        if input_choice == '1':
            message = input("Enter the message: ")
        elif input_choice == '2':
            filename = input("Enter input file name: ")
            message = input_from_file(filename)
        else:
            print("Invalid input choice.")
            exit()
        
        encoded_message = encode_any_base(message, encoding_type)
        output_filename = input("Enter output file name: ")
        output_on_file(encoded_message, output_filename)
        print(f"Encoded message saved to {output_filename}")
    else:
        print("Invalid encoding method.")

elif choice1 == '2':  
    print("Select decoding method:")
    print("1. Base64")
    print("2. Base32")
    choice2 = input("Enter the method number: ")
    encoding_type = 64 if choice2 == '1' else 32 if choice2 == '2' else None
    
    if encoding_type:
        filename = input("Enter input file name: ")
        encoded_message = input_from_file(filename)
        decoded_message = decode_any_base(encoded_message, encoding_type)
        output_filename = input("Enter output file name: ")
        output_on_file(decoded_message, output_filename)
        print(f"Decoded message saved to {output_filename}")
    else:
        print("Invalid decoding method.")
else:
    print("Invalid choice.")
