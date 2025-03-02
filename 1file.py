#base64  & base32
import json

def string_to_bits(string):
    return ''.join(format(ord(char), '08b') for char in string)

def bits_to_string(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

def encode_any_base(message, code):
    bit_message = string_to_bits(message)
    
    if code == 32:
        with open('base32_alp.json', 'r', encoding='utf-8') as file:
            alp = json.load(file)
        temp = (40 - (len(bit_message) % 40)) % 40
        bit_message += '0' * temp
        chunks = [bit_message[i:i+5] for i in range(0, len(bit_message), 5)]
        res = [alp[chunk] for chunk in chunks]
        padding_map = {3: '======', 1: '====', 4: '===', 2: '='}
        mod_value = (len(bit_message) - temp) % 5
        if mod_value in padding_map:
            res.append(padding_map[mod_value])
            
    elif code == 64:
        with open('base64_alp.json', 'r', encoding='utf-8') as file:
            alp = json.load(file)
        temp = (24 - (len(bit_message) % 24)) % 24
        bit_message += '0' * temp
        chunks = [bit_message[i:i+6] for i in range(0, len(bit_message), 6)]
        res = [alp[chunk] for chunk in chunks]
        if temp == 8:
            res.append('=')
        if temp == 16:
            res.append('==')
    else:
        print(f"Incorrect coding type: base{code}")
        return None
        
    return ''.join(res)

def decode_any_base(encoded_text, code, original_length=None):
    if code == 32:
        with open('base32_alp.json', 'r', encoding='utf-8') as file:
            alp = json.load(file)
        inverse_alp = {v: k for k, v in alp.items()}
        encoded_text = encoded_text.rstrip('=')
        bit_message = ''.join(inverse_alp[char] for char in encoded_text)
    
    elif code == 64:
        with open('base64_alp.json', 'r', encoding='utf-8') as file:
            alp = json.load(file)
        inverse_alp = {v: k for k, v in alp.items()}
        encoded_text = encoded_text.rstrip('=')
        bit_message = ''.join(inverse_alp[char] for char in encoded_text)
    
    else:
        print(f"Incorrect coding type: base{code}")
        return None
    
    decoded_string = bits_to_string(bit_message)
    
    if original_length is not None:
        decoded_string = decoded_string[:original_length]
    
    return decoded_string

def output_on_file(message, filename, original_length=None):
    data = {"message": message}
    if original_length is not None:
        data["length"] = original_length
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def input_from_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    return data.get("message", ""), data.get("length", None)

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
            message, _ = input_from_file(filename)
        else:
            print("Invalid input choice.")
            exit()
        
        original_length = len(message)
        encoded_message = encode_any_base(message, encoding_type)
        output_filename = input("Enter output file name: ")
        output_on_file(encoded_message, output_filename, original_length)
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
        encoded_message, original_length = input_from_file(filename)
        decoded_message = decode_any_base(encoded_message, encoding_type, original_length)
        output_filename = input("Enter output file name: ")
        output_on_file(decoded_message, output_filename)
        print(f"Decoded message saved to {output_filename}")
    else:
        print("Invalid decoding method.")
else:
    print("Invalid choice.")
