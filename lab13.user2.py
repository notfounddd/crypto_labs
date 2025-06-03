from hash_func import *

IP = 'localhost'
PORT = 55555

def main():
    p = generate_prime(512)
    q = generate_prime(512)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = module_inverse(e, phi)

    print(f"Server RSA public key (n, e): ({n}, {e})")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((IP, PORT))
        s.listen(1)
        print(f"[B] Listening on {IP}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"[B] Connected by {addr}")

            conn.sendall(json.dumps({"n": n, "e": e}).encode())

            data = conn.recv(8192)
            msg = json.loads(data.decode())
            hash_z_recv = msg["hash"]
            id_a_open = str(msg["ID_A"])
            ciphertext = msg["cipher"]
            hash_func_name = msg["hash_func"]

            z_a_str = decrypt(ciphertext, n, d)
            z_a_dict = json.loads(z_a_str)
            z_dec, id_a_enc = z_a_dict["z"], z_a_dict["IdA"]

            print(f"[B] Decrypted z: {z_dec}, ID_A: {id_a_enc}")

            if id_a_open != id_a_enc:
                print("[B] ID mismatch! Reject.")
                conn.sendall(json.dumps({"error": "ID mismatch"}).encode())
            else:
                hash_func = {
                    "sha256": sha256,
                    "sha512": sha512,
                    "stribog256": streebog256,
                    "stribog512": streebog512
                }[hash_func_name]
                if hash_func(z_dec.encode()) == hash_z_recv:
                    print("[B] Hash verified. Sending z back.")
                    conn.sendall(json.dumps({"z": z_dec}).encode())
                else:
                    print("[B] Hash mismatch! Reject.")
                    conn.sendall(json.dumps({"error": "Hash mismatch"}).encode())

if __name__ == "__main__":
    main()