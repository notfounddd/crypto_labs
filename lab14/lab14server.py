import socket
import json
import os

DB_FILE = "database.json"
HOST = '127.0.0.1'
PORT = 9090

def load_database() -> list:
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                else:
                    print("[SERVER] База не является списком, создаётся новая.")
                    return []
            except json.JSONDecodeError:
                return []
    return []

def save_database(db: list):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(db, f, indent=4, ensure_ascii=False)

def handle_user_data(data: dict, db: list):
    user_id = data.get("id")
    i = data.get("i")
    hash_type = data.get("hash_type")
    hash_val = data.get("hash")

    if not user_id or i is None or not hash_type or not hash_val:
        print(f"[SERVER] Некорректные данные: {data}")
        return

    for user in db:
        if user.get("id") == user_id:
            user["i"] = i
            user["hash_type"] = hash_type
            user["hash"] = hash_val
            print(f"[SERVER] Обновлена запись пользователя {user_id} (алгоритм: {hash_type})")
            save_database(db)
            return

    db.append({
        "id": user_id,
        "i": i,
        "hash_type": hash_type,
        "hash": hash_val
    })
    print(f"[SERVER] Добавлен новый пользователь {user_id} (алгоритм: {hash_type})")
    save_database(db)

def main():
    db = load_database()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Сервер запущен на {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[SERVER] Подключение от {addr}")
                try:
                    data = conn.recv(4096)
                    if not data:
                        continue
                    msg = json.loads(data.decode('utf-8'))
                    handle_user_data(msg, db)
                except Exception as e:
                    print(f"[SERVER] Ошибка: {e}")

if __name__ == '__main__':
    main()