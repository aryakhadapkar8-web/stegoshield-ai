import pymysql
import pymysql.cursors
import os
from werkzeug.security import generate_password_hash, check_password_hash
from encryption import VaultCipher

def get_db_connection():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",              # XAMPP default is empty
        database="stegoshield",
        cursorclass=pymysql.cursors.DictCursor,
    )

def init_db():
    pass

def register_user(username: str, email: str, password: str) -> tuple[bool, str]:
    """Registers a new user with hashed password."""
    username = username.strip()
    email = email.strip().lower()

    if not username or not email or not password:
        return False, "All fields (username, email, password) are required."

    if len(password) < 6:
        return False, "Password must be at least 6 characters long."

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
    if cursor.fetchone():
        conn.close()
        return False, "Username or email address is already registered."

    hashed_pw = generate_password_hash(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, hashed_pw)
        )
        conn.commit()
        conn.close()
        return True, "Account registered successfully! You can now log in."
    except Exception as e:
        conn.close()
        return False, f"Database error during registration: {str(e)}"

def authenticate_user(username_or_email: str, password: str) -> tuple[dict | None, str]:
    """Authenticates user credentials."""
    login_id = username_or_email.strip().lower()
    if not login_id or not password:
        return None, "Please provide username/email and password."

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE LOWER(username) = %s OR LOWER(email) = %s",
        (login_id, login_id)
    )
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        user_dict = dict(user)
        user_dict.pop("password_hash", None)
        return user_dict, "Login successful."
    
    return None, "Invalid username/email or password."

def get_user_by_id(user_id: int) -> dict | None:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, created_at FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def log_operation(user_id: int, action_type: str, filename: str, output_filename: str = "", payload_size: int = 0, stego_score: float = 0.0, status: str = "Success"):
    """Logs an encode or decode operation to history."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO history (user_id, action_type, filename, output_filename, payload_size, stego_score, status)
           VALUES (%s, %s, %s, %s, %s, %s, %s)''',
        (user_id, action_type, filename, output_filename, payload_size, stego_score, status)
    )
    conn.commit()
    conn.close()

def delete_history_item(user_id: int, history_id: int) -> bool:
    """Deletes a specific history log entry owned by user_id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM history WHERE id = %s AND user_id = %s", (history_id, user_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def add_vault_item(user_id: int, title: str, note: str, secret_key: str) -> bool:
    """Saves an entry in user's encrypted secret vault."""
    ciphertext = VaultCipher.encrypt(secret_key)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO vault (user_id, title, note, secret_key) VALUES (%s, %s, %s, %s)",
        (user_id, title, note, ciphertext)
    )
    conn.commit()
    conn.close()
    return True

def get_user_vault(user_id: int) -> list[dict]:
    """Retrieves vault entries for user_id with decrypted keys."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, note, secret_key, timestamp FROM vault WHERE user_id = %s ORDER BY timestamp DESC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    items = []
    for row in rows:
        item = dict(row)
        item["secret_key"] = VaultCipher.decrypt(item["secret_key"])
        items.append(item)
    return items

def get_user_history(user_id: int, query: str | None = None, action_filter: str | None = None) -> list[dict]:
    """Returns activity history, optionally filtered by filename search and encode/decode."""
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = "SELECT * FROM history WHERE user_id = %s"
    params: list = [user_id]

    if query:
        like = f"%{query.strip()}%"
        sql += " AND (filename LIKE %s OR IFNULL(output_filename, '') LIKE %s)"
        params.extend([like, like])

    if action_filter == "Encode":
        sql += " AND action_type LIKE 'Encode%%'"
    elif action_filter == "Decode":
        sql += " AND action_type LIKE 'Decode%%'"

    sql += " ORDER BY timestamp DESC"
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def user_owns_output(user_id: int, filename: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM history WHERE user_id = %s AND output_filename = %s LIMIT 1",
        (user_id, filename),
    )
    found = cursor.fetchone() is not None
    conn.close()
    return found

def delete_vault_item(user_id: int, vault_id: int) -> bool:
    """Deletes a vault item owned by user_id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault WHERE id = %s AND user_id = %s", (vault_id, user_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def get_user_stats(user_id: int) -> dict:
    """Gets aggregate user metrics."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM history WHERE user_id = %s AND action_type LIKE 'Encode%%'", (user_id,))
    total_encodes = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM history WHERE user_id = %s AND action_type LIKE 'Decode%%'", (user_id,))
    total_decodes = cursor.fetchone()["cnt"]

    cursor.execute("SELECT SUM(payload_size) as total_bytes FROM history WHERE user_id = %s AND action_type = 'Encode'", (user_id,))
    total_bytes = cursor.fetchone()["total_bytes"] or 0

    cursor.execute("SELECT COUNT(*) as cnt FROM vault WHERE user_id = %s", (user_id,))
    total_vault_items = cursor.fetchone()["cnt"]

    conn.close()
    return {
        "total_encodes": total_encodes,
        "total_decodes": total_decodes,
        "total_bytes_hidden": total_bytes,
        "total_vault_items": total_vault_items
    }

init_db()
