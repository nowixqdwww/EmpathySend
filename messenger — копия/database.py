import sqlite3

conn = sqlite3.connect("messenger.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
phone TEXT PRIMARY KEY,
username TEXT UNIQUE,
avatar TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS messages(
id INTEGER PRIMARY KEY AUTOINCREMENT,
sender TEXT,
receiver TEXT,
text TEXT,
timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()


def add_user(phone):
    cursor.execute(
        "INSERT OR IGNORE INTO users(phone,avatar) VALUES(?,?)",
        (phone, "")
    )
    conn.commit()


def get_chats(phone):
    conn = sqlite3.connect("messenger.db")
    cur = conn.cursor()

    cur.execute("""
    SELECT DISTINCT sender FROM messages WHERE receiver=?
    UNION
    SELECT DISTINCT receiver FROM messages WHERE sender=?
    """, (phone, phone))

    chats = [row[0] for row in cur.fetchall()]
    conn.close()
    return chats


def update_username(phone, username):
    # Проверяем, не занят ли username
    cursor.execute(
        "SELECT phone FROM users WHERE username=? AND phone!=?",
        (username, phone)
    )
    if cursor.fetchone():
        raise Exception("Username already taken")

    cursor.execute(
        "UPDATE users SET username=? WHERE phone=?",
        (username, phone)
    )
    conn.commit()


def find_user(username):
    cursor.execute(
        "SELECT phone, username, avatar FROM users WHERE username=?",
        (username,)
    )
    return cursor.fetchone()


def save_message(sender, receiver, text):
    cursor.execute(
        "INSERT INTO messages(sender, receiver, text) VALUES(?,?,?)",
        (sender, receiver, text)
    )
    conn.commit()


def get_chat(a, b):
    cursor.execute("""
    SELECT sender, text FROM messages
    WHERE (sender=? AND receiver=?)
    OR (sender=? AND receiver=?)
    ORDER BY timestamp
    """, (a, b, b, a))

    return cursor.fetchall()


def get_user_chats(user):
    cursor.execute("""
    SELECT DISTINCT
    CASE WHEN sender=? THEN receiver ELSE sender END
    FROM messages
    WHERE sender=? OR receiver=?
    """, (user, user, user))

    users = cursor.fetchall()
    result = []

    for u in users:
        phone = u[0]
        cursor.execute(
            "SELECT phone, username, avatar FROM users WHERE phone=?",
            (phone,)
        )
        user_data = cursor.fetchone()
        if user_data:
            result.append(user_data)
        else:
            # Если пользователя нет в БД, добавляем его
            add_user(phone)
            result.append((phone, None, ""))

    return result


def last_message(a, b):
    cursor.execute("""
    SELECT text FROM messages
    WHERE (sender=? AND receiver=?)
    OR (sender=? AND receiver=?)
    ORDER BY timestamp DESC LIMIT 1
    """, (a, b, b, a))

    r = cursor.fetchone()
    return r[0] if r else ""