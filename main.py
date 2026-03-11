from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import os
import logging
import shutil
import sqlite3
import hashlib
import secrets
from datetime import datetime
from pydantic import BaseModel
import uvicorn

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Создаем папку для аватарок
AVATAR_DIR = os.path.join(os.path.dirname(__file__), "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)

# Монтируем папку с аватарками
app.mount("/avatars", StaticFiles(directory=AVATAR_DIR), name="avatars")

# База данных
DB_PATH = os.path.join(os.path.dirname(__file__), "messenger.db")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Функция для хеширования пароля
def hash_password(password):
    """Хеширование пароля с солью"""
    salt = "nonblock_salt"  # В продакшене используйте уникальную соль
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Инициализация базы данных
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Таблица пользователей с полем password
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        phone TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        name TEXT,
        bio TEXT,
        avatar TEXT,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Таблица настроек конфиденциальности
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS privacy_settings (
        phone TEXT PRIMARY KEY,
        phone_privacy TEXT DEFAULT 'everyone',
        online_privacy TEXT DEFAULT 'everyone',
        avatar_privacy TEXT DEFAULT 'everyone'
    )
    """)
    
    # Таблица сообщений
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        text TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_deleted INTEGER DEFAULT 0,
        is_read INTEGER DEFAULT 0
    )
    """)
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

init_db()

# Хранилище активных WebSocket соединений
clients = {}

# ============= МОДЕЛИ =============

class UserRegister(BaseModel):
    phone: str
    password: str
    username: str = None
    name: str = None

class UserLogin(BaseModel):
    phone: str
    password: str

class UpdateProfile(BaseModel):
    username: str = None
    name: str = None
    bio: str = None

class ChangePassword(BaseModel):
    phone: str
    current_password: str
    new_password: str

class PrivacySettings(BaseModel):
    phone_privacy: str = "everyone"
    online_privacy: str = "everyone"
    avatar_privacy: str = "everyone"

class SearchUser(BaseModel):
    username: str

class DeleteMessage(BaseModel):
    message_id: int
    user: str

# ============= ЭНДПОИНТЫ АВТОРИЗАЦИИ =============

@app.post("/auth/register")
async def register(user: UserRegister):
    """Регистрация нового пользователя"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Проверяем, существует ли пользователь
        cursor.execute("SELECT phone FROM users WHERE phone = ?", (user.phone,))
        if cursor.fetchone():
            conn.close()
            return JSONResponse(status_code=400, content={"error": "Пользователь уже существует"})
        
        # Проверяем уникальность username
        if user.username:
            cursor.execute("SELECT phone FROM users WHERE username = ?", (user.username,))
            if cursor.fetchone():
                conn.close()
                return JSONResponse(status_code=400, content={"error": "Username уже занят"})
        
        # Хешируем пароль
        hashed_password = hash_password(user.password)
        
        # Создаем пользователя
        cursor.execute(
            "INSERT INTO users (phone, username, name, password) VALUES (?, ?, ?, ?)",
            (user.phone, user.username, user.name, hashed_password)
        )
        
        # Создаем настройки приватности
        cursor.execute(
            "INSERT INTO privacy_settings (phone) VALUES (?)",
            (user.phone,)
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"New user registered: {user.phone}")
        return {"ok": True, "phone": user.phone}
        
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/auth/login")
async def login(data: UserLogin):
    """Вход по номеру и паролю"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT phone, password FROM users WHERE phone = ?",
            (data.phone,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return JSONResponse(status_code=401, content={"error": "Неверный номер или пароль"})
        
        if user['password'] != hash_password(data.password):
            return JSONResponse(status_code=401, content={"error": "Неверный номер или пароль"})
        
        return {"ok": True, "phone": user['phone']}
        
    except Exception as e:
        logger.error(f"Error logging in: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/auth/change-password")
async def change_password(data: ChangePassword):
    """Смена пароля"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT password FROM users WHERE phone = ?",
            (data.phone,)
        )
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return JSONResponse(status_code=404, content={"error": "Пользователь не найден"})
        
        if user['password'] != hash_password(data.current_password):
            conn.close()
            return JSONResponse(status_code=401, content={"error": "Неверный текущий пароль"})
        
        hashed = hash_password(data.new_password)
        cursor.execute(
            "UPDATE users SET password = ? WHERE phone = ?",
            (hashed, data.phone)
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"Password changed for user: {data.phone}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/check-password/{phone}")
async def check_password(phone: str):
    """Проверка, установлен ли пароль у пользователя"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT password FROM users WHERE phone = ?",
            (phone,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return JSONResponse(status_code=404, content={"error": "User not found"})
        
        return {"hasPassword": user['password'] is not None}
        
    except Exception as e:
        logger.error(f"Error checking password: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ЭНДПОИНТЫ ПОЛЬЗОВАТЕЛЕЙ =============

@app.get("/user/{phone}")
async def get_user(phone: str):
    """Получение информации о пользователе"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT phone, username, name, bio, avatar FROM users WHERE phone = ?",
            (phone,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return JSONResponse(status_code=404, content={"error": "User not found"})
        
        return {
            "phone": user['phone'],
            "username": user['username'],
            "name": user['name'],
            "bio": user['bio'] or "",
            "avatar": f"/avatars/{user['avatar']}" if user['avatar'] else None
        }
        
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.put("/user/{phone}")
async def update_user(phone: str, data: UpdateProfile):
    """Обновление профиля пользователя"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Проверяем уникальность username
        if data.username:
            cursor.execute(
                "SELECT phone FROM users WHERE username = ? AND phone != ?",
                (data.username, phone)
            )
            if cursor.fetchone():
                conn.close()
                return JSONResponse(status_code=400, content={"error": "Username already taken"})
        
        # Обновляем поля
        updates = []
        values = []
        
        if data.username is not None:
            updates.append("username = ?")
            values.append(data.username)
        if data.name is not None:
            updates.append("name = ?")
            values.append(data.name)
        if data.bio is not None:
            updates.append("bio = ?")
            values.append(data.bio)
        
        if updates:
            query = f"UPDATE users SET {', '.join(updates)} WHERE phone = ?"
            values.append(phone)
            cursor.execute(query, values)
        
        conn.commit()
        conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/upload-avatar/{phone}")
async def upload_avatar(phone: str, file: UploadFile = File(...)):
    """Загрузка аватара"""
    try:
        if not file.content_type.startswith('image/'):
            return JSONResponse(status_code=400, content={"error": "File must be an image"})
        
        # Читаем файл
        content = await file.read()
        
        if len(content) > 5 * 1024 * 1024:  # 5MB
            return JSONResponse(status_code=400, content={"error": "File too large (max 5MB)"})
        
        # Создаем имя файла
        file_extension = os.path.splitext(file.filename)[1]
        filename = f"{phone}{file_extension}"
        file_path = os.path.join(AVATAR_DIR, filename)
        
        # Удаляем старый аватар
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT avatar FROM users WHERE phone = ?", (phone,))
        old = cursor.fetchone()
        if old and old['avatar']:
            old_path = os.path.join(AVATAR_DIR, old['avatar'])
            if os.path.exists(old_path):
                os.remove(old_path)
        
        # Сохраняем новый
        with open(file_path, "wb") as buffer:
            buffer.write(content)
        
        cursor.execute(
            "UPDATE users SET avatar = ? WHERE phone = ?",
            (filename, phone)
        )
        conn.commit()
        conn.close()
        
        return {"avatar": f"/avatars/{filename}"}
        
    except Exception as e:
        logger.error(f"Error uploading avatar: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/remove-avatar/{phone}")
async def remove_avatar(phone: str):
    """Удаление аватара"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT avatar FROM users WHERE phone = ?", (phone,))
        result = cursor.fetchone()
        
        if result and result['avatar']:
            file_path = os.path.join(AVATAR_DIR, result['avatar'])
            if os.path.exists(file_path):
                os.remove(file_path)
        
        cursor.execute(
            "UPDATE users SET avatar = NULL WHERE phone = ?",
            (phone,)
        )
        conn.commit()
        conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error removing avatar: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ПОИСК =============

@app.post("/search")
async def search_user(data: SearchUser):
    """Поиск пользователя по точному username"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT phone, username, name, bio, avatar FROM users WHERE username = ?",
            (data.username,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return {"found": False}
        
        return {
            "found": True,
            "phone": user['phone'],
            "username": user['username'],
            "name": user['name'],
            "bio": user['bio'] or "",
            "avatar": f"/avatars/{user['avatar']}" if user['avatar'] else None
        }
        
    except Exception as e:
        logger.error(f"Error searching user: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/search-users/{query}")
async def search_users(query: str):
    """Поиск пользователей по части username или имени"""
    try:
        if len(query) < 2:
            return {"users": []}
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT phone, username, name, avatar 
            FROM users 
            WHERE username LIKE ? OR name LIKE ?
            ORDER BY 
                CASE 
                    WHEN username LIKE ? THEN 1
                    WHEN username LIKE ? THEN 2
                    ELSE 3
                END
            LIMIT 10
        """, (f'%{query}%', f'%{query}%', f'{query}%', f'%{query}'))
        
        users = cursor.fetchall()
        conn.close()
        
        result = []
        for user in users:
            result.append({
                "phone": user['phone'],
                "username": user['username'],
                "name": user['name'],
                "avatar": f"/avatars/{user['avatar']}" if user['avatar'] else None,
                "displayName": user['name'] or user['username'] or user['phone']
            })
        
        return {"users": result}
        
    except Exception as e:
        logger.error(f"Error searching users: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ЧАТЫ И СООБЩЕНИЯ =============

@app.get("/users/{me}")
async def get_users(me: str):
    """Получение списка чатов пользователя"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Находим всех собеседников
        cursor.execute("""
            SELECT DISTINCT
                CASE WHEN sender = ? THEN receiver ELSE sender END as contact
            FROM messages
            WHERE sender = ? OR receiver = ?
        """, (me, me, me))
        
        contacts = cursor.fetchall()
        result = []
        
        for contact in contacts:
            phone = contact['contact']
            
            # Информация о собеседнике
            cursor.execute(
                "SELECT phone, username, name, avatar FROM users WHERE phone = ?",
                (phone,)
            )
            user_data = cursor.fetchone()
            
            if not user_data:
                continue
            
            # Последнее сообщение
            cursor.execute("""
                SELECT text FROM messages 
                WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                AND is_deleted = 0
                ORDER BY timestamp DESC LIMIT 1
            """, (me, phone, phone, me))
            last_msg = cursor.fetchone()
            
            # Количество непрочитанных
            cursor.execute("""
                SELECT COUNT(*) FROM messages
                WHERE sender = ? AND receiver = ? AND is_read = 0
            """, (phone, me))
            unread = cursor.fetchone()[0]
            
            display_name = user_data['name'] or user_data['username'] or phone
            
            result.append({
                "phone": user_data['phone'],
                "username": user_data['username'],
                "name": user_data['name'],
                "displayName": display_name,
                "avatar": f"/avatars/{user_data['avatar']}" if user_data['avatar'] else None,
                "online": phone in clients,
                "last": last_msg['text'] if last_msg else None,
                "unread": unread
            })
        
        conn.close()
        return result
        
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/messages/{user1}/{user2}")
async def get_messages(user1: str, user2: str):
    """Получение истории сообщений между двумя пользователями"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Отмечаем как прочитанные
        cursor.execute("""
            UPDATE messages SET is_read = 1 
            WHERE sender = ? AND receiver = ?
        """, (user2, user1))
        
        # Получаем сообщения
        cursor.execute("""
            SELECT id, sender, text, timestamp FROM messages
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            AND is_deleted = 0
            ORDER BY timestamp
        """, (user1, user2, user2, user1))
        
        messages = cursor.fetchall()
        conn.commit()
        conn.close()
        
        return [[m['id'], m['sender'], m['text']] for m in messages]
        
    except Exception as e:
        logger.error(f"Error getting messages: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/message/{message_id}")
async def delete_message(message_id: int, user: str):
    """Удаление сообщения"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Проверяем, что пользователь - автор
        cursor.execute(
            "SELECT sender FROM messages WHERE id = ?",
            (message_id,)
        )
        msg = cursor.fetchone()
        
        if not msg:
            conn.close()
            return JSONResponse(status_code=404, content={"error": "Message not found"})
        
        if msg['sender'] != user:
            conn.close()
            return JSONResponse(status_code=403, content={"error": "Not authorized"})
        
        cursor.execute(
            "UPDATE messages SET is_deleted = 1 WHERE id = ?",
            (message_id,)
        )
        conn.commit()
        conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error deleting message: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/chat/{user1}/{user2}")
async def delete_chat(user1: str, user2: str):
    """Удаление чата (всех сообщений между пользователями)"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM messages 
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        """, (user1, user2, user2, user1))
        
        conn.commit()
        conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error deleting chat: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= НАСТРОЙКИ ПРИВАТНОСТИ =============

@app.get("/privacy-settings/{phone}")
async def get_privacy_settings(phone: str):
    """Получение настроек приватности"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT phone_privacy, online_privacy, avatar_privacy FROM privacy_settings WHERE phone = ?",
            (phone,)
        )
        settings = cursor.fetchone()
        conn.close()
        
        if settings:
            return {
                "phone_privacy": settings['phone_privacy'],
                "online_privacy": settings['online_privacy'],
                "avatar_privacy": settings['avatar_privacy']
            }
        
        return {
            "phone_privacy": "everyone",
            "online_privacy": "everyone",
            "avatar_privacy": "everyone"
        }
        
    except Exception as e:
        logger.error(f"Error getting privacy settings: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/privacy-settings/{phone}")
async def save_privacy_settings(phone: str, settings: PrivacySettings):
    """Сохранение настроек приватности"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO privacy_settings (phone, phone_privacy, online_privacy, avatar_privacy)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(phone) DO UPDATE SET
                phone_privacy = excluded.phone_privacy,
                online_privacy = excluded.online_privacy,
                avatar_privacy = excluded.avatar_privacy
        """, (phone, settings.phone_privacy, settings.online_privacy, settings.avatar_privacy))
        
        conn.commit()
        conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error saving privacy settings: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= WEBSOCKET =============

@app.websocket("/ws/{user}")
async def websocket_endpoint(ws: WebSocket, user: str):
    """WebSocket для реального времени"""
    await ws.accept()
    clients[user] = ws
    logger.info(f"User {user} connected. Total: {len(clients)}")
    
    try:
        while True:
            data = await ws.receive_json()
            action = data.get("action")

            if action == "ping":
                await ws.send_json({"action": "pong"})
                continue

            if action == "send":
                to = data.get("to")
                text = data.get("text")
                
                if not to or not text:
                    continue

                # Сохраняем в БД
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO messages (sender, receiver, text) VALUES (?, ?, ?)",
                    (user, to, text)
                )
                message_id = cursor.lastrowid
                conn.commit()
                conn.close()

                # Отправляем получателю
                if to in clients:
                    try:
                        await clients[to].send_json({
                            "action": "message",
                            "id": message_id,
                            "from": user,
                            "text": text
                        })
                    except:
                        clients.pop(to, None)

                # Подтверждение отправителю
                await ws.send_json({
                    "action": "message_sent",
                    "id": message_id,
                    "to": to,
                    "text": text
                })

            elif action == "typing":
                to = data.get("to")
                if to and to in clients:
                    try:
                        await clients[to].send_json({
                            "action": "typing",
                            "from": user
                        })
                    except:
                        clients.pop(to, None)

            elif action == "status":
                to = data.get("to")
                online = data.get("online", True)
                
                if to and to in clients:
                    try:
                        await clients[to].send_json({
                            "action": "status",
                            "from": user,
                            "online": online
                        })
                    except:
                        clients.pop(to, None)

    except WebSocketDisconnect:
        clients.pop(user, None)
        logger.info(f"User {user} disconnected. Total: {len(clients)}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        clients.pop(user, None)

# ============= СТАТИЧЕСКИЕ ФАЙЛЫ =============

if os.path.exists("web"):
    app.mount("/", StaticFiles(directory="web", html=True), name="web")

@app.get("/")
async def root():
    return FileResponse("web/index.html")

@app.get("/health")
async def health():
    return {"status": "healthy", "connections": len(clients)}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True
    )

