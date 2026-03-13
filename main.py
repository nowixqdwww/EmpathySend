from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import os
import logging
import shutil
import asyncpg
import hashlib
import base64
from datetime import datetime
from typing import List
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

# Создаем папки для файлов
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AVATAR_DIR = os.path.join(BASE_DIR, "avatars")
STICKER_DIR = os.path.join(BASE_DIR, "stickers")
STATIC_DIR = os.path.join(BASE_DIR, "web", "static")

os.makedirs(AVATAR_DIR, exist_ok=True)
os.makedirs(STICKER_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# Монтируем папки
app.mount("/avatars", StaticFiles(directory=AVATAR_DIR), name="avatars")
app.mount("/stickers", StaticFiles(directory=STICKER_DIR), name="stickers")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Подключение к PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/messenger")

async def get_db():
    conn = await asyncpg.connect(DATABASE_URL)
    return conn

# Функция для создания безопасного имени файла
def create_safe_filename(phone: str, extension: str) -> str:
    phone_hash = hashlib.md5(phone.encode()).hexdigest()[:16]
    return f"avatar_{phone_hash}{extension}"

# Функция для хеширования пароля
def hash_password(password):
    salt = "nonblock_salt"
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Инициализация базы данных
async def init_db():
    conn = await get_db()
    try:
        # Таблица пользователей
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                phone TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                name TEXT,
                bio TEXT,
                avatar TEXT,
                password TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Проверяем и добавляем колонку password если нужно
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns 
                WHERE table_name = 'users' AND column_name = 'password'
            )
        """)
        if not column_exists:
            await conn.execute("ALTER TABLE users ADD COLUMN password TEXT")
            logger.info("Added password column to users table")
        
        # Таблица настроек конфиденциальности
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS privacy_settings (
                phone TEXT PRIMARY KEY,
                phone_privacy TEXT DEFAULT 'everyone',
                online_privacy TEXT DEFAULT 'everyone',
                avatar_privacy TEXT DEFAULT 'everyone',
                FOREIGN KEY (phone) REFERENCES users(phone) ON DELETE CASCADE
            )
        """)
        
        # Таблица сообщений
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                text TEXT NOT NULL,
                is_deleted INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Таблица стикеров
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS stickers (
                id SERIAL PRIMARY KEY,
                user_phone TEXT NOT NULL,
                sticker_url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_phone) REFERENCES users(phone) ON DELETE CASCADE
            )
        """)

            # Таблица реакций
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS reactions (
                id SERIAL PRIMARY KEY,
                message_id INTEGER NOT NULL,
                user_phone TEXT NOT NULL,
                reaction TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
                FOREIGN KEY (user_phone) REFERENCES users(phone) ON DELETE CASCADE,
                UNIQUE(message_id, user_phone, reaction)
            )
        """)
        
        logger.info("Reactions table created")
        
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
    finally:
        await conn.close()

# Запускаем инициализацию при старте
@app.on_event("startup")
async def startup():
    await init_db()

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

class SetPassword(BaseModel):
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
    try:
        conn = await get_db()
        
        existing = await conn.fetchval(
            "SELECT phone FROM users WHERE phone = $1",
            user.phone
        )
        if existing:
            await conn.close()
            return JSONResponse(status_code=400, content={"error": "Пользователь уже существует"})
        
        if user.username:
            existing_username = await conn.fetchval(
                "SELECT phone FROM users WHERE username = $1",
                user.username
            )
            if existing_username:
                await conn.close()
                return JSONResponse(status_code=400, content={"error": "Username уже занят"})
        
        hashed_password = hash_password(user.password)
        
        await conn.execute("""
            INSERT INTO users (phone, username, name, password) 
            VALUES ($1, $2, $3, $4)
        """, user.phone, user.username, user.name, hashed_password)
        
        await conn.execute("""
            INSERT INTO privacy_settings (phone) VALUES ($1)
        """, user.phone)
        
        await conn.close()
        
        logger.info(f"New user registered: {user.phone}")
        return {"ok": True, "phone": user.phone}
        
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/auth/login")
async def login(data: UserLogin):
    try:
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT phone, password FROM users WHERE phone = $1",
            data.phone
        )
        
        await conn.close()
        
        if not user:
            return JSONResponse(status_code=404, content={"error": "Пользователь не найден"})
        
        if user['password'] is None:
            return JSONResponse(status_code=401, content={"error": "NO_PASSWORD_SET"})
        
        if user['password'] != hash_password(data.password):
            return JSONResponse(status_code=401, content={"error": "Неверный пароль"})
        
        return {"ok": True, "phone": user['phone']}
        
    except Exception as e:
        logger.error(f"Error in /auth/login: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/set-password")
async def set_password(data: SetPassword):
    try:
        phone = data.phone
        password = data.password
        
        decoded = base64.b64decode(password).decode()
        hashed = hash_password(decoded)
        
        conn = await get_db()
        
        await conn.execute("""
            UPDATE users SET password = $1 WHERE phone = $2
        """, hashed, phone)
        
        await conn.close()
        
        logger.info(f"Password set for {phone}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error setting password: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/auth/change-password")
async def change_password(data: ChangePassword):
    try:
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT password FROM users WHERE phone = $1",
            data.phone
        )
        
        if not user:
            await conn.close()
            return JSONResponse(status_code=404, content={"error": "Пользователь не найден"})
        
        if user['password'] != hash_password(data.current_password):
            await conn.close()
            return JSONResponse(status_code=401, content={"error": "Неверный текущий пароль"})
        
        hashed = hash_password(data.new_password)
        await conn.execute(
            "UPDATE users SET password = $1 WHERE phone = $2",
            hashed, data.phone
        )
        
        await conn.close()
        
        logger.info(f"Password changed for user: {data.phone}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ЭНДПОИНТЫ ПОЛЬЗОВАТЕЛЕЙ =============

@app.get("/user/{phone}")
async def get_user(phone: str):
    try:
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT phone, username, name, bio, avatar FROM users WHERE phone = $1",
            phone
        )
        
        await conn.close()
        
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
    try:
        conn = await get_db()
        
        if data.username:
            existing = await conn.fetchval(
                "SELECT phone FROM users WHERE username = $1 AND phone != $2",
                data.username, phone
            )
            if existing:
                await conn.close()
                return JSONResponse(status_code=400, content={"error": "Username already taken"})
        
        updates = []
        values = []
        
        if data.username is not None:
            updates.append("username = $" + str(len(values) + 1))
            values.append(data.username)
        if data.name is not None:
            updates.append("name = $" + str(len(values) + 1))
            values.append(data.name)
        if data.bio is not None:
            updates.append("bio = $" + str(len(values) + 1))
            values.append(data.bio)
        
        if updates:
            query = f"UPDATE users SET {', '.join(updates)} WHERE phone = ${len(values) + 1}"
            values.append(phone)
            await conn.execute(query, *values)
        
        await conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/upload-avatar/{phone}")
async def upload_avatar(phone: str, file: UploadFile = File(...)):
    try:
        if not file.content_type.startswith('image/'):
            return JSONResponse(status_code=400, content={"error": "File must be an image"})
        
        content = await file.read()
        
        if len(content) > 5 * 1024 * 1024:
            return JSONResponse(status_code=400, content={"error": "File too large (max 5MB)"})
        
        file_extension = os.path.splitext(file.filename)[1]
        filename = create_safe_filename(phone, file_extension)
        file_path = os.path.join(AVATAR_DIR, filename)
        
        conn = await get_db()
        
        old = await conn.fetchval(
            "SELECT avatar FROM users WHERE phone = $1",
            phone
        )
        if old:
            old_path = os.path.join(AVATAR_DIR, old)
            if os.path.exists(old_path):
                os.remove(old_path)
        
        with open(file_path, "wb") as buffer:
            buffer.write(content)
        
        await conn.execute(
            "UPDATE users SET avatar = $1 WHERE phone = $2",
            filename, phone
        )
        await conn.close()
        
        return {"avatar": f"/avatars/{filename}"}
        
    except Exception as e:
        logger.error(f"Error uploading avatar: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/remove-avatar/{phone}")
async def remove_avatar(phone: str):
    try:
        conn = await get_db()
        
        avatar = await conn.fetchval(
            "SELECT avatar FROM users WHERE phone = $1",
            phone
        )
        
        if avatar:
            file_path = os.path.join(AVATAR_DIR, avatar)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        await conn.execute(
            "UPDATE users SET avatar = NULL WHERE phone = $1",
            phone
        )
        await conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error removing avatar: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= СТИКЕРЫ =============

@app.post("/upload-stickers/{phone}")
async def upload_stickers(phone: str, stickers: List[UploadFile] = File(...)):
    try:
        conn = await get_db()
        
        for sticker in stickers:
            if not sticker.content_type.startswith('image/'):
                continue
            
            content = await sticker.read()
            
            filename = f"sticker_{phone}_{datetime.now().timestamp()}.png"
            file_path = os.path.join(STICKER_DIR, filename)
            
            with open(file_path, "wb") as buffer:
                buffer.write(content)
            
            await conn.execute("""
                INSERT INTO stickers (user_phone, sticker_url)
                VALUES ($1, $2)
            """, phone, f"/stickers/{filename}")
        
        await conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error uploading stickers: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/stickers/{phone}")
async def get_stickers(phone: str):
    try:
        conn = await get_db()
        
        stickers = await conn.fetch("""
            SELECT sticker_url FROM stickers WHERE user_phone = $1
        """, phone)
        
        await conn.close()
        
        return {"stickers": [s['sticker_url'] for s in stickers]}
        
    except Exception as e:
        logger.error(f"Error getting stickers: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ПОИСК =============

@app.post("/search")
async def search_user(data: SearchUser):
    try:
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT phone, username, name, bio, avatar FROM users WHERE username = $1",
            data.username
        )
        
        await conn.close()
        
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
    try:
        if len(query) < 2:
            return {"users": []}
        
        conn = await get_db()
        
        users = await conn.fetch("""
            SELECT phone, username, name, avatar 
            FROM users 
            WHERE username ILIKE $1 OR name ILIKE $1
            ORDER BY 
                CASE 
                    WHEN username ILIKE $2 THEN 1
                    WHEN username ILIKE $3 THEN 2
                    ELSE 3
                END
            LIMIT 10
        """, f'%{query}%', f'{query}%', f'%{query}')
        
        await conn.close()
        
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
    try:
        conn = await get_db()
        
        contacts = await conn.fetch("""
            SELECT DISTINCT
                CASE WHEN sender = $1 THEN receiver ELSE sender END as contact
            FROM messages
            WHERE sender = $1 OR receiver = $1
        """, me)
        
        result = []
        for contact in contacts:
            phone = contact['contact']
            
            user_data = await conn.fetchrow(
                "SELECT phone, username, name, avatar FROM users WHERE phone = $1",
                phone
            )
            
            if not user_data:
                continue
            
            last_msg = await conn.fetchrow("""
                SELECT text FROM messages 
                WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
                AND is_deleted = 0
                ORDER BY timestamp DESC LIMIT 1
            """, me, phone)
            
            display_name = user_data['name'] or user_data['username'] or phone
            
            result.append({
                "phone": user_data['phone'],
                "username": user_data['username'],
                "name": user_data['name'],
                "displayName": display_name,
                "avatar": f"/avatars/{user_data['avatar']}" if user_data['avatar'] else None,
                "online": phone in clients,
                "last": last_msg['text'] if last_msg else None,
                "unread": 0
            })
        
        await conn.close()
        return result
        
    except Exception as e:
        logger.error(f"Error getting users for {me}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# Добавить реакцию
@app.post("/reaction/add")
async def add_reaction(data: dict):
    try:
        message_id = data.get("message_id")
        user = data.get("user")
        reaction = data.get("reaction")
        
        conn = await get_db()
        
        # Проверяем, есть ли уже такая реакция
        existing = await conn.fetchval("""
            SELECT id FROM reactions 
            WHERE message_id = $1 AND user_phone = $2 AND reaction = $3
        """, message_id, user, reaction)
        
        if existing:
            # Если есть - удаляем (toggle)
            await conn.execute("""
                DELETE FROM reactions 
                WHERE message_id = $1 AND user_phone = $2 AND reaction = $3
            """, message_id, user, reaction)
        else:
            # Если нет - добавляем
            await conn.execute("""
                INSERT INTO reactions (message_id, user_phone, reaction)
                VALUES ($1, $2, $3)
            """, message_id, user, reaction)
        
        await conn.close()
        
        # Получаем обновленные реакции для сообщения
        reactions = await get_message_reactions(message_id)
        
        return {"ok": True, "reactions": reactions}
        
    except Exception as e:
        logger.error(f"Error adding reaction: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# Получить реакции для сообщения
@app.get("/reactions/{message_id}")
async def get_reactions(message_id: int):
    try:
        reactions = await get_message_reactions(message_id)
        return {"reactions": reactions}
    except Exception as e:
        logger.error(f"Error getting reactions: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

async def get_message_reactions(message_id: int):
    conn = await get_db()
    rows = await conn.fetch("""
        SELECT reaction, COUNT(*) as count, 
               array_agg(user_phone) as users
        FROM reactions 
        WHERE message_id = $1
        GROUP BY reaction
    """, message_id)
    await conn.close()
    
    return [
        {
            "reaction": row['reaction'],
            "count": row['count'],
            "users": row['users']
        }
        for row in rows
    ]

@app.get("/messages/{user1}/{user2}")
async def get_messages(user1: str, user2: str):
    try:
        conn = await get_db()
        
        await conn.execute("""
            UPDATE messages SET is_read = 1 
            WHERE sender = $1 AND receiver = $2
        """, user2, user1)
        
        messages = await conn.fetch("""
            SELECT id, sender, text, timestamp FROM messages
            WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
            AND is_deleted = 0
            ORDER BY timestamp
        """, user1, user2)
        
        await conn.close()
        
        return [[m['id'], m['sender'], m['text']] for m in messages]
        
    except Exception as e:
        logger.error(f"Error getting messages: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/message/{message_id}")
async def delete_message(message_id: int, user: str):
    try:
        conn = await get_db()
        
        sender = await conn.fetchval(
            "SELECT sender FROM messages WHERE id = $1",
            message_id
        )
        
        if not sender:
            await conn.close()
            return JSONResponse(status_code=404, content={"error": "Message not found"})
        
        if sender != user:
            await conn.close()
            return JSONResponse(status_code=403, content={"error": "Not authorized"})
        
        await conn.execute(
            "UPDATE messages SET is_deleted = 1 WHERE id = $1",
            message_id
        )
        
        await conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error deleting message: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/chat/{user1}/{user2}")
async def delete_chat(user1: str, user2: str):
    try:
        conn = await get_db()
        
        await conn.execute("""
            DELETE FROM messages 
            WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
        """, user1, user2)
        
        await conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error deleting chat: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= НАСТРОЙКИ ПРИВАТНОСТИ =============

@app.get("/privacy-settings/{phone}")
async def get_privacy_settings(phone: str):
    try:
        conn = await get_db()
        
        settings = await conn.fetchrow(
            "SELECT phone_privacy, online_privacy, avatar_privacy FROM privacy_settings WHERE phone = $1",
            phone
        )
        
        await conn.close()
        
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
    try:
        conn = await get_db()
        
        await conn.execute("""
            INSERT INTO privacy_settings (phone, phone_privacy, online_privacy, avatar_privacy)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (phone) DO UPDATE
            SET phone_privacy = $2, online_privacy = $3, avatar_privacy = $4
        """, phone, settings.phone_privacy, settings.online_privacy, settings.avatar_privacy)
        
        await conn.close()
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error saving privacy settings: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= WEBSOCKET =============

@app.websocket("/ws/{user}")
async def websocket_endpoint(ws: WebSocket, user: str):
    await ws.accept()
    clients[user] = ws
    logger.info(f"User {user} connected. Total: {len(clients)}")
    
    try:
        while True:
            try:
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

                    conn = await get_db()
                    message_id = await conn.fetchval("""
                        INSERT INTO messages (sender, receiver, text) 
                        VALUES ($1, $2, $3) RETURNING id
                    """, user, to, text)
                    await conn.close()

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

                elif action == "history":
                    chat_user = data.get("user")
                    if chat_user:
                        conn = await get_db()
                        messages = await conn.fetch("""
                            SELECT id, sender, text FROM messages
                            WHERE ((sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1))
                            AND is_deleted = 0
                            ORDER BY timestamp
                        """, user, chat_user)
                        await conn.close()
                        
                        await ws.send_json({
                            "action": "history", 
                            "messages": [[m['id'], m['sender'], m['text']] for m in messages]
                        })

            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                continue

    finally:
        clients.pop(user, None)
        logger.info(f"User {user} disconnected. Total: {len(clients)}")

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
        reload=False
    )

