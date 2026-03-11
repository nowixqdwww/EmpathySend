from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import os
import logging
import shutil
import asyncpg
import urllib.parse
from datetime import datetime
from pydantic import BaseModel
import uvicorn
import hashlib
import base64

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

# Подключение к PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/messenger")

async def get_db():
    conn = await asyncpg.connect(DATABASE_URL)
    return conn

# Функция для создания безопасного имени файла
def create_safe_filename(phone: str, extension: str) -> str:
    phone_hash = hashlib.md5(phone.encode()).hexdigest()[:16]
    return f"avatar_{phone_hash}{extension}"

# Простая функция хеширования пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Инициализация базы данных
async def init_db():
    conn = await get_db()
    try:
        # Таблица пользователей с полем password
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                phone TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                name TEXT,
                bio TEXT,
                avatar TEXT,
                password TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица настроек конфиденциальности
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS privacy_settings (
                phone TEXT PRIMARY KEY,
                phone_privacy TEXT DEFAULT 'everyone',
                online_privacy TEXT DEFAULT 'everyone',
                avatar_privacy TEXT DEFAULT 'everyone',
                FOREIGN KEY (phone) REFERENCES users(phone) ON DELETE CASCADE
            )
        ''')
        
        # Таблица сообщений
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                text TEXT NOT NULL,
                is_deleted INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
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

class UsernameUpdate(BaseModel):
    phone: str
    username: str
    name: str = ""
    bio: str = ""

class SearchUser(BaseModel):
    username: str

class DeleteMessage(BaseModel):
    message_id: int
    user: str

@app.get("/health")
async def health_check():
    return {"status": "healthy", "connections": len(clients)}

@app.get("/user/{phone}")
async def get_user(phone: str):
    try:
        conn = await get_db()
        user = await conn.fetchrow(
            "SELECT phone, username, name, bio, avatar FROM users WHERE phone = $1",
            phone
        )
        await conn.close()
        
        if user:
            avatar_url = f"/avatars/{user['avatar']}" if user['avatar'] else ""
            return {
                "phone": user['phone'],
                "username": user['username'],
                "name": user['name'],
                "bio": user['bio'] or "",
                "avatar": avatar_url
            }
        return {"phone": phone, "username": None, "name": None, "bio": "", "avatar": ""}
    except Exception as e:
        logger.error(f"Error getting user {phone}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/username")
async def change_username(data: UsernameUpdate):
    try:
        conn = await get_db()
        
        existing = await conn.fetchrow(
            "SELECT phone FROM users WHERE username = $1 AND phone != $2",
            data.username, data.phone
        )
        if existing:
            await conn.close()
            return {"error": "Этот username уже занят"}
        
        if not data.username.startswith("@"):
            await conn.close()
            return {"error": "Username должен начинаться с @"}
        
        name = data.name if data.name else data.username[1:]
        bio = data.bio if data.bio else ""
        
        await conn.execute('''
            INSERT INTO users (phone, username, name, bio, avatar)
            VALUES ($1, $2, $3, $4, '')
            ON CONFLICT (phone) DO UPDATE
            SET username = $2, name = $3, bio = $4
        ''', data.phone, data.username, name, bio)
        
        await conn.close()
        
        logger.info(f"Profile updated: {data.phone}")
        return {"ok": True, "username": data.username, "name": name, "bio": bio}
        
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/set-password")
async def set_password(data: dict):
    try:
        phone = data.get("phone")
        password = data.get("password")
        
        # Декодируем base64
        decoded = base64.b64decode(password).decode()
        hashed = hash_password(decoded)
        
        conn = await get_db()
        
        await conn.execute('''
            UPDATE users SET password = $1 WHERE phone = $2
        ''', hashed, phone)
        
        await conn.close()
        
        logger.info(f"Password set for {phone}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error setting password: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/verify-password")
async def verify_password(data: dict):
    try:
        phone = data.get("phone")
        password = data.get("password")
        
        decoded = base64.b64decode(password).decode()
        hashed = hash_password(decoded)
        
        conn = await get_db()
        user = await conn.fetchrow(
            "SELECT password FROM users WHERE phone = $1",
            phone
        )
        await conn.close()
        
        if user and user['password'] == hashed:
            return {"ok": True}
        else:
            return {"error": "Invalid password"}
            
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/change-password")
async def change_password(data: dict):
    try:
        phone = data.get("phone")
        current = data.get("currentPassword")
        new = data.get("newPassword")
        
        decoded_current = base64.b64decode(current).decode()
        decoded_new = base64.b64decode(new).decode()
        
        hashed_current = hash_password(decoded_current)
        hashed_new = hash_password(decoded_new)
        
        conn = await get_db()
        user = await conn.fetchrow(
            "SELECT password FROM users WHERE phone = $1",
            phone
        )
        
        if not user or user['password'] != hashed_current:
            await conn.close()
            return {"error": "Current password is incorrect"}
        
        await conn.execute('''
            UPDATE users SET password = $1 WHERE phone = $2
        ''', hashed_new, phone)
        
        await conn.close()
        
        logger.info(f"Password changed for {phone}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/upload-avatar/{phone}")
async def upload_avatar(phone: str, file: UploadFile = File(...)):
    try:
        if not file.content_type.startswith('image/'):
            return JSONResponse(status_code=400, content={"error": "File must be an image"})
        
        # Читаем файл для проверки размера
        content = await file.read()
        file_size = len(content)
        
        if file_size > 5 * 1024 * 1024:  # 5MB
            return JSONResponse(status_code=400, content={"error": "File too large (max 5MB)"})
        
        # Возвращаем указатель чтения в начало
        await file.seek(0)
        
        file_extension = os.path.splitext(file.filename)[1]
        filename = create_safe_filename(phone, file_extension)
        file_path = os.path.join(AVATAR_DIR, filename)
        
        logger.info(f"Saving avatar to: {file_path}")
        
        conn = await get_db()
        
        old = await conn.fetchrow("SELECT avatar FROM users WHERE phone = $1", phone)
        if old and old['avatar']:
            old_path = os.path.join(AVATAR_DIR, old['avatar'])
            if os.path.exists(old_path):
                os.remove(old_path)
                logger.info(f"Removed old avatar: {old_path}")
        
        # Сохраняем файл
        with open(file_path, "wb") as buffer:
            buffer.write(content)
        
        logger.info(f"Saved new avatar: {file_path}")
        
        await conn.execute(
            "UPDATE users SET avatar = $1 WHERE phone = $2",
            filename, phone
        )
        await conn.close()
        
        avatar_url = f"/avatars/{filename}"
        
        logger.info(f"Avatar uploaded for {phone}: {avatar_url}")
        return {"ok": True, "avatar": avatar_url}
        
    except Exception as e:
        logger.error(f"Error uploading avatar: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/remove-avatar/{phone}")
async def remove_avatar(phone: str):
    try:
        conn = await get_db()
        
        result = await conn.fetchrow("SELECT avatar FROM users WHERE phone = $1", phone)
        if result and result['avatar']:
            file_path = os.path.join(AVATAR_DIR, result['avatar'])
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Removed avatar file: {file_path}")
        
        await conn.execute(
            "UPDATE users SET avatar = '' WHERE phone = $1",
            phone
        )
        await conn.close()
        
        logger.info(f"Avatar removed for {phone}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error removing avatar: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/delete-message")
async def delete_message(data: DeleteMessage):
    try:
        conn = await get_db()
        
        message = await conn.fetchrow(
            "SELECT sender FROM messages WHERE id = $1",
            data.message_id
        )
        
        if not message:
            await conn.close()
            return {"error": "Message not found"}
        
        if message['sender'] != data.user:
            await conn.close()
            return {"error": "You can only delete your own messages"}
        
        await conn.execute(
            "UPDATE messages SET is_deleted = 1, text = 'Сообщение удалено' WHERE id = $1",
            data.message_id
        )
        await conn.close()
        
        logger.info(f"Message {data.message_id} deleted by {data.user}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error deleting message: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/delete-chat")
async def delete_chat(data: dict):
    try:
        user = data.get("user")
        chat_with = data.get("chat_with")
        
        if not user or not chat_with:
            return JSONResponse(status_code=400, content={"error": "Missing parameters"})
        
        conn = await get_db()
        
        await conn.execute('''
            DELETE FROM messages 
            WHERE (sender = $1 AND receiver = $2) 
               OR (sender = $2 AND receiver = $1)
        ''', user, chat_with)
        
        await conn.close()
        
        logger.info(f"Chat deleted between {user} and {chat_with}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error deleting chat: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/clear-chat")
async def clear_chat(data: dict):
    try:
        user = data.get("user")
        chat_with = data.get("chat_with")
        
        if not user or not chat_with:
            return JSONResponse(status_code=400, content={"error": "Missing parameters"})
        
        conn = await get_db()
        
        await conn.execute('''
            UPDATE messages 
            SET is_deleted = 1, text = 'Сообщение удалено'
            WHERE (sender = $1 AND receiver = $2) 
               OR (sender = $2 AND receiver = $1)
        ''', user, chat_with)
        
        await conn.close()
        
        logger.info(f"Chat cleared between {user} and {chat_with}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error clearing chat: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/clear-all-chats")
async def clear_all_chats(data: dict):
    try:
        user = data.get("user")
        
        if not user:
            return JSONResponse(status_code=400, content={"error": "Missing parameters"})
        
        conn = await get_db()
        
        await conn.execute('''
            DELETE FROM messages 
            WHERE sender = $1 OR receiver = $1
        ''', user)
        
        await conn.close()
        
        logger.info(f"All chats cleared for {user}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error clearing all chats: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/export-data/{phone}")
async def export_data(phone: str):
    try:
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT phone, username, name, bio, avatar FROM users WHERE phone = $1",
            phone
        )
        
        messages = await conn.fetch('''
            SELECT id, sender, receiver, text, timestamp 
            FROM messages 
            WHERE sender = $1 OR receiver = $1
            ORDER BY timestamp
        ''', phone)
        
        chats = await conn.fetch('''
            SELECT DISTINCT
                CASE WHEN sender = $1 THEN receiver ELSE sender END as contact
            FROM messages
            WHERE sender = $1 OR receiver = $1
        ''', phone)
        
        await conn.close()
        
        return {
            "user": dict(user) if user else None,
            "messages": [dict(m) for m in messages],
            "chats": [dict(c) for c in chats],
            "exported_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/privacy-settings/{phone}")
async def get_privacy_settings(phone: str):
    try:
        conn = await get_db()
        settings = await conn.fetchrow('''
            SELECT phone_privacy, online_privacy, avatar_privacy 
            FROM privacy_settings 
            WHERE phone = $1
        ''', phone)
        await conn.close()
        
        if settings:
            return {
                "phone_privacy": settings['phone_privacy'],
                "online_privacy": settings['online_privacy'],
                "avatar_privacy": settings['avatar_privacy']
            }
        else:
            # Создаем настройки по умолчанию
            conn = await get_db()
            await conn.execute('''
                INSERT INTO privacy_settings (phone, phone_privacy, online_privacy, avatar_privacy)
                VALUES ($1, 'everyone', 'everyone', 'everyone')
                ON CONFLICT (phone) DO NOTHING
            ''', phone)
            await conn.close()
            
            return {
                "phone_privacy": "everyone",
                "online_privacy": "everyone",
                "avatar_privacy": "everyone"
            }
            
    except Exception as e:
        logger.error(f"Error getting privacy settings: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/privacy-settings/{phone}")
async def save_privacy_settings(phone: str, settings: dict):
    try:
        conn = await get_db()
        await conn.execute('''
            INSERT INTO privacy_settings (phone, phone_privacy, online_privacy, avatar_privacy)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (phone) DO UPDATE
            SET phone_privacy = $2, online_privacy = $3, avatar_privacy = $4
        ''', phone, settings.get('phone_privacy', 'everyone'),
            settings.get('online_privacy', 'everyone'),
            settings.get('avatar_privacy', 'everyone'))
        await conn.close()
        
        logger.info(f"Privacy settings saved for {phone}")
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error saving privacy settings: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/search")
async def search_user(data: SearchUser):
    try:
        conn = await get_db()
        user = await conn.fetchrow('''
            SELECT u.phone, u.username, u.name, u.bio, u.avatar,
                   ps.phone_privacy
            FROM users u
            LEFT JOIN privacy_settings ps ON u.phone = ps.phone
            WHERE u.username = $1
        ''', data.username)
        await conn.close()
        
        if not user:
            return {"found": False}
        
        # Проверяем, нужно ли показывать номер
        show_phone = user['phone_privacy'] == 'everyone'
        
        avatar_url = f"/avatars/{user['avatar']}" if user['avatar'] else ""
        return {
            "found": True,
            "phone": user['phone'] if show_phone else "hidden",
            "realPhone": user['phone'],
            "username": user['username'],
            "name": user['name'],
            "bio": user['bio'] or "",
            "avatar": avatar_url,
            "phone_hidden": not show_phone
        }
    except Exception as e:
        logger.error(f"Error searching user {data.username}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/search-users/{query}")
async def search_users(query: str):
    try:
        if len(query) < 2:
            return {"users": []}
        
        conn = await get_db()
        
        # Ищем пользователей по username или имени
        users = await conn.fetch('''
            SELECT u.phone, u.username, u.name, u.avatar, 
                   ps.phone_privacy
            FROM users u
            LEFT JOIN privacy_settings ps ON u.phone = ps.phone
            WHERE u.username ILIKE $1 OR u.name ILIKE $1
            ORDER BY 
                CASE 
                    WHEN u.username ILIKE $2 THEN 1
                    WHEN u.username ILIKE $3 THEN 2
                    ELSE 3
                END,
                u.username
            LIMIT 10
        ''', f'%{query}%', f'{query}%', f'%{query}')
        
        await conn.close()
        
        result = []
        for user in users:
            # Проверяем, нужно ли показывать номер
            show_phone = user['phone_privacy'] == 'everyone'
            
            avatar_url = f"/avatars/{user['avatar']}" if user['avatar'] else ""
            result.append({
                "phone": user['phone'] if show_phone else "hidden",
                "realPhone": user['phone'],
                "username": user['username'],
                "name": user['name'],
                "avatar": avatar_url,
                "displayName": user['name'] or user['username'] or "Пользователь",
                "phone_hidden": not show_phone
            })
        
        return {"users": result}
        
    except Exception as e:
        logger.error(f"Error searching users: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/users/{me}")
async def get_users(me: str):
    try:
        conn = await get_db()
        
        contacts = await conn.fetch('''
            SELECT DISTINCT
                CASE WHEN sender = $1 THEN receiver ELSE sender END as contact
            FROM messages
            WHERE sender = $1 OR receiver = $1
        ''', me)
        
        result = []
        for contact in contacts:
            phone = contact['contact']
            
            user_data = await conn.fetchrow(
                "SELECT phone, username, name, bio, avatar FROM users WHERE phone = $1",
                phone
            )
            
            if not user_data:
                await conn.execute(
                    "INSERT INTO users (phone, avatar) VALUES ($1, '') ON CONFLICT DO NOTHING",
                    phone
                )
                user_data = {'phone': phone, 'username': None, 'name': None, 'bio': None, 'avatar': ''}
            
            last_msg = await conn.fetchrow('''
                SELECT text FROM messages 
                WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
                AND is_deleted = 0
                ORDER BY timestamp DESC LIMIT 1
            ''', me, phone)
            
            display_name = user_data['name'] or user_data['username'] or phone
            avatar_url = f"/avatars/{user_data['avatar']}" if user_data['avatar'] else ""
            
            result.append({
                "phone": user_data['phone'],
                "username": user_data['username'],
                "name": user_data['name'],
                "bio": user_data['bio'] or "",
                "displayName": display_name,
                "avatar": avatar_url,
                "online": phone in clients,
                "last": last_msg['text'] if last_msg else ""
            })
        
        await conn.close()
        return result
        
    except Exception as e:
        logger.error(f"Error getting users for {me}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.websocket("/ws/{user}")
async def websocket_endpoint(ws: WebSocket, user: str):
    await ws.accept()
    clients[user] = ws
    logger.info(f"User {user} connected. Total: {len(clients)}")
    
    try:
        conn = await get_db()
        await conn.execute(
            "INSERT INTO users (phone, avatar) VALUES ($1, '') ON CONFLICT DO NOTHING",
            user
        )
        await conn.close()
        
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
                    if not to or text is None:
                        continue

                    conn = await get_db()
                    message_id = await conn.fetchval('''
                        INSERT INTO messages (sender, receiver, text) 
                        VALUES ($1, $2, $3) RETURNING id
                    ''', user, to, text)
                    await conn.close()

                    if to in clients:
                        try:
                            await clients[to].send_json({
                                "action": "message",
                                "from": user,
                                "text": text,
                                "id": message_id
                            })
                        except:
                            clients.pop(to, None)
                    
                    await ws.send_json({
                        "action": "message_sent",
                        "to": to,
                        "text": text,
                        "id": message_id
                    })

                elif action == "delete":
                    message_id = data.get("message_id")
                    to = data.get("to")
                    
                    if message_id:
                        conn = await get_db()
                        await conn.execute(
                            "UPDATE messages SET is_deleted = 1, text = 'Сообщение удалено' WHERE id = $1 AND sender = $2",
                            message_id, user
                        )
                        await conn.close()
                        
                        if to and to in clients:
                            await clients[to].send_json({
                                "action": "message_deleted",
                                "message_id": message_id,
                                "from": user
                            })

                elif action == "history":
                    chat_user = data.get("user")
                    if chat_user:
                        conn = await get_db()
                        messages = await conn.fetch('''
                            SELECT id, sender, text FROM messages
                            WHERE ((sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1))
                            AND is_deleted = 0
                            ORDER BY timestamp
                        ''', user, chat_user)
                        await conn.close()
                        
                        await ws.send_json({
                            "action": "history", 
                            "messages": [[m['id'], m['sender'], m['text']] for m in messages]
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
                break
            except Exception as e:
                logger.error(f"Error: {e}")
                continue

    finally:
        clients.pop(user, None)
        logger.info(f"User {user} disconnected. Total: {len(clients)}")

# Обслуживание статических файлов
if os.path.exists("web"):
    app.mount("/", StaticFiles(directory="web", html=True), name="web")

@app.get("/")
async def root():
    return FileResponse("web/index.html")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=False
    )
