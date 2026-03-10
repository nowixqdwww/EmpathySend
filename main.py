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
    """Создает безопасное имя файла на основе хеша телефона"""
    # Используем MD5 хеш телефона для создания безопасного имени
    phone_hash = hashlib.md5(phone.encode()).hexdigest()[:16]
    return f"avatar_{phone_hash}{extension}"

# Функция для кодирования имени файла в URL
def encode_avatar_filename(filename):
    """Кодирует имя файла для безопасного использования в URL"""
    if not filename:
        return ""
    # Просто возвращаем имя файла без кодирования, так как оно уже безопасное
    return filename

# Инициализация базы данных
async def init_db():
    conn = await get_db()
    try:
        # Таблица пользователей
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                phone TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                name TEXT,
                bio TEXT,
                avatar TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        
        # Проверяем и добавляем недостающие колонки
        columns = await conn.fetch('''
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users'
        ''')
        
        column_names = [col['column_name'] for col in columns]
        
        if 'bio' not in column_names:
            await conn.execute('ALTER TABLE users ADD COLUMN bio TEXT')
            logger.info("Added bio column to users table")
        
        if 'avatar' not in column_names:
            await conn.execute('ALTER TABLE users ADD COLUMN avatar TEXT')
            logger.info("Added avatar column to users table")
        
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
            # Формируем URL аватара
            avatar_filename = user['avatar']
            avatar_url = ""
            if avatar_filename:
                # Проверяем, существует ли файл
                file_path = os.path.join(AVATAR_DIR, avatar_filename)
                if os.path.exists(file_path):
                    avatar_url = f"/avatars/{avatar_filename}"
                    logger.info(f"Avatar URL for {phone}: {avatar_url}")
                else:
                    logger.warning(f"Avatar file not found: {file_path}")
            
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
        
        # Проверка уникальности username
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
        
        # Вставляем или обновляем пользователя
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

@app.post("/upload-avatar/{phone}")
async def upload_avatar(phone: str, file: UploadFile = File(...)):
    try:
        if not file.content_type.startswith('image/'):
            return JSONResponse(status_code=400, content={"error": "File must be an image"})
        
        # Создаем безопасное имя файла на основе хеша
        file_extension = os.path.splitext(file.filename)[1]
        filename = create_safe_filename(phone, file_extension)
        file_path = os.path.join(AVATAR_DIR, filename)
        
        logger.info(f"Saving avatar to: {file_path}")
        
        # Удаляем старый аватар если есть
        conn = await get_db()
        
        # Получаем старый аватар
        old = await conn.fetchrow("SELECT avatar FROM users WHERE phone = $1", phone)
        if old and old['avatar']:
            old_path = os.path.join(AVATAR_DIR, old['avatar'])
            if os.path.exists(old_path):
                os.remove(old_path)
                logger.info(f"Removed old avatar: {old_path}")
        
        # Сохраняем новый файл
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        logger.info(f"Saved new avatar: {file_path}")
        
        # Обновляем запись в БД
        await conn.execute(
            "UPDATE users SET avatar = $1 WHERE phone = $2",
            filename, phone
        )
        await conn.close()
        
        # Возвращаем URL
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
        
        # Проверяем, что пользователь - автор сообщения
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
        
        # Помечаем сообщение как удаленное
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

@app.get("/last-message/{user1}/{user2}")
async def get_last_message(user1: str, user2: str):
    try:
        conn = await get_db()
        last_msg = await conn.fetchrow('''
            SELECT text FROM messages 
            WHERE ((sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1))
            AND is_deleted = 0
            ORDER BY timestamp DESC LIMIT 1
        ''', user1, user2)
        await conn.close()
        
        return {"last": last_msg['text'] if last_msg else ""}
        
    except Exception as e:
        logger.error(f"Error getting last message: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/delete-chat")
async def delete_chat(data: dict):
    try:
        user = data.get("user")
        chat_with = data.get("chat_with")
        
        if not user or not chat_with:
            return JSONResponse(status_code=400, content={"error": "Missing parameters"})
        
        conn = await get_db()
        
        # Удаляем все сообщения между пользователями
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
        
        # Помечаем сообщения как удаленные (мягкое удаление)
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
        
        # Формируем URL аватара
        avatar_filename = user['avatar']
        avatar_url = ""
        if avatar_filename:
            file_path = os.path.join(AVATAR_DIR, avatar_filename)
            if os.path.exists(file_path):
                avatar_url = f"/avatars/{avatar_filename}"
        
        return {
            "found": True,
            "phone": user['phone'],
            "username": user['username'],
            "name": user['name'],
            "bio": user['bio'] or "",
            "avatar": avatar_url
        }
    except Exception as e:
        logger.error(f"Error searching user {data.username}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/users/{me}")
async def get_users(me: str):
    try:
        conn = await get_db()
        
        # Находим всех собеседников
        contacts = await conn.fetch('''
            SELECT DISTINCT
                CASE WHEN sender = $1 THEN receiver ELSE sender END as contact
            FROM messages
            WHERE sender = $1 OR receiver = $1
        ''', me)
        
        result = []
        for contact in contacts:
            phone = contact['contact']
            
            # Получаем информацию о пользователе
            user_data = await conn.fetchrow(
                "SELECT phone, username, name, bio, avatar FROM users WHERE phone = $1",
                phone
            )
            
            if not user_data:
                # Создаем запись если нет
                await conn.execute(
                    "INSERT INTO users (phone, avatar) VALUES ($1, '') ON CONFLICT DO NOTHING",
                    phone
                )
                user_data = {'phone': phone, 'username': None, 'name': None, 'bio': None, 'avatar': ''}
            
            # Последнее сообщение
            last_msg = await conn.fetchrow('''
                SELECT text FROM messages 
                WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
                AND is_deleted = 0
                ORDER BY timestamp DESC LIMIT 1
            ''', me, phone)
            
            display_name = user_data['name'] or user_data['username'] or phone
            
            # Формируем URL аватара
            avatar_filename = user_data['avatar']
            avatar_url = ""
            if avatar_filename:
                file_path = os.path.join(AVATAR_DIR, avatar_filename)
                if os.path.exists(file_path):
                    avatar_url = f"/avatars/{avatar_filename}"
            
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

@app.get("/check-avatar/{filename:path}")
async def check_avatar(filename: str):
    """Проверяет существование файла аватара (для отладки)"""
    try:
        file_path = os.path.join(AVATAR_DIR, filename)
        exists = os.path.exists(file_path)
        
        # Список всех файлов в папке
        all_files = []
        if os.path.exists(AVATAR_DIR):
            all_files = os.listdir(AVATAR_DIR)
        
        return {
            "filename": filename,
            "exists": exists,
            "path": file_path,
            "all_files": all_files[:10]  # Первые 10 файлов
        }
    except Exception as e:
        return {"error": str(e)}

@app.websocket("/ws/{user}")
async def websocket_endpoint(ws: WebSocket, user: str):
    await ws.accept()
    clients[user] = ws
    logger.info(f"User {user} connected. Total: {len(clients)}")
    
    try:
        # Добавляем пользователя в БД
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

                    # Отправляем получателю, если онлайн
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
                    
                    # Отправляем confirmation отправителю
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
                                "message_id": message_id
                            })

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


