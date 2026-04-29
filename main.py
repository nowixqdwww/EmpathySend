from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile, Request
import re as _re
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
from typing import List, Optional
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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AVATAR_DIR = os.path.join(BASE_DIR, "avatars")
STICKER_DIR = os.path.join(BASE_DIR, "stickers")
STATIC_DIR = os.path.join(BASE_DIR, "web", "static")

# Создаём директории безопасно
for _d in [AVATAR_DIR, STICKER_DIR, STATIC_DIR]:
    try: os.makedirs(_d, exist_ok=True)
    except Exception: pass

# Монтируем папки
app.mount("/avatars", StaticFiles(directory=AVATAR_DIR), name="avatars")
# sticker files now served via /sticker-data/{id} from DB
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Подключение к PostgreSQL
_raw_db_url = os.getenv("DATABASE_URL", "postgresql://localhost/messenger")
DATABASE_URL = _raw_db_url.replace("postgres://", "postgresql://", 1)

# ═══ Вставьте сюда токен вашего Telegram-бота ═══════════════════════════
# Получить: https://t.me/BotFather → /newbot → скопировать токен
TG_BOT_TOKEN = "ВСТАВЬТЕ_ТОКЕН_СЮДА"
# ════════════════════════════════════════════════════════════════════════

async def get_db():
    # SSL для облачных БД (Railway, Render, Heroku, Neon)
    ssl_hosts = ["railway.app", "render.com", "heroku", "amazonaws", "neon.tech", "supabase"]
    use_ssl = any(h in DATABASE_URL for h in ssl_hosts)
    try:
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            conn = await asyncpg.connect(DATABASE_URL, ssl=ctx)
        else:
            conn = await asyncpg.connect(DATABASE_URL)
        return conn
    except Exception as e:
        logger.error(f"DB connection failed: {e}")
        raise

# Функция для создания безопасного имени файла
def get_avatar_url(avatar: str) -> str:
    """Возвращает правильный URL аватарки — data URI или /avatars/filename"""
    if not avatar:
        return None
    if avatar.startswith('data:') or avatar.startswith('http'):
        return avatar
    return f"/avatars/{avatar}"

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
        
        # Проверяем и добавляем колонки если нужно
        for col, typ in [('password', 'TEXT'), ('last_seen', 'TIMESTAMP')]:
            exists = await conn.fetchval(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = '{col}'
                )
            """)
            if not exists:
                await conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
                logger.info(f"Added {col} column to users table")
        
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
                sticker_data BYTEA,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_phone) REFERENCES users(phone) ON DELETE CASCADE
            )
        """)
        # Добавляем sticker_data если не существует
        col_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns
                WHERE table_name = 'stickers' AND column_name = 'sticker_data'
            )
        """)
        if not col_exists:
            await conn.execute("ALTER TABLE stickers ADD COLUMN sticker_data BYTEA")
            logger.info("Added sticker_data column")

        # Мигрируем старые data:URI стикеры в BYTEA
        import base64 as _b64m
        old_uris = await conn.fetch(
            "SELECT id, sticker_url FROM stickers WHERE sticker_url LIKE 'data:%' AND sticker_data IS NULL LIMIT 500"
        )
        migrated = 0
        for row in old_uris:
            try:
                header, b64data = row['sticker_url'].split(',', 1)
                raw = _b64m.b64decode(b64data)
                new_id = row['id']
                await conn.execute(
                    "UPDATE stickers SET sticker_data = $1, sticker_url = $2 WHERE id = $3",
                    raw, f"/api/sticker-data/{new_id}", new_id
                )
                migrated += 1
            except Exception:
                pass
        if migrated:
            logger.info(f"Migrated {migrated} data:URI stickers to BYTEA")

        # Таблица голосовых сообщений
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS voice_messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                data BYTEA,
                voice_data BYTEA,
                duration INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Миграция: добавляем колонку data если её нет
        data_col = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns
                WHERE table_name = 'voice_messages' AND column_name = 'data'
            )
        """)
        if not data_col:
            await conn.execute("ALTER TABLE voice_messages ADD COLUMN data BYTEA")
            logger.info("Added data column to voice_messages")

        # Убираем NOT NULL с voice_data чтобы не было конфликтов
        try:
            await conn.execute("ALTER TABLE voice_messages ALTER COLUMN voice_data DROP NOT NULL")
        except Exception:
            pass

        # Таблица видео сообщений
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS video_messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                video_data BYTEA NOT NULL,
                duration INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Таблица настроек темы
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS theme_settings (
                phone TEXT PRIMARY KEY,
                theme_data JSONB NOT NULL DEFAULT '{}',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (phone) REFERENCES users(phone) ON DELETE CASCADE
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
    import asyncio
    # Создаём нужные директории
    for _d in [AVATAR_DIR, STICKER_DIR]:
        try: os.makedirs(_d, exist_ok=True)
        except Exception: pass
    # Запускаем init_db в фоне — сервер стартует немедленно даже если БД недоступна
    async def safe_init():
        try:
            await init_db()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database init failed: {e}")
    asyncio.create_task(safe_init())

clients = {}

# ============= МОДЕЛИ =============

class UserRegister(BaseModel):
    phone: str
    password: str
    username: Optional[str] = None
    name: Optional[str] = None

class UserLogin(BaseModel):
    phone: str
    password: str

class SetPassword(BaseModel):
    phone: str
    password: str

class UpdateProfile(BaseModel):
    username: Optional[str] = None
    name: Optional[str] = None
    bio: Optional[str] = None

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
            "avatar": get_avatar_url(user['avatar'])
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
        # Сохраняем как data URI прямо в БД — не зависит от диска
        import base64 as _b64
        mime = file.content_type or 'image/jpeg'
        data_uri = f"data:{mime};base64,{_b64.b64encode(content).decode()}"
        conn = await get_db()
        await conn.execute("UPDATE users SET avatar = $1 WHERE phone = $2", data_uri, phone)
        await conn.close()
        return {"avatar": data_uri}
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
        
        if avatar and not avatar.startswith('data:'):
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

@app.post("/api/upload-stickers/{phone}")
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

@app.get("/api/stickers/{phone}")
async def get_stickers(phone: str):
    try:
        # Декодируем телефон (может прийти как %2B16... или +16...)
        import urllib.parse as _up
        phone = _up.unquote(phone)
        
        conn = await get_db()
        stickers = await conn.fetch("""
            SELECT id, sticker_url, sticker_data IS NOT NULL as has_data
            FROM stickers WHERE user_phone = $1 ORDER BY created_at DESC
        """, phone)
        await conn.close()
        
        result = []
        for s in stickers:
            url = s['sticker_url']
            sid = s['id']
            has_data = s['has_data']
            if url.startswith('data:') or url.startswith('/api/sticker-data/') or has_data:
                result.append({"id": sid, "url": f"/api/sticker-data/{sid}"})
            elif url.startswith('https://api.telegram.org/'):
                # Прямая TG ссылка — истекает, пропускаем (нужно переимпортировать)
                pass
            elif not url.startswith('/stickers/'):
                result.append({"id": sid, "url": url})
            # /stickers/... без данных — пропускаем (файл не существует на Render)
        return {"stickers": result}
        
    except Exception as e:
        logger.error(f"Error getting stickers: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ИМПОРТ СТИКЕРОВ ИЗ TELEGRAM =============

import urllib.request
import urllib.parse
import json as _json
import time as _time
import asyncio
import urllib.error
import traceback as _traceback

def _tg_get(url: str) -> dict:
    """Синхронный GET к Telegram API через urllib (без внешних зависимостей)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return _json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return _json.loads(body)
        except Exception:
            return {"ok": False, "description": f"HTTP {e.code}: {body[:200]}"}
    except Exception as e:
        return {"ok": False, "description": str(e)}

# Алиасы для нового эндпоинта
_tg_request = _tg_get

def _tg_download(url: str) -> bytes:
    """Скачивает файл по URL."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()

# Алиас
_tg_download_file = _tg_download

@app.delete("/api/stickers-broken/{phone}")
async def delete_broken_stickers(phone: str):
    """Удаляем стикеры с битыми путями (файлов нет на диске и нет BYTEA)."""
    try:
        conn = await get_db()
        result = await conn.execute("""
            DELETE FROM stickers 
            WHERE user_phone = $1 
            AND sticker_url LIKE '/stickers/%'
            AND sticker_data IS NULL
        """, phone)
        deleted = int(result.split()[-1])
        await conn.close()
        logger.info(f"Deleted {deleted} broken stickers for {phone}")
        return {"ok": True, "deleted": deleted}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/api/stickers/{phone}/{sticker_id}")
async def delete_sticker(phone: str, sticker_id: int):
    try:
        conn = await get_db()
        row = await conn.fetchrow("SELECT user_phone, sticker_url FROM stickers WHERE id = $1", sticker_id)
        if not row or row['user_phone'] != phone:
            await conn.close()
            return JSONResponse(status_code=403, content={"error": "Not authorized"})
        await conn.execute("DELETE FROM stickers WHERE id = $1", sticker_id)
        await conn.close()
        # Удаляем файл если он на диске
        url = row['sticker_url']
        if url.startswith('/stickers/'):
            fpath = os.path.join(STICKER_DIR, os.path.basename(url))
            if os.path.exists(fpath):
                os.remove(fpath)
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/api/stickers-clear/{phone}")
async def clear_all_stickers(phone: str):
    """Удалить все стикеры пользователя (для сброса битых записей)."""
    try:
        conn = await get_db()
        deleted = await conn.fetchval(
            "DELETE FROM stickers WHERE user_phone = $1 RETURNING COUNT(*)", phone
        )
        await conn.close()
        return {"ok": True, "deleted": deleted}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/import-sticker-pack/{phone:path}")
async def import_sticker_pack(phone: str, request: Request):
    """Импорт стикер-пака из Telegram по ссылке или имени пака."""
    step = "init"
    try:
        step = "parse_body"
        body = await request.json()
        pack_input = body.get("url", "").strip()
        logger.info(f"TG import: phone={phone} input={pack_input!r}")

        if not pack_input:
            return JSONResponse(status_code=400, content={"error": "Укажите ссылку или название пака"})

        token = TG_BOT_TOKEN.strip()  # убираем случайные пробелы/переносы
        if not token or token == "ВСТАВЬТЕ_ТОКЕН_СЮДА":
            return JSONResponse(status_code=400, content={
                "error": "Токен бота не настроен. Вставьте токен в переменную TG_BOT_TOKEN в main.py"
            })
        if ":" not in token:
            return JSONResponse(status_code=400, content={
                "error": f"Неверный формат токена. Токен должен содержать ':'. Получено: {token[:20]}..."
            })
        logger.info(f"TG token len={len(token)} starts={token[:8]}")

        step = "parse_pack_name"
        import re as _re2
        # Берём всё после /addstickers/ до конца строки или знака вопроса
        match = _re2.search(r't\.me/addstickers/([A-Za-z0-9_]+)', pack_input, _re2.IGNORECASE)
        if match:
            pack_name = match.group(1)
        else:
            # Введено просто имя пака без ссылки
            pack_name = pack_input.strip().lstrip('@').rstrip('/')
            # Убираем лишнее если вдруг вставили что-то вроде "addstickers/PackName"
            if 'addstickers/' in pack_name:
                pack_name = pack_name.split('addstickers/')[-1]
        logger.info(f"TG import: pack_name={pack_name!r}")

        tg_api  = f"https://api.telegram.org/bot{token}"
        tg_file = f"https://api.telegram.org/file/bot{token}"
        loop    = asyncio.get_running_loop()

        step = "get_sticker_set"
        qs        = urllib.parse.urlencode({"name": pack_name})
        tg_url    = f"{tg_api}/getStickerSet?{qs}"
        pack_data = await loop.run_in_executor(None, _tg_request, tg_url)
        logger.info(f"TG getStickerSet ok={pack_data.get('ok')} desc={pack_data.get('description','')}")

        if not pack_data.get("ok"):
            desc = pack_data.get("description", "Пак не найден")
            # Маскируем токен в URL для безопасности
            safe_url = tg_url.replace(token, token[:8] + "***")
            return JSONResponse(status_code=404, content={
                "error": f"Telegram: {desc}",
                "pack_name_used": pack_name,
                "tg_url": safe_url
            })

        stickers   = pack_data["result"]["stickers"]
        pack_title = pack_data["result"]["title"]
        logger.info(f"TG import: pack={pack_title!r} stickers={len(stickers)}")
        saved = 0

        step = "get_db"
        conn = await get_db()
        try:
            step = "check_existing"
            existing = await conn.fetchval("SELECT COUNT(*) FROM stickers WHERE user_phone = $1", phone)
            can_add  = max(0, 2000 - int(existing))
            stickers = stickers[:can_add]
            logger.info(f"TG import: existing={existing} can_add={can_add}")

            first_error = None
            for i, sticker in enumerate(stickers):
                # Пропускаем анимированные (.tgs) и видео-стикеры — браузер их не покажет
                if sticker.get("is_animated") or sticker.get("is_video"):
                    logger.info(f"TG sticker {i}: skip animated/video")
                    continue

                step = f"sticker_{i}_getfile"
                file_id = sticker["file_id"]
                qs2     = urllib.parse.urlencode({"file_id": file_id})
                fdata   = await loop.run_in_executor(None, _tg_request, f"{tg_api}/getFile?{qs2}")
                if not fdata.get("ok"):
                    err = fdata.get("description", "unknown")
                    logger.warning(f"TG getFile failed sticker {i}: {err}")
                    if first_error is None:
                        first_error = err
                    continue

                file_path = fdata["result"]["file_path"]
                dl_url    = f"{tg_file}/{file_path}"

                # Скачиваем файл и сохраняем как base64 data URI в БД
                # (файловая система Render эфемерна — после деплоя файлы теряются)
                step = f"sticker_{i}_download"
                content = await loop.run_in_executor(None, _tg_download_file, dl_url)
                if not content:
                    continue

                step = f"sticker_{i}_save"
                # Сохраняем бинарные данные в БД, url = /sticker-data/{id}
                ext = ".webp" if file_path.endswith(".webp") else ".png"
                row = await conn.fetchrow(
                    """INSERT INTO stickers (user_phone, sticker_url, sticker_data)
                       VALUES ($1, $2, $3) RETURNING id""",
                    phone, f"pending", bytes(content)
                )
                await conn.execute(
                    "UPDATE stickers SET sticker_url = $1 WHERE id = $2",
                    f"/api/sticker-data/{row['id']}", row['id']
                )
                saved += 1
                logger.info(f"TG saved sticker {i}")

        finally:
            await conn.close()

        logger.info(f"TG import done: saved={saved} first_error={first_error}")
        if saved == 0 and first_error:
            return JSONResponse(status_code=500, content={"error": f"Не удалось скачать стикеры: {first_error}"})
        return {"ok": True, "title": pack_title, "total": len(stickers), "added": saved}

    except Exception as e:
        tb = _traceback.format_exc()
        logger.error(f"TG import ERROR at step={step}: {e}\n{tb}")
        return JSONResponse(status_code=500, content={"error": str(e), "step": step})

# ============= ГОЛОСОВЫЕ СООБЩЕНИЯ =============

# old voice endpoints removed

# ============= ПОИСК =============

@app.get("/api/sticker-data/{sticker_id}")
async def get_sticker_data(sticker_id: int):
    """Отдаём файл стикера из БД (для Render где диск эфемерный)."""
    try:
        conn = await get_db()
        row = await conn.fetchrow(
            "SELECT sticker_data, sticker_url FROM stickers WHERE id = $1", sticker_id
        )
        await conn.close()
        if not row:
            return JSONResponse(status_code=404, content={"error": "Not found"})
        if row['sticker_data']:
            from fastapi.responses import Response
            data_bytes = bytes(row['sticker_data'])
            # Определяем тип по magic bytes
            mime = "image/webp" if data_bytes[:4] == b'RIFF' else "image/png"
            return Response(
                content=data_bytes,
                media_type=mime,
                headers={"Cache-Control": "public, max-age=86400"}
            )
        else:
            # Старый стикер — редиректим на файл
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url=row['sticker_url'])
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ГОЛОСОВЫЕ СООБЩЕНИЯ =============

@app.post("/api/voice/upload")
async def upload_voice(request: Request):
    """Загружаем голосовое сообщение, возвращаем id."""
    try:
        body = await request.body()
        sender = request.headers.get("X-Sender", "")
        duration = int(request.headers.get("X-Duration", "0"))
        content_type = request.headers.get("Content-Type", "audio/webm")
        if not body or not sender:
            return JSONResponse(status_code=400, content={"error": "No data"})
        logger.info(f"Voice upload: sender={sender} size={len(body)} type={content_type} duration={duration}s")

        conn = await get_db()
        try:
            row = await conn.fetchrow("""
                INSERT INTO voice_messages (sender, voice_data, duration)
                VALUES ($1, $2, $3) RETURNING id
            """, sender, bytes(body), duration)
        finally:
            await conn.close()

        return {"ok": True, "voice_id": row["id"], "url": f"/voice/{row['id']}"}
    except Exception as e:
        logger.error(f"voice upload error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/voice/{voice_id}")
async def get_voice(voice_id: int):
    """Отдаём аудио файл по id."""
    try:
        conn = await get_db()
        row = await conn.fetchrow("SELECT voice_data, data FROM voice_messages WHERE id = $1", voice_id)
        await conn.close()
        if not row:
            logger.error(f"Voice {voice_id}: not found in DB")
            return JSONResponse(status_code=404, content={"error": "Not found"})
        raw = row["voice_data"] or row.get("data")
        if not raw:
            logger.error(f"Voice {voice_id}: found in DB but data is NULL")
            return JSONResponse(status_code=404, content={"error": "No audio data"})
        data = bytes(raw)
        logger.info(f"Voice {voice_id}: serving {len(data)} bytes, first4={data[:4].hex()}")
        # Определяем MIME по magic bytes
        if data[:4] == b'OggS':
            mime = "audio/ogg"
        elif data[:4] == b'RIFF':
            mime = "audio/wav"
        elif len(data) > 8 and data[4:8] in (b'ftyp', b'mdat', b'moov', b'free'):
            mime = "audio/mp4"
        elif data[:3] == b'ID3':
            mime = "audio/mpeg"
        else:
            mime = "audio/webm"
        logger.info(f"Voice {voice_id}: mime={mime}")
        from fastapi.responses import Response
        return Response(
            content=data,
            media_type=mime,
            headers={
                "Cache-Control": "public, max-age=86400",
                "Accept-Ranges": "bytes",
                "Content-Length": str(len(data)),
            }
        )
    except Exception as e:
        logger.error(f"Voice {voice_id} error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ВИДЕО СООБЩЕНИЯ =============

@app.post("/api/video/upload")
async def upload_video(request: Request):
    try:
        body = await request.body()
        sender = request.headers.get("X-Sender", "")
        duration = int(request.headers.get("X-Duration", "0"))
        if not body or not sender:
            return JSONResponse(status_code=400, content={"error": "No data"})
        if len(body) > 50 * 1024 * 1024:
            return JSONResponse(status_code=400, content={"error": "Файл слишком большой (макс 50MB)"})

        conn = await get_db()
        try:
            row = await conn.fetchrow("""
                INSERT INTO video_messages (sender, video_data, duration)
                VALUES ($1, $2, $3) RETURNING id
            """, sender, bytes(body), duration)
        finally:
            await conn.close()

        logger.info(f"Video upload: sender={sender} size={len(body)} duration={duration}s id={row['id']}")
        return {"ok": True, "video_id": row["id"]}
    except Exception as e:
        import traceback
        logger.error(f"video upload error: {e}\n{traceback.format_exc()}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/video/{video_id}")
async def get_video(video_id: int):
    try:
        conn = await get_db()
        row = await conn.fetchrow("SELECT video_data, duration FROM video_messages WHERE id = $1", video_id)
        await conn.close()
        if not row or not row["video_data"]:
            return JSONResponse(status_code=404, content={"error": "Not found"})
        data = bytes(row["video_data"])
        # Определяем MIME
        if len(data) > 8 and data[4:8] in (b'ftyp', b'mdat', b'moov'):
            mime = "video/mp4"
        else:
            mime = "video/webm"
        from fastapi.responses import Response
        return Response(
            content=data,
            media_type=mime,
            headers={"Cache-Control": "public, max-age=86400", "Accept-Ranges": "bytes", "Content-Length": str(len(data))}
        )
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ТЕМЫ =============

@app.get("/api/theme/{phone}")
async def get_theme(phone: str):
    try:
        conn = await get_db()
        row = await conn.fetchrow("SELECT theme_data FROM theme_settings WHERE phone = $1", phone)
        await conn.close()
        return {"theme": dict(row["theme_data"]) if row else {}}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/theme/{phone}")
async def save_theme(phone: str, request: Request):
    try:
        data = await request.json()
        import json as _json2
        conn = await get_db()
        await conn.execute("""
            INSERT INTO theme_settings (phone, theme_data, updated_at)
            VALUES ($1, $2::jsonb, NOW())
            ON CONFLICT (phone) DO UPDATE
            SET theme_data = $2::jsonb, updated_at = NOW()
        """, phone, _json2.dumps(data))
        await conn.close()
        return {"ok": True}
    except Exception as e:
        logger.error(f"save_theme error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============= DEEZER МУЗЫКА (без API key) =============

def _deezer_track_fmt(t: dict) -> dict:
    """Нормализуем трек Deezer в единый формат."""
    return {
        "id": str(t.get("id", "")),
        "name": t.get("title", ""),
        "artist_name": t.get("artist", {}).get("name", ""),
        "image": t.get("album", {}).get("cover_medium", ""),
        "audio": t.get("preview", ""),   # 30-сек MP3, бесплатно
        "shareurl": t.get("link", ""),
        "duration": t.get("duration", 0),
    }

@app.get("/api/jamendo/search")
async def deezer_search(q: str = "", limit: int = 25, offset: int = 0):
    """Поиск треков через Deezer API (не требует ключа)."""
    try:
        import urllib.request, urllib.parse, json as _j
        params = urllib.parse.urlencode({"q": q, "limit": limit, "index": offset, "output": "json"})
        url = f"https://api.deezer.com/search?{params}"
        req = urllib.request.Request(url, headers={"User-Agent": "NonBlock/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = _j.loads(r.read())
        tracks = [_deezer_track_fmt(t) for t in data.get("data", []) if t.get("preview")]
        return {"ok": True, "tracks": tracks, "total": data.get("total", 0)}
    except Exception as e:
        logger.error(f"Deezer search error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/jamendo/trending")
async def deezer_trending(limit: int = 25):
    """Топ треки Deezer (chart)."""
    try:
        import urllib.request, json as _j
        url = f"https://api.deezer.com/chart/0/tracks?limit={limit}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "NonBlock/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = _j.loads(r.read())
        tracks = [_deezer_track_fmt(t) for t in data.get("data", []) if t.get("preview")]
        return {"ok": True, "tracks": tracks}
    except Exception as e:
        logger.error(f"Deezer trending error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/music-status/{phone}")
async def set_music_status(phone: str, request: Request):
    """Установить статус 'слушает' для пользователя."""
    try:
        data = await request.json()
        conn = await get_db()
        await conn.execute("""
            INSERT INTO music_status (phone, track_id, track_name, artist_name, cover_url, preview_url, jamendo_url, is_playing, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
            ON CONFLICT (phone) DO UPDATE SET
                track_id=$2, track_name=$3, artist_name=$4, cover_url=$5,
                preview_url=$6, jamendo_url=$7, is_playing=$8, updated_at=NOW()
        """, phone,
            data.get("track_id",""), data.get("track_name",""),
            data.get("artist_name",""), data.get("cover_url",""),
            data.get("preview_url",""), data.get("jamendo_url",""),
            data.get("is_playing", False))
        await conn.close()

        # Уведомляем подписчиков через WS
        for uid, ws in list(clients.items()):
            try:
                import json as _j2
                await ws.send_text(_j2.dumps({
                    "action": "music_status",
                    "phone": phone,
                    **data
                }))
            except Exception:
                pass
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/music-status/{phone}")
async def get_music_status(phone: str):
    """Получить музыкальный статус пользователя."""
    try:
        conn = await get_db()
        row = await conn.fetchrow("SELECT * FROM music_status WHERE phone=$1", phone)
        await conn.close()
        if not row:
            return {"status": None}
        return {"status": dict(row)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/online-status")
async def online_status(request: Request):
    """Возвращает онлайн-статус для списка телефонов."""
    try:
        data = await request.json()
        phones = data.get("phones", [])
        return {p: (p in clients) for p in phones}
    except Exception as e:
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
        
        return {
            "found": True,
            "phone": user['phone'],
            "username": user['username'],
            "name": user['name'],
            "bio": user['bio'] or "",
            "avatar": get_avatar_url(user['avatar'])
        }
        
    except Exception as e:
        logger.error(f"Error searching user: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/search-users/{query}")
async def search_users(query: str, request: Request):
    try:
        if len(query) < 2:
            return {"users": []}
        
        conn = await get_db()
        
        # me берём из query params
        me = request.query_params.get("me", "")
        users = await conn.fetch("""
            SELECT phone, username, name, avatar 
            FROM users 
            WHERE (username ILIKE $1 OR name ILIKE $1)
            AND phone != $4
            ORDER BY 
                CASE 
                    WHEN username ILIKE $2 THEN 1
                    WHEN username ILIKE $3 THEN 2
                    ELSE 3
                END
            LIMIT 10
        """, f'%{query}%', f'{query}%', f'%{query}', me)
        
        await conn.close()
        
        result = []
        for user in users:
            result.append({
                "phone": user['phone'],
                "username": user['username'],
                "name": user['name'],
                "avatar": get_avatar_url(user['avatar']),
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
                "SELECT phone, username, name, avatar FROM users WHERE phone = $1", phone
            )
            if not user_data:
                continue
            last_msg = await conn.fetchrow("""
                SELECT text, timestamp FROM messages
                WHERE ((sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1))
                AND is_deleted = 0
                ORDER BY timestamp DESC LIMIT 1
            """, me, phone)
            unread = await conn.fetchval("""
                SELECT COUNT(*) FROM messages
                WHERE sender = $1 AND receiver = $2 AND is_read = 0 AND is_deleted = 0
            """, phone, me)
            display_name = user_data['name'] or user_data['username'] or phone
            result.append({
                "phone": user_data['phone'],
                "username": user_data['username'],
                "name": user_data['name'],
                "displayName": display_name,
                "avatar": get_avatar_url(user_data['avatar']),
                "online": phone in clients,
                "last": last_msg['text'] if last_msg else None,
                "last_ts": last_msg['timestamp'].isoformat() if last_msg and last_msg['timestamp'] else None,
                "unread": unread or 0
            })
        result.sort(key=lambda x: x['last_ts'] or '', reverse=True)
        
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

    # Уведомляем всех онлайн что этот юзер появился
    for uid, ws2 in list(clients.items()):
        if uid != user:
            try:
                await ws2.send_json({"action": "status", "from": user, "online": True})
                # И сообщаем новому юзеру кто онлайн
                await ws.send_json({"action": "status", "from": uid, "online": True})
            except Exception:
                pass

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

                elif action == "delivered":
                    msg_id = data.get("id")
                    to = data.get("to")
                    if msg_id and to and to in clients:
                        try:
                            await clients[to].send_json({"action": "delivered", "id": msg_id})
                        except:
                            clients.pop(to, None)

                elif action == "read":
                    # Помечаем сообщения прочитанными и уведомляем отправителя
                    from_user = data.get("from")  # от кого пришли сообщения
                    if from_user:
                        conn = await get_db()
                        updated = await conn.fetch("""
                            UPDATE messages SET is_read = 1
                            WHERE sender = $1 AND receiver = $2 AND is_read = 0
                            RETURNING id
                        """, from_user, user)
                        await conn.close()
                        ids = [r['id'] for r in updated]
                        if ids and from_user in clients:
                            try:
                                await clients[from_user].send_json({
                                    "action": "messages_read",
                                    "ids": ids
                                })
                            except:
                                clients.pop(from_user, None)

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

                # ── WebRTC сигналинг ──────────────────────────
                elif action in ("call_offer", "call_answer", "call_ice", "call_reject", "call_end", "call_busy"):
                    to = data.get("to")
                    if to and to in clients:
                        try:
                            payload = {k: v for k, v in data.items()}
                            payload["from"] = user
                            await clients[to].send_json(payload)
                        except:
                            clients.pop(to, None)
                    # Если вызываемый не онлайн
                    elif action == "call_offer" and to not in clients:
                        await ws.send_json({"action": "call_end", "from": to, "reason": "offline"})

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
                        conn2 = await get_db()
                        messages = await conn2.fetch("""
                            SELECT id, sender, text, is_read FROM messages
                            WHERE ((sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1))
                            AND is_deleted = 0
                            ORDER BY timestamp
                        """, user, chat_user)
                        await ws.send_json({
                            "action": "history",
                            "messages": [[m['id'], m['sender'], m['text'], m['is_read']] for m in messages]
                        })
                        # Помечаем входящие как прочитанные и уведомляем отправителя
                        updated = await conn2.fetch("""
                            UPDATE messages SET is_read = 1
                            WHERE sender = $2 AND receiver = $1 AND is_read = 0
                            RETURNING id
                        """, user, chat_user)
                        await conn2.close()
                        read_ids = [r['id'] for r in updated]
                        if read_ids and chat_user in clients:
                            try:
                                await clients[chat_user].send_json({
                                    "action": "messages_read",
                                    "ids": read_ids
                                })
                            except:
                                clients.pop(chat_user, None)

            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                continue

    finally:
        clients.pop(user, None)
        logger.info(f"User {user} disconnected. Total: {len(clients)}")
        # Уведомляем всех онлайн что юзер ушёл
        for uid, ws2 in list(clients.items()):
            try:
                await ws2.send_json({"action": "status", "from": user, "online": False})
            except Exception:
                pass
        # Сохраняем last_seen
        try:
            conn = await get_db()
            await conn.execute("UPDATE users SET last_seen = NOW() WHERE phone = $1", user)
            await conn.close()
            # Рассылаем last_seen всем онлайн-контактам
            import datetime
            now_iso = datetime.datetime.utcnow().isoformat() + 'Z'
            for uid, ws2 in list(clients.items()):
                try:
                    await ws2.send_json({
                        "action": "last_seen",
                        "from": user,
                        "last_seen": now_iso,
                        "online": False
                    })
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Error saving last_seen: {e}")

# ============= HEALTH + СТАТИЧЕСКИЕ ФАЙЛЫ =============

@app.get("/health")
async def health():
    return {"status": "healthy", "connections": len(clients)}

@app.get("/ping")
async def ping():
    return "pong"

# Статика — монтируем если папка web существует
# Используем HTMLResponse чтобы index.html отдавался по /
import pathlib
_web_dir = pathlib.Path("web")
if _web_dir.exists() and _web_dir.is_dir():
    # Явные роуты для основных файлов — они не перехватываются StaticFiles
    @app.get("/app.js")
    async def serve_js():
        return FileResponse("web/app.js", media_type="application/javascript")
    @app.get("/style.css")
    async def serve_css():
        return FileResponse("web/style.css", media_type="text/css")
    @app.get("/")
    async def serve_index():
        return FileResponse("web/index.html")
    # Монтируем статику для остальных файлов
    app.mount("/", StaticFiles(directory="web", html=True), name="web")
else:
    @app.get("/")
    async def root():
        return {"status": "ok", "message": "NonBlock Messenger API"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=False
    )
