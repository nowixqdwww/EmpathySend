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
import aiohttp
import asyncio
import secrets
import time
import bcrypt
import jwt as pyjwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AVATAR_DIR = os.path.join(BASE_DIR, "avatars")
STICKER_DIR = os.path.join(BASE_DIR, "stickers")
STATIC_DIR = os.path.join(BASE_DIR, "web", "static")
WALLPAPER_DIR = os.path.join(BASE_DIR, "wallpapers")
MEDIA_DIR = os.path.join(BASE_DIR, "media")

# Создаём директории безопасно
for _d in [AVATAR_DIR, STICKER_DIR, STATIC_DIR, WALLPAPER_DIR, MEDIA_DIR]:
    try: os.makedirs(_d, exist_ok=True)
    except Exception: pass

# Монтируем папки
# Ensure all dirs exist before mounting
for _mount_dir in [AVATAR_DIR, WALLPAPER_DIR, MEDIA_DIR, STATIC_DIR]:
    os.makedirs(_mount_dir, exist_ok=True)

app.mount("/avatars", StaticFiles(directory=AVATAR_DIR), name="avatars")
app.mount("/wallpapers", StaticFiles(directory=WALLPAPER_DIR), name="wallpapers")
app.mount("/media", StaticFiles(directory=MEDIA_DIR), name="media")
# sticker files now served via /sticker-data/{id} from DB
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Подключение к PostgreSQL
_raw_db_url = os.getenv("DATABASE_URL", "postgresql://localhost/messenger")
DATABASE_URL = _raw_db_url.replace("postgres://", "postgresql://", 1)

# ═══ Вставьте сюда токен вашего Telegram-бота ═══════════════════════════
# Получить: https://t.me/BotFather → /newbot → скопировать токен
TG_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_BOT_USERNAME = ""  # fetched on startup

# ── JWT ──────────────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGO   = "HS256"
JWT_TTL    = 60 * 60 * 24 * 30  # 30 days
_bearer    = HTTPBearer(auto_error=False)

def create_token(phone: str) -> str:
    tok = pyjwt.encode(
        {"sub": phone, "exp": int(time.time()) + JWT_TTL},
        JWT_SECRET, algorithm=JWT_ALGO
    )
    return tok.decode() if isinstance(tok, bytes) else tok

def decode_token(token: str) -> str | None:
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload.get("sub")
    except Exception:
        return None

async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer)
) -> str:
    phone = decode_token(creds.credentials) if creds else None
    if not phone:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return phone

# ── Rate limiting (in-memory) ─────────────────────────────────────────────
_rate_store: dict = {}  # ip -> [timestamps]

def rate_limit(request: Request, max_calls: int = 10, window: int = 60):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    calls = [t for t in _rate_store.get(ip, []) if now - t < window]
    if len(calls) >= max_calls:
        raise HTTPException(status_code=429, detail="Too many requests")
    calls.append(now)
    _rate_store[ip] = calls

# phone -> {token, username, name, password, expires}
_pending_registrations: dict = {}
# telegram_user_id -> phone (for matching contact share)
_tg_sessions: dict = {}
# ════════════════════════════════════════════════════════════════════════

_db_pool = None
_db_pool_lock = None

def _get_ssl_ctx():
    ssl_hosts = ["railway.app", "render.com", "heroku", "amazonaws", "neon.tech", "supabase"]
    if not any(h in DATABASE_URL for h in ssl_hosts):
        return None
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    return ctx

async def _create_pool():
    kwargs = dict(min_size=1, max_size=10, command_timeout=30)
    ssl_ctx = _get_ssl_ctx()
    if ssl_ctx:
        kwargs["ssl"] = ssl_ctx
    return await asyncpg.create_pool(DATABASE_URL, **kwargs)

async def get_db():
    global _db_pool, _db_pool_lock
    import asyncio
    if _db_pool_lock is None:
        _db_pool_lock = asyncio.Lock()
    if _db_pool is None:
        async with _db_pool_lock:
            if _db_pool is None:
                _db_pool = await _create_pool()
                logger.info("DB pool created")
    try:
        return await _db_pool.acquire()
    except Exception as e:
        logger.error(f"DB acquire failed: {e}")
        raise

from contextlib import asynccontextmanager

@asynccontextmanager
async def db_conn():
    """Контекст-менеджер пула: release выполняется автоматически при любом исходе."""
    global _db_pool
    if _db_pool is None:
        _db_pool = await _create_pool()
    async with _db_pool.acquire() as conn:
        yield conn

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
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, hashed: str) -> bool:
    try:
        # Support old SHA256 hashes during migration
        if len(hashed) == 64 and not hashed.startswith("$2"):
            import hashlib
            return hashlib.sha256(("nonblock_salt" + password).encode()).hexdigest() == hashed \
                or hashlib.sha256((password + "nonblock_salt").encode()).hexdigest() == hashed
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

# Инициализация базы данных
async def init_db():
    async with db_conn() as conn:
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
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        
            # Проверяем и добавляем колонки если нужно
            for col, typ in [('password', 'TEXT'), ('last_seen', 'TIMESTAMP'), ('is_admin', 'BOOLEAN DEFAULT FALSE'), ('verified', 'TEXT DEFAULT NULL')]:
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
            # Verification requests table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS verification_requests (
                    id SERIAL PRIMARY KEY,
                    phone TEXT NOT NULL,
                    message TEXT,
                    status TEXT DEFAULT 'pending',
                    badge_type TEXT DEFAULT 'blue',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_at TIMESTAMP
                )
            """)

            # Add edited column to messages if missing

            msg_edited_exists = await conn.fetchval("""
                SELECT EXISTS (SELECT FROM information_schema.columns
                WHERE table_name = 'messages' AND column_name = 'edited')
            """)
            if not msg_edited_exists:
                await conn.execute("ALTER TABLE messages ADD COLUMN edited BOOLEAN DEFAULT FALSE")

            reply_to_exists = await conn.fetchval("""
                SELECT EXISTS (SELECT FROM information_schema.columns
                WHERE table_name = 'messages' AND column_name = 'reply_to')
            """)
            if not reply_to_exists:
                await conn.execute("ALTER TABLE messages ADD COLUMN reply_to INTEGER REFERENCES messages(id) ON DELETE SET NULL")

            # Calls log table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS calls (
                    id SERIAL PRIMARY KEY,
                    caller TEXT NOT NULL,
                    callee TEXT NOT NULL,
                    call_type TEXT DEFAULT 'audio',
                    status TEXT NOT NULL,
                    duration INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

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
            pass

# Запускаем инициализацию при старте
# Copy ringtone to static dir if present next to main.py
_rt_src = os.path.join(BASE_DIR, "ringtone.mp3")
_rt_dst = os.path.join(STATIC_DIR, "ringtone.mp3")
if os.path.exists(_rt_src) and not os.path.exists(_rt_dst):
    try:
        import shutil; shutil.copy2(_rt_src, _rt_dst)
    except Exception: pass


async def tg_api(method: str, **kwargs):
    if not TG_BOT_TOKEN:
        return None
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/{method}"
    async with aiohttp.ClientSession() as s:
        async with s.post(url, json=kwargs, timeout=aiohttp.ClientTimeout(total=35)) as r:
            return await r.json()

async def tg_send(chat_id, text, reply_markup=None):
    kwargs = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        kwargs["reply_markup"] = reply_markup
    return await tg_api("sendMessage", **kwargs)

_verified_phones: set = set()

async def bot_polling():
    global TG_BOT_USERNAME
    if not TG_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set, skipping bot")
        return
    me = await tg_api("getMe")
    if me and me.get("ok"):
        TG_BOT_USERNAME = me["result"]["username"]
        logger.info(f"Telegram bot: @{TG_BOT_USERNAME}")

    offset = 0
    while True:
        try:
            data = await tg_api("getUpdates", offset=offset, timeout=25, allowed_updates=["message"])
            if not data or not data.get("ok"):
                await asyncio.sleep(5)
                continue
            for upd in data["result"]:
                offset = upd["update_id"] + 1
                msg = upd.get("message", {})
                tg_user = msg.get("from", {})
                tg_id = tg_user.get("id")
                text = msg.get("text", "")
                contact = msg.get("contact")

                if text.startswith("/start ") and tg_id:
                    token = text.split(" ", 1)[1].strip()
                    phone = next((p for p, v in _pending_registrations.items() if v["token"] == token), None)
                    if phone:
                        _tg_sessions[tg_id] = phone
                        await tg_send(tg_id,
                            f"Подтвердите номер <b>{phone}</b>\nНажмите кнопку ниже:",
                            reply_markup={"keyboard": [[{"text": "Поделиться номером", "request_contact": True}]], "resize_keyboard": True, "one_time_keyboard": True}
                        )
                    else:
                        await tg_send(tg_id, "Ссылка устарела. Начните регистрацию заново.")

                elif contact and tg_id:
                    phone = _tg_sessions.get(tg_id)
                    if not phone:
                        await tg_send(tg_id, "Сначала начните регистрацию в мессенджере.")
                        continue
                    def norm(p): return "".join(c for c in (p or "") if c.isdigit())
                    shared = norm(contact.get("phone_number", ""))
                    expected = norm(phone)
                    if shared == expected or shared.endswith(expected) or expected.endswith(shared):
                        reg = _pending_registrations.pop(phone, None)
                        _tg_sessions.pop(tg_id, None)
                        if reg:
                            try:
                                async with db_conn() as conn:
                                    await conn.execute(
                                        "INSERT INTO users (phone, username, name, password) VALUES ($1,$2,$3,$4) ON CONFLICT (phone) DO NOTHING",
                                        phone, reg["username"], reg["name"], reg["password"]
                                    )
                                    await conn.execute("INSERT INTO privacy_settings (phone) VALUES ($1) ON CONFLICT DO NOTHING", phone)
                                _verified_phones.add(phone)
                                await tg_send(tg_id, "✅ Номер подтверждён! Вернитесь в мессенджер и войдите.", reply_markup={"remove_keyboard": True})
                            except Exception as e:
                                logger.error(f"Bot register error: {e}")
                                await tg_send(tg_id, "Ошибка. Попробуйте позже.", reply_markup={"remove_keyboard": True})
                    else:
                        _tg_sessions.pop(tg_id, None)
                        await tg_send(tg_id, f"❌ Номер не совпадает. Ожидался: <b>{phone}</b>", reply_markup={"remove_keyboard": True})
        except asyncio.TimeoutError:
            pass  # normal long-poll timeout, just retry
        except Exception as e:
            logger.error(f"Bot polling error: {type(e).__name__}: {e}")
            await asyncio.sleep(5)

async def _cleanup_pending():
    """Remove expired pending registrations every 5 min."""
    while True:
        await asyncio.sleep(300)
        now = time.time()
        expired = [p for p, v in list(_pending_registrations.items()) if now - v.get("created", 0) > 600]
        for p in expired:
            _pending_registrations.pop(p, None)
        old_ips = [ip for ip, calls in list(_rate_store.items()) if not calls or now - max(calls) > 3600]
        for ip in old_ips:
            _rate_store.pop(ip, None)

@app.on_event("startup")
async def startup():
    import asyncio
    for _d in [AVATAR_DIR, STICKER_DIR]:
        try: os.makedirs(_d, exist_ok=True)
        except Exception: pass
    async def safe_init():
        try:
            await init_db()
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Database init failed: {e}")
    asyncio.create_task(safe_init())
    asyncio.create_task(bot_polling())
    asyncio.create_task(_cleanup_pending())

@app.on_event("shutdown")
async def shutdown():
    global _db_pool
    if _db_pool:
        await _db_pool.close()

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
async def register(user: UserRegister, request: Request):
    rate_limit(request, max_calls=5, window=300)
    try:
        async with db_conn() as conn:
            existing = await conn.fetchval("SELECT phone FROM users WHERE phone = $1", user.phone)
            if existing:
                return JSONResponse(status_code=400, content={"error": "Пользователь уже существует"})
            if user.username:
                taken = await conn.fetchval("SELECT phone FROM users WHERE username = $1", user.username)
                if taken:
                    return JSONResponse(status_code=400, content={"error": "Username уже занят"})

        if not TG_BOT_TOKEN or not TG_BOT_USERNAME:
            # No bot configured — register directly
            async with db_conn() as conn:
                await conn.execute(
                    "INSERT INTO users (phone, username, name, password) VALUES ($1,$2,$3,$4)",
                    user.phone, user.username, user.name, hash_password(user.password)
                )
                await conn.execute("INSERT INTO privacy_settings (phone) VALUES ($1)", user.phone)
            return {"ok": True, "phone": user.phone}

        # Store pending registration, return bot link
        token = secrets.token_urlsafe(16)
        _pending_registrations[user.phone] = {
            "token": token,
            "username": user.username,
            "name": user.name,
            "password": hash_password(user.password),
            "created": time.time(),
        }
        bot_link = f"https://t.me/{TG_BOT_USERNAME}?start={token}"
        return {"ok": True, "pending": True, "bot_link": bot_link, "phone": user.phone}

    except Exception as e:
        logger.error(f"Error registering user: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/auth/verify-status/{phone}")
async def verify_status(phone: str):
    """Frontend polls this until verified."""
    if phone in _verified_phones:
        _verified_phones.discard(phone)
        return {"verified": True}
    if phone not in _pending_registrations:
        # Already in DB (registered without bot)
        async with db_conn() as conn:
            exists = await conn.fetchval("SELECT 1 FROM users WHERE phone=$1", phone)
        if exists:
            return {"verified": True}
    return {"verified": False}

@app.post("/auth/login")
async def login(data: UserLogin, request: Request):
    rate_limit(request, max_calls=10, window=60)
    try:
        async with db_conn() as conn:
        
            user = await conn.fetchrow(
                "SELECT phone, password FROM users WHERE phone = $1",
                data.phone
            )
        
        
            if not user:
                return JSONResponse(status_code=404, content={"error": "Пользователь не найден"})
        
            if user['password'] is None:
                return JSONResponse(status_code=401, content={"error": "NO_PASSWORD_SET"})
        
            if not verify_password(data.password, user['password']):
                return JSONResponse(status_code=401, content={"error": "Неверный пароль"})
        
            token = create_token(user['phone'])
        token_str = token.decode() if isinstance(token, bytes) else token
        return {"ok": True, "phone": user['phone'], "token": token_str}
        
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
        
        async with db_conn() as conn:
        
            await conn.execute("""
                UPDATE users SET password = $1 WHERE phone = $2
            """, hashed, phone)
        
        
            logger.info(f"Password set for {phone}")
            return {"ok": True}
        
    except Exception as e:
            logger.error(f"Error setting password: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/auth/change-password")
async def change_password(data: ChangePassword):
    try:
        async with db_conn() as conn:
        
            user = await conn.fetchrow(
                "SELECT password FROM users WHERE phone = $1",
                data.phone
            )
        
            if not user:
                return JSONResponse(status_code=404, content={"error": "Пользователь не найден"})
        
            if not verify_password(data.current_password, user['password']):
                return JSONResponse(status_code=401, content={"error": "Неверный текущий пароль"})
        
            hashed = hash_password(data.new_password)
            await conn.execute(
                "UPDATE users SET password = $1 WHERE phone = $2",
                hashed, data.phone
            )
        
        
            logger.info(f"Password changed for user: {data.phone}")
            return {"ok": True}
        
    except Exception as e:
            logger.error(f"Error changing password: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

# ============= ЭНДПОИНТЫ ПОЛЬЗОВАТЕЛЕЙ =============

@app.get("/user/{phone}")
async def get_user(phone: str):
    try:
        async with db_conn() as conn:
        
            user = await conn.fetchrow(
                "SELECT phone, username, name, bio, avatar, verified FROM users WHERE phone = $1",
                phone
            )
        
        
            if not user:
                return JSONResponse(status_code=404, content={"error": "User not found"})
        
            return {
                "phone": user['phone'],
                "username": user['username'],
                "name": user['name'],
                "bio": user['bio'] or "",
                "avatar": get_avatar_url(user['avatar']),
                "verified": user['verified']
            }
        
    except Exception as e:
            logger.error(f"Error getting user: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

@app.put("/user/{phone}")
async def update_user(phone: str, data: UpdateProfile):
    try:
        async with db_conn() as conn:
        
            if data.username:
                existing = await conn.fetchval(
                    "SELECT phone FROM users WHERE username = $1 AND phone != $2",
                    data.username, phone
                )
                if existing:
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
        async with db_conn() as conn:
            await conn.execute("UPDATE users SET avatar = $1 WHERE phone = $2", data_uri, phone)
            return {"avatar": data_uri}
    except Exception as e:
            logger.error(f"Error uploading avatar: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

ALLOWED_MEDIA_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/heic",
    "video/mp4", "video/quicktime", "video/webm", "video/x-matroska",
}
MAX_MEDIA_SIZE = 50 * 1024 * 1024  # 50 MB

@app.get("/media/{filename}")
async def serve_media(filename: str):
    path = os.path.join(MEDIA_DIR, filename)
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"error": "Not found"})
    import mimetypes
    mt, _ = mimetypes.guess_type(path)
    return FileResponse(path, media_type=mt or "application/octet-stream")

@app.post("/api/media/upload")
async def upload_media(file: UploadFile = File(...), sender: str = ""):
    try:
        data = await file.read()
        if len(data) > MAX_MEDIA_SIZE:
            return JSONResponse(status_code=400, content={"error": "Max 50MB"})
        ct = file.content_type or "application/octet-stream"
        ext = file.filename.rsplit(".", 1)[-1].lower() if file.filename and "." in file.filename else "bin"
        fname = f"{hashlib.md5(data + sender.encode()).hexdigest()}_{int(__import__('time').time())}.{ext}"
        path = os.path.join(MEDIA_DIR, fname)
        with open(path, "wb") as f:
            f.write(data)
        kind = "image" if ct.startswith("image/") else "video" if ct.startswith("video/") else "file"
        return {"url": f"/media/{fname}", "kind": kind, "name": file.filename or fname, "size": len(data)}
    except Exception as e:
        logger.error(f"Media upload error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/wallpaper/upload")
async def upload_wallpaper(file: UploadFile = File(...)):
    try:
        if not file.content_type.startswith("image/"):
            return JSONResponse(status_code=400, content={"error": "File must be an image"})
        data = await file.read()
        if len(data) > 10 * 1024 * 1024:
            return JSONResponse(status_code=400, content={"error": "Max 10MB"})
        ext = file.filename.rsplit(".", 1)[-1] if file.filename and "." in file.filename else "jpg"
        fname = f"{hashlib.md5(data).hexdigest()}.{ext}"
        path = os.path.join(WALLPAPER_DIR, fname)
        with open(path, "wb") as f:
            f.write(data)
        return {"url": f"/wallpapers/{fname}"}
    except Exception as e:
        logger.error(f"Error uploading wallpaper: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/remove-avatar/{phone}")
async def remove_avatar(phone: str):
    try:
        async with db_conn() as conn:
        
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
        
            return {"ok": True}
        
    except Exception as e:
            logger.error(f"Error removing avatar: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

# ============= СТИКЕРЫ =============

@app.post("/api/upload-stickers/{phone}")
async def upload_stickers(phone: str, stickers: List[UploadFile] = File(...)):
    try:
        async with db_conn() as conn:
        
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
        
        async with db_conn() as conn:
            stickers = await conn.fetch("""
                SELECT id, sticker_url, sticker_data IS NOT NULL as has_data
                FROM stickers WHERE user_phone = $1 ORDER BY created_at DESC
            """, phone)
        
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
        async with db_conn() as conn:
            result = await conn.execute("""
                DELETE FROM stickers 
                WHERE user_phone = $1 
                AND sticker_url LIKE '/stickers/%'
                AND sticker_data IS NULL
            """, phone)
            deleted = int(result.split()[-1])
            logger.info(f"Deleted {deleted} broken stickers for {phone}")
            return {"ok": True, "deleted": deleted}
    except Exception as e:
            return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/api/stickers/{phone}/{sticker_id}")
async def delete_sticker(phone: str, sticker_id: int):
    try:
        async with db_conn() as conn:
            row = await conn.fetchrow("SELECT user_phone, sticker_url FROM stickers WHERE id = $1", sticker_id)
            if not row or row['user_phone'] != phone:
                return JSONResponse(status_code=403, content={"error": "Not authorized"})
            await conn.execute("DELETE FROM stickers WHERE id = $1", sticker_id)
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
        async with db_conn() as conn:
            deleted = await conn.fetchval(
                "DELETE FROM stickers WHERE user_phone = $1 RETURNING COUNT(*)", phone
            )
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
        async with db_conn() as conn:
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

                pass
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
        async with db_conn() as conn:
            row = await conn.fetchrow(
                "SELECT sticker_data, sticker_url FROM stickers WHERE id = $1", sticker_id
            )
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

        async with db_conn() as conn:
            try:
                row = await conn.fetchrow("""
                    INSERT INTO voice_messages (sender, voice_data, duration)
                    VALUES ($1, $2, $3) RETURNING id
                """, sender, bytes(body), duration)
            finally:
                pass

            return {"ok": True, "voice_id": row["id"], "url": f"/voice/{row['id']}"}
    except Exception as e:
            logger.error(f"voice upload error: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/voice/{voice_id}")
async def get_voice(voice_id: int):
    """Отдаём аудио файл по id."""
    try:
        async with db_conn() as conn:
            row = await conn.fetchrow("SELECT voice_data, data FROM voice_messages WHERE id = $1", voice_id)
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

        async with db_conn() as conn:
            try:
                row = await conn.fetchrow("""
                    INSERT INTO video_messages (sender, video_data, duration)
                    VALUES ($1, $2, $3) RETURNING id
                """, sender, bytes(body), duration)
            finally:
                pass

            logger.info(f"Video upload: sender={sender} size={len(body)} duration={duration}s id={row['id']}")
            return {"ok": True, "video_id": row["id"]}
    except Exception as e:
            import traceback
            logger.error(f"video upload error: {e}\n{traceback.format_exc()}")
            return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/video/{video_id}")
async def get_video(video_id: int):
    try:
        async with db_conn() as conn:
            row = await conn.fetchrow("SELECT video_data, duration FROM video_messages WHERE id = $1", video_id)
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
        async with db_conn() as conn:
            row = await conn.fetchrow("SELECT theme_data FROM theme_settings WHERE phone = $1", phone)
            return {"theme": dict(row["theme_data"]) if row else {}}
    except Exception as e:
            return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/theme/{phone}")
async def save_theme(phone: str, request: Request):
    try:
        data = await request.json()
        import json as _json2
        async with db_conn() as conn:
            await conn.execute("""
                INSERT INTO theme_settings (phone, theme_data, updated_at)
                VALUES ($1, $2::jsonb, NOW())
                ON CONFLICT (phone) DO UPDATE
                SET theme_data = $2::jsonb, updated_at = NOW()
            """, phone, _json2.dumps(data))
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
        async with db_conn() as conn:
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
        async with db_conn() as conn:
            row = await conn.fetchrow("SELECT * FROM music_status WHERE phone=$1", phone)
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
        async with db_conn() as conn:
        
            user = await conn.fetchrow(
                "SELECT phone, username, name, bio, avatar, verified FROM users WHERE username = $1",
                data.username
            )
        
        
            if not user:
                return {"found": False}
        
            return {
                "found": True,
                "phone": user['phone'],
                "username": user['username'],
                "name": user['name'],
                "bio": user['bio'] or "",
                "avatar": get_avatar_url(user['avatar']),
                "verified": user['verified']
            }
        
    except Exception as e:
            logger.error(f"Error searching user: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/search-users/{query}")
async def search_users(query: str, request: Request):
    try:
        if len(query) < 2:
            return {"users": []}
        
        async with db_conn() as conn:
        
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

@app.get('/users/{me}')
async def get_user_chats(
    me: str,
    current_user: str = Depends(get_current_user)
):
    if me != current_user:
        raise HTTPException(status_code=403, detail='Forbidden')

    async with db_conn() as conn:
        rows = await conn.fetch("""
            WITH latest_messages AS (
                SELECT DISTINCT ON (
                    LEAST(sender_phone, receiver_phone),
                    GREATEST(sender_phone, receiver_phone)
                )
                    id,
                    sender_phone,
                    receiver_phone,
                    text,
                    created_at
                FROM messages
                WHERE sender_phone = $1 OR receiver_phone = $1
                ORDER BY
                    LEAST(sender_phone, receiver_phone),
                    GREATEST(sender_phone, receiver_phone),
                    created_at DESC
            ),

            unread_counts AS (
                SELECT
                    sender_phone,
                    COUNT(*) as unread_count
                FROM messages
                WHERE receiver_phone = $1
                AND read = false
                GROUP BY sender_phone
            )

            SELECT
                u.phone,
                u.username,
                u.name,
                u.avatar,
                u.last_seen,

                lm.text as last_message,
                lm.created_at as last_message_time,

                COALESCE(uc.unread_count, 0) as unread_count

            FROM users u

            LEFT JOIN latest_messages lm ON (
                (lm.sender_phone = u.phone AND lm.receiver_phone = $1)
                OR
                (lm.receiver_phone = u.phone AND lm.sender_phone = $1)
            )

            LEFT JOIN unread_counts uc ON uc.sender_phone = u.phone

            WHERE u.phone != $1
            AND EXISTS (
                SELECT 1
                FROM messages m
                WHERE
                    (m.sender_phone = $1 AND m.receiver_phone = u.phone)
                    OR
                    (m.receiver_phone = $1 AND m.sender_phone = u.phone)
            )

            ORDER BY lm.created_at DESC NULLS LAST
        """, me)

        return [dict(r) for r in rows]

# Добавить реакцию
@app.post("/reaction/add")
async def add_reaction(data: dict):
    try:
        message_id = data.get("message_id")
        user = data.get("user")
        reaction = data.get("reaction")
        
        async with db_conn() as conn:
        
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
    async with db_conn() as conn:
        rows = await conn.fetch("""
            SELECT reaction, COUNT(*) as count, 
                   array_agg(user_phone) as users
            FROM reactions 
            WHERE message_id = $1
            GROUP BY reaction
        """, message_id)
    
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
        async with db_conn() as conn:
        
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
        
        
            return [[m['id'], m['sender'], m['text']] for m in messages]
        
    except Exception as e:
            logger.error(f"Error getting messages: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

class EditMessage(BaseModel):
    user: str
    text: str

@app.patch("/message/{message_id}")
async def edit_message(message_id: int, data: EditMessage):
    try:
        async with db_conn() as conn:
            row = await conn.fetchrow(
                "SELECT sender, receiver FROM messages WHERE id = $1 AND is_deleted = 0",
                message_id
            )
            if not row:
                return JSONResponse(status_code=404, content={"error": "Message not found"})
            if row["sender"] != data.user:
                return JSONResponse(status_code=403, content={"error": "Not authorized"})
            new_text = data.text.strip()
            if not new_text:
                return JSONResponse(status_code=400, content={"error": "Empty text"})
            await conn.execute(
                "UPDATE messages SET text = $1, edited = TRUE WHERE id = $2",
                new_text, message_id
            )
            receiver = row["receiver"]

        # WS broadcast to both sides
        payload = {"action": "message_edited", "id": message_id, "text": new_text}
        for target in (data.user, receiver):
            if target in clients:
                try: await clients[target].send_json(payload)
                except: clients.pop(target, None)

        return {"ok": True}
    except Exception as e:
        logger.error(f"Error editing message: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/message/{message_id}")
async def delete_message(message_id: int, user: str):
    try:
        async with db_conn() as conn:
        
            row = await conn.fetchrow(
                "SELECT sender, receiver FROM messages WHERE id = $1",
                message_id
            )
        
            if not row:
                return JSONResponse(status_code=404, content={"error": "Message not found"})
        
            if row["sender"] != user:
                return JSONResponse(status_code=403, content={"error": "Not authorized"})
        
            await conn.execute(
                "UPDATE messages SET is_deleted = 1 WHERE id = $1",
                message_id
            )
            receiver = row["receiver"]

        # Broadcast message_deleted via WebSocket
        for target in (receiver, user):
            if target and target in clients:
                try:
                    await clients[target].send_json({"action": "message_deleted", "id": message_id})
                except:
                    clients.pop(target, None)

        return {"ok": True}
        
    except Exception as e:
            logger.error(f"Error deleting message: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/chat/{user1}/{user2}")
async def delete_chat(user1: str, user2: str):
    try:
        async with db_conn() as conn:
        
            await conn.execute("""
                DELETE FROM messages 
                WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
            """, user1, user2)
        
        
            return {"ok": True}
        
    except Exception as e:
            logger.error(f"Error deleting chat: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

# ============= НАСТРОЙКИ ПРИВАТНОСТИ =============

@app.get("/privacy-settings/{phone}")
async def get_privacy_settings(phone: str):
    try:
        async with db_conn() as conn:
        
            settings = await conn.fetchrow(
                "SELECT phone_privacy, online_privacy, avatar_privacy FROM privacy_settings WHERE phone = $1",
                phone
            )
        
        
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
        async with db_conn() as conn:
        
            await conn.execute("""
                INSERT INTO privacy_settings (phone, phone_privacy, online_privacy, avatar_privacy)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (phone) DO UPDATE
                SET phone_privacy = $2, online_privacy = $3, avatar_privacy = $4
            """, phone, settings.phone_privacy, settings.online_privacy, settings.avatar_privacy)
        
        
            return {"ok": True}
        
    except Exception as e:
            logger.error(f"Error saving privacy settings: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

# ============= WEBSOCKET =============

@app.websocket("/ws/{user}")
async def websocket_endpoint(ws: WebSocket, user: str, token: str = ""):
    # Verify JWT token passed as ?token=... query param
    verified = decode_token(token)
    if not verified or verified != user:
        await ws.close(code=4001)
        return

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

                    async with db_conn() as conn:
                        reply_to = data.get("reply_to")
                        message_id = await conn.fetchval("""
                            INSERT INTO messages (sender, receiver, text, reply_to) 
                            VALUES ($1, $2, $3, $4) RETURNING id
                        """, user, to, text, reply_to)

                    # Fetch reply preview if any
                    reply_preview = None
                    if reply_to:
                        async with db_conn() as rc:
                            rrow = await rc.fetchrow("SELECT sender, text FROM messages WHERE id=$1", reply_to)
                            if rrow:
                                reply_preview = {"id": reply_to, "sender": rrow["sender"], "text": rrow["text"]}

                    if to in clients:
                        try:
                            await clients[to].send_json({
                                "action": "message",
                                "id": message_id,
                                "from": user,
                                "text": text,
                                "reply": reply_preview
                            })
                        except:
                            clients.pop(to, None)

                    await ws.send_json({
                        "action": "message_sent",
                        "id": message_id,
                        "to": to,
                        "text": text,
                        "reply": reply_preview
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
                        async with db_conn() as conn:
                            updated = await conn.fetch("""
                                UPDATE messages SET is_read = 1
                                WHERE sender = $1 AND receiver = $2 AND is_read = 0
                                RETURNING id
                            """, from_user, user)
                        ids = [r['id'] for r in updated]
                        if ids and from_user in clients:
                            try:
                                await clients[from_user].send_json({
                                    "action": "messages_read",
                                    "ids": ids,
                                    "by": user
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
                    elif action == "call_offer" and to not in clients:
                        await ws.send_json({"action": "call_end", "from": to, "reason": "offline"})

                    # Save call record to DB on terminal actions
                    if action in ("call_end", "call_reject", "call_busy") and to:
                        _duration = data.get("duration", 0) or 0
                        _call_type = data.get("callType", "audio")
                        _status = "completed" if action == "call_end" else "rejected"
                        try:
                            async with db_conn() as _cc:
                                await _cc.execute(
                                    "INSERT INTO calls (caller, callee, call_type, status, duration) VALUES ($1,$2,$3,$4,$5)",
                                    user, to, _call_type, _status, int(_duration)
                                )
                            # Notify both sides to add call bubble
                            _call_payload = {"action": "call_record", "caller": user, "callee": to,
                                             "call_type": _call_type, "status": _status, "duration": int(_duration)}
                            for _target in (user, to):
                                if _target in clients:
                                    try: await clients[_target].send_json(_call_payload)
                                    except: clients.pop(_target, None)
                        except Exception as _ce:
                            logger.error(f"Error saving call: {_ce}")

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
                        async with db_conn() as conn2:
                            messages = await conn2.fetch("""
                                SELECT m.id, m.sender, m.text, m.is_read, m.edited, m.timestamp, 'msg' AS kind,
                                       m.reply_to, r.sender AS reply_sender, r.text AS reply_text
                                FROM messages m
                                LEFT JOIN messages r ON r.id = m.reply_to
                                WHERE ((m.sender = $1 AND m.receiver = $2) OR (m.sender = $2 AND m.receiver = $1))
                                AND m.is_deleted = 0
                                UNION ALL
                                SELECT id, caller AS sender, '' AS text, 0 AS is_read, FALSE AS edited, timestamp, 'call' AS kind, NULL::INTEGER, NULL::TEXT, NULL::TEXT FROM calls
                                WHERE (caller = $1 AND callee = $2) OR (caller = $2 AND callee = $1)
                                ORDER BY timestamp
                            """, user, chat_user)
                            history = []
                            for m in messages:
                                if m['kind'] == 'msg':
                                    reply_data = None
                                    if m['reply_to']:
                                        reply_data = {"id": m['reply_to'], "sender": m['reply_sender'], "text": m['reply_text']}
                                    history.append({"type": "msg", "id": m['id'], "sender": m['sender'], "text": m['text'], "is_read": m['is_read'], "edited": bool(m['edited']), "reply": reply_data})
                                else:
                                    # fetch call details
                                    call_row = await conn2.fetchrow("SELECT caller,callee,call_type,status,duration FROM calls WHERE id=$1", m['id'])
                                    if call_row:
                                        history.append({"type": "call", "id": m['id'], "caller": call_row['caller'], "callee": call_row['callee'],
                                                        "call_type": call_row['call_type'], "status": call_row['status'], "duration": call_row['duration']})
                            await ws.send_json({"action": "history", "messages": history})
                            # Помечаем входящие как прочитанные и уведомляем отправителя
                            updated = await conn2.fetch("""
                                UPDATE messages SET is_read = 1
                                WHERE sender = $2 AND receiver = $1 AND is_read = 0
                                RETURNING id
                            """, user, chat_user)
                        read_ids = [r['id'] for r in updated]
                        if read_ids and chat_user in clients:
                            try:
                                await clients[chat_user].send_json({
                                    "action": "messages_read",
                                    "ids": read_ids,
                                    "by": user
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
            async with db_conn() as conn:
                await conn.execute("UPDATE users SET last_seen = NOW() WHERE phone = $1", user)
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
# ── Admin credentials (separate from messenger accounts) ─────────────────────
# Stored in DB table admin_credentials. Created on first /admin/setup call.

async def _init_admin_table():
    async with db_conn() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_credentials (
                id SERIAL PRIMARY KEY,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

async def _require_admin(request: Request):
    """Check admin JWT token."""
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    try:
        payload = pyjwt.decode(token, JWT_SECRET + "_admin", algorithms=[JWT_ALGO])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ── Verification endpoints ───────────────────────────────────────────────────

class VerificationRequest(BaseModel):
    phone: str
    message: Optional[str] = None

@app.post("/api/verification/request")
async def request_verification(data: VerificationRequest, request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    phone = decode_token(token)
    if not phone or phone != data.phone:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    try:
        async with db_conn() as conn:
            existing = await conn.fetchval("SELECT verified FROM users WHERE phone=$1", phone)
            if existing:
                return JSONResponse(status_code=400, content={"error": "Already verified"})
            pending = await conn.fetchval(
                "SELECT id FROM verification_requests WHERE phone=$1 AND status='pending'", phone
            )
            if pending:
                return JSONResponse(status_code=400, content={"error": "Request already pending"})
            await conn.execute(
                "INSERT INTO verification_requests (phone, message) VALUES ($1, $2)",
                phone, data.message or ""
            )
        return {"ok": True}
    except Exception as e:
        logger.error(f"Verification request error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/admin/verifications")
async def admin_verifications(request: Request):
    await _require_admin(request)
    async with db_conn() as conn:
        rows = await conn.fetch("""
            SELECT vr.id, vr.phone, vr.message, vr.status, vr.badge_type, vr.created_at,
                   u.name, u.username
            FROM verification_requests vr
            LEFT JOIN users u ON u.phone = vr.phone
            ORDER BY (vr.status = 'pending') DESC, vr.created_at DESC
        """)
    return [
        {"id": r["id"], "phone": r["phone"], "message": r["message"],
         "status": r["status"], "badge_type": r["badge_type"],
         "name": r["name"], "username": r["username"],
         "created_at": r["created_at"].isoformat() if r["created_at"] else None}
        for r in rows
    ]

class VerificationDecision(BaseModel):
    request_id: int
    action: str

@app.post("/admin/verifications/decide")
async def admin_verification_decide(data: VerificationDecision, request: Request):
    await _require_admin(request)
    async with db_conn() as conn:
        req = await conn.fetchrow("SELECT phone FROM verification_requests WHERE id=$1", data.request_id)
        if not req:
            return JSONResponse(status_code=404, content={"error": "Not found"})
        phone = req["phone"]
        if data.action in ("approve_blue", "approve_black"):
            badge = "blue" if data.action == "approve_blue" else "black"
            await conn.execute(
                "UPDATE verification_requests SET status='approved', badge_type=$1, reviewed_at=NOW() WHERE id=$2",
                badge, data.request_id
            )
            await conn.execute("UPDATE users SET verified=$1 WHERE phone=$2", badge, phone)
            if phone in clients:
                try:
                    await clients[phone].send_json({"action": "verified", "badge": badge})
                except:
                    clients.pop(phone, None)
        else:
            await conn.execute(
                "UPDATE verification_requests SET status='rejected', reviewed_at=NOW() WHERE id=$1",
                data.request_id
            )
            if phone in clients:
                try:
                    await clients[phone].send_json({"action": "verification_rejected"})
                except:
                    clients.pop(phone, None)
    return {"ok": True}

@app.get("/api/verification/status/{phone}")
async def verification_status(phone: str):
    async with db_conn() as conn:
        verified = await conn.fetchval("SELECT verified FROM users WHERE phone=$1", phone)
        pending = await conn.fetchval(
            "SELECT id FROM verification_requests WHERE phone=$1 AND status='pending'", phone
        )
    return {"verified": verified, "pending": bool(pending)}

class AdminSetup(BaseModel):
    login: str
    password: str

class AdminLogin(BaseModel):
    login: str
    password: str

@app.post("/admin/setup")
async def admin_setup(data: AdminSetup):
    """First-time setup — only works when no admin exists yet."""
    await _init_admin_table()
    async with db_conn() as conn:
        existing = await conn.fetchval("SELECT COUNT(*) FROM admin_credentials")
        if existing > 0:
            return JSONResponse(status_code=403, content={"error": "Admin already configured"})
        if len(data.login) < 3:
            return JSONResponse(status_code=400, content={"error": "Login too short (min 3)"})
        if len(data.password) < 6:
            return JSONResponse(status_code=400, content={"error": "Password too short (min 6)"})
        hashed = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt(rounds=12)).decode()
        await conn.execute(
            "INSERT INTO admin_credentials (login, password_hash) VALUES ($1, $2)",
            data.login, hashed
        )
    return {"ok": True, "message": "Admin account created"}

@app.post("/admin/login")
async def admin_login(data: AdminLogin):
    await _init_admin_table()
    async with db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT password_hash FROM admin_credentials WHERE login=$1", data.login
        )
    if not row:
        return JSONResponse(status_code=401, content={"error": "Неверный логин или пароль"})
    if not bcrypt.checkpw(data.password.encode(), row["password_hash"].encode()):
        return JSONResponse(status_code=401, content={"error": "Неверный логин или пароль"})
    token = pyjwt.encode(
        {"role": "admin", "login": data.login, "exp": int(time.time()) + 60 * 60 * 8},
        JWT_SECRET + "_admin", algorithm=JWT_ALGO
    )
    return {"ok": True, "token": token}

@app.get("/admin/has-setup")
async def admin_has_setup():
    """Check if admin account exists — used by frontend to show setup or login."""
    await _init_admin_table()
    async with db_conn() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM admin_credentials")
    return {"configured": count > 0}

@app.get("/admin/stats")
async def admin_stats(request: Request):
    await _require_admin(request)
    async with db_conn() as conn:
        total_users    = await conn.fetchval("SELECT COUNT(*) FROM users")
        total_messages = await conn.fetchval("SELECT COUNT(*) FROM messages WHERE is_deleted=0")
        total_chats    = await conn.fetchval(
            "SELECT COUNT(*) FROM (SELECT LEAST(sender,receiver)||'_'||GREATEST(sender,receiver) AS pair FROM messages GROUP BY pair) t"
        )
        new_today      = await conn.fetchval(
            "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '24 hours'"
        )
        msgs_today     = await conn.fetchval(
            "SELECT COUNT(*) FROM messages WHERE timestamp >= NOW() - INTERVAL '24 hours' AND is_deleted=0"
        )
        recent_users   = await conn.fetch(
            "SELECT phone, username, name, created_at, last_seen FROM users ORDER BY created_at DESC LIMIT 10"
        )
    online_now = len(clients)
    return {
        "online_now":    online_now,
        "total_users":   total_users,
        "total_chats":   total_chats,
        "total_messages": total_messages,
        "new_today":     new_today,
        "msgs_today":    msgs_today,
        "recent_users":  [
            {"phone": r["phone"], "username": r["username"], "name": r["name"],
             "created_at": r["created_at"].isoformat() if r["created_at"] else None,
             "last_seen":  r["last_seen"].isoformat()  if r["last_seen"]  else None,
             "online": r["phone"] in clients}
            for r in recent_users
        ],
    }

@app.get("/admin")
async def serve_admin():
    return FileResponse("web/admin.html")

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

