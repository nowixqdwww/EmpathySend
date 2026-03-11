from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import logging
import shutil
import asyncpg
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator
import uvicorn
import hashlib
import hmac
import base64
import secrets
import jwt
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import redis.asyncio as redis
import json
import asyncio
from contextlib import asynccontextmanager

# Настройка логирования для продакшена
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Конфигурация из переменных окружения
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 дней
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/messenger")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
AVATAR_MAX_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,https://yourdomain.com").split(",")

# Настройка лимитера запросов
limiter = Limiter(key_func=get_remote_address)

# Настройка хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Настройка безопасности
security = HTTPBearer()

# Инициализация Redis для кэширования и сессий
redis_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global redis_client
    try:
        redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
        logger.info("Connected to Redis")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}")
        redis_client = None
    
    await init_db()
    yield
    
    # Shutdown
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed")

app = FastAPI(
    title="NonBlock Messenger API",
    description="Real-time messaging platform",
    version="1.0.0",
    lifespan=lifespan
)

# Настройка CORS для продакшена
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Создаем папку для аватарок
AVATAR_DIR = os.path.join(os.path.dirname(__file__), "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)

# Монтируем папку с аватарками с кэшированием
app.mount("/avatars", StaticFiles(directory=AVATAR_DIR, check_dir=False), name="avatars")

# ============= МОДЕЛИ ДАННЫХ =============

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class TokenData(BaseModel):
    phone: Optional[str] = None

class UserCreate(BaseModel):
    phone: str
    username: Optional[str] = None
    name: Optional[str] = None
    
    @validator('phone')
    def validate_phone(cls, v):
        if not v.startswith('+') or not v[1:].isdigit():
            raise ValueError('Phone must start with + and contain only digits')
        if len(v) < 10 or len(v) > 15:
            raise ValueError('Phone length must be between 10 and 15 characters')
        return v

class UserUpdate(BaseModel):
    username: Optional[str] = None
    name: Optional[str] = None
    bio: Optional[str] = None
    
    @validator('username')
    def validate_username(cls, v):
        if v and not v.startswith('@'):
            raise ValueError('Username must start with @')
        if v and len(v) < 3:
            raise ValueError('Username too short')
        return v

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c.isalpha() for c in v):
            raise ValueError('Password must contain at least one letter')
        return v

class MessageCreate(BaseModel):
    receiver: str
    text: str
    
    @validator('text')
    def validate_text(cls, v):
        if len(v) > 5000:
            raise ValueError('Message too long (max 5000 chars)')
        return v

class PrivacySettings(BaseModel):
    phone_privacy: str = "everyone"
    online_privacy: str = "everyone"
    avatar_privacy: str = "everyone"

class SearchQuery(BaseModel):
    query: str = Field(..., min_length=2, max_length=50)

# ============= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =============

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def verify_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone: str = payload.get("sub")
        if phone is None:
            return None
        return phone
    except jwt.PyJWTError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    phone = await verify_token(token)
    if phone is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return phone

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_safe_filename(phone: str, extension: str) -> str:
    """Создает безопасное имя файла на основе хеша"""
    phone_hash = hashlib.sha256(phone.encode()).hexdigest()[:16]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"avatar_{phone_hash}_{timestamp}{extension}"

async def get_db():
    """Получение соединения с БД с повторными попытками"""
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            conn = await asyncpg.connect(DATABASE_URL)
            return conn
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            await asyncio.sleep(retry_delay * (attempt + 1))
    
    raise Exception("Could not connect to database")

async def cache_get(key: str):
    """Получение данных из кэша"""
    if not redis_client:
        return None
    try:
        data = await redis_client.get(key)
        return json.loads(data) if data else None
    except:
        return None

async def cache_set(key: str, value: Any, expire: int = 300):
    """Сохранение данных в кэш"""
    if not redis_client:
        return
    try:
        await redis_client.setex(key, expire, json.dumps(value))
    except:
        pass

async def cache_delete(key: str):
    """Удаление из кэша"""
    if not redis_client:
        return
    try:
        await redis_client.delete(key)
    except:
        pass

# ============= ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ =============

async def init_db():
    """Инициализация базы данных с миграциями"""
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
                password TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                version INTEGER DEFAULT 1
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
        
        # Таблица сообщений с индексами
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                text TEXT NOT NULL,
                is_deleted INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender) REFERENCES users(phone) ON DELETE CASCADE,
                FOREIGN KEY (receiver) REFERENCES users(phone) ON DELETE CASCADE
            )
        ''')
        
        # Индексы для оптимизации запросов
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
            CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active);
        ''')
        
        # Таблица для хранения WebSocket соединений
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS active_connections (
                phone TEXT PRIMARY KEY,
                connection_id TEXT,
                connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_ping TIMESTAMP,
                FOREIGN KEY (phone) REFERENCES users(phone) ON DELETE CASCADE
            )
        ''')
        
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise
    finally:
        await conn.close()

# ============= ЭНДПОИНТЫ АУТЕНТИФИКАЦИИ =============

@app.post("/auth/register", response_model=Token)
@limiter.limit("5/minute")
async def register(request: Request, user: UserCreate):
    """Регистрация нового пользователя"""
    try:
        conn = await get_db()
        
        # Проверяем существование пользователя
        existing = await conn.fetchrow(
            "SELECT phone FROM users WHERE phone = $1",
            user.phone
        )
        
        if existing:
            await conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists"
            )
        
        # Создаем пользователя
        await conn.execute('''
            INSERT INTO users (phone, username, name)
            VALUES ($1, $2, $3)
        ''', user.phone, user.username, user.name)
        
        # Создаем настройки приватности по умолчанию
        await conn.execute('''
            INSERT INTO privacy_settings (phone)
            VALUES ($1)
        ''', user.phone)
        
        await conn.close()
        
        # Создаем токен
        access_token = create_access_token(
            data={"sub": user.phone}
        )
        
        logger.info(f"New user registered: {user.phone}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@app.post("/auth/login", response_model=Token)
@limiter.limit("10/minute")
async def login(request: Request, phone: str, password: str):
    """Вход по номеру телефона и паролю"""
    try:
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT phone, password FROM users WHERE phone = $1",
            phone
        )
        
        await conn.close()
        
        if not user or not user['password']:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if not verify_password(password, user['password']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        access_token = create_access_token(
            data={"sub": user['phone']}
        )
        
        logger.info(f"User logged in: {phone}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error logging in: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@app.post("/auth/set-password")
@limiter.limit("5/minute")
async def set_password(
    request: Request,
    phone: str,
    password: str,
    current_user: str = Depends(get_current_user)
):
    """Установка пароля (для новых пользователей)"""
    try:
        if current_user != phone:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized"
            )
        
        conn = await get_db()
        
        # Проверяем, не установлен ли уже пароль
        user = await conn.fetchrow(
            "SELECT password FROM users WHERE phone = $1",
            phone
        )
        
        if user and user['password']:
            await conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password already set"
            )
        
        hashed = get_password_hash(password)
        
        await conn.execute('''
            UPDATE users SET password = $1 WHERE phone = $2
        ''', hashed, phone)
        
        await conn.close()
        
        logger.info(f"Password set for user: {phone}")
        
        return {"ok": True}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting password: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to set password"
        )

@app.post("/auth/change-password")
@limiter.limit("5/minute")
async def change_password(
    request: Request,
    password_data: PasswordChange,
    current_user: str = Depends(get_current_user)
):
    """Смена пароля"""
    try:
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT password FROM users WHERE phone = $1",
            current_user
        )
        
        if not user or not user['password']:
            await conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password not set"
            )
        
        if not verify_password(password_data.current_password, user['password']):
            await conn.close()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )
        
        hashed = get_password_hash(password_data.new_password)
        
        await conn.execute('''
            UPDATE users SET password = $1 WHERE phone = $2
        ''', hashed, current_user)
        
        await conn.close()
        
        logger.info(f"Password changed for user: {current_user}")
        
        return {"ok": True}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )

@app.post("/auth/refresh", response_model=Token)
async def refresh_token(current_user: str = Depends(get_current_user)):
    """Обновление токена"""
    access_token = create_access_token(
        data={"sub": current_user}
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

# ============= ЭНДПОИНТЫ ПОЛЬЗОВАТЕЛЕЙ =============

@app.get("/users/me")
@limiter.limit("30/minute")
async def get_current_user_profile(
    request: Request,
    current_user: str = Depends(get_current_user)
):
    """Получение профиля текущего пользователя"""
    try:
        # Проверяем кэш
        cache_key = f"user:{current_user}"
        cached = await cache_get(cache_key)
        if cached:
            return cached
        
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT phone, username, name, bio, avatar, created_at, last_active FROM users WHERE phone = $1",
            current_user
        )
        
        settings = await conn.fetchrow(
            "SELECT phone_privacy, online_privacy, avatar_privacy FROM privacy_settings WHERE phone = $1",
            current_user
        )
        
        await conn.close()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        result = {
            "phone": user['phone'],
            "username": user['username'],
            "name": user['name'],
            "bio": user['bio'] or "",
            "avatar": f"/avatars/{user['avatar']}" if user['avatar'] else None,
            "created_at": user['created_at'].isoformat() if user['created_at'] else None,
            "last_active": user['last_active'].isoformat() if user['last_active'] else None,
            "settings": {
                "phone_privacy": settings['phone_privacy'] if settings else "everyone",
                "online_privacy": settings['online_privacy'] if settings else "everyone",
                "avatar_privacy": settings['avatar_privacy'] if settings else "everyone"
            }
        }
        
        # Сохраняем в кэш на 5 минут
        await cache_set(cache_key, result, 300)
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get profile"
        )

@app.put("/users/me")
@limiter.limit("10/minute")
async def update_user_profile(
    request: Request,
    update: UserUpdate,
    current_user: str = Depends(get_current_user)
):
    """Обновление профиля пользователя"""
    try:
        conn = await get_db()
        
        # Проверяем уникальность username
        if update.username:
            existing = await conn.fetchrow(
                "SELECT phone FROM users WHERE username = $1 AND phone != $2",
                update.username, current_user
            )
            if existing:
                await conn.close()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )
        
        # Обновляем данные
        update_fields = []
        update_values = []
        
        if update.username is not None:
            update_fields.append("username = $" + str(len(update_values) + 1))
            update_values.append(update.username)
        
        if update.name is not None:
            update_fields.append("name = $" + str(len(update_values) + 1))
            update_values.append(update.name)
        
        if update.bio is not None:
            update_fields.append("bio = $" + str(len(update_values) + 1))
            update_values.append(update.bio)
        
        if update_fields:
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE phone = ${len(update_values) + 1}"
            update_values.append(current_user)
            await conn.execute(query, *update_values)
        
        await conn.close()
        
        # Инвалидируем кэш
        await cache_delete(f"user:{current_user}")
        await cache_delete(f"search:{current_user}")
        
        logger.info(f"Profile updated for user: {current_user}")
        
        return {"ok": True}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )

@app.post("/users/me/avatar")
@limiter.limit("5/minute")
async def upload_user_avatar(
    request: Request,
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    """Загрузка аватара пользователя"""
    try:
        if not file.content_type.startswith('image/'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an image"
            )
        
        # Читаем файл
        content = await file.read()
        file_size = len(content)
        
        if file_size > AVATAR_MAX_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File too large (max {AVATAR_MAX_SIZE//1024//1024}MB)"
            )
        
        conn = await get_db()
        
        # Получаем старый аватар
        old = await conn.fetchrow(
            "SELECT avatar FROM users WHERE phone = $1",
            current_user
        )
        
        # Создаем новое имя файла
        file_extension = os.path.splitext(file.filename)[1]
        filename = create_safe_filename(current_user, file_extension)
        file_path = os.path.join(AVATAR_DIR, filename)
        
        # Удаляем старый файл
        if old and old['avatar']:
            old_path = os.path.join(AVATAR_DIR, old['avatar'])
            if os.path.exists(old_path):
                os.remove(old_path)
        
        # Сохраняем новый файл
        with open(file_path, "wb") as buffer:
            buffer.write(content)
        
        # Обновляем запись в БД
        await conn.execute(
            "UPDATE users SET avatar = $1 WHERE phone = $2",
            filename, current_user
        )
        
        await conn.close()
        
        # Инвалидируем кэш
        await cache_delete(f"user:{current_user}")
        
        avatar_url = f"/avatars/{filename}"
        
        logger.info(f"Avatar uploaded for user: {current_user}")
        
        return {"avatar": avatar_url}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading avatar: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar"
        )

@app.delete("/users/me/avatar")
@limiter.limit("5/minute")
async def delete_user_avatar(
    request: Request,
    current_user: str = Depends(get_current_user)
):
    """Удаление аватара пользователя"""
    try:
        conn = await get_db()
        
        result = await conn.fetchrow(
            "SELECT avatar FROM users WHERE phone = $1",
            current_user
        )
        
        if result and result['avatar']:
            file_path = os.path.join(AVATAR_DIR, result['avatar'])
            if os.path.exists(file_path):
                os.remove(file_path)
        
        await conn.execute(
            "UPDATE users SET avatar = '' WHERE phone = $1",
            current_user
        )
        
        await conn.close()
        
        # Инвалидируем кэш
        await cache_delete(f"user:{current_user}")
        
        logger.info(f"Avatar removed for user: {current_user}")
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error removing avatar: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove avatar"
        )

@app.get("/users/{phone}")
@limiter.limit("60/minute")
async def get_user(
    request: Request,
    phone: str,
    current_user: str = Depends(get_current_user)
):
    """Получение информации о пользователе"""
    try:
        # Проверяем кэш
        cache_key = f"user:{phone}"
        cached = await cache_get(cache_key)
        if cached:
            return cached
        
        conn = await get_db()
        
        user = await conn.fetchrow(
            "SELECT phone, username, name, bio, avatar, last_active FROM users WHERE phone = $1",
            phone
        )
        
        settings = await conn.fetchrow(
            "SELECT phone_privacy, online_privacy, avatar_privacy FROM privacy_settings WHERE phone = $1",
            phone
        )
        
        await conn.close()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Проверяем права на просмотр
        is_owner = phone == current_user
        
        result = {
            "phone": phone,
            "username": user['username'],
            "name": user['name'],
            "bio": user['bio'] or "",
            "avatar": f"/avatars/{user['avatar']}" if user['avatar'] and (is_owner or settings['avatar_privacy'] == 'everyone') else None,
            "last_active": user['last_active'].isoformat() if user['last_active'] and (is_owner or settings['online_privacy'] == 'everyone') else None
        }
        
        # Сохраняем в кэш
        await cache_set(cache_key, result, 300)
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user"
        )

@app.get("/users/search/{query}")
@limiter.limit("30/minute")
async def search_users(
    request: Request,
    query: str,
    current_user: str = Depends(get_current_user)
):
    """Поиск пользователей по username или имени"""
    try:
        if len(query) < 2:
            return {"users": []}
        
        # Проверяем кэш
        cache_key = f"search:{query}"
        cached = await cache_get(cache_key)
        if cached:
            return cached
        
        conn = await get_db()
        
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
            LIMIT 20
        ''', f'%{query}%', f'{query}%', f'%{query}')
        
        await conn.close()
        
        result = []
        for user in users:
            show_phone = user['phone_privacy'] == 'everyone' or user['phone'] == current_user
            
            result.append({
                "phone": user['phone'] if show_phone else "hidden",
                "realPhone": user['phone'],
                "username": user['username'],
                "name": user['name'],
                "avatar": f"/avatars/{user['avatar']}" if user['avatar'] else None,
                "displayName": user['name'] or user['username'] or "User",
                "phone_hidden": not show_phone
            })
        
        response = {"users": result}
        
        # Сохраняем в кэш на 1 минуту
        await cache_set(cache_key, response, 60)
        
        return response
        
    except Exception as e:
        logger.error(f"Error searching users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search failed"
        )

# ============= ЭНДПОИНТЫ ЧАТОВ И СООБЩЕНИЙ =============

@app.get("/chats")
@limiter.limit("60/minute")
async def get_chats(
    request: Request,
    current_user: str = Depends(get_current_user)
):
    """Получение списка чатов пользователя"""
    try:
        conn = await get_db()
        
        chats = await conn.fetch('''
            SELECT DISTINCT
                CASE WHEN sender = $1 THEN receiver ELSE sender END as contact
            FROM messages
            WHERE sender = $1 OR receiver = $1
            ORDER BY contact
        ''', current_user)
        
        result = []
        for chat in chats:
            contact = chat['contact']
            
            user_data = await conn.fetchrow(
                "SELECT username, name, avatar FROM users WHERE phone = $1",
                contact
            )
            
            last_msg = await conn.fetchrow('''
                SELECT text, timestamp FROM messages 
                WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
                AND is_deleted = 0
                ORDER BY timestamp DESC LIMIT 1
            ''', current_user, contact)
            
            unread_count = await conn.fetchval('''
                SELECT COUNT(*) FROM messages
                WHERE sender = $1 AND receiver = $2 AND is_read = 0
            ''', contact, current_user)
            
            display_name = user_data['name'] or user_data['username'] or contact
            
            result.append({
                "phone": contact,
                "username": user_data['username'],
                "name": user_data['name'],
                "displayName": display_name,
                "avatar": f"/avatars/{user_data['avatar']}" if user_data['avatar'] else None,
                "lastMessage": last_msg['text'] if last_msg else None,
                "lastMessageTime": last_msg['timestamp'].isoformat() if last_msg else None,
                "unreadCount": unread_count or 0
            })
        
        await conn.close()
        
        return {"chats": result}
        
    except Exception as e:
        logger.error(f"Error getting chats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get chats"
        )

@app.get("/messages/{contact}")
@limiter.limit("60/minute")
async def get_messages(
    request: Request,
    contact: str,
    limit: int = 50,
    offset: int = 0,
    current_user: str = Depends(get_current_user)
):
    """Получение истории сообщений с контактом"""
    try:
        conn = await get_db()
        
        # Отмечаем сообщения как прочитанные
        await conn.execute('''
            UPDATE messages 
            SET is_read = 1 
            WHERE sender = $1 AND receiver = $2
        ''', contact, current_user)
        
        # Получаем сообщения
        messages = await conn.fetch('''
            SELECT id, sender, text, timestamp, is_read
            FROM messages
            WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
            AND is_deleted = 0
            ORDER BY timestamp DESC
            LIMIT $3 OFFSET $4
        ''', current_user, contact, limit, offset)
        
        await conn.close()
        
        result = []
        for msg in messages:
            result.append({
                "id": msg['id'],
                "sender": msg['sender'],
                "text": msg['text'],
                "timestamp": msg['timestamp'].isoformat(),
                "isRead": msg['is_read'] == 1,
                "isMine": msg['sender'] == current_user
            })
        
        return {"messages": result}
        
    except Exception as e:
        logger.error(f"Error getting messages: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get messages"
        )

@app.delete("/messages/{message_id}")
@limiter.limit("10/minute")
async def delete_message(
    request: Request,
    message_id: int,
    current_user: str = Depends(get_current_user)
):
    """Удаление сообщения"""
    try:
        conn = await get_db()
        
        message = await conn.fetchrow(
            "SELECT sender FROM messages WHERE id = $1",
            message_id
        )
        
        if not message:
            await conn.close()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )
        
        if message['sender'] != current_user:
            await conn.close()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only delete own messages"
            )
        
        await conn.execute(
            "UPDATE messages SET is_deleted = 1 WHERE id = $1",
            message_id
        )
        
        await conn.close()
        
        logger.info(f"Message {message_id} deleted by {current_user}")
        
        return {"ok": True}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete message"
        )

# ============= ЭНДПОИНТЫ НАСТРОЕК =============

@app.get("/settings/privacy")
@limiter.limit("30/minute")
async def get_privacy_settings(
    request: Request,
    current_user: str = Depends(get_current_user)
):
    """Получение настроек конфиденциальности"""
    try:
        conn = await get_db()
        
        settings = await conn.fetchrow(
            "SELECT phone_privacy, online_privacy, avatar_privacy FROM privacy_settings WHERE phone = $1",
            current_user
        )
        
        await conn.close()
        
        if not settings:
            return {
                "phone_privacy": "everyone",
                "online_privacy": "everyone",
                "avatar_privacy": "everyone"
            }
        
        return {
            "phone_privacy": settings['phone_privacy'],
            "online_privacy": settings['online_privacy'],
            "avatar_privacy": settings['avatar_privacy']
        }
        
    except Exception as e:
        logger.error(f"Error getting privacy settings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get settings"
        )

@app.put("/settings/privacy")
@limiter.limit("10/minute")
async def update_privacy_settings(
    request: Request,
    settings: PrivacySettings,
    current_user: str = Depends(get_current_user)
):
    """Обновление настроек конфиденциальности"""
    try:
        conn = await get_db()
        
        await conn.execute('''
            INSERT INTO privacy_settings (phone, phone_privacy, online_privacy, avatar_privacy)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (phone) DO UPDATE
            SET phone_privacy = $2, online_privacy = $3, avatar_privacy = $4
        ''', current_user, settings.phone_privacy, settings.online_privacy, settings.avatar_privacy)
        
        await conn.close()
        
        logger.info(f"Privacy settings updated for {current_user}")
        
        return {"ok": True}
        
    except Exception as e:
        logger.error(f"Error updating privacy settings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update settings"
        )

# ============= WEBSOCKET ДЛЯ РЕАЛЬНОГО ВРЕМЕНИ =============

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_rooms: Dict[str, set] = {}
    
    async def connect(self, websocket: WebSocket, user: str):
        await websocket.accept()
        self.active_connections[user] = websocket
        
        # Обновляем время последней активности
        try:
            conn = await get_db()
            await conn.execute(
                "UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE phone = $1",
                user
            )
            await conn.close()
        except:
            pass
        
        logger.info(f"User {user} connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, user: str):
        if user in self.active_connections:
            del self.active_connections[user]
        if user in self.user_rooms:
            del self.user_rooms[user]
        logger.info(f"User {user} disconnected. Total: {len(self.active_connections)}")
    
    async def send_message(self, to: str, message: dict):
        if to in self.active_connections:
            try:
                await self.active_connections[to].send_json(message)
                return True
            except:
                self.disconnect(to)
        return False
    
    async def broadcast(self, users: list, message: dict):
        for user in users:
            await self.send_message(user, message)
    
    def add_to_room(self, user: str, room: str):
        if user not in self.user_rooms:
            self.user_rooms[user] = set()
        self.user_rooms[user].add(room)
    
    def remove_from_room(self, user: str, room: str):
        if user in self.user_rooms and room in self.user_rooms[user]:
            self.user_rooms[user].remove(room)
    
    async def broadcast_to_room(self, room: str, message: dict, exclude: str = None):
        for user, rooms in self.user_rooms.items():
            if room in rooms and user != exclude:
                await self.send_message(user, message)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint для реального времени"""
    user = None
    
    try:
        # Получаем токен из query параметров
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=1008, reason="Missing token")
            return
        
        # Верифицируем токен
        user = await verify_token(token)
        if not user:
            await websocket.close(code=1008, reason="Invalid token")
            return
        
        await manager.connect(websocket, user)
        
        while True:
            try:
                data = await websocket.receive_json()
                action = data.get("action")

                if action == "ping":
                    await websocket.send_json({"action": "pong"})
                    
                    # Обновляем last_active
                    try:
                        conn = await get_db()
                        await conn.execute(
                            "UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE phone = $1",
                            user
                        )
                        await conn.close()
                    except:
                        pass
                    
                    continue

                if action == "send":
                    to = data.get("to")
                    text = data.get("text")
                    
                    if not to or not text:
                        continue
                    
                    # Сохраняем сообщение
                    conn = await get_db()
                    message_id = await conn.fetchval('''
                        INSERT INTO messages (sender, receiver, text) 
                        VALUES ($1, $2, $3) RETURNING id
                    ''', user, to, text)
                    await conn.close()
                    
                    # Отправляем получателю
                    sent = await manager.send_message(to, {
                        "action": "message",
                        "id": message_id,
                        "from": user,
                        "text": text,
                        "timestamp": datetime.now().isoformat()
                    })
                    
                    # Подтверждение отправителю
                    await websocket.send_json({
                        "action": "message_sent",
                        "id": message_id,
                        "to": to,
                        "text": text,
                        "delivered": sent
                    })

                elif action == "typing":
                    to = data.get("to")
                    if to:
                        await manager.send_message(to, {
                            "action": "typing",
                            "from": user
                        })

                elif action == "read":
                    contact = data.get("contact")
                    if contact:
                        conn = await get_db()
                        await conn.execute('''
                            UPDATE messages 
                            SET is_read = 1 
                            WHERE sender = $1 AND receiver = $2
                        ''', contact, user)
                        await conn.close()
                        
                        await manager.send_message(contact, {
                            "action": "read",
                            "by": user
                        })

                elif action == "join_room":
                    room = data.get("room")
                    if room:
                        manager.add_to_room(user, room)

                elif action == "leave_room":
                    room = data.get("room")
                    if room:
                        manager.remove_from_room(user, room)

                elif action == "room_message":
                    room = data.get("room")
                    text = data.get("text")
                    
                    if room and text:
                        await manager.broadcast_to_room(room, {
                            "action": "room_message",
                            "from": user,
                            "text": text,
                            "timestamp": datetime.now().isoformat()
                        }, exclude=user)

            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error for user {user}: {e}")
                continue

    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
    finally:
        if user:
            manager.disconnect(user)

# ============= ЗДОРОВЬЕ И МЕТРИКИ =============

@app.get("/health")
async def health_check():
    """Проверка здоровья сервиса"""
    status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "connections": len(manager.active_connections),
        "database": "unknown",
        "redis": "unknown"
    }
    
    # Проверяем БД
    try:
        conn = await get_db()
        await conn.execute("SELECT 1")
        await conn.close()
        status["database"] = "connected"
    except:
        status["database"] = "disconnected"
        status["status"] = "degraded"
    
    # Проверяем Redis
    if redis_client:
        try:
            await redis_client.ping()
            status["redis"] = "connected"
        except:
            status["redis"] = "disconnected"
            status["status"] = "degraded"
    else:
        status["redis"] = "not configured"
    
    return status

@app.get("/metrics")
@limiter.limit("10/minute")
async def get_metrics(request: Request):
    """Получение метрик (только для админов)"""
    # В реальном проекте здесь должна быть аутентификация админа
    return {
        "active_connections": len(manager.active_connections),
        "users_in_rooms": sum(len(rooms) for rooms in manager.user_rooms.values()),
        "total_rooms": len(set().union(*manager.user_rooms.values())) if manager.user_rooms else 0,
        "timestamp": datetime.now().isoformat()
    }

# ============= СТАТИЧЕСКИЕ ФАЙЛЫ =============

# В продакшене статические файлы должны раздаваться через CDN или nginx
if os.getenv("ENVIRONMENT") == "development":
    if os.path.exists("web"):
        app.mount("/", StaticFiles(directory="web", html=True), name="web")

@app.get("/")
async def root():
    """Корневой эндпоинт"""
    if os.getenv("ENVIRONMENT") == "development":
        return FileResponse("web/index.html")
    else:
        return {
            "name": "NonBlock Messenger API",
            "version": "1.0.0",
            "status": "running",
            "documentation": "/docs"
        }

# ============= ОБРАБОТЧИКИ ОШИБОК =============

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500
        }
    )

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    environment = os.getenv("ENVIRONMENT", "development")
    
    if environment == "production":
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=port,
            workers=4,
            loop="uvloop",
            http="httptools",
            limit_concurrency=1000,
            backlog=2048,
            proxy_headers=True,
            forwarded_allow_ips="*"
        )
    else:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=port,
            reload=True
        )
