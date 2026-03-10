from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import sqlite3
import os
import logging
from pydantic import BaseModel
import uvicorn

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS для публичного доступа
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# База данных - используем путь в папке проекта
DB_PATH = os.path.join(os.path.dirname(__file__), "messenger.db")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Функция для обновления структуры БД
def upgrade_db():
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Проверяем структуру таблицы users
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Если нет колонки name - добавляем
        if 'name' not in columns:
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN name TEXT")
                logger.info("Added 'name' column to users table")
            except:
                pass
        
        conn.commit()
        conn.close()
        logger.info("Database upgrade completed")
    except Exception as e:
        logger.error(f"Error upgrading database: {e}")

# Инициализация БД
def init_db():
    try:
        conn = get_db()
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
        conn.close()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

init_db()
upgrade_db()

clients = {}

class UsernameUpdate(BaseModel):
    phone: str
    username: str
    name: str = ""

class SearchUser(BaseModel):
    username: str

@app.get("/health")
async def health_check():
    return {"status": "healthy", "connections": len(clients)}

@app.get("/user/{phone}")
async def get_user(phone: str):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT phone, username, name, avatar FROM users WHERE phone=?", 
                (phone,)
            )
        except:
            cursor.execute(
                "SELECT phone, username, avatar FROM users WHERE phone=?", 
                (phone,)
            )
            user = cursor.fetchone()
            conn.close()
            if user:
                return {
                    "phone": user[0],
                    "username": user[1],
                    "name": None,
                    "avatar": user[2] if len(user) > 2 else ""
                }
            return {"phone": phone, "username": None, "name": None, "avatar": ""}
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                "phone": user[0],
                "username": user[1],
                "name": user[2],
                "avatar": user[3] if len(user) > 3 and user[3] else ""
            }
        return {"phone": phone, "username": None, "name": None, "avatar": ""}
    except Exception as e:
        logger.error(f"Error getting user {phone}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/username")
async def change_username(data: UsernameUpdate):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT phone FROM users WHERE username=? AND phone!=?", 
            (data.username, data.phone)
        )
        if cursor.fetchone():
            conn.close()
            return {"error": "Этот username уже занят"}
        
        if not data.username.startswith("@"):
            conn.close()
            return {"error": "Username должен начинаться с @"}
        
        name = data.name if data.name else data.username[1:]
        
        try:
            cursor.execute("""
                UPDATE users 
                SET username=?, name=? 
                WHERE phone=?
            """, (data.username, name, data.phone))
        except:
            cursor.execute("""
                UPDATE users 
                SET username=? 
                WHERE phone=?
            """, (data.username, data.phone))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Username updated: {data.phone} -> {data.username}")
        return {"ok": True, "username": data.username, "name": name}
        
    except Exception as e:
        logger.error(f"Error updating username: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/search")
async def search_user(data: SearchUser):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT phone, username, name, avatar FROM users WHERE username=?", 
                (data.username,)
            )
        except:
            cursor.execute(
                "SELECT phone, username, avatar FROM users WHERE username=?", 
                (data.username,)
            )
            user = cursor.fetchone()
            conn.close()
            if not user:
                return {"found": False}
            return {
                "found": True,
                "phone": user[0],
                "username": user[1],
                "name": None,
                "avatar": user[2] if len(user) > 2 else ""
            }
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return {"found": False}
        
        return {
            "found": True,
            "phone": user[0],
            "username": user[1],
            "name": user[2],
            "avatar": user[3] if len(user) > 3 and user[3] else ""
        }
    except Exception as e:
        logger.error(f"Error searching user {data.username}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/users/{me}")
async def get_users(me: str):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT DISTINCT
        CASE WHEN sender=? THEN receiver ELSE sender END as contact
        FROM messages
        WHERE sender=? OR receiver=?
        """, (me, me, me))
        
        contacts = cursor.fetchall()
        result = []
        
        for contact in contacts:
            phone = contact[0]
            
            try:
                cursor.execute(
                    "SELECT phone, username, name, avatar FROM users WHERE phone=?", 
                    (phone,)
                )
                user_data = cursor.fetchone()
                has_name = True
            except:
                cursor.execute(
                    "SELECT phone, username, avatar FROM users WHERE phone=?", 
                    (phone,)
                )
                user_data = cursor.fetchone()
                has_name = False
            
            if not user_data:
                cursor.execute(
                    "INSERT OR IGNORE INTO users(phone, avatar) VALUES(?,?)",
                    (phone, "")
                )
                conn.commit()
                if has_name:
                    user_data = (phone, None, None, "")
                else:
                    user_data = (phone, None, "")
            
            cursor.execute("""
            SELECT text FROM messages 
            WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
            ORDER BY timestamp DESC LIMIT 1
            """, (me, phone, phone, me))
            last_msg = cursor.fetchone()
            
            if has_name:
                display_name = user_data[2] or user_data[1] or phone
                result.append({
                    "phone": user_data[0],
                    "username": user_data[1],
                    "name": user_data[2],
                    "displayName": display_name,
                    "avatar": user_data[3] if len(user_data) > 3 and user_data[3] else "",
                    "online": phone in clients,
                    "last": last_msg[0] if last_msg else ""
                })
            else:
                display_name = user_data[1] or phone
                result.append({
                    "phone": user_data[0],
                    "username": user_data[1],
                    "name": None,
                    "displayName": display_name,
                    "avatar": user_data[2] if len(user_data) > 2 and user_data[2] else "",
                    "online": phone in clients,
                    "last": last_msg[0] if last_msg else ""
                })
        
        conn.close()
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
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO users(phone, avatar) VALUES(?,?)",
            (user, "")
        )
        conn.commit()
        conn.close()
        
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

                    conn = get_db()
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO messages(sender, receiver, text) VALUES(?,?,?)",
                        (user, to, text)
                    )
                    conn.commit()
                    conn.close()

                    if to in clients:
                        try:
                            await clients[to].send_json({
                                "action": "message",
                                "from": user,
                                "text": text
                            })
                        except:
                            clients.pop(to, None)

                elif action == "history":
                    chat_user = data.get("user")
                    if chat_user:
                        conn = get_db()
                        cursor = conn.cursor()
                        cursor.execute("""
                        SELECT sender, text FROM messages
                        WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
                        ORDER BY timestamp
                        """, (user, chat_user, chat_user, user))
                        messages = cursor.fetchall()
                        conn.close()
                        
                        await ws.send_json({
                            "action": "history", 
                            "messages": [[m[0], m[1]] for m in messages]
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

# Обслуживание статических файлов
if os.path.exists("web"):
    app.mount("/", StaticFiles(directory="web", html=True), name="web")

@app.get("/")
async def root():
    return FileResponse("web/index.html")

# ЕДИНСТВЕННОЕ ИЗМЕНЕНИЕ ДЛЯ RENDER - эта строчка в конце
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=False
    )