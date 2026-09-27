import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Iterator

import bcrypt
import jwt
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, field_validator

SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me-before-deployment")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DB = os.getenv("DB", "app.db")

app = FastAPI(title="FastAPI JWT CRUD API", version="1.0.0")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    email: EmailStr
    password: str = Field(min_length=6, max_length=100)

    @field_validator("password")
    @classmethod
    def password_fits_bcrypt(cls, password: str) -> str:
        if len(password.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 bytes when UTF-8 encoded")
        return password


class ItemIn(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)

    @field_validator("title", mode="before")
    @classmethod
    def strip_title(cls, title: str) -> str:
        if isinstance(title, str):
            return title.strip()
        return title


def db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    conn = sqlite3.connect(DB)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                owner_id INTEGER NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def create_token(user_id: int) -> str:
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    return jwt.encode(
        {"sub": str(user_id), "exp": expires},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def get_current_user(
    token: str = Depends(oauth2_scheme),
    conn: sqlite3.Connection = Depends(db),
) -> dict:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise credentials_error

    user = conn.execute(
        "SELECT id, name, email FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if user is None:
        raise credentials_error
    return dict(user)


def owned_item(
    conn: sqlite3.Connection, item_id: int, user_id: int
) -> sqlite3.Row:
    item = conn.execute(
        """
        SELECT id, title, description
        FROM items
        WHERE id=? AND owner_id=?
        """,
        (item_id, user_id),
    ).fetchone()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@app.get("/")
def home() -> dict:
    return {"message": "FastAPI JWT CRUD API is running", "docs": "/docs"}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterIn, conn: sqlite3.Connection = Depends(db)) -> dict:
    password_hash = bcrypt.hashpw(
        data.password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    try:
        cur = conn.execute(
            "INSERT INTO users(name, email, password_hash) VALUES(?,?,?)",
            (data.name, str(data.email), password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")
    return {"message": "User registered", "user_id": cur.lastrowid}


@app.post("/login")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    conn: sqlite3.Connection = Depends(db),
) -> dict:
    user = conn.execute(
        "SELECT id, password_hash FROM users WHERE email=?", (form.username,)
    ).fetchone()
    password = form.password.encode("utf-8")
    if (
        user is None
        or len(password) > 72
        or not bcrypt.checkpw(password, user["password_hash"].encode("utf-8"))
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": create_token(user["id"]), "token_type": "bearer"}


@app.get("/me")
def me(user: dict = Depends(get_current_user)) -> dict:
    return user


@app.post("/items", status_code=status.HTTP_201_CREATED)
def create_item(
    data: ItemIn,
    user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(db),
) -> dict:
    cur = conn.execute(
        "INSERT INTO items(title, description, owner_id) VALUES(?,?,?)",
        (data.title, data.description, user["id"]),
    )
    conn.commit()
    return {
        "id": cur.lastrowid,
        "title": data.title,
        "description": data.description,
    }


@app.get("/items")
def list_items(
    user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(db),
) -> list[dict]:
    items = conn.execute(
        "SELECT id, title, description FROM items WHERE owner_id=? ORDER BY id DESC",
        (user["id"],),
    ).fetchall()
    return [dict(item) for item in items]


@app.get("/items/{item_id}")
def get_item(
    item_id: int,
    user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(db),
) -> dict:
    return dict(owned_item(conn, item_id, user["id"]))


@app.put("/items/{item_id}")
def update_item(
    item_id: int,
    data: ItemIn,
    user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(db),
) -> dict:
    cur = conn.execute(
        "UPDATE items SET title=?, description=? WHERE id=? AND owner_id=?",
        (data.title, data.description, item_id, user["id"]),
    )
    conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item updated"}


@app.delete("/items/{item_id}")
def delete_item(
    item_id: int,
    user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(db),
) -> dict:
    cur = conn.execute(
        "DELETE FROM items WHERE id=? AND owner_id=?", (item_id, user["id"])
    )
    conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted"}


init_db()


def main() -> None:
    uvicorn.run("main:app", host="127.0.0.1", port=int(os.getenv("PORT", "8000")))


if __name__ == "__main__":
    main()
