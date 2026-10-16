"""
Items router.

Security features:
- Input sanitization: ItemCreate strips HTML tags and whitespace from
  name and description before saving, which prevents stored XSS.
- SQL injection prevention: every query uses ? placeholders so user input
  is always treated as data, never as SQL. See list_items for an example.
"""

import re
import sqlite3
from typing import Optional

from fastapi import APIRouter, status
from pydantic import BaseModel, ValidationInfo, field_validator

router = APIRouter(prefix="/items", tags=["items"])

DB_PATH = "items.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us turn rows into dicts
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


init_db()

# ---------- Sanitization ----------
# Stored XSS: if an attacker saves "<script>...</script>" as an item name,
# any frontend that displays it could run that script in other users' browsers.
# Cleaning the text BEFORE it reaches the database stops that.
# NOTE: regex is fine for this exercise. Production apps usually use a
# dedicated library (like bleach or nh3) and also escape output in the frontend.

# 1) Remove <script>...</script> and <style>...</style> blocks entirely (tags AND contents)
SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
# 2) Remove any remaining HTML tags like <b>, <img ...>, </div>
TAG_RE = re.compile(r"<[^>]*>")


class ItemCreate(BaseModel):
    name: str
    description: Optional[str] = None

    @field_validator("name", "description")
    @classmethod
    def sanitize_text(cls, value: Optional[str], info: ValidationInfo) -> Optional[str]:
        """Strip HTML tags and surrounding whitespace to prevent stored XSS."""
        if value is None:
            return None
        cleaned = SCRIPT_STYLE_RE.sub("", value)
        cleaned = TAG_RE.sub("", cleaned)
        cleaned = cleaned.strip()

        # A name like "<b></b>" becomes empty after cleaning, so reject it
        if info.field_name == "name" and not cleaned:
            raise ValueError("name cannot be empty after removing HTML")
        return cleaned


class Item(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    

@router.get("", response_model=list[Item])
def list_items(search: Optional[str] = None):
    """
    List items, optionally filtered by a name search.

    WHY PARAMETERIZED QUERIES PREVENT SQL INJECTION
    -----------------------------------------------
    VULNERABLE (never do this) - user input is pasted directly into the SQL string:

        query = f"SELECT * FROM items WHERE name LIKE '%{search}%'"
        conn.execute(query)

        If a user sends:  search = "%' OR 1=1 --"
        the SQL becomes:  SELECT * FROM items WHERE name LIKE '%%' OR 1=1 --%'
        OR 1=1 is always true, and -- turns the leftover %' into a comment,
        so every row comes back no matter what the filter was supposed to do.
        A worse payload could add a second statement or change data.
        The database can't tell your code apart from the attacker's text.

    SAFE (what we do below) - use a ? placeholder and pass the value separately:

        conn.execute("SELECT * FROM items WHERE name LIKE ?", (f"%{search}%",))

        The SQL structure is sent to the database first, and the value is bound
        afterward as plain data. Quotes, OR, semicolons, etc. inside `search`
        are just characters to match. They can never become SQL commands.
    """
    conn = get_connection()
    try:
        if search:
            rows = conn.execute(
                "SELECT id, name, description FROM items WHERE name LIKE ?",
                (f"%{search}%",),
            ).fetchall()
        else:
            rows = conn.execute("SELECT id, name, description FROM items").fetchall()
    finally:
        conn.close()

    return [dict(row) for row in rows]


@router.post("", response_model=Item, status_code=status.HTTP_201_CREATED)
def create_item(item: ItemCreate):
    # By the time we get here, item.name and item.description are already sanitized
    conn = get_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO items (name, description) VALUES (?, ?)",
            (item.name, item.description),
        )
        conn.commit()
        new_id = cursor.lastrowid
    finally:
        conn.close()

    return {"id": new_id, "name": item.name, "description": item.description}