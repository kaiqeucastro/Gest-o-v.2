import calendar
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("FINANCE_DB", ROOT / "financeiro.db"))
HOST = os.environ.get("FINANCE_HOST", "127.0.0.1")
PORT = int(os.environ.get("FINANCE_PORT", "8000"))
INVITE_CODE = os.environ.get("FINANCE_INVITE_CODE", "")
SESSION_SECONDS = 30 * 24 * 60 * 60
PASSWORD_ROUNDS = 310_000


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                entry_date TEXT NOT NULL,
                item TEXT NOT NULL,
                category TEXT NOT NULL,
                amount_cents INTEGER NOT NULL,
                kind TEXT NOT NULL,
                person TEXT NOT NULL DEFAULT '',
                payment_method TEXT NOT NULL DEFAULT '',
                due_date TEXT NOT NULL DEFAULT '',
                installments INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS entries_user_date
                ON entries(user_id, entry_date);
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                description TEXT NOT NULL,
                kind TEXT NOT NULL,
                amount_cents INTEGER NOT NULL,
                installments INTEGER NOT NULL DEFAULT 0,
                due_date TEXT NOT NULL,
                paid INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, id)
            );
            CREATE INDEX IF NOT EXISTS accounts_user_due
                ON accounts(user_id, due_date);
            """
        )


def cents(value):
    if isinstance(value, str):
        value = value.strip().replace("R$", "").replace(" ", "")
        if "," in value:
            value = value.replace(".", "").replace(",", ".")
    return round(float(value) * 100)


def account_row(row):
    return {
        "Id": row["id"],
        "Descrição": row["description"],
        "Tipo": row["kind"],
        "Valor": row["amount_cents"] / 100,
        "Parcelas": row["installments"] or "",
        "Vencimento": row["due_date"],
        "Pagas": row["paid"],
    }


def entry_row(row):
    return {
        "Data": row["entry_date"],
        "Item": row["item"],
        "Categoria": row["category"],
        "Valor": row["amount_cents"] / 100,
        "Tipo": row["kind"],
        "Responsável": row["person"],
        "Forma de pagamento": row["payment_method"],
        "Data de vencimento": row["due_date"],
        "Parcelas": row["installments"] or "",
    }


def month_after(iso_date):
    current = date.fromisoformat(iso_date)
    month_index = current.month
    year = current.year + (month_index == 12)
    month = month_index % 12 + 1
    day = min(current.day, calendar.monthrange(year, month)[1])
    return date(year, month, day).isoformat()


class APIError(Exception):
    def __init__(self, code):
        self.code = code


def create_session(db, user_id):
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions(token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, int(time.time()) + SESSION_SECONDS),
    )
    return token


def authenticate(db, payload):
    username = str(payload.get("usuario", "")).strip().lower()
    password = str(payload.get("senha", ""))

    if payload.get("acao") == "criar":
        if not username:
            raise APIError("usuario")
        if (
            len(password) < 8
            or not re.search(r"[A-Z]", password)
            or not re.search(r"[0-9]", password)
            or not re.search(r"[^A-Za-z0-9\s]", password)
        ):
            raise APIError("senha")
        supplied_invite = str(payload.get("convite", ""))
        if INVITE_CODE and not hmac.compare_digest(supplied_invite, INVITE_CODE):
            raise APIError("convite")
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, PASSWORD_ROUNDS
        )
        try:
            cursor = db.execute(
                "INSERT INTO users(username, password_salt, password_hash, created_at) "
                "VALUES (?, ?, ?, ?)",
                (username, salt.hex(), password_hash.hex(), int(time.time())),
            )
            user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            raise APIError("existe") from None
    else:
        row = db.execute(
            "SELECT id, password_salt, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            raise APIError("credenciais")
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(row["password_salt"]), PASSWORD_ROUNDS
        )
        if not hmac.compare_digest(candidate.hex(), row["password_hash"]):
            raise APIError("credenciais")
        user_id = row["id"]

    return {"ok": True, "token": create_session(db, user_id), "usuario": username}


def handle_action(db, payload):
    action = payload.get("acao")
    if action in ("entrar", "criar"):
        return authenticate(db, payload)
    if action == "google":
        raise APIError("google")

    token = str(payload.get("token", ""))
    session = db.execute(
        "SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?",
        (token, int(time.time())),
    ).fetchone()
    if not session:
        raise APIError("sessao")
    user_id = session["user_id"]

    if action == "ler":
        if payload.get("aba") == "Lançamentos":
            rows = db.execute(
                "SELECT * FROM entries WHERE user_id = ? ORDER BY entry_date, id",
                (user_id,),
            ).fetchall()
            return {"ok": True, "dados": [entry_row(row) for row in rows]}
        if payload.get("aba") == "Contas":
            rows = db.execute(
                "SELECT * FROM accounts WHERE user_id = ? ORDER BY due_date",
                (user_id,),
            ).fetchall()
            return {"ok": True, "dados": [account_row(row) for row in rows]}
        raise APIError("aba")

    if action == "lancamento_novo":
        entry_date = str(payload.get("Data", ""))
        date.fromisoformat(entry_date)
        description = str(payload.get("Item", "")).strip()
        if not description:
            raise APIError("dados")
        db.execute(
            "INSERT INTO entries(user_id, entry_date, item, category, amount_cents, kind, "
            "person, payment_method, due_date, installments) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_id,
                entry_date,
                description,
                str(payload.get("Categoria", "Outros")),
                cents(payload.get("Valor", 0)),
                str(payload.get("Tipo", "Despesa")),
                str(payload.get("Responsável", "")),
                str(payload.get("Forma de pagamento", "")),
                str(payload.get("Data de vencimento", "")),
                int(payload.get("Parcelas") or 0),
            ),
        )
        return {"ok": True}

    if action == "conta_nova":
        account_id = str(payload.get("Id", ""))
        description = str(payload.get("Descrição", "")).strip()
        due_date = str(payload.get("Vencimento", ""))
        date.fromisoformat(due_date)
        if not account_id or not description:
            raise APIError("dados")
        db.execute(
            "INSERT INTO accounts(id, user_id, description, kind, amount_cents, installments, "
            "due_date, paid) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                account_id,
                user_id,
                description,
                str(payload.get("Tipo", "Mensal")),
                cents(payload.get("Valor", 0)),
                int(payload.get("Parcelas") or 0),
                due_date,
                int(payload.get("Pagas") or 0),
            ),
        )
        return {"ok": True}

    if action == "conta_paga":
        account_id = str(payload.get("Id", ""))
        account = db.execute(
            "SELECT due_date, paid FROM accounts WHERE user_id = ? AND id = ?",
            (user_id, account_id),
        ).fetchone()
        if not account:
            raise APIError("conta")
        db.execute(
            "UPDATE accounts SET paid = ?, due_date = ? WHERE user_id = ? AND id = ?",
            (
                account["paid"] + 1,
                month_after(account["due_date"]),
                user_id,
                account_id,
            ),
        )
        return {"ok": True}

    raise APIError("acao")


class Handler(BaseHTTPRequestHandler):
    def send_json(self, result, status=200):
        body = json.dumps(result, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path not in ("/", "/Index.html"):
            self.send_error(404)
            return
        body = (ROOT / "Index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path != "/api":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1_000_000:
                raise APIError("dados")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise APIError("dados")
            with connect_db() as db:
                result = handle_action(db, payload)
            self.send_json(result)
        except APIError as error:
            self.send_json({"ok": False, "erro": error.code})
        except (ValueError, TypeError, OverflowError, json.JSONDecodeError):
            self.send_json({"ok": False, "erro": "dados"})

    def log_message(self, format, *args):
        print("%s - %s" % (self.address_string(), format % args))


if __name__ == "__main__":
    init_db()
    print("Banco SQLite: %s" % DB_PATH)
    print("Site local: http://%s:%s" % (HOST, PORT))
    if INVITE_CODE:
        print("Cadastro protegido por código de convite.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
