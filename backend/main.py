"""
Lexy Hub - License backend (Flask + SQLite).

Run (dev):        python main.py
Run (production): gunicorn -w 1 --threads 8 -b 0.0.0.0:8000 "main:create_app()"
See docs/INSTALL.md and docs/DEPLOY.md.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.request
from collections import defaultdict, deque
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory
from cryptography.fernet import Fernet, InvalidToken

try:  # Argon2id preferred when available
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHashError
    _ARGON = PasswordHasher()
except Exception:  # pragma: no cover - depends on environment
    _ARGON = None

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = (BASE_DIR.parent / "web").resolve()
KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I
HWID_SOURCES = {"gethwid", "clientid", "generated"}
ADMIN_PRESETS = {"1d": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400}
UNIT_SECONDS = {"minutes": 60, "hours": 3600, "days": 86400}
MAX_DURATION = 3650 * 86400
MAX_QTY = 500
KEY_RE = re.compile(r"^LEXY(-[A-Z2-9]{4}){4}$")


# --------------------------------------------------------------------------- config
def load_config(overrides=None):
    env = os.environ.get
    cfg = {
        "ENV": env("LEXY_ENV", "development").lower(),
        "DB_PATH": env("LEXY_DB_PATH", str(BASE_DIR.parent / "data" / "lexyhub.db")),
        "SECRET": env("LEXY_SECRET_KEY", ""),
        "PEPPER": env("LEXY_KEY_PEPPER", ""),
        "FERNET": env("LEXY_FERNET_KEY", ""),
        "BOOTSTRAP_PASSWORD": env("LEXY_BOOTSTRAP_PASSWORD", "admin"),
        "SESSION_HOURS": float(env("LEXY_SESSION_HOURS", "8")),
        "IDLE_MINUTES": float(env("LEXY_IDLE_MINUTES", "60")),
        "TRUST_PROXY": env("LEXY_TRUST_PROXY", "0") == "1",
        "ROBLOX_VERIFY": env("LEXY_ROBLOX_VERIFY", "profile").lower(),  # profile | off
        "LICENSE_TYPES": [t.strip() for t in env("LEXY_LICENSE_TYPES", "Standard,Premium,VIP").split(",") if t.strip()],
        "LOGIN_MAX_FAILS_IP": int(env("LEXY_LOGIN_MAX_FAILS_IP", "10")),
        "LOGIN_MAX_FAILS_USER": int(env("LEXY_LOGIN_MAX_FAILS_USER", "5")),
        "LOGIN_WINDOW": int(env("LEXY_LOGIN_WINDOW_SECONDS", "900")),
        "CLIENT_RATE": int(env("LEXY_CLIENT_RATE_PER_MIN", "60")),
        "ACTIVATE_RATE": int(env("LEXY_ACTIVATE_RATE_PER_MIN", "12")),
        "ADMIN_RATE": int(env("LEXY_ADMIN_RATE_PER_MIN", "240")),
        "CHALLENGE_TTL": int(env("LEXY_CHALLENGE_TTL_SECONDS", "900")),
        "SCRYPT_N": int(env("LEXY_SCRYPT_N", str(2 ** 15))),
        "COOKIE_SECURE": None,
    }
    if overrides:
        cfg.update(overrides)
    prod = cfg["ENV"] == "production"
    if cfg["COOKIE_SECURE"] is None:
        cfg["COOKIE_SECURE"] = prod
    if prod:
        if cfg["BOOTSTRAP_PASSWORD"] in ("", "admin") or len(cfg["BOOTSTRAP_PASSWORD"]) < 12:
            raise RuntimeError("Production refuses the default/weak bootstrap password. "
                               "Set LEXY_BOOTSTRAP_PASSWORD to a strong temporary value (>=12 chars); "
                               "you must change it on first login.")
        missing = [n for n, k in (("LEXY_SECRET_KEY", "SECRET"), ("LEXY_KEY_PEPPER", "PEPPER")) if len(cfg[k]) < 32]
        if missing:
            raise RuntimeError("Production requires strong (>=32 chars) values for: " + ", ".join(missing))
        try:
            Fernet(cfg["FERNET"].encode())
        except Exception:
            raise RuntimeError("Production requires LEXY_FERNET_KEY (generate with: "
                               "python -c \"from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())\")")
        if cfg["ROBLOX_VERIFY"] != "profile":
            raise RuntimeError("Production requires LEXY_ROBLOX_VERIFY=profile")
    else:
        # Dev convenience: persist random secrets next to the DB so keys survive restarts.
        if not cfg["PEPPER"] or not cfg["SECRET"] or not cfg["FERNET"]:
            sec_path = Path(cfg["DB_PATH"]).with_suffix(".devsecrets.json")
            sec_path.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            if sec_path.exists():
                data = json.loads(sec_path.read_text())
            changed = False
            for k in ("SECRET", "PEPPER", "FERNET"):
                if not data.get(k):
                    data[k] = Fernet.generate_key().decode() if k == "FERNET" else secrets.token_hex(32)
                    changed = True
            if changed:
                sec_path.write_text(json.dumps(data))
                try:
                    os.chmod(sec_path, 0o600)
                except OSError:
                    pass
            cfg["SECRET"] = cfg["SECRET"] or data["SECRET"]
            cfg["PEPPER"] = cfg["PEPPER"] or data["PEPPER"]
            cfg["FERNET"] = cfg["FERNET"] or data["FERNET"]
    return cfg


# --------------------------------------------------------------------------- helpers
def now():
    return int(time.time())


def iso(ts):
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def b64(b):
    return base64.b64encode(b).decode()


def hash_password(pw, n=2 ** 15):
    if _ARGON is not None:
        return _ARGON.hash(pw)
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=8, p=1, maxmem=2 ** 27, dklen=32)
    return f"scrypt${n}$8$1${b64(salt)}${b64(dk)}"


def verify_password(stored, pw):
    try:
        if stored.startswith("$argon2"):
            if _ARGON is None:
                return False
            try:
                return _ARGON.verify(stored, pw)
            except (VerifyMismatchError, InvalidHashError):
                return False
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=2 ** 27, dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


def password_problem(pw, username):
    if len(pw) < 12:
        return "La contraseña debe tener al menos 12 caracteres."
    if len(pw) > 128:
        return "La contraseña es demasiado larga (máximo 128)."
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)
            and re.search(r"[^A-Za-z0-9]", pw)):
        return "Debe incluir mayúsculas, minúsculas, números y un símbolo."
    low = pw.lower()
    if low in ("admin", "administrator") or "admin" == low.strip() or username.lower() in low:
        return "La contraseña no puede contener el nombre de usuario ni valores por defecto."
    if "password" in low or "123456" in low:
        return "La contraseña es demasiado común."
    return None


class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, bucket, limit, window=60):
        t = time.monotonic()
        with self.lock:
            q = self.hits[bucket]
            while q and q[0] <= t - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(t)
            if len(self.hits) > 20000:  # crude memory guard
                for k in [k for k, v in self.hits.items() if not v][:5000]:
                    self.hits.pop(k, None)
            return True


def roblox_fetch_user(uid):
    """Fetch public Roblox profile. Returns dict or None. Replaceable (tests mock it)."""
    try:
        req = urllib.request.Request(
            f"https://users.roblox.com/v1/users/{int(uid)}",
            headers={"Accept": "application/json", "User-Agent": "LexyHubLicense/1.0"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read(65536))
        return {"id": int(data["id"]), "name": str(data["name"]),
                "displayName": str(data.get("displayName") or data["name"]),
                "description": str(data.get("description") or "")}
    except Exception:
        return None


# --------------------------------------------------------------------------- app factory
def create_app(overrides=None):
    cfg = load_config(overrides)
    app = Flask(__name__, static_folder=None)
    app.config["LEXY"] = cfg
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    app.extensions["limiter"] = RateLimiter()
    app.extensions["roblox_fetch"] = roblox_fetch_user
    if cfg["TRUST_PROXY"]:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    Path(cfg["DB_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    init_db(cfg)

    # ---- db access
    def db():
        if "db" not in g:
            conn = sqlite3.connect(cfg["DB_PATH"], timeout=15, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 15000")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    fernet = Fernet(cfg["FERNET"].encode())

    def key_plain(row):
        """Key completa para el administrador. None si la licencia es anterior al cifrado."""
        if not row["key_enc"]:
            return None
        try:
            return fernet.decrypt(row["key_enc"].encode()).decode()
        except InvalidToken:
            return None

    def hmac_hex(tag, value):
        return hmac.new(cfg["PEPPER"].encode(), f"{tag}:{value}".encode(), hashlib.sha256).hexdigest()

    def err(code, message, status=400, **extra):
        body = {"ok": False, "code": code, "message": message}
        body.update(extra)
        return jsonify(body), status

    def audit(action, result, license_id=None, admin=None, reason=None):
        db().execute(
            "INSERT INTO audit_log (created_at, action, license_id, admin_id, admin_name, result, reason, ip)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (now(), action, license_id, admin["id"] if admin else None,
             admin["username"] if admin else None, result, (reason or "")[:300] or None, request.remote_addr))

    def client_ip():
        return request.remote_addr or "?"

    # ---- security headers / CSRF origin
    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        if cfg["ENV"] == "production":
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.before_request
    def origin_check():
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.path.startswith("/api/admin/"):
            origin = request.headers.get("Origin")
            if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
                return err("bad_origin", "Origen no permitido.", 403)

    @app.errorhandler(404)
    def e404(_e):
        if request.path.startswith("/api/"):
            return err("not_found", "Recurso no encontrado.", 404)
        resp = send_from_directory(WEB_DIR, "index.html")
        resp.status_code = 404
        return resp

    @app.errorhandler(405)
    def e405(_e):
        return err("method_not_allowed", "Método no permitido.", 405)

    @app.errorhandler(413)
    def e413(_e):
        return err("too_large", "Solicitud demasiado grande.", 413)

    @app.errorhandler(Exception)
    def e500(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return err("http_error", e.description or "Error.", e.code or 500)
        app.logger.exception("Unhandled error")
        return err("server_error", "Error interno del servidor.", 500)

    # ---- static web
    @app.get("/")
    def index():
        resp = send_from_directory(WEB_DIR, "index.html")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(WEB_DIR, name)

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "server_time": now()})

    # ======================================================================= admin auth
    def current_session():
        sid = request.cookies.get("lexy_sid")
        if not sid or len(sid) > 128:
            return None, None
        h = hashlib.sha256(sid.encode()).hexdigest()
        t = now()
        row = db().execute(
            "SELECT s.*, a.username, a.must_change_password, a.status AS admin_status "
            "FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.id_hash=?", (h,)).fetchone()
        if not row or row["status"] != "active" or row["expires_at"] <= t \
                or row["last_seen_at"] + cfg["IDLE_MINUTES"] * 60 <= t or row["admin_status"] != "active":
            if row and row["status"] == "active":
                db().execute("UPDATE sessions SET status='revoked' WHERE id_hash=?", (h,))
            return None, None
        db().execute("UPDATE sessions SET last_seen_at=? WHERE id_hash=?", (t, h))
        admin = {"id": row["admin_id"], "username": row["username"],
                 "must_change_password": bool(row["must_change_password"])}
        return admin, row

    def admin_required(allow_pending=False, csrf=True):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                if not app.extensions["limiter"].allow(("admin", client_ip()), cfg["ADMIN_RATE"]):
                    return err("rate_limited", "Demasiadas solicitudes.", 429)
                admin, sess = current_session()
                if not admin:
                    return err("unauthorized", "Sesión no válida o expirada.", 401)
                if csrf and request.method != "GET":
                    tok = request.headers.get("X-CSRF-Token", "")
                    if not hmac.compare_digest(tok, sess["csrf_token"]):
                        return err("csrf", "Token CSRF inválido.", 403)
                if admin["must_change_password"] and not allow_pending:
                    return err("password_change_required",
                               "Debes establecer una contraseña nueva antes de usar el panel.", 403)
                g.admin, g.sess = admin, sess
                return fn(*a, **kw)
            return wrapper
        return deco

    def json_body():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def new_session(admin_id):
        sid = secrets.token_urlsafe(32)
        t = now()
        csrf = secrets.token_urlsafe(24)
        db().execute(
            "INSERT INTO sessions (id_hash, admin_id, csrf_token, created_at, expires_at, last_seen_at, status, ip)"
            " VALUES (?,?,?,?,?,?, 'active', ?)",
            (hashlib.sha256(sid.encode()).hexdigest(), admin_id, csrf, t,
             t + int(cfg["SESSION_HOURS"] * 3600), t, client_ip()))
        return sid, csrf

    def set_cookie(resp, sid):
        resp.set_cookie("lexy_sid", sid, max_age=int(cfg["SESSION_HOURS"] * 3600), httponly=True,
                        secure=bool(cfg["COOKIE_SECURE"]), samesite="Strict", path="/")

    @app.post("/api/admin/login")
    def login():
        data = json_body()
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not isinstance(password, str) or not username or not password \
                or len(username) > 64 or len(password) > 256:
            return err("invalid_input", "Usuario y contraseña son obligatorios.", 400)
        ip, t = client_ip(), now()
        win = t - cfg["LOGIN_WINDOW"]
        c = db()
        fails_ip = c.execute("SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND created_at>?",
                             (ip, win)).fetchone()[0]
        fails_user = c.execute("SELECT COUNT(*) FROM login_attempts WHERE username=? AND success=0 AND created_at>?",
                               (username.lower(), win)).fetchone()[0]
        if fails_ip >= cfg["LOGIN_MAX_FAILS_IP"] or fails_user >= cfg["LOGIN_MAX_FAILS_USER"]:
            audit("admin.login", "failure", reason="locked_out")
            return err("locked", "Demasiados intentos fallidos. Espera unos minutos e inténtalo de nuevo.", 429)
        row = c.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        ok = False
        if row and row["status"] == "active":
            ok = verify_password(row["password_hash"], password)
        else:  # equalise timing
            verify_password("scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$" + b64(b"x" * 32), password)
        c.execute("INSERT INTO login_attempts (ip, username, created_at, success) VALUES (?,?,?,?)",
                  (ip, username.lower(), t, 1 if ok else 0))
        if not ok:
            audit("admin.login", "failure", reason="bad_credentials")
            return err("bad_credentials", "Usuario o contraseña incorrectos.", 401)
        sid, csrf = new_session(row["id"])
        c.execute("UPDATE admins SET last_login_at=? WHERE id=?", (t, row["id"]))
        audit("admin.login", "success", admin={"id": row["id"], "username": row["username"]})
        resp = jsonify({"ok": True, "username": row["username"],
                        "must_change_password": bool(row["must_change_password"]), "csrf_token": csrf})
        set_cookie(resp, sid)
        return resp

    @app.post("/api/admin/logout")
    @admin_required(allow_pending=True)
    def logout():
        db().execute("UPDATE sessions SET status='revoked' WHERE id_hash=?", (g.sess["id_hash"],))
        audit("admin.logout", "success", admin=g.admin)
        resp = jsonify({"ok": True})
        resp.delete_cookie("lexy_sid", path="/")
        return resp

    @app.get("/api/admin/me")
    @admin_required(allow_pending=True)
    def me():
        return jsonify({"ok": True, "username": g.admin["username"],
                        "must_change_password": g.admin["must_change_password"],
                        "csrf_token": g.sess["csrf_token"], "license_types": cfg["LICENSE_TYPES"],
                        "server_time": now()})

    @app.post("/api/admin/password")
    @admin_required(allow_pending=True)
    def change_password():
        data = json_body()
        cur, new = data.get("current_password"), data.get("new_password")
        if not isinstance(cur, str) or not isinstance(new, str):
            return err("invalid_input", "Datos incompletos.", 400)
        c = db()
        row = c.execute("SELECT * FROM admins WHERE id=?", (g.admin["id"],)).fetchone()
        if not verify_password(row["password_hash"], cur):
            audit("admin.password_change", "failure", admin=g.admin, reason="wrong_current_password")
            return err("bad_credentials", "La contraseña actual es incorrecta.", 401)
        problem = password_problem(new, row["username"])
        if problem:
            return err("weak_password", problem, 400)
        if verify_password(row["password_hash"], new):
            return err("weak_password", "La nueva contraseña debe ser distinta de la actual.", 400)
        c.execute("UPDATE admins SET password_hash=?, must_change_password=0 WHERE id=?",
                  (hash_password(new, cfg["SCRYPT_N"]), row["id"]))
        c.execute("UPDATE sessions SET status='revoked' WHERE admin_id=?", (row["id"],))  # rotate all sessions
        sid, csrf = new_session(row["id"])
        audit("admin.password_change", "success", admin=g.admin)
        resp = jsonify({"ok": True, "csrf_token": csrf, "must_change_password": False})
        set_cookie(resp, sid)
        return resp

    # ======================================================================= license helpers
    STATUS_SQL = ("CASE WHEN status='revoked' THEN 'revoked' WHEN status='pending' THEN 'pending' "
                  "WHEN is_permanent=0 AND expires_at<=:now THEN 'expired' ELSE 'active' END")

    def eff_status(row, t):
        if row["status"] == "revoked":
            return "revoked"
        if row["status"] == "pending":
            return "pending"
        if not row["is_permanent"] and row["expires_at"] is not None and row["expires_at"] <= t:
            return "expired"
        return "active"

    def license_json(r, t, resets=None):
        remaining = None
        if not r["is_permanent"] and r["expires_at"] is not None and r["status"] == "active":
            remaining = max(0, r["expires_at"] - t)
        out = {
            "id": r["id"], "key": key_plain(r), "key_hint": r["key_hint"], "license_type": r["license_type"],
            "remaining_seconds": remaining, "server_time": t,
            "activated_ip": r["activated_ip"], "last_ip": r["last_ip"],
            "status": eff_status(r, t), "is_permanent": bool(r["is_permanent"]),
            "duration_seconds": r["duration_seconds"],
            "created_at": r["created_at"], "activated_at": r["activated_at"], "expires_at": r["expires_at"],
            "revoked_at": r["revoked_at"], "last_validated_at": r["last_validated_at"],
            "roblox_user_id": r["roblox_user_id"], "roblox_username": r["roblox_username"],
            "roblox_display": r["roblox_display"],
            "device_bound": r["hwid_hash"] is not None,
            "device_fingerprint": (r["hwid_hash"][:10] if r["hwid_hash"] else None),
            "device_source": r["hwid_source"],
            "device_first_bound_at": r["hwid_first_bound_at"], "device_bound_at": r["hwid_bound_at"],
        }
        if resets is not None:
            out["hwid_resets"] = resets
        return out

    def new_key():
        groups = ["".join(secrets.choice(KEY_ALPHABET) for _ in range(4)) for _ in range(4)]
        return "LEXY-" + "-".join(groups)

    # ======================================================================= admin: generate / list
    @app.post("/api/admin/licenses/generate")
    @admin_required()
    def generate():
        data = json_body()
        qty = data.get("quantity")
        if isinstance(qty, bool) or not isinstance(qty, int) or not 1 <= qty <= MAX_QTY:
            return err("invalid_input", f"La cantidad debe ser un entero entre 1 y {MAX_QTY}.", 400)
        ltype = data.get("license_type")
        if ltype not in cfg["LICENSE_TYPES"]:
            return err("invalid_input", "Tipo de licencia no válido.", 400)
        dur = data.get("duration")
        if not isinstance(dur, dict):
            return err("invalid_input", "Duración no válida.", 400)
        preset = dur.get("preset")
        permanent, seconds = False, None
        if preset == "permanent":
            permanent = True
        elif preset in ADMIN_PRESETS:
            seconds = ADMIN_PRESETS[preset]
        elif preset == "custom":
            val, unit = dur.get("custom_value"), dur.get("custom_unit")
            if isinstance(val, bool) or not isinstance(val, int) or val < 1 or unit not in UNIT_SECONDS:
                return err("invalid_input", "Duración personalizada no válida.", 400)
            seconds = val * UNIT_SECONDS[unit]
            if seconds > MAX_DURATION:
                return err("invalid_input", "La duración personalizada máxima es de 3650 días.", 400)
        else:
            return err("invalid_input", "Duración no válida.", 400)

        c, t, keys = db(), now(), []
        c.execute("BEGIN IMMEDIATE")
        try:
            lids = []
            while len(keys) < qty:
                k = new_key()
                try:
                    cur = c.execute(
                        "INSERT INTO licenses (key_hash, key_hint, key_enc, license_type, duration_seconds,"
                        " is_permanent, status, created_at, created_by) VALUES (?,?,?,?,?,?, 'pending', ?, ?)",
                        (hmac_hex("key", k), "LEXY-****-****-****-" + k[-4:], fernet.encrypt(k.encode()).decode(),
                         ltype, seconds, 1 if permanent else 0, t, g.admin["id"]))
                except sqlite3.IntegrityError:  # astronomically unlikely duplicate: retry
                    continue
                keys.append({"id": cur.lastrowid, "key": k})
                lids.append(cur.lastrowid)
            audit("license.generate", "success", admin=g.admin,
                  reason=f"qty={qty};type={ltype};duration={'permanent' if permanent else seconds}")
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        return jsonify({"ok": True, "count": len(keys), "keys": keys,
                        "message": f"{len(keys)} key(s) generada(s) correctamente. Cópialas ahora: no se volverán a mostrar."})

    def license_filters(args, t):
        where, params = ["1=1"], {"now": t}
        st = args.get("status", "")
        if st in ("pending", "active", "expired", "revoked"):
            where.append(f"({STATUS_SQL}) = :st")
            params["st"] = st
        dev = args.get("device", "")
        if dev == "bound":
            where.append("hwid_hash IS NOT NULL")
        elif dev == "unbound":
            where.append("hwid_hash IS NULL")
        q = (args.get("q") or "").strip()[:64]
        if q:
            esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conds = ["key_hint LIKE :q ESCAPE '\\'", "roblox_username LIKE :q ESCAPE '\\'",
                     "roblox_display LIKE :q ESCAPE '\\'"]
            params["q"] = f"%{esc}%"
            if q.isdigit():
                conds += ["id = :qid", "roblox_user_id = :qid"]
                params["qid"] = int(q)
            where.append("(" + " OR ".join(conds) + ")")
        return " AND ".join(where), params

    def paging(args, default=15):
        try:
            page = max(1, int(args.get("page", 1)))
            per = min(100, max(1, int(args.get("per_page", default))))
        except ValueError:
            page, per = 1, default
        return page, per

    @app.get("/api/admin/licenses")
    @admin_required()
    def list_licenses():
        t = now()
        where, params = license_filters(request.args, t)
        page, per = paging(request.args)
        c = db()
        total = c.execute(f"SELECT COUNT(*) FROM licenses WHERE {where}", params).fetchone()[0]
        rows = c.execute(
            f"SELECT licenses.*, (SELECT COUNT(*) FROM audit_log a WHERE a.license_id=licenses.id"
            f" AND a.action='license.hwid_reset' AND a.result='success') AS resets FROM licenses WHERE {where} "
            f"ORDER BY licenses.id DESC LIMIT :lim OFFSET :off",
            {**params, "lim": per, "off": (page - 1) * per}).fetchall()
        return jsonify({"ok": True, "total": total, "page": page, "per_page": per,
                        "pages": max(1, -(-total // per)), "server_time": t,
                        "items": [license_json(r, t, r["resets"]) for r in rows]})

    def get_license(lid):
        return db().execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()

    @app.get("/api/admin/licenses/<int:lid>")
    @admin_required()
    def license_detail(lid):
        r = get_license(lid)
        if not r:
            return err("not_found", "Licencia no encontrada.", 404)
        t = now()
        hist = db().execute("SELECT created_at, action, result, admin_name, reason FROM audit_log "
                            "WHERE license_id=? ORDER BY id DESC LIMIT 100", (lid,)).fetchall()
        resets = sum(1 for h in hist if h["action"] == "license.hwid_reset" and h["result"] == "success")
        return jsonify({"ok": True, "server_time": t, "license": license_json(r, t, resets),
                        "history": [dict(h) for h in hist]})

    def simple_action(lid, action, reason_default):
        r = get_license(lid)
        if not r:
            return None, err("not_found", "Licencia no encontrada.", 404)
        reason = json_body().get("reason")
        reason = reason.strip()[:200] if isinstance(reason, str) and reason.strip() else reason_default
        return (r, reason), None

    @app.post("/api/admin/licenses/<int:lid>/revoke")
    @admin_required()
    def revoke(lid):
        res, e = simple_action(lid, "revoke", "Revocada desde el panel")
        if e:
            return e
        r, reason = res
        if r["status"] == "revoked":
            return err("already_revoked", "La licencia ya estaba revocada.", 409)
        db().execute("UPDATE licenses SET status='revoked', revoked_at=? WHERE id=?", (now(), lid))
        audit("license.revoke", "success", lid, g.admin, reason)
        return jsonify({"ok": True, "message": "Licencia revocada."})

    @app.post("/api/admin/licenses/<int:lid>/reset-hwid")
    @admin_required()
    def reset_hwid(lid):
        res, e = simple_action(lid, "reset", "Restablecimiento de HWID")
        if e:
            return e
        r, reason = res
        if r["status"] == "revoked":
            return err("revoked", "No se puede restablecer una licencia revocada.", 409)
        if r["hwid_hash"] is None:
            return err("not_bound", "La licencia no tiene un dispositivo vinculado.", 409)
        # Only the device binding is cleared. The Roblox account link is intentionally untouched.
        db().execute("UPDATE licenses SET hwid_hash=NULL, hwid_source=NULL, hwid_bound_at=NULL WHERE id=?", (lid,))
        audit("license.hwid_reset", "success", lid, g.admin, reason)
        return jsonify({"ok": True, "message": "HWID restablecido. La cuenta de Roblox sigue vinculada."})

    @app.post("/api/admin/licenses/<int:lid>/unlink-account")
    @admin_required()
    def unlink_account(lid):
        res, e = simple_action(lid, "unlink", "Desvinculación de cuenta")
        if e:
            return e
        r, reason = res
        if r["roblox_user_id"] is None:
            return err("not_linked", "La licencia no tiene una cuenta vinculada.", 409)
        # Unlinking the account also drops the device binding so the new owner re-verifies cleanly.
        c = db()
        c.execute("UPDATE licenses SET roblox_user_id=NULL, roblox_username=NULL, roblox_display=NULL,"
                  " hwid_hash=NULL, hwid_source=NULL, hwid_bound_at=NULL WHERE id=?", (lid,))
        c.execute("DELETE FROM roblox_challenges WHERE license_id=?", (lid,))
        audit("license.unlink_account", "success", lid, g.admin, reason)
        return jsonify({"ok": True, "message": "Cuenta desvinculada. La siguiente activación requerirá verificar la nueva cuenta."})

    @app.post("/api/admin/licenses/<int:lid>/delete")
    @admin_required()
    def delete_license(lid):
        res, e = simple_action(lid, "delete", "Borrado desde el panel")
        if e:
            return e
        r, reason = res
        # Se registra antes de borrar; el id queda en el texto porque la FK se pondrá a NULL.
        audit("license.delete", "success", None, g.admin, f"id={lid};{reason}")
        db().execute("DELETE FROM licenses WHERE id=?", (lid,))
        return jsonify({"ok": True, "message": "Licencia borrada."})

    # ======================================================================= admin: stats / audit
    @app.get("/api/admin/stats")
    @admin_required()
    def stats():
        t, c = now(), db()
        row = c.execute(
            "SELECT COUNT(*) total,"
            " SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending,"
            " SUM(CASE WHEN status='revoked' THEN 1 ELSE 0 END) revoked,"
            " SUM(CASE WHEN status='active' AND is_permanent=0 AND expires_at<=? THEN 1 ELSE 0 END) expired,"
            " SUM(CASE WHEN status='active' AND (is_permanent=1 OR expires_at>?) THEN 1 ELSE 0 END) active,"
            " COUNT(DISTINCT roblox_user_id) accounts FROM licenses", (t, t)).fetchone()
        acts = c.execute(
            "SELECT a.created_at, l.key_hint, l.roblox_username, a.action FROM audit_log a "
            "LEFT JOIN licenses l ON l.id=a.license_id WHERE a.action IN ('license.activate','license.rebind') "
            "AND a.result='success' ORDER BY a.id DESC LIMIT 8").fetchall()
        evs = c.execute(
            "SELECT created_at, action, result, admin_name, reason, license_id FROM audit_log "
            "WHERE action NOT IN ('license.activate','license.rebind','client.reject') ORDER BY id DESC LIMIT 8").fetchall()
        return jsonify({"ok": True, "server_time": t, "total": row["total"] or 0, "active": row["active"] or 0,
                        "expired": row["expired"] or 0, "revoked": row["revoked"] or 0,
                        "pending": row["pending"] or 0, "linked_accounts": row["accounts"] or 0,
                        "recent_activations": [dict(a) for a in acts], "recent_events": [dict(e) for e in evs]})

    @app.get("/api/admin/audit")
    @admin_required()
    def audit_list():
        page, per = paging(request.args, 20)
        kind = request.args.get("kind", "admin")
        cond = "1=1"
        if kind == "admin":
            cond = "action NOT IN ('license.activate','license.rebind','client.reject')"
        elif kind == "client":
            cond = "action IN ('license.activate','license.rebind','client.reject')"
        c = db()
        total = c.execute(f"SELECT COUNT(*) FROM audit_log WHERE {cond}").fetchone()[0]
        rows = c.execute(
            f"SELECT a.id, a.created_at, a.action, a.result, a.admin_name, a.reason, a.license_id, l.key_hint "
            f"FROM audit_log a LEFT JOIN licenses l ON l.id=a.license_id WHERE {cond.replace('action', 'a.action')} "
            f"ORDER BY a.id DESC LIMIT ? OFFSET ?", (per, (page - 1) * per)).fetchall()
        return jsonify({"ok": True, "total": total, "page": page, "per_page": per,
                        "pages": max(1, -(-total // per)), "items": [dict(r) for r in rows]})

    # ======================================================================= client API
    def client_payload(r, t, verified=True, message=None):
        remaining = None if r["is_permanent"] else max(0, (r["expires_at"] or t) - t)
        return {
            "ok": True, "status": "active", "message": message or "Licencia activa.",
            "server_time": t, "license_type": r["license_type"], "is_permanent": bool(r["is_permanent"]),
            "activated_at": r["activated_at"], "expires_at": r["expires_at"], "remaining_seconds": remaining,
            "key_hint": r["key_hint"],
            "roblox": {"user_id": r["roblox_user_id"], "username": r["roblox_username"],
                       "display_name": r["roblox_display"]},
            "device": {"bound": r["hwid_hash"] is not None, "source": r["hwid_source"],
                       "strength": "weak" if r["hwid_source"] == "generated" else "hardware_id"},
            "identity_verified": verified,
        }

    def parse_client(data):
        key = data.get("key")
        hwid = data.get("hwid")
        src = data.get("hwid_source")
        uid = data.get("roblox_user_id")
        if not isinstance(key, str) or not KEY_RE.match(key.strip().upper()):
            return None, ("invalid_key", "La key no tiene un formato válido.")
        if not isinstance(hwid, str) or not 8 <= len(hwid) <= 256 or not hwid.isprintable():
            return None, ("invalid_input", "Identificador de dispositivo no válido.")
        if src not in HWID_SOURCES:
            return None, ("invalid_input", "Origen de identificador no válido.")
        if isinstance(uid, bool) or not isinstance(uid, int) or not 0 < uid < 2 ** 53:
            return None, ("invalid_input", "Identificador de cuenta Roblox no válido.")
        uname = data.get("roblox_username")
        uname = uname[:64] if isinstance(uname, str) else None
        return {"key": key.strip().upper(), "hwid": hwid, "src": src, "uid": uid, "uname": uname,
                "verify": bool(data.get("verify"))}, None

    def reject(code, message, status, lid=None, audit_reason=None):
        audit("client.reject", "failure", lid, None, audit_reason or code)
        return err(code, message, status, status_code=code,
                   status_label={"revoked": "revoked", "expired": "expired", "invalid_key": "invalid"}.get(code, code))

    def client_flow(mode):
        ip = client_ip()
        lim = app.extensions["limiter"]
        if not lim.allow(("client", ip), cfg["CLIENT_RATE"]) or \
                (mode == "activate" and not lim.allow(("activate", ip), cfg["ACTIVATE_RATE"])):
            return err("rate_limited", "Demasiadas solicitudes. Inténtalo en un minuto.", 429)
        p, problem = parse_client(json_body())
        if problem:
            return err(problem[0], problem[1], 400 if problem[0] != "invalid_key" else 403)
        c = db()
        kh, hh = hmac_hex("key", p["key"]), hmac_hex("hwid", p["hwid"])
        rinfo = None

        # Phase 0 (outside any write transaction): network call to Roblox, only when completing verification.
        if mode == "activate" and cfg["ROBLOX_VERIFY"] == "profile" and p["verify"]:
            pre = c.execute("SELECT id, roblox_user_id FROM licenses WHERE key_hash=?", (kh,)).fetchone()
            if pre and pre["roblox_user_id"] is None:
                rinfo = app.extensions["roblox_fetch"](p["uid"])
                if rinfo is None:
                    return err("roblox_unavailable", "No se pudo consultar Roblox. Inténtalo de nuevo.", 503)

        c.execute("BEGIN IMMEDIATE")
        try:
            r = c.execute("SELECT * FROM licenses WHERE key_hash=?", (kh,)).fetchone()
            t = now()
            if not r:
                resp = reject("invalid_key", "KEY INVÁLIDA", 403)
            else:
                st = eff_status(r, t)
                if st == "revoked":
                    resp = reject("revoked", "KEY REVOCADA", 403, r["id"])
                elif st == "expired":
                    resp = reject("expired", "KEY EXPIRADA", 403, r["id"])
                elif r["roblox_user_id"] is not None and r["roblox_user_id"] != p["uid"]:
                    resp = reject("account_mismatch", "Esta key está vinculada a otra cuenta de Roblox.", 403, r["id"])
                elif r["hwid_hash"] is not None and not hmac.compare_digest(r["hwid_hash"], hh):
                    resp = reject("hwid_mismatch", "Esta key está vinculada a otro dispositivo.", 403, r["id"])
                elif r["hwid_hash"] is not None:  # fully bound and matching -> valid
                    c.execute("UPDATE licenses SET last_validated_at=?, last_ip=? WHERE id=?",
                              (t, client_ip(), r["id"]))
                    r = get_license(r["id"])
                    resp = jsonify(client_payload(r, t))
                elif mode == "validate":
                    code = "not_activated" if r["status"] == "pending" else "hwid_not_bound"
                    resp = err(code, "La licencia necesita activarse en este dispositivo.", 403, status_code=code)
                else:
                    resp = bind_license(c, r, p, t, rinfo)
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        return resp

    def bind_license(c, r, p, t, rinfo):
        """Runs inside BEGIN IMMEDIATE. Binds device (and account on first activation)."""
        verified = True
        uname, udisp = r["roblox_username"], r["roblox_display"]
        if r["roblox_user_id"] is None:  # first-time account link requires ownership proof
            if cfg["ROBLOX_VERIFY"] == "profile":
                ch = c.execute("SELECT * FROM roblox_challenges WHERE license_id=? AND roblox_user_id=?",
                               (r["id"], p["uid"])).fetchone()
                if not ch or ch["expires_at"] <= t:
                    code = "lexy-" + "".join(secrets.choice(KEY_ALPHABET).lower() for _ in range(10))
                    c.execute("INSERT OR REPLACE INTO roblox_challenges (license_id, roblox_user_id, code, created_at,"
                              " expires_at) VALUES (?,?,?,?,?)", (r["id"], p["uid"], code, t, t + cfg["CHALLENGE_TTL"]))
                    return verification_response(code, cfg["CHALLENGE_TTL"], t)
                if rinfo is None:  # challenge exists but client hasn't asked to verify yet
                    return verification_response(ch["code"], ch["expires_at"] - t, t)
                if rinfo["id"] != p["uid"] or ch["code"] not in rinfo["description"].lower():
                    audit("client.reject", "failure", r["id"], None, "verification_failed")
                    return err("verification_failed",
                               "No encontramos el código en la descripción de tu perfil de Roblox.", 403,
                               status_code="verification_failed", verification_code=ch["code"],
                               expires_in=ch["expires_at"] - t)
                uname, udisp = rinfo["name"], rinfo["displayName"]
            else:  # LEXY_ROBLOX_VERIFY=off: dev only, identity comes from the client
                verified = False
                uname = p["uname"] or f"user{p['uid']}"
                udisp = uname
        first_activation = r["activated_at"] is None
        had_account = r["roblox_user_id"] is not None
        expires = None if r["is_permanent"] else (t + r["duration_seconds"] if first_activation else r["expires_at"])
        c.execute(
            "UPDATE licenses SET status='active', activated_at=COALESCE(activated_at, ?), expires_at=?,"
            " roblox_user_id=?, roblox_username=?, roblox_display=?, hwid_hash=?, hwid_source=?,"
            " hwid_first_bound_at=COALESCE(hwid_first_bound_at, ?), hwid_bound_at=?, last_validated_at=?,"
            " activated_ip=COALESCE(activated_ip, ?), last_ip=? WHERE id=?",
            (t, expires, p["uid"], uname, udisp, hmac_hex("hwid", p["hwid"]), p["src"], t, t, t,
             client_ip(), client_ip(), r["id"]))
        c.execute("DELETE FROM roblox_challenges WHERE license_id=?", (r["id"],))
        audit("license.activate" if first_activation else "license.rebind", "success", r["id"], None,
              "first activation" if first_activation else "device rebound after reset")
        fresh = c.execute("SELECT * FROM licenses WHERE id=?", (r["id"],)).fetchone()
        return jsonify(client_payload(fresh, t, verified, "Licencia activada correctamente."))

    def verification_response(code, ttl, t):
        return jsonify({"ok": False, "status": "verification_required", "code": "verification_required",
                        "status_code": "verification_required", "verification_code": code, "expires_in": ttl,
                        "server_time": t,
                        "message": "Pega este código en la descripción (About) de tu perfil de Roblox y pulsa Verificar."}), 202

    @app.post("/api/client/activate")
    def client_activate():
        return client_flow("activate")

    @app.post("/api/client/validate")
    def client_validate():
        return client_flow("validate")

    # ---- bootstrap admin
    with app.app_context():
        conn = sqlite3.connect(cfg["DB_PATH"], isolation_level=None)
        try:
            if conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
                conn.execute("INSERT INTO admins (username, password_hash, must_change_password, status, created_at)"
                             " VALUES ('admin', ?, 1, 'active', ?)",
                             (hash_password(cfg["BOOTSTRAP_PASSWORD"], cfg["SCRYPT_N"]), now()))
                app.logger.warning("Initial admin created. Log in and change the password immediately.")
        finally:
            conn.close()
    return app


def init_db(cfg):
    conn = sqlite3.connect(cfg["DB_PATH"])
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript((BASE_DIR / "schema.sql").read_text())
        # Migración: bases creadas antes de añadir estas columnas.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(licenses)")}
        for col in ("key_enc", "activated_ip", "last_ip"):
            if col not in cols:
                conn.execute(f"ALTER TABLE licenses ADD COLUMN {col} TEXT")
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    application = create_app()
    application.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
