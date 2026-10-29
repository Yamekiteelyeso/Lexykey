-- Lexy Hub License System - SQLite schema (idempotent)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admins (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash        TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0,1)),
    status               TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at           INTEGER NOT NULL,
    last_login_at        INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id_hash      TEXT PRIMARY KEY,
    admin_id     INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    ip           TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_admin ON sessions(admin_id);

CREATE TABLE IF NOT EXISTS licenses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash         TEXT NOT NULL UNIQUE,
    key_hint         TEXT NOT NULL,
    license_type     TEXT NOT NULL,
    duration_seconds INTEGER,
    is_permanent     INTEGER NOT NULL DEFAULT 0 CHECK (is_permanent IN (0,1)),
    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','revoked')),
    created_at       INTEGER NOT NULL,
    created_by       INTEGER REFERENCES admins(id),
    activated_at     INTEGER,
    expires_at       INTEGER,
    revoked_at       INTEGER,
    roblox_user_id   INTEGER,
    roblox_username  TEXT,
    roblox_display   TEXT,
    hwid_hash        TEXT,
    hwid_source      TEXT,
    hwid_first_bound_at INTEGER,
    hwid_bound_at    INTEGER,
    last_validated_at INTEGER,
    CHECK (is_permanent = 1 OR duration_seconds IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
CREATE INDEX IF NOT EXISTS idx_licenses_roblox ON licenses(roblox_user_id);

CREATE TABLE IF NOT EXISTS roblox_challenges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id  INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    roblox_user_id INTEGER NOT NULL,
    code        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    UNIQUE (license_id, roblox_user_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  INTEGER NOT NULL,
    action      TEXT NOT NULL,
    license_id  INTEGER REFERENCES licenses(id) ON DELETE SET NULL,
    admin_id    INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    admin_name  TEXT,
    result      TEXT NOT NULL CHECK (result IN ('success','failure')),
    reason      TEXT,
    ip          TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_license ON audit_log(license_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    username    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    success     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts ON login_attempts(ip, username, created_at);
