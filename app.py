"""ZamGig - a Zambian gig marketplace API (TaskRabbit-style).

Run locally:   python app_v2_hardened.py
Production:    gunicorn app_v2_hardened:app   (and set the environment variables below)

Environment variables (all optional for local development):
  ZAMGIG_SECRET        session signing key (set this in production)
  ZAMGIG_ADMIN_PHONE   phone number of the Super Admin to promote/create on first run
  ZAMGIG_ADMIN_PASSWORD password for a newly-created Super Admin
  ZAMGIG_PRODUCTION=1  enable stricter production startup checks
  ZAMGIG_CSRF=1        require X-CSRF-Token on unsafe authenticated requests
  ZAMGIG_DATABASE_URL  database URL (default: sqlite:///zamgig.db)
  ZAMGIG_CORS_ORIGINS  comma-separated origins allowed to call the API from another site
  ZAMGIG_HTTPS=1       mark session cookies Secure (set this when served over HTTPS)
  ZAMGIG_HOST / PORT   dev server bind address / port
  FLASK_DEBUG=1        enable debug mode (never in production)
"""
import os
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import click
from flask import Flask, jsonify, render_template, request, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, event, func, inspect, or_, text
from sqlalchemy.engine import Engine
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# App + configuration
# --------------------------------------------------------------------------
app = Flask(__name__)


def utcnow():
    """Naive UTC 'now' (avoids the deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def load_secret_key():
    key = os.environ.get("ZAMGIG_SECRET")
    if key:
        if len(key) < 32:
            raise RuntimeError("ZAMGIG_SECRET must be at least 32 characters")
        return key
    if os.environ.get("ZAMGIG_PRODUCTION", "0") == "1":
        raise RuntimeError("ZAMGIG_SECRET must be set when ZAMGIG_PRODUCTION=1")
    path = Path(app.instance_path) / "secret.key"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(secrets.token_hex(32))
    return path.read_text().strip()


def database_url():
    url = os.environ.get("ZAMGIG_DATABASE_URL") or os.environ.get("DATABASE_URL") or "sqlite:///zamgig.db"
    return url.replace("postgres://", "postgresql://", 1) if url.startswith("postgres://") else url


app.config.update(
    SECRET_KEY=load_secret_key(),
    SQLALCHEMY_DATABASE_URI=database_url(),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("ZAMGIG_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_PROFILE_PHOTO_BYTES=2 * 1024 * 1024,
    ZAMGIG_CSRF=os.environ.get("ZAMGIG_CSRF", "0") == "1",
)

if os.environ.get("ZAMGIG_HTTPS") == "1":  # behind Render/Railway/Caddy: trust the proxy for client IP + scheme
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

_origins = [o.strip() for o in os.environ.get("ZAMGIG_CORS_ORIGINS", "").split(",") if o.strip()]
if _origins:  # The bundled frontend is same-origin, so CORS stays off unless asked for.
    CORS(app, origins=_origins, supports_credentials=True)

db = SQLAlchemy(app)

UPLOAD_DIR = Path(app.static_folder or "static") / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

CATEGORIES = ["Construction", "Transport", "Cleaning", "Agriculture", "Technology", "Beauty", "Tutoring", "Other"]
PROVINCES = ["Central", "Copperbelt", "Eastern", "Luapula", "Lusaka", "Muchinga", "Northern", "North-Western", "Southern", "Western"]
GIG_STATUSES = {"open", "assigned", "in_progress", "completed", "cancelled"}
# What a normal user may move a gig to, from each state. Admins can set any status.
TRANSITIONS = {
    "open": {"cancelled"},
    "assigned": {"in_progress", "cancelled", "open"},  # "open" = worker withdraws
    "in_progress": {"completed", "cancelled"},
    "completed": set(),
    "cancelled": set(),
}
MIN_TOPUP, MAX_TOPUP = 10, 20000
MIN_WITHDRAW = 20
MAX_OPEN_GIGS_PER_USER = 20
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    """Better concurrency for SQLite (several users at once)."""
    if type(dbapi_conn).__module__.startswith("sqlite3"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    phone = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    profile_photo = db.Column(db.String(255), nullable=True)
    profile_status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    role = db.Column(db.String(20), default="user", nullable=False)
    bio = db.Column(db.Text, nullable=True)
    skills = db.Column(db.Text, nullable=True)
    availability = db.Column(db.String(100), default="Available", nullable=False)
    rating = db.Column(db.Float, default=0.0, nullable=False)
    rating_count = db.Column(db.Integer, default=0, nullable=False)
    wallet_balance = db.Column(db.Float, default=0.0, nullable=False)
    free_until = db.Column(db.DateTime, nullable=True)
    suspended = db.Column(db.Boolean, default=False, nullable=False)


class Gig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    province = db.Column(db.String(100), nullable=False, index=True)
    city = db.Column(db.String(100), nullable=False, index=True)
    area = db.Column(db.String(100), nullable=False)
    payment = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    owner_id = db.Column(db.Integer, nullable=True, index=True)
    status = db.Column(db.String(30), default="open", nullable=False, index=True)
    scheduled_at = db.Column(db.DateTime, nullable=True)
    assigned_worker_id = db.Column(db.Integer, nullable=True, index=True)
    min_price = db.Column(db.Float, nullable=True)
    max_price = db.Column(db.Float, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    agreed_price = db.Column(db.Float, nullable=True)  # price the owner and worker settled on
    escrow_status = db.Column(db.String(20), nullable=True)  # held | released | refunded
    employer_fee = db.Column(db.Float, nullable=True)  # service fee paid by the poster when funding


class PlatformSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True, index=True)  # NULL = broadcast to everyone
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    kind = db.Column(db.String(30), default="system")
    read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class NotificationRead(db.Model):
    """Per-user 'read' marker for broadcast notifications (so one user reading it doesn't hide it for all)."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    notification_id = db.Column(db.Integer, nullable=False, index=True)


class Favourite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    gig_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gig_id = db.Column(db.Integer, nullable=False, index=True)
    reviewer_id = db.Column(db.Integer, nullable=False)
    worker_id = db.Column(db.Integer, nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gig_id = db.Column(db.Integer, nullable=True, index=True)
    sender_id = db.Column(db.Integer, nullable=False, index=True)
    receiver_id = db.Column(db.Integer, nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    read = db.Column(db.Boolean, default=False, nullable=False)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, nullable=True)
    target_type = db.Column(db.String(30), nullable=False)
    target_id = db.Column(db.Integer, nullable=True)
    reason = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default="open", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class WalletTransaction(db.Model):
    """Immutable-style audit ledger for wallet, fee, withdrawal and escrow movements."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    kind = db.Column(db.String(30), nullable=False)      # topup | fee | withdrawal | escrow_*
    amount = db.Column(db.Float, nullable=False)          # + credit, - debit
    status = db.Column(db.String(20), default="completed", nullable=False, index=True)  # pending | completed | rejected
    method = db.Column(db.String(20), nullable=True)      # mtn | airtel | zamtel | other
    reference = db.Column(db.String(80), nullable=True)   # mobile-money transaction ID / external reference
    payout_phone = db.Column(db.String(30), nullable=True) # withdrawal destination
    gig_id = db.Column(db.Integer, nullable=True)
    note = db.Column(db.String(255), nullable=True)
    reviewed_by = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)


class AuditLog(db.Model):
    """Who did what in the admin area."""
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(60), nullable=False)
    target_type = db.Column(db.String(30), nullable=True)
    target_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)


# --------------------------------------------------------------------------
# Database setup / light migrations
# --------------------------------------------------------------------------
def ensure_column(table, column, definition):
    existing = {c["name"] for c in inspect(db.engine).get_columns(table)}
    if column not in existing:
        db.session.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {column} {definition}'))
        db.session.commit()


LEGACY_INDEXES = [
    ("user", "profile_status"),
    ("gig", "category"), ("gig", "province"), ("gig", "city"), ("gig", "created_at"),
    ("gig", "owner_id"), ("gig", "status"), ("gig", "assigned_worker_id"),
    ("notification", "user_id"), ("favourite", "user_id"),
    ("review", "gig_id"), ("review", "worker_id"),
    ("message", "gig_id"), ("message", "sender_id"), ("message", "receiver_id"),
]


def migrate_existing_schema():
    additions = {
        "user": {
            "bio": "TEXT", "skills": "TEXT", "availability": "VARCHAR(100) DEFAULT 'Available'",
            "rating": "FLOAT DEFAULT 0", "rating_count": "INTEGER DEFAULT 0", "wallet_balance": "FLOAT DEFAULT 0",
            "free_until": "DATETIME", "suspended": "BOOLEAN DEFAULT 0",
        },
        "wallet_transaction": {
            "payout_phone": "VARCHAR(30)",
        },
        "gig": {
            "owner_id": "INTEGER", "status": "VARCHAR(30) DEFAULT 'open'", "scheduled_at": "DATETIME",
            "assigned_worker_id": "INTEGER", "min_price": "FLOAT", "max_price": "FLOAT",
            "completed_at": "DATETIME", "agreed_price": "FLOAT", "escrow_status": "VARCHAR(20)", "employer_fee": "FLOAT",
        },
    }
    for table, cols in additions.items():
        for col, definition in cols.items():
            ensure_column(table, col, definition)
    db.session.execute(text("UPDATE \"user\" SET role='user' WHERE role IS NULL OR role=''"))
    for table, col in LEGACY_INDEXES:  # speeds up search/filtering on databases made by older versions
        db.session.execute(text(f'CREATE INDEX IF NOT EXISTS ix_{table}_{col} ON "{table}" ({col})'))
    db.session.commit()


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def ok(**payload):
    return jsonify({"status": "success", **payload})


def fail(message, code=400):
    return jsonify({"status": "error", "message": message}), code


def iso(dt):
    """System timestamps are stored in UTC; the trailing Z lets browsers show Zambian local time correctly."""
    return dt.isoformat() + "Z" if dt else None


def clean(value, max_len=255):
    return str(value if value is not None else "").strip()[:max_len]


def to_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def to_money(value):
    """Blank -> None. Otherwise a non-negative Kwacha amount, or ValueError."""
    if value is None or str(value).strip() == "":
        return None
    amount = float(value)
    if amount != amount or amount < 0 or amount > 1_000_000:  # NaN / negative / absurd
        raise ValueError("bad amount")
    return round(amount, 2)


def money(value):
    """Normalize all wallet arithmetic to two-decimal Kwacha while retaining Float storage."""
    try:
        return round(float(value or 0), 2)
    except (TypeError, ValueError):
        return 0.0


def parse_dt(value):
    """Accepts ISO strings from the browser. Returns naive datetime or raises ValueError."""
    dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def like(term):
    """Escape % and _ so users can't inject wildcards into searches."""
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def normalize_phone(raw):
    """Zambian mobile -> local format 0977123456. Accepts +260..., 260..., spaces and dashes. None if invalid."""
    digits = re.sub(r"[^\d+]", "", str(raw or ""))
    if digits.startswith("+260"):
        digits = "0" + digits[4:]
    elif digits.startswith("260") and len(digits) == 12:
        digits = "0" + digits[3:]
    return digits if re.fullmatch(r"0[79]\d{8}", digits) else None


def phone_variants(local):
    return [local, "+260" + local[1:], "260" + local[1:]]


def paginate(query):
    """?page=1&per_page=100 (max 200). Returns (rows, meta)."""
    page = max(to_int(request.args.get("page"), 1), 1)
    per_page = min(max(to_int(request.args.get("per_page"), 100), 1), 200)
    total = query.count()
    rows = query.limit(per_page).offset((page - 1) * per_page).all()
    meta = {"total": total, "page": page, "pages": max(-(-total // per_page), 1), "has_more": page * per_page < total}
    return rows, meta


# Tiny in-memory login throttle (per server process). Use Redis or Flask-Limiter if you run several workers.
_failed_logins = defaultdict(deque)


def too_many_attempts(key, limit=5, window=600):
    now, attempts = time.time(), _failed_logins[key]
    while attempts and now - attempts[0] > window:
        attempts.popleft()
    return len(attempts) >= limit


def setting(key, default):
    row = PlatformSetting.query.filter_by(key=key).first()
    if not row:
        row = PlatformSetting(key=key, value=str(default))
        db.session.add(row)
        db.session.commit()
    return row.value


def set_setting(key, value):
    row = PlatformSetting.query.filter_by(key=key).first()
    if not row:
        db.session.add(PlatformSetting(key=key, value=str(value)))
    else:
        row.value = str(value)
        row.updated_at = utcnow()
    db.session.commit()


def notify(user_id, title, message, kind="system"):
    """Queue a notification (committed together with the caller's other changes)."""
    db.session.add(Notification(user_id=user_id, title=title[:150], message=message, kind=kind))


def audit(actor, action, target_type=None, target_id=None, details=""):
    db.session.add(AuditLog(actor_id=actor.id if actor else None, action=action,
                            target_type=target_type, target_id=target_id, details=str(details)[:500]))


# --------------------------------------------------------------------------
# Users, auth decorators, serializers
# --------------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        return db.session.get(User, int(uid))
    except (TypeError, ValueError):
        return None


def is_admin(user):
    return bool(user) and user.role in ("admin", "super_admin")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return fail("Please log in first", 401)
        if user.suspended:
            return fail("Your account is suspended", 403)
        return fn(*args, **kwargs)
    return wrapper


def approved_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return fail("Please log in first", 401)
        if user.suspended:
            return fail("Your account is suspended", 403)
        if user.role == "super_admin" or user.profile_status == "approved":
            return fn(*args, **kwargs)
        return fail("Your profile is awaiting admin approval", 403)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not is_admin(user) or user.suspended:
            return fail("Admin access required", 403)
        return fn(*args, **kwargs)
    return wrapper


def super_admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user.role != "super_admin" or user.suspended:
            return fail("Super Admin access required", 403)
        return fn(*args, **kwargs)
    return wrapper


def user_dict(user):
    """Full private view (the user themself, or an admin)."""
    if not user:
        return None
    return {
        "id": user.id, "name": user.name, "email": user.email, "phone": user.phone,
        "location": user.location, "role": user.role, "profile_status": user.profile_status,
        "profile_photo": user.profile_photo, "bio": user.bio, "skills": user.skills,
        "availability": user.availability, "rating": user.rating, "rating_count": user.rating_count,
        "wallet_balance": round(user.wallet_balance or 0, 2), "free_until": iso(user.free_until),
        "suspended": bool(user.suspended), "created_at": iso(user.created_at),
    }


def public_user_dict(user):
    """What strangers may see: no phone, email or wallet."""
    return {
        "id": user.id, "name": user.name, "location": user.location, "profile_photo": user.profile_photo,
        "bio": user.bio, "skills": user.skills, "availability": user.availability,
        "rating": user.rating, "rating_count": user.rating_count,
        "profile_status": user.profile_status, "created_at": iso(user.created_at),
    }


def shares_gig(a_id, b_id):
    return db.session.query(Gig.id).filter(or_(
        and_(Gig.owner_id == a_id, Gig.assigned_worker_id == b_id),
        and_(Gig.owner_id == b_id, Gig.assigned_worker_id == a_id),
    )).first() is not None


def user_view(target, viewer):
    if viewer and (viewer.id == target.id or is_admin(viewer)):
        return user_dict(target)
    data = public_user_dict(target)
    if viewer and shares_gig(viewer.id, target.id):  # contact details unlock once you're working together
        data["phone"] = target.phone
    return data


def gig_dict(g, viewer=None, people=None, favs=None):
    people = people or {}
    owner, worker = people.get(g.owner_id), people.get(g.assigned_worker_id)
    can_contact = g.owner_id is None or (bool(viewer) and (
        viewer.id in (g.owner_id, g.assigned_worker_id) or is_admin(viewer)))
    return {
        "id": g.id, "title": g.title, "category": g.category, "description": g.description,
        "province": g.province, "city": g.city, "area": g.area, "payment": g.payment,
        "phone": g.phone if can_contact else None, "contact_hidden": not can_contact,
        "created_at": iso(g.created_at), "owner_id": g.owner_id, "status": g.status,
        "scheduled_at": g.scheduled_at.isoformat() if g.scheduled_at else None,  # local time, as entered
        "assigned_worker_id": g.assigned_worker_id, "min_price": g.min_price, "max_price": g.max_price,
        "agreed_price": g.agreed_price, "escrow_status": g.escrow_status, "employer_fee": g.employer_fee, "completed_at": iso(g.completed_at),
        "owner_name": owner.name if owner else None, "owner_rating": owner.rating if owner else None,
        "worker_name": worker.name if worker else None,
        "is_favourite": (g.id in favs) if favs is not None else False,
    }


def gigs_payload(gigs, viewer=None):
    """Serialise many gigs with 3 queries total instead of 2-3 per gig."""
    if not gigs:
        return []
    ids = {i for g in gigs for i in (g.owner_id, g.assigned_worker_id) if i}
    people = {u.id: u for u in User.query.filter(User.id.in_(list(ids)))} if ids else {}
    favs = None
    if viewer:
        favs = {f.gig_id for f in Favourite.query.filter(
            Favourite.user_id == viewer.id, Favourite.gig_id.in_([g.id for g in gigs]))}
    return [gig_dict(g, viewer, people, favs) for g in gigs]


def tx_dict(t):
    return {"id": t.id, "kind": t.kind, "amount": t.amount, "status": t.status, "method": t.method,
            "reference": t.reference, "payout_phone": t.payout_phone, "gig_id": t.gig_id,
            "note": t.note, "created_at": iso(t.created_at)}


# --------------------------------------------------------------------------
# Startup: tables, defaults, Super Admin
# --------------------------------------------------------------------------
def init_db():
    db.create_all()
    migrate_existing_schema()
    for key, value in {"platform_fee_percent": 5, "employer_fee_percent": 2, "worker_min_balance": 50,
                       "first_month_free": "true", "platform_status": "ONLINE", "escrow_enabled": "false"}.items():
        setting(key, value)

    supers = User.query.filter_by(role="super_admin").order_by(User.id.asc()).all()
    if not supers:
        env_phone = normalize_phone(os.environ.get("ZAMGIG_ADMIN_PHONE", "0766483891"))
        env_password = os.environ.get("ZAMGIG_ADMIN_PASSWORD")
        if not env_phone:
            print("[ZamGig] WARNING: no Super Admin configured. Set ZAMGIG_ADMIN_PHONE and ZAMGIG_ADMIN_PASSWORD.")
        elif not env_password or len(env_password) < 8:
            if os.environ.get("ZAMGIG_PRODUCTION", "0") == "1":
                raise RuntimeError("Set ZAMGIG_ADMIN_PHONE and an 8+ character ZAMGIG_ADMIN_PASSWORD before production startup")
            print("[ZamGig] WARNING: admin phone is configured but no valid admin password was supplied; no admin account was created.")
        else:
            existing = User.query.filter(User.phone.in_(phone_variants(env_phone))).first()
            if existing:
                existing.role, existing.profile_status, existing.suspended = "super_admin", "approved", False
            else:
                db.session.add(User(name="ZamGig Owner", phone=env_phone, password=generate_password_hash(env_password),
                                    profile_status="approved", role="super_admin"))
            db.session.commit()
    elif len(supers) > 1:  # there can only be one
        for extra in supers[1:]:
            extra.role = "admin"
        db.session.commit()


with app.app_context():
    try:
        init_db()
    except Exception:  # two gunicorn workers booting together can race on first run; retry once
        db.session.rollback()
        init_db()


# --------------------------------------------------------------------------
# Cross-cutting: maintenance mode + JSON errors
# --------------------------------------------------------------------------
def csrf_gate():
    """Optional double-submit CSRF protection for cookie-authenticated deployments."""
    if not app.config.get("ZAMGIG_CSRF") or request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if request.path in ("/login", "/register", "/logout", "/health"):
        return None
    if not session.get("user_id"):
        return None
    token = request.headers.get("X-CSRF-Token") or (request.get_json(silent=True) or {}).get("_csrf")
    expected = session.get("csrf_token")
    if not expected:
        expected = secrets.token_urlsafe(32)
        session["csrf_token"] = expected
    if not token or not secrets.compare_digest(str(token), str(expected)):
        return fail("Missing or invalid CSRF token", 403)
    return None


@app.before_request
def security_gate():
    csrf_error = csrf_gate()
    if csrf_error:
        return csrf_error
    return maintenance_gate()


def maintenance_gate():
    """When platform_status is not ONLINE, only admins can make changes (browsing still works)."""
    if request.method in ("GET", "HEAD", "OPTIONS") or request.path in ("/login", "/logout"):
        return None
    if setting("platform_status", "ONLINE").strip().upper() == "ONLINE":
        return None
    if is_admin(current_user()):
        return None
    return fail("ZamGig is temporarily unavailable. Please try again soon.", 503)


@app.errorhandler(HTTPException)
def http_error(err):
    message = "File too large (max 5 MB)" if err.code == 413 else err.description
    return fail(message, err.code)


@app.errorhandler(Exception)
def unexpected_error(err):
    app.logger.exception("Unhandled error")
    db.session.rollback()
    return fail("Something went wrong on our side. Please try again.", 500)


@app.route("/")
def home():
    return render_template("index.html")


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/health")
def health():
    db.session.execute(text("SELECT 1"))
    return ok(time=iso(utcnow()))


# --------------------------------------------------------------------------
# Auth + profile
# --------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    name = clean(data.get("name"), 100)
    email = clean(data.get("email"), 150).lower()
    phone = normalize_phone(data.get("phone"))
    password = str(data.get("password", ""))
    if not name or not data.get("phone") or not password or not data.get("termsAccepted"):
        return fail("Name, phone number, password and acceptance of the Terms are required")
    if not phone:
        return fail("Enter a valid Zambian mobile number, e.g. 0977 123 456")
    if email and not EMAIL_RE.match(email):
        return fail("Enter a valid email address")
    if len(password) < 8:
        return fail("Password must be at least 8 characters")
    conditions = [User.phone.in_(phone_variants(phone))]
    if email:
        conditions.append(User.email == email)
    if User.query.filter(or_(*conditions)).first():
        return fail("An account with this phone number or email already exists", 409)

    free = setting("first_month_free", "true").lower() == "true"
    user = User(name=name, email=email or None, phone=phone, password=generate_password_hash(password),
                location=clean(data.get("location"), 150), profile_status="pending", role="user",
                free_until=utcnow() + timedelta(days=30) if free else None)
    db.session.add(user)
    db.session.flush()
    notify(user.id, "Welcome to ZamGig",
           "Your account was created. Complete your profile and wait for admin approval.", "welcome")
    db.session.commit()
    return ok(message="Account created successfully. Your profile is awaiting approval.", user=user_dict(user)), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    raw_phone = clean(data.get("phone"), 30)
    email = clean(data.get("email"), 150).lower()
    password = str(data.get("password", ""))
    identifier = raw_phone or email
    if not identifier:
        return fail("Enter your phone number or email")
    key = f"{request.remote_addr}|{identifier}"
    if too_many_attempts(key):
        return fail("Too many failed attempts. Please wait 10 minutes and try again.", 429)

    if raw_phone:
        local = normalize_phone(raw_phone)
        user = User.query.filter(User.phone.in_(phone_variants(local) if local else [raw_phone])).first()
    else:
        user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        _failed_logins[key].append(time.time())
        return fail("Invalid phone/email or password", 401)
    if user.suspended:
        return fail("This account is suspended. Contact ZamGig administration.", 403)

    _failed_logins.pop(key, None)
    session.clear()
    session.permanent = True
    session["user_id"] = user.id
    session["csrf_token"] = secrets.token_urlsafe(32)
    return ok(message="Login successful", user=user_dict(user), csrf_token=session["csrf_token"] if app.config.get("ZAMGIG_CSRF") else None)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return ok(message="Logged out")


@app.route("/me", methods=["GET"])
def me():
    user = current_user()
    if not user:
        return fail("Not logged in", 401)
    return ok(user=user_dict(user), unread_notifications=unread_notification_count(user))


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    target = db.session.get(User, user_id)
    if not target:
        return fail("User not found", 404)
    return ok(user=user_view(target, current_user()))


@app.route("/profile", methods=["PUT"])
@login_required  # pending users can fill in their profile while they wait for approval
def update_profile():
    user, data = current_user(), request.get_json(silent=True) or {}
    limits = {"name": 100, "location": 150, "bio": 1000, "skills": 500, "availability": 100}
    for field, limit in limits.items():
        if field in data:
            value = clean(data[field], limit)
            if field == "name" and not value:
                return fail("Name cannot be empty")
            setattr(user, field, value)
    db.session.commit()
    return ok(message="Profile updated", user=user_dict(user))


@app.route("/profile/password", methods=["PUT"])
@login_required
def change_password():
    user, data = current_user(), request.get_json(silent=True) or {}
    if not check_password_hash(user.password, str(data.get("current_password", ""))):
        return fail("Your current password is incorrect", 403)
    new_password = str(data.get("new_password", ""))
    if len(new_password) < 8:
        return fail("New password must be at least 8 characters")
    user.password = generate_password_hash(new_password)
    db.session.commit()
    return ok(message="Password changed")


def sniff_image(head):
    """Identify the real file type from its first bytes (the filename can lie)."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


@app.route("/profile/photo", methods=["POST"])
@login_required
def upload_photo():
    user, file = current_user(), request.files.get("photo")
    if not file or not file.filename:
        return fail("Choose a photo")
    data = file.stream.read(app.config["MAX_PROFILE_PHOTO_BYTES"] + 1)
    if len(data) > app.config["MAX_PROFILE_PHOTO_BYTES"]:
        return fail("Profile photo must be 2 MB or smaller", 413)
    ext = sniff_image(data[:16])
    if not ext:
        return fail("Use a real PNG, JPG or WEBP image")
    filename = f"user_{user.id}_{uuid.uuid4().hex}.{ext}"
    (UPLOAD_DIR / filename).write_bytes(data)
    old = user.profile_photo
    user.profile_photo = f"/static/uploads/{filename}"
    db.session.commit()
    if old and old.startswith("/static/uploads/"):
        (UPLOAD_DIR / Path(old).name).unlink(missing_ok=True)
    return ok(message="Profile photo updated", user=user_dict(user))


@app.route("/workers", methods=["GET"])
def find_workers():
    """Browse approved workers (like TaskRabbit 'Taskers'). Filters: q, location, available=1, min_rating."""
    a = request.args
    q = User.query.filter(User.role == "user", User.profile_status == "approved", User.suspended.is_(False))
    if a.get("q", "").strip():
        p = like(a["q"].strip()[:80])
        q = q.filter(or_(User.name.ilike(p, escape="\\"), User.skills.ilike(p, escape="\\"), User.bio.ilike(p, escape="\\")))
    if a.get("location", "").strip():
        q = q.filter(User.location.ilike(like(a["location"].strip()[:80]), escape="\\"))
    if a.get("available") == "1":
        q = q.filter(User.availability == "Available")
    try:
        if a.get("min_rating"):
            min_rating = float(a["min_rating"])
            if not 0 <= min_rating <= 5:
                return fail("min_rating must be between 0 and 5")
            q = q.filter(User.rating >= min_rating)
    except ValueError:
        return fail("min_rating must be a number")
    rows, meta = paginate(q.order_by(User.rating.desc(), User.rating_count.desc(), User.id.asc()))
    return ok(workers=[public_user_dict(u) for u in rows], **meta)


# --------------------------------------------------------------------------
# Gigs
# --------------------------------------------------------------------------
GIG_SORTS = {
    "newest": Gig.created_at.desc(), "oldest": Gig.created_at.asc(),
    "price_low": Gig.min_price.asc(), "price_high": Gig.max_price.desc(),
}


def query_gigs():
    a, q = request.args, Gig.query
    if a.get("q", "").strip():
        p = like(a["q"].strip()[:80])
        q = q.filter(or_(Gig.title.ilike(p, escape="\\"), Gig.description.ilike(p, escape="\\"),
                         Gig.category.ilike(p, escape="\\")))
    for field in ("category", "province", "city", "area"):
        value = a.get(field, "").strip()
        if value:
            q = q.filter(getattr(Gig, field).ilike(like(value[:80]), escape="\\"))
    if a.get("status", "").strip():
        q = q.filter(Gig.status == a["status"].strip())
    try:  # budget filters: show gigs whose price range overlaps what the worker wants
        if a.get("min_budget"):
            q = q.filter(or_(Gig.max_price.is_(None), Gig.max_price >= float(a["min_budget"])))
        if a.get("max_budget"):
            q = q.filter(or_(Gig.min_price.is_(None), Gig.min_price <= float(a["max_budget"])))
    except ValueError:
        pass
    return q.order_by(GIG_SORTS.get(a.get("sort"), GIG_SORTS["newest"]), Gig.id.desc())


def read_gig_fields(data, partial=False):
    """Validate gig input. Returns (fields, error_message)."""
    out = {}
    for key, limit in (("title", 150), ("area", 100), ("city", 100)):
        if key in data or not partial:
            value = clean(data.get(key), limit)
            if not value:
                return None, f"{key.title()} is required"
            out[key] = value
    for key, options, label in (("category", CATEGORIES, "category"), ("province", PROVINCES, "province")):
        if key in data or not partial:
            value = clean(data.get(key), 100).lower()
            match = next((o for o in options if o.lower() == value), None)
            if not match:
                return None, f"Invalid {label}"
            out[key] = match
    for key, limit in (("description", 2000), ("payment", 100)):
        if key in data:
            out[key] = clean(data.get(key), limit)
        elif not partial:
            out[key] = ""
    for key in ("min_price", "max_price"):
        if key in data or not partial:
            try:
                out[key] = to_money(data.get(key))
            except (TypeError, ValueError):
                return None, "Prices must be valid amounts in Kwacha"
    return out, None


@app.route("/gigs", methods=["POST"])
@approved_required
def create_gig():
    user, data = current_user(), request.get_json(silent=True) or {}
    fields, error = read_gig_fields(data)
    if error:
        return fail(error)
    lo, hi = fields["min_price"], fields["max_price"]
    if lo is not None and hi is not None and lo > hi:
        return fail("Minimum price cannot be higher than maximum price")
    scheduled = None
    if data.get("scheduled_at"):
        try:
            scheduled = parse_dt(data["scheduled_at"])
        except ValueError:
            return fail("Use a valid date and time")
    if Gig.query.filter_by(owner_id=user.id, status="open").count() >= MAX_OPEN_GIGS_PER_USER:
        return fail(f"You can have at most {MAX_OPEN_GIGS_PER_USER} open gigs at once", 429)
    gig = Gig(**fields, phone=normalize_phone(data.get("phone")) or user.phone,
              owner_id=user.id, status="open", scheduled_at=scheduled)
    db.session.add(gig)
    db.session.commit()
    return ok(message="Gig created successfully", gig=gig_dict(gig, user)), 201


@app.route("/gigs", methods=["GET"])
def get_gigs():
    user = current_user()
    rows, meta = paginate(query_gigs())
    return ok(count=len(rows), gigs=gigs_payload(rows, user), **meta)


@app.route("/gigs/search", methods=["GET"])
def search_gigs():
    return get_gigs()


@app.route("/gigs/mine", methods=["GET"])
@login_required
def my_gigs():
    user = current_user()
    newest = Gig.created_at.desc()
    posted = Gig.query.filter_by(owner_id=user.id).order_by(newest).limit(200).all()
    taken = Gig.query.filter_by(assigned_worker_id=user.id).order_by(newest).limit(200).all()
    return ok(posted=gigs_payload(posted, user), assigned=gigs_payload(taken, user))


@app.route("/gigs/<int:gig_id>", methods=["GET"])
def get_gig(gig_id):
    g = db.session.get(Gig, gig_id)
    if not g:
        return fail("Gig not found", 404)
    user = current_user()
    return ok(gig=gigs_payload([g], user)[0])


@app.route("/gigs/<int:gig_id>", methods=["PUT"])
@approved_required
def edit_gig(gig_id):
    user, g, data = current_user(), None, request.get_json(silent=True) or {}
    g = db.session.get(Gig, gig_id)
    if not g:
        return fail("Gig not found", 404)
    if user.id != g.owner_id and not is_admin(user):
        return fail("Only the gig owner can edit it", 403)
    if g.status != "open" and not is_admin(user):
        return fail("Only open gigs can be edited", 409)
    fields, error = read_gig_fields(data, partial=True)
    if error:
        return fail(error)
    lo = fields.get("min_price", g.min_price)
    hi = fields.get("max_price", g.max_price)
    if lo is not None and hi is not None and lo > hi:
        return fail("Minimum price cannot be higher than maximum price")
    for key, value in fields.items():
        setattr(g, key, value)
    db.session.commit()
    return ok(message="Gig updated", gig=gig_dict(g, user))


@app.route("/gigs/<int:gig_id>", methods=["DELETE"])
@admin_required
def delete_gig(gig_id):
    g = db.session.get(Gig, gig_id)
    if not g:
        return fail("Gig not found", 404)
    if g.escrow_status == "held":
        refund_escrow(g, "Gig removed by admin")
    Favourite.query.filter_by(gig_id=gig_id).delete()
    audit(current_user(), "delete_gig", "gig", gig_id, g.title)
    db.session.delete(g)
    db.session.commit()
    return ok(message="Gig deleted successfully")


@app.route("/gigs/<int:gig_id>/apply", methods=["POST"])
@approved_required
def apply_gig(gig_id):
    """First eligible worker to accept gets the gig."""
    user, g = current_user(), db.session.get(Gig, gig_id)
    if not g:
        return fail("Gig not found", 404)
    if g.owner_id == user.id:
        return fail("You cannot apply to your own gig")
    if g.status != "open":
        return fail("This gig is no longer open", 409)
    minimum = float(setting("worker_min_balance", 50))
    in_free_period = bool(user.free_until and user.free_until > utcnow())
    if not in_free_period and (user.wallet_balance or 0) < minimum:
        return fail(f"Minimum wallet balance is K{minimum:.2f} to accept gigs", 403)

    # Atomic claim: if two workers tap "accept" at once, only one UPDATE matches status='open'.
    claimed = Gig.query.filter_by(id=g.id, status="open").update(
        {"assigned_worker_id": user.id, "status": "assigned"}, synchronize_session=False)
    if not claimed:
        db.session.rollback()
        return fail("Someone else just accepted this gig", 409)
    notify(g.owner_id, "Worker assigned", f"{user.name} has accepted your gig: {g.title}", "gig")
    db.session.commit()
    db.session.refresh(g)
    return ok(message="Gig accepted", gig=gig_dict(g, user))


def charge_platform_fee(gig):
    """Deduct the platform fee from the worker's wallet once a gig with an agreed price is completed."""
    if not gig.agreed_price or not gig.assigned_worker_id:
        return
    worker = db.session.get(User, gig.assigned_worker_id)
    percent = float(setting("platform_fee_percent", 5))
    if not worker or percent <= 0 or (worker.free_until and worker.free_until > utcnow()):
        return
    fee = round(gig.agreed_price * percent / 100, 2)
    if fee <= 0:
        return
    worker.wallet_balance = (worker.wallet_balance or 0) - fee  # may dip below 0; they must top up before the next gig
    db.session.add(WalletTransaction(user_id=worker.id, kind="fee", amount=-fee, status="completed", gig_id=gig.id,
                                     note=f"{percent:g}% platform fee on K{gig.agreed_price:.2f}"))
    notify(worker.id, "Platform fee charged", f"K{fee:.2f} was deducted for '{gig.title}'.", "wallet")


def escrow_on():
    return setting("escrow_enabled", "false").lower() == "true"


def credit(user_id, amount):
    """Atomically add (or subtract, if negative) money on a wallet, rounded to 2dp."""
    amount = money(amount)
    User.query.filter_by(id=user_id).update(
        {"wallet_balance": func.round(User.wallet_balance + amount, 2)}, synchronize_session=False)


def refund_escrow(g, note):
    """Return everything held for this gig (price + service fee) to the poster."""
    if not Gig.query.filter_by(id=g.id, escrow_status="held").update({"escrow_status": "refunded"}, synchronize_session=False):
        return
    g.escrow_status = "refunded"
    total = round((g.agreed_price or 0) + (g.employer_fee or 0), 2)
    credit(g.owner_id, total)
    db.session.add(WalletTransaction(user_id=g.owner_id, kind="escrow_refund", amount=total, status="completed",
                                     gig_id=g.id, note=note))
    notify(g.owner_id, "Payment refunded", f"K{total:.2f} was returned to your wallet ({note.lower()}).", "wallet")


def release_escrow(g):
    """Pay the worker the agreed price minus the platform fee. ZamGig keeps the fees."""
    if not Gig.query.filter_by(id=g.id, escrow_status="held").update({"escrow_status": "released"}, synchronize_session=False):
        return
    g.escrow_status = "released"
    worker = db.session.get(User, g.assigned_worker_id)
    percent = float(setting("platform_fee_percent", 5))
    free = bool(worker.free_until and worker.free_until > utcnow())
    fee = 0 if free else round(g.agreed_price * percent / 100, 2)
    credit(worker.id, round(g.agreed_price - fee, 2))
    db.session.add(WalletTransaction(user_id=worker.id, kind="escrow_release", amount=g.agreed_price, status="completed",
                                     gig_id=g.id, note=f"Payment for '{g.title}'"))
    if fee:
        db.session.add(WalletTransaction(user_id=worker.id, kind="fee", amount=-fee, status="completed", gig_id=g.id,
                                         note=f"{percent:g}% platform fee on K{g.agreed_price:.2f}"))
    notify(worker.id, "You got paid", f"K{g.agreed_price - fee:.2f} was added to your wallet for '{g.title}'.", "wallet")


@app.route("/gigs/<int:gig_id>/fund", methods=["POST"])
@approved_required
def fund_gig(gig_id):
    """Poster moves price + service fee from their wallet into secure holding. Released when they confirm the job."""
    user, g = current_user(), db.session.get(Gig, gig_id)
    if not g:
        return fail("Gig not found", 404)
    if not escrow_on():
        return fail("Secure payments are not switched on yet")
    if user.id != g.owner_id:
        return fail("Only the poster can fund a gig", 403)
    if g.status not in ("assigned", "in_progress") or not g.assigned_worker_id:
        return fail("You can fund a gig once a worker has accepted it", 409)
    if not g.agreed_price or g.agreed_price <= 0:
        return fail("Set the agreed price first", 409)
    fee = round(g.agreed_price * float(setting("employer_fee_percent", 2)) / 100, 2)
    total = round(g.agreed_price + fee, 2)
    paid = User.query.filter(User.id == user.id, User.wallet_balance >= total).update(
        {"wallet_balance": func.round(User.wallet_balance - total, 2)}, synchronize_session=False)
    if not paid:
        db.session.rollback()
        return fail(f"You need K{total:.2f} in your wallet (price K{g.agreed_price:.2f} + K{fee:.2f} service fee). Please top up first.", 402)
    marked = Gig.query.filter(Gig.id == g.id, or_(Gig.escrow_status.is_(None), Gig.escrow_status == "refunded")).update(
        {"escrow_status": "held", "employer_fee": fee}, synchronize_session=False)
    if not marked:
        db.session.rollback()
        return fail("This gig is already funded", 409)
    g.escrow_status, g.employer_fee = "held", fee
    db.session.add(WalletTransaction(user_id=user.id, kind="escrow_hold", amount=-total, status="completed", gig_id=g.id,
                                     note=f"Held for '{g.title}' (K{g.agreed_price:.2f} + K{fee:.2f} service fee)"))
    notify(g.assigned_worker_id, "Gig funded", f"The payment for '{g.title}' is secured. You can start work.", "wallet")
    db.session.commit()
    return ok(message=f"K{total:.2f} is now held securely. It is released to the worker when you confirm the job is done.",
              gig=gig_dict(g, user))


@app.route("/gigs/<int:gig_id>/status", methods=["PUT"])
@approved_required
def update_gig_status(gig_id):
    user, g, data = current_user(), db.session.get(Gig, gig_id), request.get_json(silent=True) or {}
    if not g:
        return fail("Gig not found", 404)
    admin = is_admin(user)
    is_owner, is_worker = user.id == g.owner_id, user.id == g.assigned_worker_id
    if not (is_owner or is_worker or admin):
        return fail("Not authorized", 403)

    if "agreed_price" in data:
        if not (is_owner or admin):
            return fail("Only the gig owner can set the agreed price", 403)
        if g.escrow_status == "held":
            return fail("The price is locked while payment is held", 409)
        try:
            g.agreed_price = to_money(data["agreed_price"])
        except (TypeError, ValueError):
            return fail("Agreed price must be a valid amount in Kwacha")

    new = clean(data.get("status"), 30)
    if not new and "agreed_price" in data:  # price-only update
        db.session.commit()
        return ok(message="Agreed price saved", gig=gig_dict(g, user))
    if new not in GIG_STATUSES:
        return fail("Invalid gig status")
    if not admin:
        if new not in TRANSITIONS.get(g.status, set()):
            return fail(f"A {g.status.replace('_', ' ')} gig can't be changed to {new.replace('_', ' ')}", 409)
        if new == "cancelled" and not is_owner:
            return fail("Only the gig owner can cancel a gig", 403)

    if not admin and new == "in_progress" and escrow_on() and g.escrow_status != "held":
        return fail("The poster needs to fund this gig before work starts", 409)
    if not admin and new == "completed" and g.escrow_status == "held" and not is_owner:
        return fail("Only the poster can confirm the job is done and release payment", 403)
    previous, worker_id = g.status, g.assigned_worker_id
    if new in ("cancelled", "open") and g.escrow_status == "held":
        refund_escrow(g, "Gig cancelled" if new == "cancelled" else "Worker withdrew")
    g.status = new
    if new == "open":  # worker withdrew (or admin re-opened): free the slot
        g.assigned_worker_id = None
    if new == "completed" and previous != "completed":
        g.completed_at = utcnow()
        if g.escrow_status == "held":
            release_escrow(g)
        else:
            charge_platform_fee(g)
    other = g.owner_id if user.id == worker_id else worker_id
    if other and other != user.id:
        notify(other, "Gig update", f"'{g.title}' is now {new.replace('_', ' ')}.", "gig")
    db.session.commit()
    return ok(message="Gig status updated", gig=gig_dict(g, user))


@app.route("/gigs/<int:gig_id>/schedule", methods=["PUT"])
@approved_required
def schedule_gig(gig_id):
    user, g, data = current_user(), db.session.get(Gig, gig_id), request.get_json(silent=True) or {}
    if not g:
        return fail("Gig not found", 404)
    if user.id not in (g.owner_id, g.assigned_worker_id) and not is_admin(user):
        return fail("Not authorized", 403)
    try:
        g.scheduled_at = parse_dt(data.get("scheduled_at"))
    except ValueError:
        return fail("Use a valid date and time")
    other = g.assigned_worker_id if user.id == g.owner_id else g.owner_id
    if other and other != user.id:
        notify(other, "Gig rescheduled", f"'{g.title}' was scheduled for {g.scheduled_at:%d %b %Y, %H:%M}.", "gig")
    db.session.commit()
    return ok(message="Schedule updated", gig=gig_dict(g, user))


@app.route("/favourites/<int:gig_id>", methods=["POST", "DELETE"])
@approved_required
def favourite(gig_id):
    user = current_user()
    if not db.session.get(Gig, gig_id):
        return fail("Gig not found", 404)
    row = Favourite.query.filter_by(user_id=user.id, gig_id=gig_id).first()
    if request.method == "POST" and not row:
        db.session.add(Favourite(user_id=user.id, gig_id=gig_id))
    elif request.method == "DELETE" and row:
        db.session.delete(row)
    db.session.commit()
    return ok(favourite=request.method == "POST")


@app.route("/favourites", methods=["GET"])
@approved_required
def favourites():
    user = current_user()
    gigs = (Gig.query.join(Favourite, Favourite.gig_id == Gig.id)
            .filter(Favourite.user_id == user.id).order_by(Favourite.created_at.desc()).all())
    return ok(gigs=gigs_payload(gigs, user))


# --------------------------------------------------------------------------
# Reviews
# --------------------------------------------------------------------------
@app.route("/reviews", methods=["POST"])
@approved_required
def create_review():
    user, data = current_user(), request.get_json(silent=True) or {}
    gig = db.session.get(Gig, to_int(data.get("gig_id"), 0))
    if not gig or not gig.assigned_worker_id or gig.status != "completed":
        return fail("You can only review a completed gig that had a worker")
    if user.id != gig.owner_id:
        return fail("Only the person who posted the gig can review the worker", 403)
    rating = to_int(data.get("rating"), 0)
    if rating < 1 or rating > 5:
        return fail("Rating must be 1 to 5")
    if Review.query.filter_by(gig_id=gig.id, reviewer_id=user.id).first():
        return fail("You already reviewed this gig", 409)

    db.session.add(Review(gig_id=gig.id, reviewer_id=user.id, worker_id=gig.assigned_worker_id,
                          rating=rating, comment=clean(data.get("comment"), 1000)))
    db.session.flush()
    worker = db.session.get(User, gig.assigned_worker_id)
    avg, count = db.session.query(func.avg(Review.rating), func.count(Review.id)).filter(
        Review.worker_id == worker.id).one()
    worker.rating, worker.rating_count = round(float(avg or 0), 2), count
    notify(worker.id, "New review", f"You received {rating}/5 for '{gig.title}'.", "review")
    db.session.commit()
    return ok(message="Review submitted", worker=public_user_dict(worker))


@app.route("/reviews/<int:worker_id>", methods=["GET"])
def worker_reviews(worker_id):
    rows = Review.query.filter_by(worker_id=worker_id).order_by(Review.created_at.desc()).limit(100).all()
    return ok(reviews=[{"id": r.id, "gig_id": r.gig_id, "rating": r.rating, "comment": r.comment,
                        "created_at": iso(r.created_at)} for r in rows])


# --------------------------------------------------------------------------
# Messages (only between the two people on a gig)
# --------------------------------------------------------------------------
@app.route("/messages", methods=["GET", "POST"])
@approved_required
def messages():
    user = current_user()
    if request.method == "GET":
        a = request.args
        q = Message.query.filter(or_(Message.sender_id == user.id, Message.receiver_id == user.id))
        if a.get("gig_id"):
            q = q.filter(Message.gig_id == to_int(a["gig_id"], 0))
        if a.get("with"):  # conversation with one person
            other = to_int(a["with"], 0)
            q = q.filter(or_(Message.sender_id == other, Message.receiver_id == other))
        if a.get("after_id"):  # cheap polling: only fetch what's new
            q = q.filter(Message.id > to_int(a["after_id"], 0))
        rows = q.order_by(Message.id.asc()).limit(500).all()
        unread = Message.query.filter_by(receiver_id=user.id, read=False).count()
        return ok(unread=unread, messages=[{
            "id": m.id, "gig_id": m.gig_id, "sender_id": m.sender_id, "receiver_id": m.receiver_id,
            "message": m.message, "read": m.read, "created_at": iso(m.created_at)} for m in rows])

    data = request.get_json(silent=True) or {}
    receiver = db.session.get(User, to_int(data.get("receiver_id"), 0))
    text_ = clean(data.get("message"), 2000)
    if not receiver or not text_:
        return fail("Recipient and message are required")
    if receiver.id == user.id:
        return fail("You can't message yourself")
    gig = db.session.get(Gig, to_int(data.get("gig_id"), 0)) if data.get("gig_id") else None
    if not is_admin(user):  # keeps conversations (and fees) on the platform
        if not gig or user.id not in (gig.owner_id, gig.assigned_worker_id) \
                or receiver.id not in (gig.owner_id, gig.assigned_worker_id):
            return fail("Messaging is limited to participants of the selected gig", 403)
    db.session.add(Message(gig_id=gig.id if gig else None, sender_id=user.id, receiver_id=receiver.id, message=text_))
    db.session.commit()
    return ok(message="Message sent")


@app.route("/messages/read", methods=["PUT"])
@approved_required
def mark_messages_read():
    user, data = current_user(), request.get_json(silent=True) or {}
    q = Message.query.filter_by(receiver_id=user.id, read=False)
    if data.get("sender_id"):
        q = q.filter_by(sender_id=to_int(data["sender_id"], 0))
    if data.get("gig_id"):
        q = q.filter_by(gig_id=to_int(data["gig_id"], 0))
    q.update({"read": True}, synchronize_session=False)
    db.session.commit()
    return ok()


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------
def visible_notifications(user):
    """Personal notifications plus broadcasts sent after the user joined."""
    since = user.created_at or datetime(2000, 1, 1)
    return Notification.query.filter(or_(
        Notification.user_id == user.id,
        and_(Notification.user_id.is_(None), Notification.created_at >= since)))


def read_broadcast_ids(user):
    return {r[0] for r in db.session.query(NotificationRead.notification_id).filter_by(user_id=user.id)}


def unread_notification_count(user):
    seen = read_broadcast_ids(user)
    unread = 0
    for n in visible_notifications(user).with_entities(Notification.id, Notification.user_id, Notification.read):
        unread += (not n.read) if n.user_id else (n.id not in seen)
    return unread


def send_admin_notification():
    data = request.get_json(silent=True) or {}
    title, message = clean(data.get("title"), 150), clean(data.get("message"), 2000)
    target = data.get("user_id")
    if not title or not message:
        return fail("Title and message are required")
    if target and not db.session.get(User, to_int(target, 0)):
        return fail("Recipient not found", 404)
    notify(to_int(target) if target else None, title, message, "admin")
    audit(current_user(), "send_notification", "user", to_int(target), title)
    db.session.commit()
    return ok(message="Notification sent")


@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    user = current_user()
    if request.method == "POST":
        if not is_admin(user):
            return fail("Admin access required", 403)
        return send_admin_notification()
    limit = min(max(to_int(request.args.get("limit"), 100), 1), 200)
    rows = visible_notifications(user).order_by(Notification.created_at.desc(), Notification.id.desc()).limit(limit).all()
    seen = read_broadcast_ids(user)
    return ok(unread=unread_notification_count(user), notifications=[{
        "id": n.id, "title": n.title, "message": n.message, "kind": n.kind,
        "read": n.read if n.user_id else n.id in seen, "created_at": iso(n.created_at)} for n in rows])


@app.route("/notifications/<int:nid>/read", methods=["PUT"])
@login_required
def notification_read(nid):
    user, n = current_user(), db.session.get(Notification, nid)
    if not n or n.user_id not in (None, user.id):
        return fail("Not found", 404)
    if n.user_id:
        n.read = True
    elif not NotificationRead.query.filter_by(user_id=user.id, notification_id=n.id).first():
        db.session.add(NotificationRead(user_id=user.id, notification_id=n.id))
    db.session.commit()
    return ok()


@app.route("/notifications/read-all", methods=["PUT"])
@login_required
def notifications_read_all():
    user = current_user()
    Notification.query.filter_by(user_id=user.id, read=False).update({"read": True}, synchronize_session=False)
    seen = read_broadcast_ids(user)
    for n in visible_notifications(user).filter(Notification.user_id.is_(None)):
        if n.id not in seen:
            db.session.add(NotificationRead(user_id=user.id, notification_id=n.id))
    db.session.commit()
    return ok()


# --------------------------------------------------------------------------
# Wallet
# --------------------------------------------------------------------------
@app.route("/wallet", methods=["GET", "POST"])
@approved_required
def wallet():
    user = current_user()
    if request.method == "GET":
        recent = (WalletTransaction.query.filter_by(user_id=user.id)
                  .order_by(WalletTransaction.created_at.desc(), WalletTransaction.id.desc()).limit(20).all())
        return ok(balance=round(user.wallet_balance or 0, 2), minimum=float(setting("worker_min_balance", 50)),
                  free_until=iso(user.free_until), transactions=[tx_dict(t) for t in recent])

    # A top-up is a REQUEST. Money only lands in the wallet after an admin confirms the mobile-money payment.
    data = request.get_json(silent=True) or {}
    try:
        amount = round(float(data.get("amount", 0)), 2)
    except (TypeError, ValueError):
        amount = 0
    if not (MIN_TOPUP <= amount <= MAX_TOPUP):
        return fail(f"Top-up must be between K{MIN_TOPUP} and K{MAX_TOPUP:,}")
    reference = clean(data.get("reference"), 40)
    method = clean(data.get("method"), 20).lower() or "other"
    if reference and WalletTransaction.query.filter(
            WalletTransaction.reference == reference, WalletTransaction.status != "rejected").first():
        return fail("That transaction ID has already been submitted", 409)
    if WalletTransaction.query.filter_by(user_id=user.id, kind="topup", status="pending").count() >= 5:
        return fail("You have several top-ups waiting for confirmation. Please wait for them to be approved.", 429)
    db.session.add(WalletTransaction(user_id=user.id, kind="topup", amount=amount, status="pending",
                                     method=method, reference=reference or None, note="Mobile money top-up"))
    db.session.commit()
    return ok(message=f"Top-up request of K{amount:.2f} received. It will be added once your payment is confirmed.",
              balance=round(user.wallet_balance or 0, 2), pending=True)


@app.route("/wallet/withdraw", methods=["POST"])
@approved_required
def withdraw():
    """Worker asks to cash out. The amount leaves the wallet now; an admin sends it by mobile money and marks it paid."""
    user, data = current_user(), request.get_json(silent=True) or {}
    try:
        amount = round(float(data.get("amount", 0)), 2)
    except (TypeError, ValueError):
        amount = 0
    if not (MIN_WITHDRAW <= amount <= MAX_TOPUP):
        return fail(f"Withdrawals must be between K{MIN_WITHDRAW} and K{MAX_TOPUP:,}")
    payout = normalize_phone(data.get("phone")) or user.phone
    method = clean(data.get("method"), 20).lower() or "other"
    if WalletTransaction.query.filter_by(user_id=user.id, kind="withdrawal", status="pending").count() >= 3:
        return fail("You already have withdrawals waiting to be paid", 429)
    took = User.query.filter(User.id == user.id, User.wallet_balance >= amount).update(
        {"wallet_balance": func.round(User.wallet_balance - amount, 2)}, synchronize_session=False)
    if not took:
        db.session.rollback()
        return fail("You don't have enough in your wallet")
    db.session.add(WalletTransaction(user_id=user.id, kind="withdrawal", amount=-amount, status="pending",
                                     method=method, payout_phone=payout, note="Awaiting admin payout"))
    db.session.commit()
    return ok(message=f"Withdrawal of K{amount:.2f} requested. You'll be paid on {payout} shortly.")


@app.route("/admin/topups", methods=["GET"])
@admin_required
def admin_topups():
    status = clean(request.args.get("status", "pending"), 20)
    kind = "withdrawal" if request.args.get("kind") == "withdrawal" else "topup"
    q = WalletTransaction.query.filter_by(kind=kind)
    if status != "all":
        q = q.filter_by(status=status)
    rows, meta = paginate(q.order_by(WalletTransaction.created_at.asc()))
    people = {u.id: u for u in User.query.filter(User.id.in_(list({r.user_id for r in rows})))} if rows else {}
    return ok(topups=[{**tx_dict(r), "user_name": people[r.user_id].name if r.user_id in people else None,
                       "user_phone": people[r.user_id].phone if r.user_id in people else None} for r in rows], **meta)


@app.route("/admin/topups/<int:tid>", methods=["PUT"])
@admin_required
def review_topup(tid):
    admin, data = current_user(), request.get_json(silent=True) or {}
    decision = clean(data.get("status"), 20)
    if decision not in ("approved", "rejected"):
        return fail("Status must be 'approved' or 'rejected'")
    tx = db.session.get(WalletTransaction, tid)
    if not tx or tx.kind not in ("topup", "withdrawal"):
        return fail("Request not found", 404)
    if tx.kind == "withdrawal" and decision == "approved" and not clean(data.get("payout_reference"), 80):
        return fail("A payout reference is required before approving a withdrawal")
    new_status = "completed" if decision == "approved" else "rejected"
    # Conditional update so a top-up can never be credited twice, even if two admins click at once.
    changed = WalletTransaction.query.filter_by(id=tid, status="pending").update(
        {"status": new_status, "reviewed_by": admin.id}, synchronize_session=False)
    if not changed:
        db.session.rollback()
        return fail("This top-up has already been reviewed", 409)
    if tx.kind == "withdrawal":
        if decision == "approved":
            tx.reference = clean(data.get("payout_reference"), 80)
            notify(tx.user_id, "Withdrawal paid", f"K{-tx.amount:.2f} was sent to {tx.payout_phone or 'your registered number'} by mobile money.", "wallet")
        else:
            credit(tx.user_id, -tx.amount)  # tx.amount is negative: give the money back
            notify(tx.user_id, "Withdrawal not paid", f"K{-tx.amount:.2f} was returned to your wallet.", "wallet")
    elif decision == "approved":
        user = db.session.get(User, tx.user_id)
        user.wallet_balance = money((user.wallet_balance or 0) + tx.amount)
        notify(user.id, "Wallet topped up", f"K{tx.amount:.2f} was added to your wallet.", "wallet")
    else:
        notify(tx.user_id, "Top-up not confirmed",
               f"We couldn't confirm your K{tx.amount:.2f} payment. Contact support if this is a mistake.", "wallet")
    audit(admin, f"topup_{decision}", "wallet_transaction", tid, f"K{tx.amount:.2f}")
    db.session.commit()
    return ok(message=f"Top-up {decision}")


# --------------------------------------------------------------------------
# Platform settings
# --------------------------------------------------------------------------
@app.route("/settings/rates", methods=["GET"])
def get_rates():
    return ok(rates={
        "platform_fee_percent": float(setting("platform_fee_percent", 5)),
        "employer_fee_percent": float(setting("employer_fee_percent", 2)),
        "worker_min_balance": float(setting("worker_min_balance", 50)),
        "first_month_free": setting("first_month_free", "true").lower() == "true",
        "escrow_enabled": escrow_on(),
        "platform_status": setting("platform_status", "ONLINE"),
    })


@app.route("/admin/rates", methods=["PUT"])
@super_admin_required
def update_rates():
    data = request.get_json(silent=True) or {}
    ranges = {"platform_fee_percent": (0, 50), "employer_fee_percent": (0, 50), "worker_min_balance": (0, 100000)}
    for key, (low, high) in ranges.items():
        if key in data:
            try:
                value = float(data[key])
            except (TypeError, ValueError):
                return fail(f"{key} must be a number")
            if not low <= value <= high:
                return fail(f"{key} must be between {low} and {high}")
            set_setting(key, value)
    if "first_month_free" in data:
        set_setting("first_month_free", "true" if str(data["first_month_free"]).lower() in ("true", "1", "yes") else "false")
    if "escrow_enabled" in data:
        set_setting("escrow_enabled", "true" if str(data["escrow_enabled"]).lower() in ("true", "1", "yes") else "false")
    if "platform_status" in data:
        set_setting("platform_status", clean(data["platform_status"], 30) or "ONLINE")
    audit(current_user(), "update_rates", details={k: data[k] for k in list(ranges) + ["first_month_free", "platform_status", "escrow_enabled"] if k in data})
    db.session.commit()
    return get_rates()


# --------------------------------------------------------------------------
# Reports (any logged-in user can report; admins review)
# --------------------------------------------------------------------------
def create_report(reporter):
    data = request.get_json(silent=True) or {}
    target_type = clean(data.get("target_type", "platform"), 30).lower()
    if target_type not in ("user", "gig", "message", "platform"):
        return fail("Invalid report type")
    reason = clean(data.get("reason"), 255)
    if not reason:
        return fail("Please tell us why you are reporting this")
    db.session.add(Report(reporter_id=reporter.id, target_type=target_type, target_id=to_int(data.get("target_id")),
                          reason=reason, details=clean(data.get("details"), 2000)))
    db.session.commit()
    return ok(message="Report submitted. Thank you.")


@app.route("/reports", methods=["POST"])
@login_required
def submit_report():
    return create_report(current_user())


# --------------------------------------------------------------------------
# Admin
# --------------------------------------------------------------------------
PROFILE_STATUSES = {"pending", "approved", "rejected"}


@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    a, q = request.args, User.query
    if a.get("q", "").strip():
        p = like(a["q"].strip()[:80])
        q = q.filter(or_(User.name.ilike(p, escape="\\"), User.phone.ilike(p, escape="\\"), User.email.ilike(p, escape="\\")))
    if a.get("profile_status"):
        q = q.filter(User.profile_status == a["profile_status"])
    if a.get("role"):
        q = q.filter(User.role == a["role"])
    rows, meta = paginate(q.order_by(User.created_at.desc(), User.id.desc()))
    return ok(users=[user_dict(u) for u in rows], **meta)


@app.route("/admin/users/<int:user_id>", methods=["PUT"])
@admin_required
def admin_update_user(user_id):
    actor, data = current_user(), request.get_json(silent=True) or {}
    u = db.session.get(User, user_id)
    if not u:
        return fail("User not found", 404)
    if u.role == "super_admin" and actor.role != "super_admin":
        return fail("Only Super Admin can modify Super Admin", 403)
    if u.role == "admin" and actor.role != "super_admin":
        return fail("Only Super Admin can modify other admins", 403)
    if u.id == actor.id and ("suspended" in data or "role" in data):
        return fail("You can't change your own role or suspend yourself")

    changes = []
    if "profile_status" in data:
        status = clean(data["profile_status"], 20)
        if status not in PROFILE_STATUSES:
            return fail("profile_status must be pending, approved or rejected")
        if status != u.profile_status:
            u.profile_status = status
            changes.append(f"profile_status={status}")
            messages_ = {"approved": ("Profile approved", "Your profile was approved. You can now post and accept gigs."),
                         "rejected": ("Profile not approved", "Your profile wasn't approved. Update your details or contact support.")}
            if status in messages_:
                notify(u.id, *messages_[status], "profile")
    if "suspended" in data:
        u.suspended = bool(data["suspended"])
        changes.append(f"suspended={u.suspended}")
    if "role" in data:
        new_role = clean(data["role"], 20)
        if new_role not in ("user", "admin"):
            return fail("role must be 'user' or 'admin' (there is only one Super Admin)")
        if u.role == "super_admin":
            return fail("The Super Admin's role can't be changed")
        if new_role == "admin" and actor.role != "super_admin":
            return fail("Only Super Admin can manage admins", 403)
        u.role = new_role
        changes.append(f"role={new_role}")
    if changes:
        audit(actor, "update_user", "user", u.id, ", ".join(changes))
    db.session.commit()
    return ok(user=user_dict(u))


@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@super_admin_required
def admin_delete_user(user_id):
    u = db.session.get(User, user_id)
    if not u:
        return fail("User not found", 404)
    if u.role == "super_admin":
        return fail("The Super Admin account cannot be deleted")
    active = Gig.query.filter(or_(Gig.owner_id == u.id, Gig.assigned_worker_id == u.id),
                              Gig.status.in_(("open", "assigned", "in_progress"))).count()
    if active:
        return fail("This user still has active gigs. Suspend the account instead, or cancel their gigs first.", 409)
    Favourite.query.filter_by(user_id=u.id).delete()
    Notification.query.filter_by(user_id=u.id).delete()
    NotificationRead.query.filter_by(user_id=u.id).delete()
    audit(current_user(), "delete_user", "user", u.id, u.name)
    db.session.delete(u)
    db.session.commit()
    return ok(message="User removed")


@app.route("/admin/gigs", methods=["GET"])
@admin_required
def admin_gigs():
    return get_gigs()


@app.route("/admin/gigs/<int:gig_id>", methods=["DELETE"])
@admin_required
def admin_delete_gig(gig_id):
    return delete_gig(gig_id)


def build_stats():
    def counts(column):
        return dict(db.session.query(column, func.count()).group_by(column).all())

    by_status, by_category = counts(Gig.status), counts(Gig.category)
    users_by_status, users_by_role = counts(User.profile_status), counts(User.role)
    week_ago = utcnow() - timedelta(days=7)
    fees = db.session.query(func.coalesce(func.sum(-WalletTransaction.amount), 0)).filter(
        WalletTransaction.kind == "fee").scalar()
    employer_fees = db.session.query(func.coalesce(func.sum(Gig.employer_fee), 0)).filter(Gig.escrow_status == "released").scalar()
    held = db.session.query(func.coalesce(func.sum(Gig.agreed_price + Gig.employer_fee), 0)).filter(Gig.escrow_status == "held").scalar()
    return {
        "users": sum(users_by_status.values()), "gigs": sum(by_status.values()),
        "approved_users": users_by_status.get("approved", 0), "pending_users": users_by_status.get("pending", 0),
        "completed_gigs": by_status.get("completed", 0), "admins": users_by_role.get("admin", 0),
        "category_counts": {c: by_category.get(c, 0) for c in CATEGORIES},
        # new in v2
        "open_gigs": by_status.get("open", 0), "gigs_by_status": by_status,
        "new_users_7d": User.query.filter(User.created_at >= week_ago).count(),
        "pending_topups": WalletTransaction.query.filter_by(kind="topup", status="pending").count(),
        "open_reports": Report.query.filter_by(status="open").count(),
        "platform_fees_collected": round(float(fees or 0) + float(employer_fees or 0), 2),
        "escrow_held": round(float(held or 0), 2),
        "pending_withdrawals": WalletTransaction.query.filter_by(kind="withdrawal", status="pending").count(),
    }


@app.route("/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    return ok(stats=build_stats())


@app.route("/admin/dashboard", methods=["GET"])
@admin_required
def dashboard():
    return ok(user=user_dict(current_user()), stats=build_stats())


@app.route("/admin/reports", methods=["GET", "POST"])
@admin_required
def admin_reports():
    if request.method == "POST":
        return create_report(current_user())
    rows, meta = paginate(Report.query.order_by(Report.created_at.desc()))
    return ok(reports=[{"id": r.id, "reporter_id": r.reporter_id, "target_type": r.target_type,
                        "target_id": r.target_id, "reason": r.reason, "details": r.details,
                        "status": r.status, "created_at": iso(r.created_at)} for r in rows], **meta)


@app.route("/admin/reports/<int:rid>", methods=["PUT"])
@admin_required
def update_report(rid):
    r, data = db.session.get(Report, rid), request.get_json(silent=True) or {}
    if not r:
        return fail("Report not found", 404)
    r.status = clean(data.get("status", r.status), 30) or r.status
    audit(current_user(), "update_report", "report", rid, r.status)
    db.session.commit()
    return ok()


@app.route("/admin/notify", methods=["POST"])
@admin_required
def admin_notify():
    return send_admin_notification()


@app.route("/admin/admins", methods=["GET", "POST"])
@super_admin_required
def admins():
    if request.method == "GET":
        rows = User.query.filter(User.role.in_(["admin", "super_admin"])).all()
        return ok(admins=[user_dict(u) for u in rows])
    data = request.get_json(silent=True) or {}
    name, phone, password = clean(data.get("name"), 100), normalize_phone(data.get("phone")), str(data.get("password", ""))
    if not name or not phone or len(password) < 8:
        return fail("Name, a valid phone number and a password of at least 8 characters are required")
    if User.query.filter(User.phone.in_(phone_variants(phone))).first():
        return fail("Phone already exists", 409)
    u = User(name=name, phone=phone, password=generate_password_hash(password), profile_status="approved", role="admin")
    db.session.add(u)
    db.session.flush()
    audit(current_user(), "create_admin", "user", u.id, name)
    db.session.commit()
    return ok(user=user_dict(u))


@app.route("/admin/admins/<int:user_id>", methods=["PUT"])
@super_admin_required
def change_admin(user_id):
    u, data = db.session.get(User, user_id), request.get_json(silent=True) or {}
    if not u:
        return fail("User not found", 404)
    if u.role == "super_admin":
        return fail("The Super Admin cannot be demoted here")
    role = clean(data.get("role", "admin"), 20)
    if role not in ("user", "admin"):
        return fail("role must be 'user' or 'admin'")
    u.role = role
    audit(current_user(), "change_role", "user", u.id, role)
    db.session.commit()
    return ok(user=user_dict(u))


@app.route("/admin/audit", methods=["GET"])
@super_admin_required
def audit_log():
    rows, meta = paginate(AuditLog.query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()))
    people = {u.id: u.name for u in User.query.filter(User.id.in_(list({r.actor_id for r in rows if r.actor_id})))} if rows else {}
    return ok(entries=[{"id": r.id, "actor_id": r.actor_id, "actor_name": people.get(r.actor_id), "action": r.action,
                        "target_type": r.target_type, "target_id": r.target_id, "details": r.details,
                        "created_at": iso(r.created_at)} for r in rows], **meta)


@app.cli.command("make-super-admin")
@click.argument("phone")
def make_super_admin(phone):
    """Make the account with this phone number the ONLY Super Admin."""
    local = normalize_phone(phone)
    if not local:
        raise click.ClickException("That is not a valid Zambian mobile number.")
    user = User.query.filter(User.phone.in_(phone_variants(local))).first()
    if not user:
        raise click.ClickException("No account with that number. Register it on the website first, then run this again.")
    for other in User.query.filter(User.role == "super_admin", User.id != user.id).all():
        other.role = "user"
    user.role, user.profile_status, user.suspended = "super_admin", "approved", False
    db.session.commit()
    print(f"Done. {user.name} ({user.phone}) is now the only Super Admin.")


if __name__ == "__main__":
    app.run(host=os.environ.get("ZAMGIG_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG", "0") == "1")
