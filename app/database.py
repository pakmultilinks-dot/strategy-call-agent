"""SQLAlchemy engine/session setup.

Engine creation is lazy — no connection is opened at import time.
ORM models are added in Phase 0.5.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings

# connect_timeout is PostgreSQL-specific; SQLite's python driver does not
# accept it, so we only pass it for postgresql URLs.
_connect_args: dict = {}
if settings.database_url.startswith("postgresql"):
    _connect_args = {"connect_timeout": 10}

# Pool settings are PostgreSQL-specific; SQLite does not support
# pool_size / max_overflow / pool_recycle.
_is_postgres = settings.database_url.startswith("postgresql")

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,          # Verify connections before use
    **(
        {
            "pool_size": 5,
            "max_overflow": 10,
            "pool_recycle": 300,
        }
        if _is_postgres
        else {}
    ),
    connect_args=_connect_args,  # 10s connection timeout (PostgreSQL only)
)

# Install SQLite compatibility adapters when running against SQLite.
# This fixes C05 (DateTime binding), C07 (UUID), C12 (Boolean), C06 (JSON).
try:
    from app.sqlite_compat import install_sqlite_compat
    install_sqlite_compat(engine)
except Exception:
    pass  # Non-critical; tests will fail informatively if adapters are needed

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency yielding a DB session (used from Phase 0.5 onward)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
