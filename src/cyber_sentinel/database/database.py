"""Database engine and session management."""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from cyber_sentinel.utils.logging import get_logger

logger = get_logger(__name__)

_engine = None
_SessionLocal = None


def _get_db_url() -> str:
    """Get the database URL from settings."""
    try:
        from cyber_sentinel.config.settings import settings
        return settings.get_database_url()
    except Exception:
        return "sqlite:///database/cyber_sentinel.db"


def get_engine():
    """Get or create the SQLAlchemy engine (singleton)."""
    global _engine
    if _engine is None:
        db_url = _get_db_url()
        _engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=False,
        )
        # Enable WAL mode for better concurrent reads
        if "sqlite" in db_url:
            @event.listens_for(_engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        logger.info("Database engine created: %s", db_url)
    return _engine


def get_session_factory():
    """Get or create the session factory."""
    global _SessionLocal
    if _SessionLocal is None:
        engine = get_engine()
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine,
        )
    return _SessionLocal


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Context manager yielding a database session.

    Usage:
        with get_session() as session:
            session.add(record)
            session.commit()
    """
    SessionLocal = get_session_factory()
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def initialize_database(db_url: str = None) -> None:
    """Create all database tables if they don't exist.

    Args:
        db_url: Optional database URL override.
    """
    global _engine, _SessionLocal

    if db_url:
        _engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=False,
        )
        _SessionLocal = None  # Reset session factory

    from cyber_sentinel.database.models import Base
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized (tables created if needed)")
