"""Database engine, session factory and the declarative base."""

from collections.abc import Generator
from datetime import datetime

from sqlalchemy import DateTime, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    pool_pre_ping=True,  # Recycle connections dropped by the server.
    pool_size=5,
    max_overflow=10,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    """Declarative base shared by every ORM model."""


class TimestampMixin:
    """`created_at` / `updated_at` columns maintained by the database."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a session that is always closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
