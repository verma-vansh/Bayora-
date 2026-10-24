"""SQLAlchemy models and engine helpers."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))


class AuditEvent(Base):
    """Append-only, hash-chained. In PostgreSQL UPDATE/DELETE are blocked (db/init)."""
    __tablename__ = "audit_events"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ts: Mapped[str] = mapped_column(String(40))
    actor: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(16))
    event_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    source_ip: Mapped[str] = mapped_column(String(64))
    details: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    sig: Mapped[str] = mapped_column(String(64))


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(10))  # keyword | regex
    pattern: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(8))  # block | flag
    severity: Mapped[str] = mapped_column(String(10))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))


class Campaign(Base):
    __tablename__ = "campaigns"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))
    mode: Mapped[str] = mapped_column(String(10))
    summary: Mapped[str] = mapped_column(Text)


class AttackResult(Base):
    __tablename__ = "attack_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"))
    attack_id: Mapped[str] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(24))
    severity: Mapped[str] = mapped_column(String(10))
    outcome: Mapped[str] = mapped_column(String(12))
    blocked_by: Mapped[str] = mapped_column(String(64), default="")
    leaked: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)


def make_engine(url: str):
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


def init_db(engine) -> None:
    Base.metadata.create_all(engine)
    if engine.dialect.name != "postgresql":
        return
    # Normally db/init/01-roles.sh already installed the trigger and a least-privilege role.
    # If we are running with a privileged role (dev setups), install it here as defence in depth.
    with engine.connect() as c:
        has = c.execute(text("SELECT 1 FROM pg_trigger WHERE tgname='audit_no_mutation'")).first()
    if has:
        return
    try:
        with engine.begin() as c:
            c.execute(text("""
                CREATE OR REPLACE FUNCTION bayora_audit_immutable() RETURNS trigger AS $$
                BEGIN RAISE EXCEPTION 'audit_events is append-only'; END; $$ LANGUAGE plpgsql;
            """))
            c.execute(text("""
                CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON audit_events
                FOR EACH ROW EXECUTE FUNCTION bayora_audit_immutable();
            """))
    except Exception as e:  # pragma: no cover - needs a real Postgres
        import logging
        logging.getLogger("bayora").warning("could not install audit immutability trigger: %s", type(e).__name__)


def make_session_factory(engine):
    return sessionmaker(engine, expire_on_commit=False)
