"""Модель данных VulnTrack: пользователи, активы (assets) и уязвимости."""
from datetime import datetime

from sqlalchemy import String, Integer, Float, Text, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    """Аналитик, работающий с трекером."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    team: Mapped[str] = mapped_column(String(64), default="default")

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="reported_by", cascade="all, delete-orphan"
    )


class Asset(Base):
    """Актив (хост, сервис, репозиторий), к которому привязаны уязвимости."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    hostname: Mapped[str] = mapped_column(String(200), default="")
    team: Mapped[str] = mapped_column(String(64), default="default")

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    """Запись об уязвимости, найденной на активе."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), default="")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|fixed|accepted
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    asset: Mapped["Asset"] = relationship(back_populates="vulnerabilities")

    reported_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reported_by: Mapped["User"] = relationship(back_populates="vulnerabilities")
