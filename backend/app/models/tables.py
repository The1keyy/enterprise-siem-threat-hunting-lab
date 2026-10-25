"""Analyst state that Wazuh does not store."""

from typing import Any

from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.db import Base


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    owner: Mapped[str] = mapped_column(String, nullable=False)
    users: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    hosts: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    mitre: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    first_seen: Mapped[str] = mapped_column(String, nullable=False)
    last_seen: Mapped[str] = mapped_column(String, nullable=False)
    demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    entities: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    risk: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    disposition: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(String, nullable=False)
    recommended_containment: Mapped[list[str]] = mapped_column(JSON, nullable=False)


class IncidentEventRow(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    time: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class NoteRow(Base):
    __tablename__ = "notes"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    author: Mapped[str] = mapped_column(String, nullable=False)
    time: Mapped[str] = mapped_column(String, nullable=False)
    text: Mapped[str] = mapped_column(String, nullable=False)


class RiskEventRow(Base):
    __tablename__ = "risk_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    event: Mapped[str] = mapped_column(String, nullable=False)
    rule_id: Mapped[str] = mapped_column(String, nullable=False)
    points: Mapped[int] = mapped_column(Integer, nullable=False)


class SavedHuntRow(Base):
    __tablename__ = "saved_hunts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    hypothesis: Mapped[str] = mapped_column(String, nullable=False)
    data_source: Mapped[str] = mapped_column(String, nullable=False)
    query: Mapped[str] = mapped_column(String, nullable=False)
    expected_behavior: Mapped[str] = mapped_column(String, nullable=False)
    suspicious_behavior: Mapped[str] = mapped_column(String, nullable=False)
    mitre: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    investigation_guidance: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class AuditLogRow(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    time: Mapped[str] = mapped_column(String, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False)
