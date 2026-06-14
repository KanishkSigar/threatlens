"""
Scan ORM Model
Represents phishing scan results.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    """Phishing scan result model."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    scan_type: Mapped[str] = mapped_column(
        String(10),
        nullable=False,  # 'url' or 'email'
    )
    input_data: Mapped[str] = mapped_column(
        Text,
        nullable=False,  # The URL or email content scanned
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,  # 0.0 to 100.0
    )
    verdict: Mapped[str] = mapped_column(
        String(20),
        nullable=False,  # 'SAFE', 'SUSPICIOUS', 'PHISHING'
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,  # 0.0 to 1.0
    )
    details_json: Mapped[str] = mapped_column(
        Text,
        nullable=True,  # Full feature breakdown as JSON string
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    user = relationship("User", back_populates="scans")

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, type={self.scan_type}, verdict={self.verdict})>"
