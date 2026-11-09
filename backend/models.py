from datetime import datetime, timezone
from backend.extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    scans = db.relationship(
        "Scan",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )
    scan_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(30), nullable=False)
    score = db.Column(db.Integer)
    details = db.Column(db.JSON)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )