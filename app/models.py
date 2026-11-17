from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    incidents = db.relationship(
        "Incident", back_populates="user", cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    severity = db.Column(db.String(30), nullable=False, default="Medium")
    status = db.Column(db.String(30), nullable=False, default="Open")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    user = db.relationship("User", back_populates="incidents")
    log_entries = db.relationship(
        "LogEntry", back_populates="incident", cascade="all, delete-orphan"
    )
    investigation_notes = db.relationship(
        "InvestigationNote", back_populates="incident", cascade="all, delete-orphan"
    )


class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=False)
    event_type = db.Column(db.String(100), nullable=False)
    raw_log = db.Column(db.Text, nullable=False)
    incident_id = db.Column(
        db.Integer, db.ForeignKey("incident.id"), nullable=False, index=True
    )

    incident = db.relationship("Incident", back_populates="log_entries")


class InvestigationNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    incident_id = db.Column(
        db.Integer, db.ForeignKey("incident.id"), nullable=False, index=True
    )

    incident = db.relationship("Incident", back_populates="investigation_notes")
