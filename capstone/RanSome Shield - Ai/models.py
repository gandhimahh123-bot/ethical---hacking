from datetime import datetime, timezone
import json
from database import db

def utc_now():
    return datetime.now(timezone.utc)

class AgentNode(db.Model):
    __tablename__ = 'agent_nodes'
    
    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.String(128), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(128), nullable=False)
    os_info = db.Column(db.String(256), nullable=False, default='Windows')
    status = db.Column(db.String(32), default='ONLINE')  # ONLINE, ACTIVE_MONITORING, OFFLINE
    last_seen = db.Column(db.DateTime, default=utc_now, index=True)
    monitored_paths = db.Column(db.Text, nullable=True)  # JSON list
    active_monitors = db.Column(db.Integer, default=0)
    version = db.Column(db.String(32), default='1.0.0-PRO')
    ip_address = db.Column(db.String(64), nullable=True)

    def is_online(self, max_seconds_offline=90):
        if not self.last_seen:
            return False
        now = datetime.now(timezone.utc)
        seen = self.last_seen
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return (now - seen).total_seconds() < max_seconds_offline

    def get_monitored_paths(self):
        try:
            return json.loads(self.monitored_paths) if self.monitored_paths else []
        except Exception:
            return []

    def to_dict(self):
        online = self.is_online()
        return {
            'id': self.id,
            'node_id': self.node_id,
            'hostname': self.hostname,
            'os_info': self.os_info,
            'status': self.status if online else 'OFFLINE',
            'is_online': online,
            'last_seen': self.last_seen.strftime('%Y-%m-%d %H:%M:%S') if self.last_seen else None,
            'monitored_paths': self.get_monitored_paths(),
            'active_monitors': self.active_monitors if online else 0,
            'version': self.version,
            'ip_address': self.ip_address
        }


class MonitoredFolder(db.Model):
    __tablename__ = 'monitored_folders'
    
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(512), unique=True, nullable=False, index=True)
    name = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    recursive = db.Column(db.Boolean, default=True)
    is_demo = db.Column(db.Boolean, default=False)
    added_at = db.Column(db.DateTime, default=utc_now)
    last_scan = db.Column(db.DateTime, nullable=True)
    
    events = db.relationship('FileEvent', backref='folder', lazy='dynamic', cascade='all, delete-orphan')
    baselines = db.relationship('IntegrityBaseline', backref='folder', lazy='dynamic', cascade='all, delete-orphan')
    checks = db.relationship('IntegrityCheck', backref='folder', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'path': self.path,
            'name': self.name,
            'is_active': self.is_active,
            'recursive': self.recursive,
            'is_demo': self.is_demo,
            'added_at': self.added_at.strftime('%Y-%m-%d %H:%M:%S') if self.added_at else None,
            'last_scan': self.last_scan.strftime('%Y-%m-%d %H:%M:%S') if self.last_scan else None,
            'event_count': self.events.count()
        }


class FileEvent(db.Model):
    __tablename__ = 'file_events'
    
    id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('monitored_folders.id', ondelete='CASCADE'), nullable=True, index=True)
    file_path = db.Column(db.String(512), nullable=False, index=True)
    relative_path = db.Column(db.String(512), nullable=True)
    event_type = db.Column(db.String(32), nullable=False)  # 'created', 'modified', 'deleted', 'moved'
    old_path = db.Column(db.String(512), nullable=True)     # For rename/move events
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    is_suspicious = db.Column(db.Boolean, default=False)
    is_demo = db.Column(db.Boolean, default=False)
    process_info = db.Column(db.String(256), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'folder_id': self.folder_id,
            'file_path': self.file_path,
            'relative_path': self.relative_path,
            'event_type': self.event_type,
            'old_path': self.old_path,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None,
            'is_suspicious': self.is_suspicious,
            'is_demo': self.is_demo,
            'process_info': self.process_info
        }


class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    severity = db.Column(db.String(32), nullable=False, default='Medium')  # Low, Medium, High, Critical
    risk_score = db.Column(db.Integer, nullable=False, default=50)         # 0 - 100
    file_path = db.Column(db.String(512), nullable=False)
    detection_reasons = db.Column(db.Text, nullable=False)                 # JSON string or bullet points
    event_count = db.Column(db.Integer, default=1)
    status = db.Column(db.String(32), default='New', index=True)           # New, Acknowledged, Resolved, False Positive
    investigation_notes = db.Column(db.Text, nullable=True)
    is_demo = db.Column(db.Boolean, default=False)
    
    def get_reasons_list(self):
        try:
            return json.loads(self.detection_reasons)
        except Exception:
            return [self.detection_reasons]

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'file_path': self.file_path,
            'detection_reasons': self.get_reasons_list(),
            'event_count': self.event_count,
            'status': self.status,
            'investigation_notes': self.investigation_notes or '',
            'is_demo': self.is_demo
        }


class IntegrityBaseline(db.Model):
    __tablename__ = 'integrity_baselines'
    
    id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('monitored_folders.id', ondelete='CASCADE'), nullable=False, index=True)
    file_path = db.Column(db.String(512), nullable=False, index=True)
    relative_path = db.Column(db.String(512), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    last_modified = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    status = db.Column(db.String(32), default='active')  # 'active', 'superseded'
    is_demo = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'folder_id': self.folder_id,
            'file_path': self.file_path,
            'relative_path': self.relative_path,
            'sha256_hash': self.sha256_hash,
            'file_size': self.file_size,
            'last_modified': self.last_modified.strftime('%Y-%m-%d %H:%M:%S') if self.last_modified else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'status': self.status,
            'is_demo': self.is_demo
        }


class IntegrityCheck(db.Model):
    __tablename__ = 'integrity_checks'
    
    id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('monitored_folders.id', ondelete='CASCADE'), nullable=False)
    checked_at = db.Column(db.DateTime, default=utc_now, index=True)
    total_files = db.Column(db.Integer, default=0)
    modified_files = db.Column(db.Integer, default=0)
    missing_files = db.Column(db.Integer, default=0)
    new_files = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default='clean')  # clean, anomalies_detected, error
    details = db.Column(db.Text, nullable=True)         # JSON containing modified/missing/new file lists
    is_demo = db.Column(db.Boolean, default=False)

    def to_dict(self):
        try:
            details_obj = json.loads(self.details) if self.details else {}
        except Exception:
            details_obj = {}
            
        return {
            'id': self.id,
            'folder_id': self.folder_id,
            'folder_name': self.folder.name if self.folder else 'Unknown',
            'checked_at': self.checked_at.strftime('%Y-%m-%d %H:%M:%S') if self.checked_at else None,
            'total_files': self.total_files,
            'modified_files': self.modified_files,
            'missing_files': self.missing_files,
            'new_files': self.new_files,
            'status': self.status,
            'details': details_obj,
            'is_demo': self.is_demo
        }


class BackupRecord(db.Model):
    __tablename__ = 'backup_records'
    
    id = db.Column(db.Integer, primary_key=True)
    original_path = db.Column(db.String(512), nullable=False)
    backup_path = db.Column(db.String(512), nullable=False)
    relative_path = db.Column(db.String(512), nullable=True)
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    sha256_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, index=True)
    notes = db.Column(db.String(256), nullable=True)
    is_valid = db.Column(db.Boolean, default=True)
    is_demo = db.Column(db.Boolean, default=False)
    
    recoveries = db.relationship('RecoveryRecord', backref='backup', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'original_path': self.original_path,
            'backup_path': self.backup_path,
            'relative_path': self.relative_path,
            'file_size': self.file_size,
            'sha256_hash': self.sha256_hash,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'notes': self.notes or '',
            'is_valid': self.is_valid,
            'is_demo': self.is_demo
        }


class RecoveryRecord(db.Model):
    __tablename__ = 'recovery_records'
    
    id = db.Column(db.Integer, primary_key=True)
    backup_id = db.Column(db.Integer, db.ForeignKey('backup_records.id', ondelete='SET NULL'), nullable=True)
    target_path = db.Column(db.String(512), nullable=False)
    recovered_at = db.Column(db.DateTime, default=utc_now, index=True)
    verified_hash = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(32), default='Success')  # Success, Mismatch, Failed
    notes = db.Column(db.Text, nullable=True)
    is_demo = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'backup_id': self.backup_id,
            'target_path': self.target_path,
            'recovered_at': self.recovered_at.strftime('%Y-%m-%d %H:%M:%S') if self.recovered_at else None,
            'verified_hash': self.verified_hash,
            'status': self.status,
            'notes': self.notes or '',
            'is_demo': self.is_demo
        }


class QuarantineRecord(db.Model):
    __tablename__ = 'quarantine_records'
    
    id = db.Column(db.Integer, primary_key=True)
    original_path = db.Column(db.String(512), nullable=False)
    quarantine_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    sha256_hash = db.Column(db.String(64), nullable=False)
    quarantined_at = db.Column(db.DateTime, default=utc_now, index=True)
    reason = db.Column(db.String(256), nullable=False)
    status = db.Column(db.String(32), default='Quarantined', index=True)  # Quarantined, Restored, Deleted
    is_demo = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'original_path': self.original_path,
            'quarantine_path': self.quarantine_path,
            'file_size': self.file_size,
            'sha256_hash': self.sha256_hash,
            'quarantined_at': self.quarantined_at.strftime('%Y-%m-%d %H:%M:%S') if self.quarantined_at else None,
            'reason': self.reason,
            'status': self.status,
            'is_demo': self.is_demo
        }


class ApplicationSetting(db.Model):
    __tablename__ = 'application_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    value = db.Column(db.String(512), nullable=False)
    description = db.Column(db.String(256), nullable=True)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

    def to_dict(self):
        return {
            'key': self.key,
            'value': self.value,
            'description': self.description,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    ip_address = db.Column(db.String(64), default='127.0.0.1')
    is_demo = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None,
            'ip_address': self.ip_address,
            'is_demo': self.is_demo
        }
