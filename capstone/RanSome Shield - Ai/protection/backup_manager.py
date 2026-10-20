import shutil
import uuid
from pathlib import Path
from datetime import datetime
from config import Config
from detection.integrity_checker import IntegrityChecker
from models import BackupRecord, AuditLog
from database import db

class BackupManager:
    @staticmethod
    def create_file_backup(source_file_path: Path | str, notes: str = None) -> BackupRecord | None:
        """
        Safely copies a single file to the application backup store.
        """
        src = Path(source_file_path).resolve()
        if not src.exists() or not src.is_file():
            return None

        # Guard against backing up application internal directories
        if Config.INSTANCE_DIR in src.parents or src == Config.INSTANCE_DIR:
            if not (Config.DEMO_DIR in src.parents or src == Config.DEMO_DIR):
                return None

        file_hash = IntegrityChecker.calculate_sha256(src)
        if not file_hash:
            return None

        file_size = src.stat().st_size
        timestamp_prefix = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        unique_name = f"{timestamp_prefix}_{uuid.uuid4().hex[:8]}_{src.name}"
        dest = Config.BACKUP_DIR / unique_name

        try:
            shutil.copy2(src, dest)
            # Verify copied file hash
            copied_hash = IntegrityChecker.calculate_sha256(dest)
            if copied_hash != file_hash:
                dest.unlink(missing_ok=True)
                return None

            record = BackupRecord(
                original_path=str(src),
                backup_path=str(dest),
                relative_path=src.name,
                file_size=file_size,
                sha256_hash=file_hash,
                created_at=datetime.utcnow(),
                notes=notes or 'Manual file snapshot',
                is_valid=True
            )
            db.session.add(record)
            
            audit = AuditLog(
                action='BACKUP_CREATED',
                details=f"Backup created for {src} -> {dest} (Hash: {file_hash[:12]}...)"
            )
            db.session.add(audit)
            db.session.commit()
            return record
        except Exception:
            db.session.rollback()
            dest.unlink(missing_ok=True)
            return None

    @staticmethod
    def create_folder_backup(folder_path: Path | str, notes: str = None) -> list[BackupRecord]:
        """
        Safely backs up all valid files in a directory.
        """
        folder = Path(folder_path).resolve()
        if not folder.exists() or not folder.is_dir():
            return []

        # Prevent recursive backup of backup store
        if Config.BACKUP_DIR in folder.parents or folder == Config.BACKUP_DIR:
            return []

        created_records = []
        for file_p in folder.rglob('*'):
            if file_p.is_file() and not file_p.is_symlink():
                # Ignore internal files
                parts = file_p.relative_to(folder).parts
                if any(part in Config.INTERNAL_IGNORED_NAMES for part in parts):
                    continue
                record = BackupManager.create_file_backup(file_p, notes=notes or f"Folder snapshot: {folder.name}")
                if record:
                    created_records.append(record)

        return created_records

    @staticmethod
    def verify_backup(backup_id: int) -> dict:
        """
        Verifies that a stored backup file exists and matches its initial SHA-256 hash.
        """
        record = db.session.get(BackupRecord, backup_id)
        if not record:
            return {'status': 'error', 'message': 'Backup record not found'}

        dest = Path(record.backup_path)
        if not dest.exists() or not dest.is_file():
            record.is_valid = False
            db.session.commit()
            return {'status': 'missing', 'message': 'Backup file is missing from storage', 'is_valid': False}

        current_hash = IntegrityChecker.calculate_sha256(dest)
        is_match = (current_hash == record.sha256_hash)
        record.is_valid = is_match
        db.session.commit()

        return {
            'status': 'verified' if is_match else 'tampered',
            'is_valid': is_match,
            'original_hash': record.sha256_hash,
            'current_hash': current_hash,
            'message': 'Backup integrity verified successfully' if is_match else 'Backup integrity check failed: hash mismatch'
        }
