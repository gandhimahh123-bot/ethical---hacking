import shutil
import uuid
from pathlib import Path
from datetime import datetime
from config import Config
from detection.integrity_checker import IntegrityChecker
from models import QuarantineRecord, AuditLog
from database import db

class QuarantineManager:
    @staticmethod
    def quarantine_file(source_path: Path | str, reason: str = 'User initiated quarantine') -> dict:
        """
        Safely isolates a file by moving it to the quarantine store.
        """
        src = Path(source_path).resolve()
        if not src.exists() or not src.is_file():
            return {'success': False, 'message': 'Target file does not exist'}

        # Calculate initial hash
        orig_hash = IntegrityChecker.calculate_sha256(src)
        if not orig_hash:
            return {'success': False, 'message': 'Could not read file to compute checksum'}

        file_size = src.stat().st_size
        quarantine_filename = f"quarantine_{uuid.uuid4().hex}_{src.name}"
        dest = Config.QUARANTINE_DIR / quarantine_filename

        try:
            # Move file
            shutil.move(str(src), str(dest))
            
            # Post-move verification
            dest_hash = IntegrityChecker.calculate_sha256(dest)
            if dest_hash != orig_hash:
                return {'success': False, 'message': 'Hash check mismatch after quarantine move'}

            record = QuarantineRecord(
                original_path=str(src),
                quarantine_path=str(dest),
                file_size=file_size,
                sha256_hash=dest_hash,
                quarantined_at=datetime.utcnow(),
                reason=reason,
                status='Quarantined'
            )
            db.session.add(record)
            
            audit = AuditLog(
                action='FILE_QUARANTINED',
                details=f"File {src} moved to quarantine {dest} (Hash: {dest_hash[:12]}...)"
            )
            db.session.add(audit)
            db.session.commit()

            return {
                'success': True,
                'record_id': record.id,
                'original_path': str(src),
                'quarantine_path': str(dest),
                'sha256_hash': dest_hash,
                'message': 'File isolated in quarantine successfully'
            }
        except Exception as e:
            db.session.rollback()
            return {'success': False, 'message': f"Failed to quarantine file: {str(e)}"}

    @staticmethod
    def restore_quarantined_file(record_id: int, destination_path: str = None) -> dict:
        """
        Restores a quarantined file to a target destination or original location.
        """
        record = db.session.get(QuarantineRecord, record_id)
        if not record or record.status != 'Quarantined':
            return {'success': False, 'message': 'Quarantine record not active or not found'}

        src = Path(record.quarantine_path).resolve()
        if not src.exists() or not src.is_file():
            return {'success': False, 'message': 'Quarantined file missing on disk'}

        target_str = destination_path.strip() if destination_path and destination_path.strip() else record.original_path
        target = Path(target_str).resolve()

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(target))
            
            record.status = 'Restored'
            
            audit = AuditLog(
                action='FILE_UNQUARANTINED',
                details=f"Quarantined file #{record.id} restored to {target}"
            )
            db.session.add(audit)
            db.session.commit()

            return {
                'success': True,
                'restored_path': str(target),
                'message': 'File restored from quarantine successfully'
            }
        except Exception as e:
            db.session.rollback()
            return {'success': False, 'message': f"Failed to restore quarantined file: {str(e)}"}
