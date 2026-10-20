import shutil
from pathlib import Path
from datetime import datetime
from detection.integrity_checker import IntegrityChecker
from models import BackupRecord, RecoveryRecord, AuditLog
from database import db

class RecoveryManager:
    @staticmethod
    def restore_backup(backup_id: int, target_destination: str = None) -> dict:
        """
        Restores a backup record to either its original path or a user-specified destination.
        Never blindly overwrites without integrity checks.
        """
        backup = db.session.get(BackupRecord, backup_id)
        if not backup:
            return {'success': False, 'message': 'Backup not found'}

        src_backup = Path(backup.backup_path).resolve()
        if not src_backup.exists() or not src_backup.is_file():
            return {'success': False, 'message': 'Backup source file missing on disk'}

        # Verify source backup has not been corrupted
        src_hash = IntegrityChecker.calculate_sha256(src_backup)
        if src_hash != backup.sha256_hash:
            return {'success': False, 'message': 'Backup source failed hash verification prior to restore'}

        # Target resolution
        target_path_str = target_destination.strip() if target_destination and target_destination.strip() else backup.original_path
        target = Path(target_path_str).resolve()

        # Path traversal and safety guards
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_backup, target)
            
            # Post-restoration verification
            restored_hash = IntegrityChecker.calculate_sha256(target)
            is_verified = (restored_hash == backup.sha256_hash)

            status = 'Success' if is_verified else 'Mismatch'
            notes = f"Restored from backup #{backup.id} to {target}"

            rec = RecoveryRecord(
                backup_id=backup.id,
                target_path=str(target),
                recovered_at=datetime.utcnow(),
                verified_hash=restored_hash,
                status=status,
                notes=notes
            )
            db.session.add(rec)
            
            audit = AuditLog(
                action='FILE_RESTORED',
                details=f"File restored from backup #{backup.id} to {target} (Status: {status})"
            )
            db.session.add(audit)
            db.session.commit()

            return {
                'success': is_verified,
                'status': status,
                'target_path': str(target),
                'verified_hash': restored_hash,
                'expected_hash': backup.sha256_hash,
                'message': 'File restored and verified successfully' if is_verified else 'File restored but hash mismatch occurred'
            }
        except Exception as e:
            db.session.rollback()
            return {'success': False, 'message': f"Restore failed with error: {str(e)}"}
