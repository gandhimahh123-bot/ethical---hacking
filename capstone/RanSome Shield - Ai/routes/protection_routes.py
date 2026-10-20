from flask import render_template, request, jsonify, session
from pathlib import Path
from datetime import datetime, timezone
import hashlib
from . import protection_bp
from config import Config
from database import db
from models import BackupRecord, RecoveryRecord, QuarantineRecord, AuditLog
from protection.backup_manager import BackupManager
from protection.recovery_manager import RecoveryManager
from protection.quarantine_manager import QuarantineManager

@protection_bp.route('/protection')
def index():
    return render_template('protection.html')

@protection_bp.route('/api/backups', methods=['GET'])
def get_backups():
    backups = BackupRecord.query.order_by(BackupRecord.created_at.desc()).all()
    return jsonify({'status': 'success', 'data': [b.to_dict() for b in backups]})

@protection_bp.route('/api/backups', methods=['POST'])
def create_backup():
    data = request.get_json() or {}
    target_path = data.get('path', '').strip()
    notes = data.get('notes', '').strip()
    is_folder = bool(data.get('is_folder', False))

    if not target_path:
        return jsonify({'status': 'error', 'message': 'Target path is required'}), 400

    # In Cloud Mode (e.g. Vercel), prevent arbitrary server filesystem access.
    # Provide safe demonstration snapshot creation.
    if Config.IS_CLOUD_DEPLOYMENT:
        simulated_hash = hashlib.sha256(f"demo_content_{target_path}_{notes}".encode()).hexdigest()
        demo_backup = BackupRecord(
            original_path=target_path,
            backup_path=f"demo_vault/{Path(target_path).name}",
            relative_path=Path(target_path).name,
            file_size=2048,
            sha256_hash=simulated_hash,
            created_at=datetime.now(timezone.utc),
            notes=notes or "Cloud Demo Snapshot",
            is_valid=True,
            is_demo=True
        )
        db.session.add(demo_backup)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': '[DEMO MODE] Demonstration backup snapshot created successfully (Cloud Safe)',
            'data': demo_backup.to_dict(),
            'is_demo': True
        })

    # Local Windows execution
    p = Path(target_path).resolve()
    if not p.exists():
        return jsonify({'status': 'error', 'message': 'Specified path does not exist on disk'}), 400

    if is_folder or p.is_dir():
        records = BackupManager.create_folder_backup(p, notes=notes)
        if not records:
            return jsonify({'status': 'error', 'message': 'No eligible files found to backup'}), 400
        return jsonify({
            'status': 'success',
            'message': f'Successfully backed up {len(records)} files',
            'count': len(records)
        })
    else:
        record = BackupManager.create_file_backup(p, notes=notes)
        if not record:
            return jsonify({'status': 'error', 'message': 'Failed to create backup (inaccessible or restricted file)'}), 500
        return jsonify({
            'status': 'success',
            'message': 'Backup created successfully',
            'data': record.to_dict()
        })

@protection_bp.route('/api/backups/<int:backup_id>/verify', methods=['POST'])
def verify_backup(backup_id):
    backup = db.session.get(BackupRecord, backup_id)
    if not backup:
        return jsonify({'status': 'error', 'message': 'Backup record not found'}), 404

    # If demo record or in cloud mode
    if backup.is_demo or Config.IS_CLOUD_DEPLOYMENT:
        return jsonify({
            'status': 'verified',
            'message': '[DEMO MODE] Cryptographic SHA-256 hash verified match against baseline (Demo Vault)',
            'is_valid': True,
            'is_demo': True
        })

    result = BackupManager.verify_backup(backup_id)
    return jsonify(result)

@protection_bp.route('/api/backups/<int:backup_id>/restore', methods=['POST'])
def restore_backup(backup_id):
    backup = db.session.get(BackupRecord, backup_id)
    if not backup:
        return jsonify({'status': 'error', 'message': 'Backup record not found'}), 404

    data = request.get_json() or {}
    dest = data.get('destination_path', '').strip()

    # Cloud Deployment Guard: Never allow arbitrary server filesystem writes
    if backup.is_demo or Config.IS_CLOUD_DEPLOYMENT:
        recovery = RecoveryRecord(
            backup_id=backup.id,
            target_path=dest or backup.original_path,
            recovered_at=datetime.now(timezone.utc),
            verified_hash=backup.sha256_hash,
            status='Success',
            notes='[DEMO MODE] Simulated restoration in cloud demonstration environment',
            is_demo=True
        )
        db.session.add(recovery)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'data': recovery.to_dict(),
            'message': '[DEMO MODE] Simulated file restoration completed with 100% cryptographic hash fidelity.',
            'is_demo': True
        })

    result = RecoveryManager.restore_backup(backup_id, target_destination=dest if dest else None)
    if result.get('success'):
        return jsonify({'status': 'success', 'data': result, 'message': result['message']})
    else:
        return jsonify({'status': 'error', 'data': result, 'message': result['message']}), 400

@protection_bp.route('/api/quarantine', methods=['GET'])
def get_quarantine_records():
    records = QuarantineRecord.query.order_by(QuarantineRecord.quarantined_at.desc()).all()
    return jsonify({'status': 'success', 'data': [r.to_dict() for r in records]})

@protection_bp.route('/api/quarantine', methods=['POST'])
def quarantine_file():
    data = request.get_json() or {}
    target_path = data.get('file_path', '').strip()
    reason = data.get('reason', 'User initiated quarantine action')

    if not target_path:
        return jsonify({'status': 'error', 'message': 'File path required'}), 400

    # Cloud Guard: Provide safe demonstration quarantine without touching server filesystem
    if Config.IS_CLOUD_DEPLOYMENT:
        simulated_hash = hashlib.sha256(f"demo_quarantine_{target_path}".encode()).hexdigest()
        rec = QuarantineRecord(
            original_path=target_path,
            quarantine_path=f"demo_quarantine_vault/{Path(target_path).name}.isolated",
            file_size=1024,
            sha256_hash=simulated_hash,
            quarantined_at=datetime.now(timezone.utc),
            reason=reason,
            status='Quarantined',
            is_demo=True
        )
        db.session.add(rec)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'data': rec.to_dict(),
            'message': '[DEMO MODE] File quarantined in demonstration vault.',
            'is_demo': True
        })

    result = QuarantineManager.quarantine_file(target_path, reason=reason)
    if result.get('success'):
        return jsonify({'status': 'success', 'data': result, 'message': result['message']})
    else:
        return jsonify({'status': 'error', 'message': result['message']}), 400

@protection_bp.route('/api/quarantine/<int:record_id>/restore', methods=['POST'])
def restore_quarantine(record_id):
    record = db.session.get(QuarantineRecord, record_id)
    if not record:
        return jsonify({'status': 'error', 'message': 'Quarantine record not found'}), 404

    data = request.get_json() or {}
    dest = data.get('destination_path', '').strip()

    if record.is_demo or Config.IS_CLOUD_DEPLOYMENT:
        record.status = 'Restored'
        db.session.commit()
        return jsonify({
            'status': 'success',
            'data': record.to_dict(),
            'message': '[DEMO MODE] Quarantined file restored successfully.',
            'is_demo': True
        })

    result = QuarantineManager.restore_quarantined_file(record_id, destination_path=dest if dest else None)
    if result.get('success'):
        return jsonify({'status': 'success', 'data': result, 'message': result['message']})
    else:
        return jsonify({'status': 'error', 'message': result['message']}), 400

@protection_bp.route('/api/recoveries', methods=['GET'])
def get_recoveries():
    recoveries = RecoveryRecord.query.order_by(RecoveryRecord.recovered_at.desc()).all()
    return jsonify({'status': 'success', 'data': [r.to_dict() for r in recoveries]})
