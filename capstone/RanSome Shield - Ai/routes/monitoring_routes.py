import json
from flask import render_template, request, jsonify
from pathlib import Path
from datetime import datetime, timezone
import hashlib
from . import monitoring_bp
from database import db
from models import MonitoredFolder, FileEvent, IntegrityBaseline, IntegrityCheck, AuditLog, AgentNode
from monitoring.monitoring_manager import MonitoringManager
from detection.integrity_checker import IntegrityChecker
from config import Config

@monitoring_bp.route('/monitoring')
def index():
    return render_template('monitoring.html')

@monitoring_bp.route('/api/monitoring/folders', methods=['GET'])
def get_folders():
    folders = MonitoredFolder.query.all()
    manager = MonitoringManager() if not Config.IS_CLOUD_DEPLOYMENT else None
    
    # Check if any live agent is reporting active monitors
    live_agent = AgentNode.query.filter_by(status='ACTIVE_MONITORING').first()
    agent_is_online = live_agent.is_online() if live_agent else False

    result = []
    for f in folders:
        d = f.to_dict()
        if not Config.IS_CLOUD_DEPLOYMENT and manager:
            d['is_running'] = manager.is_folder_monitoring(f.id)
        else:
            d['is_running'] = (agent_is_online and not f.is_demo) or (f.is_active and f.is_demo)
        result.append(d)
        
    return jsonify({'status': 'success', 'data': result})

@monitoring_bp.route('/api/monitoring/folders', methods=['POST'])
def add_folder():
    data = request.get_json() or {}
    path_str = data.get('path', '').strip()
    name = data.get('name', '').strip()
    recursive = bool(data.get('recursive', True))
    
    if not path_str:
        return jsonify({'status': 'error', 'message': 'Directory path is required'}), 400

    # In Cloud Mode, provide safe demonstration folder registration without local OS disk access
    if Config.IS_CLOUD_DEPLOYMENT:
        existing = MonitoredFolder.query.filter_by(path=path_str).first()
        if existing:
            return jsonify({'status': 'error', 'message': 'This folder path is already registered'}), 400

        folder = MonitoredFolder(
            path=path_str,
            name=name if name else Path(path_str).name or path_str,
            recursive=recursive,
            is_active=True,
            is_demo=True
        )
        db.session.add(folder)
        
        audit = AuditLog(
            action='DEMO_FOLDER_ADDED',
            details=f"[DEMO] Registered simulated folder '{folder.name}'",
            is_demo=True
        )
        db.session.add(audit)
        db.session.commit()

        # Seed initial demo baseline for the new demo folder
        sample_files = [
            "financial_report_2026.docx",
            "executive_summary.pdf",
            "customer_records.csv",
            "system_config.json"
        ]
        for s_file in sample_files:
            file_path = f"{path_str}/{s_file}"
            base = IntegrityBaseline(
                folder_id=folder.id,
                file_path=file_path,
                relative_path=s_file,
                sha256_hash=hashlib.sha256(file_path.encode()).hexdigest(),
                file_size=4096,
                last_modified=datetime.now(timezone.utc),
                status='active',
                is_demo=True
            )
            db.session.add(base)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'data': folder.to_dict(),
            'message': '[DEMO MODE] Folder registered in demonstration environment with baseline hashes.',
            'is_demo': True
        })

    # Local execution with real path validation
    target = Path(path_str).resolve()
    
    if not target.exists() or not target.is_dir():
        return jsonify({'status': 'error', 'message': 'The specified directory does not exist on this machine'}), 400

    # Security guards: prohibit monitoring drive root or system root
    if target == Path(target.anchor) or target == target.parent:
        return jsonify({'status': 'error', 'message': 'Monitoring drive root directly is prohibited for security'}), 400

    if Config.INSTANCE_DIR in target.parents or target == Config.INSTANCE_DIR:
        if not (Config.DEMO_DIR in target.parents or target == Config.DEMO_DIR):
            return jsonify({'status': 'error', 'message': 'Cannot monitor internal application storage directly'}), 400

    existing = MonitoredFolder.query.filter_by(path=str(target)).first()
    if existing:
        return jsonify({'status': 'error', 'message': 'This folder is already registered'}), 400

    folder = MonitoredFolder(
        path=str(target),
        name=name if name else target.name,
        recursive=recursive,
        is_active=True,
        is_demo=False
    )
    db.session.add(folder)
    
    audit = AuditLog(
        action='MONITOR_FOLDER_ADDED',
        details=f"Added folder {target} (Recursive: {recursive})"
    )
    db.session.add(audit)
    db.session.commit()

    manager = MonitoringManager()
    manager.start_monitoring_folder(folder.id, str(target), recursive=recursive)

    return jsonify({'status': 'success', 'data': folder.to_dict(), 'message': 'Folder registered and monitoring started'})

@monitoring_bp.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    data = request.get_json() or {}
    folder_id = data.get('folder_id')
    folder = db.session.get(MonitoredFolder, folder_id)
    if not folder:
        return jsonify({'status': 'error', 'message': 'Folder not found'}), 404

    folder.is_active = True
    db.session.commit()

    if Config.IS_CLOUD_DEPLOYMENT or folder.is_demo:
        return jsonify({
            'status': 'success',
            'message': f'[DEMO MODE] Monitoring activated for {folder.name}',
            'is_demo': True
        })

    manager = MonitoringManager()
    success = manager.start_monitoring_folder(folder.id, folder.path, recursive=folder.recursive)
    if success:
        return jsonify({'status': 'success', 'message': f'Monitoring started for {folder.name}'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to start file observer on folder'}), 500

@monitoring_bp.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    data = request.get_json() or {}
    folder_id = data.get('folder_id')
    folder = db.session.get(MonitoredFolder, folder_id)
    if not folder:
        return jsonify({'status': 'error', 'message': 'Folder not found'}), 404

    folder.is_active = False
    db.session.commit()

    if Config.IS_CLOUD_DEPLOYMENT or folder.is_demo:
        return jsonify({
            'status': 'success',
            'message': f'[DEMO MODE] Monitoring paused for {folder.name}',
            'is_demo': True
        })

    manager = MonitoringManager()
    manager.stop_monitoring_folder(folder.id)
    return jsonify({'status': 'success', 'message': f'Monitoring stopped for {folder.name}'})

@monitoring_bp.route('/api/monitoring/folders/<int:folder_id>', methods=['DELETE'])
def remove_folder(folder_id):
    folder = db.session.get(MonitoredFolder, folder_id)
    if not folder:
        return jsonify({'status': 'error', 'message': 'Folder not found'}), 404

    if not Config.IS_CLOUD_DEPLOYMENT:
        try:
            manager = MonitoringManager()
            manager.stop_monitoring_folder(folder.id)
        except Exception:
            pass
    
    db.session.delete(folder)
    audit = AuditLog(
        action='MONITOR_FOLDER_REMOVED',
        details=f"Removed monitored folder {folder.path}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Folder removed from monitoring'})

@monitoring_bp.route('/api/monitoring/events', methods=['GET'])
def get_events():
    folder_id = request.args.get('folder_id', type=int)
    event_type = request.args.get('event_type')
    suspicious_only = request.args.get('suspicious_only', '').lower() == 'true'
    demo_filter = request.args.get('demo') # 'true', 'false', None
    limit = min(request.args.get('limit', 50, type=int), 200)

    query = FileEvent.query
    if folder_id:
        query = query.filter_by(folder_id=folder_id)
    if event_type:
        query = query.filter_by(event_type=event_type)
    if suspicious_only:
        query = query.filter_by(is_suspicious=True)
    if demo_filter == 'true':
        query = query.filter_by(is_demo=True)
    elif demo_filter == 'false':
        query = query.filter_by(is_demo=False)

    events = query.order_by(FileEvent.timestamp.desc()).limit(limit).all()
    return jsonify({'status': 'success', 'data': [e.to_dict() for e in events]})

# ----------------- INTEGRITY CHECKER APIS -----------------

@monitoring_bp.route('/api/integrity/baseline/create', methods=['POST'])
def create_baseline():
    data = request.get_json() or {}
    folder_id = data.get('folder_id')
    folder = db.session.get(MonitoredFolder, folder_id)
    if not folder:
        return jsonify({'status': 'error', 'message': 'Monitored folder not found'}), 404

    # Archive previous active baselines
    IntegrityBaseline.query.filter_by(folder_id=folder.id, status='active').update({'status': 'superseded'})
    
    # In Cloud Mode or Demo Folder: generate simulated baseline
    if Config.IS_CLOUD_DEPLOYMENT or folder.is_demo:
        sample_names = ["report_q1.docx", "financial_ledger.xlsx", "database_dump.sql", "user_auth.key"]
        for name in sample_names:
            file_path = f"{folder.path}/{name}"
            base = IntegrityBaseline(
                folder_id=folder.id,
                file_path=file_path,
                relative_path=name,
                sha256_hash=hashlib.sha256(f"{name}_{datetime.now(timezone.utc)}".encode()).hexdigest(),
                file_size=8192,
                last_modified=datetime.now(timezone.utc),
                status='active',
                is_demo=True
            )
            db.session.add(base)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': f'[DEMO MODE] Baseline generated with {len(sample_names)} SHA-256 hashes.',
            'file_count': len(sample_names),
            'is_demo': True
        })

    # Real local file scanning
    scanned = IntegrityChecker.scan_directory(folder.path, recursive=folder.recursive)
    for item in scanned:
        base = IntegrityBaseline(
            folder_id=folder.id,
            file_path=item['file_path'],
            relative_path=item['relative_path'],
            sha256_hash=item['sha256_hash'],
            file_size=item['file_size'],
            last_modified=item['last_modified'],
            status='active',
            is_demo=False
        )
        db.session.add(base)

    audit = AuditLog(
        action='BASELINE_INITIALIZED',
        details=f"Generated SHA-256 integrity baseline for {folder.name} ({len(scanned)} files)"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Baseline created successfully with {len(scanned)} file checksums',
        'file_count': len(scanned)
    })

@monitoring_bp.route('/api/integrity/check', methods=['POST'])
def run_integrity_check():
    data = request.get_json() or {}
    folder_id = data.get('folder_id')
    folder = db.session.get(MonitoredFolder, folder_id)
    if not folder:
        return jsonify({'status': 'error', 'message': 'Monitored folder not found'}), 404

    active_baselines = IntegrityBaseline.query.filter_by(folder_id=folder.id, status='active').all()
    if not active_baselines:
        return jsonify({
            'status': 'warning',
            'message': 'No active baseline exists for this folder. Please generate a baseline first.'
        }), 400

    # In Cloud Mode or Demo: simulate comparison cleanly
    if Config.IS_CLOUD_DEPLOYMENT or folder.is_demo:
        comparison = {
            'status': 'clean',
            'total_baseline': len(active_baselines),
            'total_current': len(active_baselines),
            'modified_files': [],
            'missing_files': [],
            'new_files': [],
            'checked_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        }
        check_record = IntegrityCheck(
            folder_id=folder.id,
            checked_at=datetime.now(timezone.utc),
            total_files=len(active_baselines),
            modified_files=0,
            missing_files=0,
            new_files=0,
            status='clean',
            details=json.dumps(comparison),
            is_demo=True
        )
        db.session.add(check_record)
        folder.last_scan = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'data': check_record.to_dict(),
            'message': '[DEMO MODE] Cryptographic SHA-256 integrity check verified 100% clean baseline match.',
            'is_demo': True
        })

    # Local comparison against real disk files
    baseline_data = [b.to_dict() for b in active_baselines]
    comparison = IntegrityChecker.compare_against_baseline(folder.path, baseline_data, recursive=folder.recursive)

    check_record = IntegrityCheck(
        folder_id=folder.id,
        checked_at=datetime.now(timezone.utc),
        total_files=comparison['total_current'],
        modified_files=len(comparison['modified_files']),
        missing_files=len(comparison['missing_files']),
        new_files=len(comparison['new_files']),
        status=comparison['status'],
        details=json.dumps(comparison),
        is_demo=False
    )
    db.session.add(check_record)
    
    folder.last_scan = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'data': check_record.to_dict(),
        'message': 'Integrity check completed'
    })

@monitoring_bp.route('/api/integrity/results', methods=['GET'])
def get_integrity_results():
    folder_id = request.args.get('folder_id', type=int)
    query = IntegrityCheck.query
    if folder_id:
        query = query.filter_by(folder_id=folder_id)
    checks = query.order_by(IntegrityCheck.checked_at.desc()).limit(20).all()
    return jsonify({'status': 'success', 'data': [c.to_dict() for c in checks]})

@monitoring_bp.route('/api/integrity/baseline/approve', methods=['POST'])
def approve_new_baseline():
    """Explicit user action to approve new baseline after reviewing modifications."""
    data = request.get_json() or {}
    folder_id = data.get('folder_id')
    folder = db.session.get(MonitoredFolder, folder_id)
    if not folder:
        return jsonify({'status': 'error', 'message': 'Monitored folder not found'}), 404

    IntegrityBaseline.query.filter_by(folder_id=folder.id, status='active').update({'status': 'superseded'})
    
    if Config.IS_CLOUD_DEPLOYMENT or folder.is_demo:
        return jsonify({'status': 'success', 'message': '[DEMO MODE] New baseline approved and saved.'})

    scanned = IntegrityChecker.scan_directory(folder.path, recursive=folder.recursive)
    for item in scanned:
        base = IntegrityBaseline(
            folder_id=folder.id,
            file_path=item['file_path'],
            relative_path=item['relative_path'],
            sha256_hash=item['sha256_hash'],
            file_size=item['file_size'],
            last_modified=item['last_modified'],
            status='active',
            is_demo=False
        )
        db.session.add(base)

    audit = AuditLog(
        action='BASELINE_APPROVED_UPDATE',
        details=f"User approved new baseline update for {folder.name} ({len(scanned)} files)"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'New baseline approved and saved.'})
