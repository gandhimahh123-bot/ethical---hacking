import time
import shutil
from pathlib import Path
from flask import request, jsonify
from . import demo_bp
from config import Config
from models import MonitoredFolder, AuditLog
from database import db
from monitoring.monitoring_manager import MonitoringManager

@demo_bp.route('/api/demo/status', methods=['GET'])
def get_demo_status():
    demo_dir = Config.DEMO_DIR
    files = list(demo_dir.glob('*')) if demo_dir.exists() else []
    sample_files = [f.name for f in files if f.is_file()]
    
    # Check if demo folder is registered in monitoring
    demo_folder = MonitoredFolder.query.filter_by(path=str(demo_dir)).first()
    manager = MonitoringManager()
    is_active = manager.is_folder_monitoring(demo_folder.id) if demo_folder else False

    return jsonify({
        'status': 'success',
        'data': {
            'sandbox_path': str(demo_dir),
            'file_count': len(sample_files),
            'files': sample_files[:15],
            'is_monitored': is_active,
            'folder_id': demo_folder.id if demo_folder else None
        }
    })

@demo_bp.route('/api/demo/prepare', methods=['POST'])
def prepare_demo():
    """
    Initializes the safe demonstration sandbox with harmless sample text files.
    """
    demo_dir = Config.DEMO_DIR
    demo_dir.mkdir(parents=True, exist_ok=True)
    
    # Ensure demo folder is registered and actively monitored
    demo_folder = MonitoredFolder.query.filter_by(path=str(demo_dir)).first()
    if not demo_folder:
        demo_folder = MonitoredFolder(
            path=str(demo_dir),
            name='Capstone Demonstration Sandbox',
            recursive=True,
            is_active=True
        )
        db.session.add(demo_folder)
        db.session.commit()

    manager = MonitoringManager()
    if not manager.is_folder_monitoring(demo_folder.id):
        manager.start_monitoring_folder(demo_folder.id, str(demo_dir), recursive=True)

    # Populate 12 harmless sample text files
    sample_names = [
        "annual_budget_2026.txt",
        "client_roster.txt",
        "security_policy_v2.txt",
        "network_topology.txt",
        "employee_directory.txt",
        "research_notes.txt",
        "database_schema.txt",
        "audit_checklist.txt",
        "incident_response_plan.txt",
        "vendor_contracts.txt",
        "project_roadmap.txt",
        "compliance_report.txt"
    ]

    for name in sample_names:
        file_path = demo_dir / name
        content = f"CONFIDENTIAL SAMPLE DATA — {name}\nInitialized at {time.ctime()}\nThis is a harmless test file for RansomShield AI simulation."
        file_path.write_text(content, encoding='utf-8')

    audit = AuditLog(
        action='DEMO_SANDBOX_PREPARED',
        details=f"Created {len(sample_names)} harmless sample files in {demo_dir}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Sandbox prepared with {len(sample_names)} sample files in isolated demo directory.',
        'sandbox_path': str(demo_dir)
    })

@demo_bp.route('/api/demo/simulate', methods=['POST'])
def simulate_behavior():
    """
    Executes a safe behavioral simulation strictly inside the demo directory:
    - Rapid modification of sample files
    - Appending simulated .locked extensions
    Triggers behavior detection engine safely.
    """
    data = request.get_json() or {}
    simulation_type = data.get('type', 'rapid_mod_rename')
    demo_dir = Config.DEMO_DIR

    if not demo_dir.exists():
        return jsonify({'status': 'error', 'message': 'Demo sandbox not prepared. Please prepare sandbox first.'}), 400

    sample_files = [f for f in demo_dir.glob('*.txt') if f.is_file()]
    if len(sample_files) < 3:
        return jsonify({'status': 'error', 'message': 'Insufficient sample files. Please click Prepare Demo Sandbox first.'}), 400

    operations_count = 0

    if simulation_type in ('rapid_mod', 'rapid_mod_rename'):
        # Step 1: Rapid bursts of file modifications
        for f in sample_files[:10]:
            try:
                with open(f, 'a', encoding='utf-8') as handle:
                    handle.write(f"\n[SIMULATED MODIFICATION TIMESTAMP: {time.time()}] Harmless payload marker.")
                operations_count += 1
                time.sleep(0.05) # Brief micro-interval to simulate rapid process
            except Exception:
                pass

    if simulation_type in ('rapid_rename', 'rapid_mod_rename'):
        # Step 2: Rapid renaming with simulated ransomware extension
        for f in sample_files[:8]:
            try:
                locked_name = f.with_name(f.name + '.locked')
                f.rename(locked_name)
                operations_count += 1
                time.sleep(0.05)
            except Exception:
                pass

    audit = AuditLog(
        action='DEMO_SIMULATION_EXECUTED',
        details=f"Safe ransomware behavioral simulation ({simulation_type}) triggered {operations_count} ops in sandbox"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Simulation executed ({operations_count} operations). Check Dashboard and Alerts for detection response.',
        'operations_count': operations_count
    })

@demo_bp.route('/api/demo/cleanup', methods=['POST'])
def cleanup_demo():
    """
    Safely purges only the contents of Config.DEMO_DIR.
    """
    demo_dir = Config.DEMO_DIR
    if not demo_dir.exists():
        return jsonify({'status': 'success', 'message': 'Demo directory is already empty'})

    # Stop file observer on demo folder first so Windows file handles are fully released
    demo_folder = MonitoredFolder.query.filter_by(path=str(demo_dir)).first()
    if demo_folder:
        try:
            MonitoringManager().stop_monitoring_folder(demo_folder.id)
        except Exception:
            pass

    # Safety check: make sure we are only clearing inside the demo dir
    count = 0
    for item in list(demo_dir.glob('*')):
        if item.is_file() or item.is_symlink():
            deleted = False
            for _ in range(5):
                try:
                    item.unlink(missing_ok=True)
                    deleted = True
                    break
                except (PermissionError, OSError):
                    time.sleep(0.05)
            if deleted:
                count += 1
        elif item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
            count += 1

    audit = AuditLog(
        action='DEMO_SANDBOX_CLEANED',
        details=f"Purged {count} temporary simulation files from {demo_dir}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Demo sandbox cleared successfully ({count} items removed).'
    })
