from datetime import datetime, timezone
import json
from functools import wraps
from flask import request, jsonify, session
from . import agent_bp
from database import db
from models import AgentNode, FileEvent, SecurityAlert, MonitoredFolder, BackupRecord, IntegrityCheck, AuditLog
from config import Config

def require_agent_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        provided_key = request.headers.get('X-Agent-Key')
        if not provided_key:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                provided_key = auth_header.split(' ', 1)[1].strip()

        if not provided_key or provided_key != Config.AGENT_API_KEY:
            return jsonify({
                'status': 'error',
                'error_code': 'AGENT_UNAUTHORIZED',
                'message': 'Unauthorized agent: Invalid or missing X-Agent-Key'
            }), 401
        return f(*args, **kwargs)
    return decorated

@agent_bp.route('/api/agent/status', methods=['GET'])
def get_agent_status():
    """
    Public telemetry health endpoint.
    Reports whether any authenticated local Windows agent is actively streaming.
    """
    nodes = AgentNode.query.order_by(AgentNode.last_seen.desc()).all()
    active_nodes = [n.to_dict() for n in nodes if n.is_online()]
    is_live = len(active_nodes) > 0

    return jsonify({
        'status': 'success',
        'data': {
            'is_agent_online': is_live,
            'active_agent_count': len(active_nodes),
            'nodes': active_nodes,
            'is_cloud_deployment': Config.IS_CLOUD_DEPLOYMENT,
            'demo_mode_active': not is_live or Config.DEMO_MODE == 'true'
        }
    })

@agent_bp.route('/api/agent/register', methods=['POST'])
@require_agent_auth
def register_agent():
    """
    Registers a local Windows agent node with the cloud backend.
    """
    data = request.get_json() or {}
    node_id = data.get('node_id', '').strip()
    hostname = data.get('hostname', 'Windows-Host').strip()
    os_info = data.get('os_info', 'Windows OS').strip()
    monitored_paths = data.get('monitored_paths', [])
    version = data.get('version', '1.0.0-PRO')

    if not node_id:
        return jsonify({'status': 'error', 'message': 'node_id is required'}), 400

    node = AgentNode.query.filter_by(node_id=node_id).first()
    if not node:
        node = AgentNode(node_id=node_id)
        db.session.add(node)

    node.hostname = hostname
    node.os_info = os_info
    node.monitored_paths = json.dumps(monitored_paths)
    node.active_monitors = len(monitored_paths)
    node.status = 'ACTIVE_MONITORING' if monitored_paths else 'ONLINE'
    node.version = version
    node.last_seen = datetime.now(timezone.utc)
    node.ip_address = request.remote_addr

    audit = AuditLog(
        action='AGENT_REGISTERED',
        details=f"Agent '{hostname}' ({node_id}) registered with {len(monitored_paths)} folders",
        ip_address=request.remote_addr or '127.0.0.1'
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Agent {node_id} successfully registered',
        'data': node.to_dict()
    })

@agent_bp.route('/api/agent/heartbeat', methods=['POST'])
@require_agent_auth
def agent_heartbeat():
    """
    Periodic heartbeat ping from the Windows agent node.
    """
    data = request.get_json() or {}
    node_id = data.get('node_id', '').strip()
    active_monitors = data.get('active_monitors', 0)
    status_str = data.get('status', 'ACTIVE_MONITORING')

    if not node_id:
        return jsonify({'status': 'error', 'message': 'node_id required'}), 400

    node = AgentNode.query.filter_by(node_id=node_id).first()
    if not node:
        node = AgentNode(
            node_id=node_id,
            hostname=data.get('hostname', 'Windows-Host'),
            os_info=data.get('os_info', 'Windows')
        )
        db.session.add(node)

    node.last_seen = datetime.now(timezone.utc)
    node.active_monitors = active_monitors
    node.status = status_str
    node.ip_address = request.remote_addr
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'Heartbeat acknowledged',
        'server_time': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    })

@agent_bp.route('/api/agent/telemetry', methods=['POST'])
@require_agent_auth
def ingest_telemetry():
    """
    Ingests live file events, alerts, and backup metrics from the Windows agent.
    Tagged as is_demo=False to clearly identify genuine endpoint telemetry.
    """
    data = request.get_json() or {}
    node_id = data.get('node_id')
    events = data.get('events', [])
    alerts = data.get('alerts', [])
    folders = data.get('folders', [])
    backups = data.get('backups', [])

    # Update node timestamp
    if node_id:
        node = AgentNode.query.filter_by(node_id=node_id).first()
        if node:
            node.last_seen = datetime.now(timezone.utc)
            if folders:
                node.monitored_paths = json.dumps([f.get('path') for f in folders if f.get('path')])
                node.active_monitors = len(folders)

    # Ingest Monitored Folders
    for f in folders:
        path = f.get('path')
        if not path:
            continue
        existing_folder = MonitoredFolder.query.filter_by(path=path).first()
        if not existing_folder:
            existing_folder = MonitoredFolder(
                path=path,
                name=f.get('name', path.split('\\')[-1]),
                recursive=f.get('recursive', True),
                is_active=f.get('is_active', True),
                is_demo=False
            )
            db.session.add(existing_folder)
        else:
            existing_folder.is_active = f.get('is_active', True)
            existing_folder.is_demo = False

    # Ingest File Events
    ingested_events_count = 0
    for e in events:
        file_path = e.get('file_path')
        if not file_path:
            continue
        ev = FileEvent(
            file_path=file_path,
            relative_path=e.get('relative_path'),
            event_type=e.get('event_type', 'modified'),
            old_path=e.get('old_path'),
            timestamp=datetime.now(timezone.utc),
            is_suspicious=bool(e.get('is_suspicious', False)),
            is_demo=False,
            process_info=e.get('process_info')
        )
        db.session.add(ev)
        ingested_events_count += 1

    # Ingest Security Alerts
    ingested_alerts_count = 0
    for a in alerts:
        file_path = a.get('file_path')
        if not file_path:
            continue
        reasons = a.get('detection_reasons', ['Endpoint behavior heuristic'])
        if isinstance(reasons, list):
            reasons_str = json.dumps(reasons)
        else:
            reasons_str = str(reasons)

        alert = SecurityAlert(
            timestamp=datetime.now(timezone.utc),
            severity=a.get('severity', 'High'),
            risk_score=int(a.get('risk_score', 75)),
            file_path=file_path,
            detection_reasons=reasons_str,
            event_count=int(a.get('event_count', 1)),
            status=a.get('status', 'New'),
            is_demo=False
        )
        db.session.add(alert)
        ingested_alerts_count += 1

    # Ingest Backup Records
    for b in backups:
        orig = b.get('original_path')
        b_path = b.get('backup_path')
        if orig and b_path:
            existing_backup = BackupRecord.query.filter_by(
                original_path=orig,
                sha256_hash=b.get('sha256_hash', '')
            ).first()
            if not existing_backup:
                rec = BackupRecord(
                    original_path=orig,
                    backup_path=b_path,
                    relative_path=b.get('relative_path'),
                    file_size=b.get('file_size', 0),
                    sha256_hash=b.get('sha256_hash', ''),
                    notes=b.get('notes', 'Agent automated snapshot'),
                    is_valid=b.get('is_valid', True),
                    is_demo=False
                )
                db.session.add(rec)

    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'Telemetry ingested successfully',
        'data': {
            'events_ingested': ingested_events_count,
            'alerts_ingested': ingested_alerts_count
        }
    })
