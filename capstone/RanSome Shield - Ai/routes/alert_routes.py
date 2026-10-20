from flask import render_template, request, jsonify
from . import alert_bp
from database import db
from models import SecurityAlert, AuditLog

@alert_bp.route('/alerts')
def index():
    return render_template('alerts.html')

@alert_bp.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity')
    status = request.args.get('status')
    search = request.args.get('search', '').strip()
    limit = min(request.args.get('limit', 100, type=int), 200)

    query = SecurityAlert.query
    if severity and severity != 'All':
        query = query.filter_by(severity=severity)
    if status and status != 'All':
        query = query.filter_by(status=status)
    if search:
        query = query.filter(SecurityAlert.file_path.ilike(f'%{search}%'))

    alerts = query.order_by(SecurityAlert.timestamp.desc()).limit(limit).all()
    return jsonify({'status': 'success', 'data': [a.to_dict() for a in alerts]})

@alert_bp.route('/api/alerts/<int:alert_id>', methods=['GET'])
def get_alert_detail(alert_id):
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
    return jsonify({'status': 'success', 'data': alert.to_dict()})

@alert_bp.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        return jsonify({'status': 'error', 'message': 'Alert not found'}), 404

    alert.status = 'Acknowledged'
    audit = AuditLog(
        action='ALERT_ACKNOWLEDGED',
        details=f"Alert #{alert.id} ({alert.severity}) acknowledged by operator"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'success', 'message': f'Alert #{alert_id} marked as Acknowledged', 'data': alert.to_dict()})

@alert_bp.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    data = request.get_json() or {}
    resolution_status = data.get('status', 'Resolved')
    notes = data.get('notes', '').strip()

    if resolution_status not in ('Resolved', 'False Positive'):
        resolution_status = 'Resolved'

    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        return jsonify({'status': 'error', 'message': 'Alert not found'}), 404

    alert.status = resolution_status
    if notes:
        alert.investigation_notes = notes

    audit = AuditLog(
        action='ALERT_RESOLVED',
        details=f"Alert #{alert.id} resolved as [{resolution_status}]. Notes: {notes[:80]}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'success', 'message': f'Alert #{alert_id} resolved as {resolution_status}', 'data': alert.to_dict()})
