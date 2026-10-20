from flask import render_template, request, jsonify
from . import settings_bp
from database import db
from models import ApplicationSetting, AuditLog
from monitoring.monitoring_manager import MonitoringManager
from config import Config

DEFAULT_SETTINGS = {
    'detection_window_seconds': str(Config.DETECTION_WINDOW_SECONDS),
    'burst_mod_threshold': str(Config.BURST_MODIFICATION_THRESHOLD),
    'burst_rename_threshold': str(Config.BURST_RENAME_THRESHOLD),
    'cooldown_seconds': str(Config.ALERT_COOLDOWN_SECONDS),
    'risk_low_max': str(Config.RISK_LOW_MAX),
    'risk_medium_max': str(Config.RISK_MEDIUM_MAX),
    'risk_high_max': str(Config.RISK_HIGH_MAX),
    'default_backup_dir': str(Config.BACKUP_DIR),
    'retention_days': '30'
}

@settings_bp.route('/settings')
def index():
    return render_template('settings.html')

@settings_bp.route('/api/settings', methods=['GET'])
def get_settings():
    settings = {}
    for key, def_val in DEFAULT_SETTINGS.items():
        record = ApplicationSetting.query.filter_by(key=key).first()
        if record:
            settings[key] = record.value
        else:
            settings[key] = def_val
            
    return jsonify({'status': 'success', 'data': settings})

@settings_bp.route('/api/settings', methods=['POST'])
def save_settings():
    data = request.get_json() or {}
    
    # Server-side validation
    try:
        window_sec = int(data.get('detection_window_seconds', Config.DETECTION_WINDOW_SECONDS))
        mod_thresh = int(data.get('burst_mod_threshold', Config.BURST_MODIFICATION_THRESHOLD))
        rename_thresh = int(data.get('burst_rename_threshold', Config.BURST_RENAME_THRESHOLD))
        cooldown_sec = int(data.get('cooldown_seconds', Config.ALERT_COOLDOWN_SECONDS))
        retention = int(data.get('retention_days', 30))
        
        if window_sec < 1 or window_sec > 300:
            return jsonify({'status': 'error', 'message': 'Window seconds must be between 1 and 300'}), 400
        if mod_thresh < 1 or mod_thresh > 500:
            return jsonify({'status': 'error', 'message': 'Modification threshold must be between 1 and 500'}), 400
        if rename_thresh < 1 or rename_thresh > 500:
            return jsonify({'status': 'error', 'message': 'Rename threshold must be between 1 and 500'}), 400
        if cooldown_sec < 0 or cooldown_sec > 600:
            return jsonify({'status': 'error', 'message': 'Cooldown must be between 0 and 600 seconds'}), 400
        if retention < 1 or retention > 365:
            return jsonify({'status': 'error', 'message': 'Retention days must be between 1 and 365'}), 400

    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid numerical value submitted'}), 400

    # Save to database
    for k, v in data.items():
        if k in DEFAULT_SETTINGS:
            record = ApplicationSetting.query.filter_by(key=k).first()
            if not record:
                record = ApplicationSetting(key=k, value=str(v))
                db.session.add(record)
            else:
                record.value = str(v)

    # Sync live engine
    manager = MonitoringManager()
    manager.detector.update_settings(
        window_seconds=window_sec,
        mod_threshold=mod_thresh,
        rename_threshold=rename_thresh,
        cooldown_seconds=cooldown_sec
    )

    audit = AuditLog(
        action='SETTINGS_UPDATED',
        details=f"Detection parameters updated: window={window_sec}s, mod_thresh={mod_thresh}, rename_thresh={rename_thresh}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Application settings updated successfully'})
