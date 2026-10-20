from flask import render_template, jsonify
from datetime import datetime, timedelta
from . import dashboard_bp
from models import MonitoredFolder, FileEvent, SecurityAlert, BackupRecord, IntegrityCheck
from monitoring.monitoring_manager import MonitoringManager

@dashboard_bp.route('/')
def index():
    return render_template('dashboard.html')

@dashboard_bp.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    manager = MonitoringManager()
    active_monitoring_count = manager.get_active_count()
    total_folders = MonitoredFolder.query.count()
    
    # Calculate protected files count across active baselines or backups
    total_backups = BackupRecord.query.count()
    
    # Suspicious events
    suspicious_events_count = FileEvent.query.filter_by(is_suspicious=True).count()
    
    # Critical alerts
    critical_alerts_count = SecurityAlert.query.filter_by(severity='Critical').count()
    total_alerts_count = SecurityAlert.query.count()
    
    # Last integrity check
    last_check = IntegrityCheck.query.order_by(IntegrityCheck.checked_at.desc()).first()
    
    # Severity distribution
    sev_counts = {
        'Low': SecurityAlert.query.filter_by(severity='Low').count(),
        'Medium': SecurityAlert.query.filter_by(severity='Medium').count(),
        'High': SecurityAlert.query.filter_by(severity='High').count(),
        'Critical': critical_alerts_count
    }
    
    # Activity time buckets (events per hour for past 24h)
    now = datetime.utcnow()
    past_24h = now - timedelta(hours=24)
    recent_events = FileEvent.query.filter(FileEvent.timestamp >= past_24h).all()
    
    # Group by 4-hour buckets for smooth chart
    time_labels = []
    normal_counts = []
    suspicious_counts = []
    
    for i in range(6):
        bucket_start = now - timedelta(hours=(6 - i) * 4)
        bucket_end = now - timedelta(hours=(5 - i) * 4)
        label = bucket_start.strftime('%H:%M')
        time_labels.append(label)
        
        b_normal = sum(1 for e in recent_events if bucket_start <= e.timestamp < bucket_end and not e.is_suspicious)
        b_suspicious = sum(1 for e in recent_events if bucket_start <= e.timestamp < bucket_end and e.is_suspicious)
        normal_counts.append(b_normal)
        suspicious_counts.append(b_suspicious)

    return jsonify({
        'status': 'success',
        'data': {
            'monitoring_status': 'ACTIVE' if active_monitoring_count > 0 else 'IDLE',
            'active_monitors': active_monitoring_count,
            'total_folders': total_folders,
            'protected_files': total_backups,
            'suspicious_events': suspicious_events_count,
            'critical_alerts': critical_alerts_count,
            'total_alerts': total_alerts_count,
            'backup_count': total_backups,
            'last_integrity_check': last_check.to_dict() if last_check else None,
            'severity_distribution': sev_counts,
            'activity_chart': {
                'labels': time_labels,
                'normal': normal_counts,
                'suspicious': suspicious_counts
            }
        }
    })

@dashboard_bp.route('/api/dashboard/activity', methods=['GET'])
def get_recent_activity():
    recent_events = FileEvent.query.order_by(FileEvent.timestamp.desc()).limit(20).all()
    recent_alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).limit(10).all()
    
    return jsonify({
        'status': 'success',
        'data': {
            'events': [e.to_dict() for e in recent_events],
            'alerts': [a.to_dict() for a in recent_alerts]
        }
    })
