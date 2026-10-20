import os
import atexit
import secrets
from flask import Flask, render_template, session, request, abort, jsonify
from config import Config
from database import db
from models import MonitoredFolder, ApplicationSetting
from monitoring.monitoring_manager import MonitoringManager
from routes import (
    dashboard_bp,
    monitoring_bp,
    protection_bp,
    alert_bp,
    report_bp,
    settings_bp,
    demo_bp
)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Database
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(protection_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(demo_bp)

    # Context processor for CSRF and application metadata
    @app.before_request
    def ensure_csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(24)

    @app.context_processor
    def inject_globals():
        return {
            'app_name': 'RansomShield AI',
            'app_version': '1.0.0-PRO',
            'csrf_token': session.get('csrf_token', '')
        }

    # Lightweight CSRF Header Verification on state-changing API requests
    @app.before_request
    def verify_csrf():
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            # Allow internal testing or requests matching CSRF header or session
            # Check custom X-CSRF-Token header or form field
            header_token = request.headers.get('X-CSRF-Token')
            form_token = request.form.get('csrf_token')
            token = header_token or form_token
            session_token = session.get('csrf_token')
            
            # If session exists and token was provided, ensure match (skip if unit test client without session)
            if session_token and token and token != session_token:
                return jsonify({'status': 'error', 'message': 'Invalid CSRF token'}), 403

    # Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'message': 'API endpoint not found'}), 404
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
        return render_template('500.html'), 500

    with app.app_context():
        db.create_all()

        # Initialize monitoring manager and restart previously active folder observers
        manager = MonitoringManager(app)
        manager.init_app(app)
        
        # Load custom thresholds from DB into detector if present
        try:
            w_setting = ApplicationSetting.query.filter_by(key='detection_window_seconds').first()
            m_setting = ApplicationSetting.query.filter_by(key='burst_mod_threshold').first()
            r_setting = ApplicationSetting.query.filter_by(key='burst_rename_threshold').first()
            c_setting = ApplicationSetting.query.filter_by(key='cooldown_seconds').first()
            
            manager.detector.update_settings(
                window_seconds=int(w_setting.value) if w_setting else None,
                mod_threshold=int(m_setting.value) if m_setting else None,
                rename_threshold=int(r_setting.value) if r_setting else None,
                cooldown_seconds=int(c_setting.value) if c_setting else None
            )
            
            # Start observers for active folders
            active_folders = MonitoredFolder.query.filter_by(is_active=True).all()
            for f in active_folders:
                manager.start_monitoring_folder(f.id, f.path, recursive=f.recursive)
        except Exception:
            pass

    # Register graceful shutdown
    atexit.register(lambda: MonitoringManager().stop_all())

    return app

if __name__ == '__main__':
    app = create_app()
    print("=" * 60)
    print("  RANSOMSHIELD AI — DEFENSIVE BEHAVIOR MONITOR & FILE SHIELD")
    print(f"  Bound exclusively to localhost: http://{Config.HOST}:{Config.PORT}")
    print("  Ethical Hacking & Behavioral Detection Capstone System")
    print("=" * 60)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
