import threading
import json
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer

from database import db
from models import MonitoredFolder, FileEvent, SecurityAlert, AuditLog
from detection.behavior_detector import BehaviorDetector
from .file_monitor import ShieldEventHandler

class MonitoringManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, app=None):
        if self._initialized:
            return
        self.app = app
        self.observers = {}  # folder_id -> Observer
        self.detector = BehaviorDetector()
        self.lock = threading.Lock()
        self._initialized = True

    def init_app(self, app):
        self.app = app

    def start_monitoring_folder(self, folder_id: int, folder_path: str, recursive: bool = True) -> bool:
        """
        Starts a Watchdog observer for a given folder.
        """
        with self.lock:
            if folder_id in self.observers:
                return True  # Already active

            p = Path(folder_path).resolve()
            if not p.exists() or not p.is_dir():
                return False

            try:
                handler = ShieldEventHandler(
                    folder_id=folder_id,
                    base_path=str(p),
                    event_callback=self._handle_event
                )
                observer = Observer()
                observer.schedule(handler, str(p), recursive=recursive)
                observer.start()
                self.observers[folder_id] = observer
                return True
            except Exception as e:
                if self.app:
                    self.app.logger.error(f"Failed to start monitoring {folder_path}: {e}")
                return False

    def stop_monitoring_folder(self, folder_id: int) -> bool:
        """
        Stops monitoring for a specific folder.
        """
        with self.lock:
            observer = self.observers.pop(folder_id, None)
            if observer:
                try:
                    observer.stop()
                    observer.join(timeout=2.0)
                    return True
                except Exception:
                    return False
            return False

    def is_folder_monitoring(self, folder_id: int) -> bool:
        with self.lock:
            return folder_id in self.observers

    def get_active_count(self) -> int:
        with self.lock:
            return len(self.observers)

    def stop_all(self):
        """
        Stops all active folder observers gracefully.
        """
        with self.lock:
            for folder_id, observer in list(self.observers.items()):
                try:
                    observer.stop()
                    observer.join(timeout=1.0)
                except Exception:
                    pass
            self.observers.clear()

    def _handle_event(self, event_type: str, file_path: str, old_path: str = None, folder_id: int = None):
        """
        Thread-safe callback triggered by watchdog event handler.
        Persists FileEvent in SQLite and passes event to BehaviorDetector.
        """
        if not self.app:
            return

        with self.app.app_context():
            try:
                # Compute relative path if folder known
                rel_path = file_path
                if folder_id:
                    folder = db.session.get(MonitoredFolder, folder_id)
                    if folder:
                        try:
                            rel_path = str(Path(file_path).relative_to(Path(folder.path).resolve()))
                        except Exception:
                            rel_path = Path(file_path).name

                # Run through behavioral detection engine
                alert_data = self.detector.process_event(event_type, file_path, old_path=old_path)
                is_suspicious = alert_data is not None

                # Record FileEvent
                event_record = FileEvent(
                    folder_id=folder_id,
                    file_path=file_path,
                    relative_path=rel_path,
                    event_type=event_type,
                    old_path=old_path,
                    timestamp=datetime.utcnow(),
                    is_suspicious=is_suspicious
                )
                db.session.add(event_record)

                # If behavior engine generated an alert, persist SecurityAlert
                if alert_data:
                    alert = SecurityAlert(
                        timestamp=alert_data['timestamp'],
                        severity=alert_data['severity'],
                        risk_score=alert_data['risk_score'],
                        file_path=alert_data['file_path'],
                        detection_reasons=json.dumps(alert_data['reasons']),
                        event_count=alert_data['event_count'],
                        status='New'
                    )
                    db.session.add(alert)
                    
                    audit = AuditLog(
                        action='SECURITY_ALERT_TRIGGERED',
                        details=f"Alert [{alert_data['severity']}] generated for {file_path} (Score: {alert_data['risk_score']})"
                    )
                    db.session.add(audit)

                db.session.commit()
            except Exception as e:
                db.session.rollback()
                self.app.logger.error(f"Error handling file event: {e}")
