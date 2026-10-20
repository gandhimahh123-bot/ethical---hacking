import time
import threading
from collections import deque
from pathlib import Path
from datetime import datetime
from config import Config
from .risk_scorer import RiskScorer

SUSPICIOUS_EXTENSIONS = {
    '.locked', '.crypto', '.crypt', '.crypted', '.enc', '.encrypted',
    '.ransom', '.wnry', '.wncry', '.zepto', '.locky', '.cerber', '.odin',
    '.aes', '.dark', '.pay', '.stop', '.djvu', '.mallox', '.blackcat', '.lockbit'
}

class BehaviorDetector:
    def __init__(self, window_seconds=10, 
                 mod_threshold=8, 
                 rename_threshold=5, 
                 churn_threshold=8, 
                 ext_threshold=4,
                 cooldown_seconds=20):
        self.window_seconds = window_seconds
        self.mod_threshold = mod_threshold
        self.rename_threshold = rename_threshold
        self.churn_threshold = churn_threshold
        self.ext_threshold = ext_threshold
        self.cooldown_seconds = cooldown_seconds
        
        self.events_buffer = deque()
        self.recent_alerts = {}  # key: target_folder_or_path -> last_alert_timestamp
        self.lock = threading.Lock()
        self.scorer = RiskScorer()

    def update_settings(self, window_seconds=None, mod_threshold=None, rename_threshold=None, cooldown_seconds=None):
        with self.lock:
            if window_seconds is not None:
                self.window_seconds = max(int(window_seconds), 1)
            if mod_threshold is not None:
                self.mod_threshold = max(int(mod_threshold), 1)
            if rename_threshold is not None:
                self.rename_threshold = max(int(rename_threshold), 1)
            if cooldown_seconds is not None:
                self.cooldown_seconds = max(int(cooldown_seconds), 0)

    def process_event(self, event_type: str, file_path: str, old_path: str = None) -> dict | None:
        """
        Receives a single event, maintains sliding window, checks for behavioral patterns.
        Returns an alert dictionary if suspicious behavior meets thresholds, otherwise None.
        """
        now = time.time()
        
        with self.lock:
            # Append new event
            self.events_buffer.append({
                'time': now,
                'type': event_type,
                'file_path': file_path,
                'old_path': old_path,
                'ext': Path(file_path).suffix.lower()
            })

            # Trim events older than window_seconds
            cutoff = now - self.window_seconds
            while self.events_buffer and self.events_buffer[0]['time'] < cutoff:
                self.events_buffer.popleft()

            # Analyze the sliding window
            mods = 0
            renames = 0
            creates = 0
            deletes = 0
            extensions = set()
            affected_files = set()
            has_suspicious_ext = False

            for ev in self.events_buffer:
                affected_files.add(ev['file_path'])
                if ev['ext']:
                    extensions.add(ev['ext'])
                if ev['ext'] in SUSPICIOUS_EXTENSIONS:
                    has_suspicious_ext = True

                if ev['type'] == 'modified':
                    mods += 1
                elif ev['type'] in ('moved', 'renamed'):
                    renames += 1
                elif ev['type'] == 'created':
                    creates += 1
                elif ev['type'] == 'deleted':
                    deletes += 1

            time_span = max(now - self.events_buffer[0]['time'] if self.events_buffer else 1.0, 0.5)

            # Heuristic triggers
            triggered = False
            if mods >= self.mod_threshold:
                triggered = True
            if renames >= self.rename_threshold:
                triggered = True
            if (creates + deletes) >= self.churn_threshold:
                triggered = True
            if has_suspicious_ext:
                triggered = True
            if len(extensions) >= self.ext_threshold and len(self.events_buffer) >= 6:
                triggered = True

            if not triggered:
                return None

            # Calculate explainable risk score
            factors = {
                'modification_count': mods,
                'rename_count': renames,
                'create_count': creates,
                'delete_count': deletes,
                'unique_extensions_changed': len(extensions),
                'time_span_seconds': time_span,
                'known_suspicious_extension': has_suspicious_ext,
                'affected_files_count': len(affected_files)
            }
            score, severity, reasons = self.scorer.calculate_score(factors)

            # Cooldown deduplication per folder/path prefix
            target_key = str(Path(file_path).parent)
            last_alert_time = self.recent_alerts.get(target_key, 0)
            if (now - last_alert_time) < self.cooldown_seconds:
                # Suppress duplicate alert during cooldown
                return None

            self.recent_alerts[target_key] = now

            # Clean old cooldown keys
            expired_keys = [k for k, v in self.recent_alerts.items() if (now - v) > self.cooldown_seconds * 2]
            for k in expired_keys:
                del self.recent_alerts[k]

            return {
                'file_path': file_path,
                'severity': severity,
                'risk_score': score,
                'reasons': reasons,
                'event_count': len(self.events_buffer),
                'timestamp': datetime.utcnow()
            }
