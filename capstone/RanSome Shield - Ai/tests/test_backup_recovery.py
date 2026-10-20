import tempfile
from pathlib import Path
import pytest
from flask import Flask
from config import Config
from database import db
from models import BackupRecord, RecoveryRecord, QuarantineRecord
from protection.backup_manager import BackupManager
from protection.recovery_manager import RecoveryManager
from protection.quarantine_manager import QuarantineManager

@pytest.fixture
def app_context():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_path = Path(tmpdir)
        app.config['BACKUP_DIR'] = temp_path / 'backups'
        app.config['QUARANTINE_DIR'] = temp_path / 'quarantine'
        app.config['INSTANCE_DIR'] = temp_path
        
        Config.BACKUP_DIR = app.config['BACKUP_DIR']
        Config.QUARANTINE_DIR = app.config['QUARANTINE_DIR']
        Config.INSTANCE_DIR = app.config['INSTANCE_DIR']
        
        Config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        Config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

        db.init_app(app)
        with app.app_context():
            db.create_all()
            yield app

def test_backup_and_recovery_flow(app_context):
    with tempfile.TemporaryDirectory() as user_dir:
        # Create user file
        source_file = Path(user_dir) / "contract.docx.txt"
        original_content = "Super Confidential Business Contract 2026"
        source_file.write_text(original_content, encoding='utf-8')

        # 1. Create Backup
        record = BackupManager.create_file_backup(source_file, notes="Pre-incident safe copy")
        assert record is not None
        assert record.is_valid is True
        assert Path(record.backup_path).exists()

        # 2. Verify Backup
        verify_res = BackupManager.verify_backup(record.id)
        assert verify_res['status'] == 'verified'
        assert verify_res['is_valid'] is True

        # 3. Simulate tamper of original file
        source_file.write_text("TAMPERED FILE CONTENT !!!", encoding='utf-8')

        # 4. Restore file to original destination
        restored_dest = Path(user_dir) / "restored_contract.txt"
        restore_res = RecoveryManager.restore_backup(record.id, target_destination=str(restored_dest))
        assert restore_res['success'] is True
        assert restore_res['status'] == 'Success'
        assert restored_dest.exists()
        assert restored_dest.read_text(encoding='utf-8') == original_content

def test_quarantine_isolation_and_restoration(app_context):
    with tempfile.TemporaryDirectory() as user_dir:
        suspect_file = Path(user_dir) / "malicious_script.vbs.txt"
        suspect_file.write_text("Simulated suspicious script text", encoding='utf-8')

        # 1. Quarantine file
        q_res = QuarantineManager.quarantine_file(suspect_file, reason="Heuristic rapid renaming pattern")
        assert q_res['success'] is True
        assert not suspect_file.exists()  # Moved out of original location
        assert Path(q_res['quarantine_path']).exists()

        # 2. Restore from quarantine
        restored_dest = Path(user_dir) / "safe_restored.txt"
        unq_res = QuarantineManager.restore_quarantined_file(q_res['record_id'], destination_path=str(restored_dest))
        assert unq_res['success'] is True
        assert restored_dest.exists()
def test_backup_internal_guard_prevention(app_context):
    # Attempting to back up internal instance folder directly should be blocked
    res = BackupManager.create_file_backup(Config.INSTANCE_DIR / "some_internal_db.db")
    assert res is None

def test_backup_folder_recursive_prevention(app_context):
    # Backing up backup directory itself should be safely refused
    records = BackupManager.create_folder_backup(Config.BACKUP_DIR)
    assert records == []
