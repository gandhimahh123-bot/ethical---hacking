import os
import tempfile
from pathlib import Path

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent

# Cloud and Vercel serverless environment detection
IS_VERCEL = bool(
    os.environ.get('VERCEL') 
    or os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
    or os.environ.get('VERCEL_ENV')
)
IS_CLOUD_DEPLOYMENT = IS_VERCEL or os.environ.get('CLOUD_MODE', '').lower() in ('1', 'true', 'yes')

# Use /tmp directory on Vercel / Lambda since base directory is read-only
if IS_VERCEL:
    INSTANCE_DIR = Path(tempfile.gettempdir()) / 'ransomshield_instance'
else:
    INSTANCE_DIR = BASE_DIR / 'instance'

try:
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    INSTANCE_DIR = Path(tempfile.gettempdir()) / 'ransomshield_instance'
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

class Config:
    # Cryptographic Secrets
    SECRET_KEY = os.environ.get(
        'SECRET_KEY', 
        os.environ.get('FLASK_SECRET_KEY', 'ransomshield-ai-secure-dev-key-capstone-2026')
    )
    AGENT_API_KEY = os.environ.get('AGENT_API_KEY', 'rs-agent-secret-key-capstone-2026')
    ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', 'admin123')

    # Deployment flags
    IS_VERCEL = IS_VERCEL
    IS_CLOUD_DEPLOYMENT = IS_CLOUD_DEPLOYMENT
    DEMO_MODE = os.environ.get('DEMO_MODE', 'auto').lower()  # 'auto', 'true', 'false'

    # Managed Database Configuration
    raw_db_url = os.environ.get('DATABASE_URL')
    if raw_db_url:
        # SQLAlchemy 1.4+ requires postgresql:// instead of postgres://
        if raw_db_url.startswith('postgres://'):
            raw_db_url = raw_db_url.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = raw_db_url
    else:
        if IS_VERCEL:
            # In Vercel serverless without managed DB, run with memory-backed database for demo
            SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        else:
            SQLALCHEMY_DATABASE_URI = f'sqlite:///{INSTANCE_DIR / "ransomshield.db"}'

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Storage directories outside static
    BACKUP_DIR = INSTANCE_DIR / 'backups'
    QUARANTINE_DIR = INSTANCE_DIR / 'quarantine'
    DEMO_DIR = INSTANCE_DIR / 'demo_sandbox'
    LOGS_DIR = INSTANCE_DIR / 'logs'
    
    # Ensure directories exist where filesystem permissions allow
    for directory in (BACKUP_DIR, QUARANTINE_DIR, DEMO_DIR, LOGS_DIR):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    
    # Network Security Binding
    HOST = os.environ.get('HOST', '127.0.0.1')
    PORT = int(os.environ.get('PORT', 5000))
    DEBUG = os.environ.get('DEBUG', '').lower() in ('1', 'true', 'yes')
    
    # Behavioral Detection Engine Defaults
    DETECTION_WINDOW_SECONDS = int(os.environ.get('DETECTION_WINDOW_SECONDS', 10))
    BURST_MODIFICATION_THRESHOLD = int(os.environ.get('BURST_MODIFICATION_THRESHOLD', 8))
    BURST_RENAME_THRESHOLD = int(os.environ.get('BURST_RENAME_THRESHOLD', 5))
    BURST_DELETE_CREATE_THRESHOLD = int(os.environ.get('BURST_DELETE_CREATE_THRESHOLD', 8))
    RAPID_EXTENSION_CHANGE_THRESHOLD = int(os.environ.get('RAPID_EXTENSION_CHANGE_THRESHOLD', 4))
    ALERT_COOLDOWN_SECONDS = int(os.environ.get('ALERT_COOLDOWN_SECONDS', 20))
    
    # Risk Score Thresholds
    RISK_LOW_MAX = 29
    RISK_MEDIUM_MAX = 59
    RISK_HIGH_MAX = 79
    # 80-100 is Critical
    
    # Maximum file size for sha256 checksum streaming (100 MB default max for instant integrity)
    MAX_FILE_SIZE_HASH_MB = int(os.environ.get('MAX_FILE_SIZE_HASH_MB', 100))
    
    # Ignore patterns for monitoring (system & internal files)
    INTERNAL_IGNORED_NAMES = {
        '.git', '__pycache__', '.venv', 'instance', 'ransomshield.db',
        'ransomshield.db-journal', '.DS_Store', 'Thumbs.db', 'desktop.ini'
    }
