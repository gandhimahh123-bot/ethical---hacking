from flask import Blueprint

dashboard_bp = Blueprint('dashboard', __name__)
monitoring_bp = Blueprint('monitoring', __name__)
protection_bp = Blueprint('protection', __name__)
alert_bp = Blueprint('alerts', __name__)
report_bp = Blueprint('reports', __name__)
settings_bp = Blueprint('settings', __name__)
demo_bp = Blueprint('demo', __name__)
agent_bp = Blueprint('agent', __name__)

from . import dashboard_routes
from . import monitoring_routes
from . import protection_routes
from . import alert_routes
from . import report_routes
from . import settings_routes
from . import demo_routes
from . import agent_routes
