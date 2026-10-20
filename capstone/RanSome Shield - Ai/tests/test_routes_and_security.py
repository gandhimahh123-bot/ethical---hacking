import pytest
from app import create_app
from database import db
from models import SecurityAlert, MonitoredFolder

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client

def test_dashboard_stats_api(client):
    res = client.get('/api/dashboard/stats')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'active_monitors' in data['data']
    assert 'critical_alerts' in data['data']

def test_reports_csv_export(client):
    res = client.get('/api/reports/export/csv?days=30')
    assert res.status_code == 200
    assert res.headers['Content-Type'].startswith('text/csv')
    assert b'Alert ID' in res.data

def test_reports_pdf_export(client):
    res = client.get('/api/reports/export/pdf?days=30')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert res.data.startswith(b'%PDF')

def test_demo_sandbox_lifecycle(client):
    # 1. Prepare
    prep_res = client.post('/api/demo/prepare')
    assert prep_res.status_code == 200
    assert prep_res.get_json()['status'] == 'success'

    # 2. Check status
    stat_res = client.get('/api/demo/status')
    assert stat_res.status_code == 200
    stat_data = stat_res.get_json()['data']
    assert stat_data['file_count'] > 0

    # 3. Simulate
    sim_res = client.post('/api/demo/simulate', json={'type': 'rapid_mod_rename'})
    assert sim_res.status_code == 200
    assert sim_res.get_json()['status'] == 'success'

    # 4. Cleanup
    clean_res = client.post('/api/demo/cleanup')
    assert clean_res.status_code == 200
    assert clean_res.get_json()['status'] == 'success'

    # 5. Check empty status
    stat_after = client.get('/api/demo/status')
    assert stat_after.get_json()['data']['file_count'] == 0
