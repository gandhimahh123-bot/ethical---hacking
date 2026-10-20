/**
 * RansomShield AI — Incident Reports & Audit Export Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    loadReportSummary();
});

async function loadReportSummary() {
    const days = document.getElementById('reportPeriodDays')?.value || 30;

    try {
        const res = await fetch(`/api/reports/summary?days=${days}`);
        const json = await res.json();
        if (json.status === 'success') {
            renderReportSummary(json.data);
        }
    } catch (e) {
        showToast('Failed to load incident summary', 'error');
    }
}

function renderReportSummary(data) {
    document.getElementById('reportPeriodScope').textContent = `Scope: Since ${data.since} UTC`;
    document.getElementById('repTotalEvents').textContent = data.total_events || 0;
    document.getElementById('repSuspiciousEvents').textContent = data.suspicious_events || 0;
    document.getElementById('repTotalAlerts').textContent = data.total_alerts || 0;
    document.getElementById('repCriticalAlerts').textContent = data.severity_breakdown?.Critical || 0;
    document.getElementById('repIntegrityScans').textContent = data.integrity_checks || 0;
    document.getElementById('repRecoveries').textContent = data.recoveries_performed || 0;
    document.getElementById('repQuarantineSub').textContent = `Quarantines: ${data.quarantined_files || 0}`;

    // Severity matrix
    const sev = data.severity_breakdown || {};
    document.getElementById('repSevCritical').textContent = sev.Critical || 0;
    document.getElementById('repSevHigh').textContent = sev.High || 0;
    document.getElementById('repSevMedium').textContent = sev.Medium || 0;
    document.getElementById('repSevLow').textContent = sev.Low || 0;
}

function triggerExport(format) {
    const days = document.getElementById('reportPeriodDays')?.value || 30;
    const url = `/api/reports/export/${format}?days=${days}`;
    window.location.href = url;
    showToast(`Generating ${format.toUpperCase()} report download...`, 'info');
}
