/**
 * RansomShield AI — Security Alerts & Incident Triage Controller
 */

let activeAlertDetailId = null;

document.addEventListener('DOMContentLoaded', () => {
    loadAlerts();
});

function handleAlertSearch(event) {
    if (event.key === 'Enter') {
        loadAlerts();
    }
}

async function loadAlerts() {
    const severity = document.getElementById('filterSeverity')?.value || 'All';
    const status = document.getElementById('filterStatus')?.value || 'All';
    const search = document.getElementById('searchFilePath')?.value.trim() || '';

    let url = `/api/alerts?limit=100`;
    if (severity !== 'All') url += `&severity=${encodeURIComponent(severity)}`;
    if (status !== 'All') url += `&status=${encodeURIComponent(status)}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    try {
        const res = await fetch(url);
        const json = await res.json();
        if (json.status === 'success') {
            renderAlertsTable(json.data);
            const countEl = document.getElementById('alertsCountBadge');
            if (countEl) countEl.textContent = `${json.data.length} Incidents`;
        }
    } catch (e) {
        showToast('Failed to load incident alerts', 'error');
    }
}

function renderAlertsTable(alerts) {
    const tbody = document.getElementById('alertsTableBody');
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No matching security incidents flagged.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        let sevBadge = 'badge-subtle';
        if (a.severity === 'Critical') sevBadge = 'badge-danger';
        else if (a.severity === 'High') sevBadge = 'badge-amber';
        else if (a.severity === 'Medium') sevBadge = 'badge-blue';
        else if (a.severity === 'Low') sevBadge = 'badge-emerald';

        const reasonsSummary = a.detection_reasons && a.detection_reasons.length > 0
            ? a.detection_reasons[0]
            : 'Behavioral heuristic anomaly';

        let statusBadge = 'badge-subtle';
        if (a.status === 'New') statusBadge = 'badge-danger';
        else if (a.status === 'Acknowledged') statusBadge = 'badge-amber';
        else if (a.status === 'Resolved') statusBadge = 'badge-emerald';

        return `
            <tr>
                <td class="font-mono text-muted">#${a.id}</td>
                <td class="font-mono font-sm text-muted">${escapeHtml(a.timestamp)}</td>
                <td><span class="badge ${sevBadge}">${escapeHtml(a.severity)}</span></td>
                <td><span class="font-mono font-weight-600 ${a.risk_score >= 80 ? 'text-crimson' : (a.risk_score >= 60 ? 'text-amber' : 'text-blue')}">${a.risk_score}/100</span></td>
                <td class="font-mono text-cyan" title="${escapeHtml(a.file_path)}">${escapeHtml(a.file_path.length > 30 ? '...' + a.file_path.slice(-27) : a.file_path)}</td>
                <td class="font-sm" title="${escapeHtml(reasonsSummary)}">${escapeHtml(reasonsSummary.length > 45 ? reasonsSummary.slice(0, 42) + '...' : reasonsSummary)}</td>
                <td><span class="badge ${statusBadge}">${escapeHtml(a.status)}</span></td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="openAlertDetailModal(${a.id})">Investigate</button>
                </td>
            </tr>
        `;
    }).join('');
}

async function openAlertDetailModal(alertId) {
    activeAlertDetailId = alertId;
    const modal = document.getElementById('alertDetailModal');
    const modalBody = document.getElementById('alertModalBody');
    const modalTitle = document.getElementById('alertModalTitle');

    modalTitle.textContent = `Incident Investigation — Alert #${alertId}`;
    modalBody.innerHTML = '<div class="text-center py-4"><span class="pulse-dot"></span> Loading incident forensics...</div>';
    modal.style.display = 'flex';

    try {
        const res = await fetch(`/api/alerts/${alertId}`);
        const json = await res.json();
        if (json.status === 'success') {
            const a = json.data;

            let reasonsHtml = '';
            if (a.detection_reasons && a.detection_reasons.length > 0) {
                reasonsHtml = `<ul class="font-sm text-muted mt-2" style="padding-left: 1.2rem;">${a.detection_reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>`;
            }

            modalBody.innerHTML = `
                <div class="stats-grid mb-3">
                    <div class="stat-card p-2"><div class="stat-title">SEVERITY</div><div class="stat-value font-sm ${a.severity === 'Critical' ? 'text-crimson' : 'text-amber'}">${escapeHtml(a.severity)}</div></div>
                    <div class="stat-card p-2"><div class="stat-title">RISK SCORE</div><div class="stat-value font-sm text-cyan">${a.risk_score} / 100</div></div>
                    <div class="stat-card p-2"><div class="stat-title">STATUS</div><div class="stat-value font-sm text-emerald">${escapeHtml(a.status)}</div></div>
                </div>

                <div class="form-group mb-3">
                    <label class="form-label">Target File / Location</label>
                    <div class="font-mono font-sm text-cyan" style="word-break: break-all; background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 4px;">${escapeHtml(a.file_path)}</div>
                </div>

                <div class="form-group mb-3">
                    <label class="form-label">Explainable Heuristic Evidence</label>
                    ${reasonsHtml}
                </div>

                <div class="form-group">
                    <label class="form-label" for="investigationNotesInput">Operator Investigation Notes</label>
                    <textarea class="form-control" id="investigationNotesInput" rows="3" placeholder="Enter findings, root cause analysis, or disposition notes...">${escapeHtml(a.investigation_notes || '')}</textarea>
                </div>
            `;
        } else {
            modalBody.innerHTML = `<div class="alert-box alert-warning">${escapeHtml(json.message)}</div>`;
        }
    } catch (e) {
        modalBody.innerHTML = `<div class="alert-box alert-warning">Failed to load incident details.</div>`;
    }
}

function closeAlertDetailModal() {
    const modal = document.getElementById('alertDetailModal');
    if (modal) modal.style.display = 'none';
    activeAlertDetailId = null;
}

async function submitAcknowledgeAlert() {
    if (!activeAlertDetailId) return;
    try {
        const res = await fetchWithCsrf(`/api/alerts/${activeAlertDetailId}/acknowledge`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            closeAlertDetailModal();
            loadAlerts();
        } else {
            showToast(data.message || 'Operation failed', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

async function submitResolveAlert(status) {
    if (!activeAlertDetailId) return;
    const notes = document.getElementById('investigationNotesInput')?.value.trim() || '';

    try {
        const res = await fetchWithCsrf(`/api/alerts/${activeAlertDetailId}/resolve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: status, notes: notes })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            closeAlertDetailModal();
            loadAlerts();
        } else {
            showToast(data.message || 'Resolution failed', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}
