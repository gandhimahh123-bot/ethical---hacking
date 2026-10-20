/**
 * RansomShield AI — SOC Dashboard Controller
 */

let activityChart = null;
let severityChart = null;
let dashboardPollTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    loadDashboardData();
    loadRecentActivity();

    // Auto-refresh telemetry every 5 seconds
    dashboardPollTimer = setInterval(() => {
        loadDashboardData(true);
        loadRecentActivity(true);
    }, 5000);
});

function initCharts() {
    // 1. Activity Timeline Chart
    const ctxActivity = document.getElementById('activityTimelineChart')?.getContext('2d');
    if (ctxActivity) {
        activityChart = new Chart(ctxActivity, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [
                    {
                        label: 'Normal I/O Events',
                        data: [0, 0, 0, 0, 0, 0],
                        borderColor: '#00E5FF',
                        backgroundColor: 'rgba(0, 229, 255, 0.1)',
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true
                    },
                    {
                        label: 'Suspicious / Burst Anomalies',
                        data: [0, 0, 0, 0, 0, 0],
                        borderColor: '#EF4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.2)',
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: '#94A3B8', font: { family: 'Inter', size: 11 } }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748B', precision: 0 },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // 2. Severity Doughnut Chart
    const ctxSev = document.getElementById('severityDoughnutChart')?.getContext('2d');
    if (ctxSev) {
        severityChart = new Chart(ctxSev, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#EF4444', '#F59E0B', '#3B82F6', '#10B981'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94A3B8', font: { family: 'Inter', size: 11 } }
                    }
                },
                cutout: '72%'
            }
        });
    }
}

async function loadDashboardData(isBackground = false) {
    try {
        const res = await fetch('/api/dashboard/stats');
        const json = await res.json();
        if (json.status === 'success') {
            renderStats(json.data);
        }
    } catch (e) {
        if (!isBackground) showToast('Failed to sync dashboard telemetry', 'error');
    }
}

function renderStats(data) {
    // 1. Monitoring Status Card
    const monStatusEl = document.getElementById('statMonStatus');
    const monSubEl = document.getElementById('statMonSub');
    if (monStatusEl && monSubEl) {
        if (data.active_monitors > 0) {
            monStatusEl.textContent = 'ACTIVE';
            monStatusEl.className = 'stat-value text-emerald';
            monSubEl.innerHTML = `<span class="badge badge-emerald">${data.active_monitors} Active Observers</span>`;
        } else {
            monStatusEl.textContent = 'IDLE';
            monStatusEl.className = 'stat-value text-muted';
            monSubEl.innerHTML = `<span class="badge badge-subtle">No Active Monitors</span>`;
        }
    }

    // 2. Metrics values
    document.getElementById('statProtectedFiles').textContent = data.protected_files || 0;
    document.getElementById('statSuspiciousEvents').textContent = data.suspicious_events || 0;
    document.getElementById('statCriticalAlerts').textContent = data.critical_alerts || 0;
    document.getElementById('statTotalAlertsSub').textContent = `Total Alerts: ${data.total_alerts || 0}`;
    document.getElementById('statBackupCount').textContent = data.backup_count || 0;

    // 3. Last Integrity Check
    const lastCheckEl = document.getElementById('statLastIntegrityTime');
    const lastCheckSub = document.getElementById('statLastIntegrityStatus');
    if (data.last_integrity_check) {
        const timeStr = data.last_integrity_check.checked_at?.split(' ')[1] || 'Today';
        lastCheckEl.textContent = timeStr;
        if (data.last_integrity_check.status === 'clean') {
            lastCheckSub.innerHTML = `<span class="badge badge-emerald">Verified Clean</span>`;
        } else {
            lastCheckSub.innerHTML = `<span class="badge badge-amber">Anomalies Detected</span>`;
        }
    } else {
        lastCheckEl.textContent = 'None';
        lastCheckSub.textContent = 'No baseline scans';
    }

    // 4. Update Charts
    if (activityChart && data.activity_chart) {
        activityChart.data.labels = data.activity_chart.labels;
        activityChart.data.datasets[0].data = data.activity_chart.normal;
        activityChart.data.datasets[1].data = data.activity_chart.suspicious;
        activityChart.update('none');
    }

    if (severityChart && data.severity_distribution) {
        const sev = data.severity_distribution;
        severityChart.data.datasets[0].data = [
            sev.Critical || 0,
            sev.High || 0,
            sev.Medium || 0,
            sev.Low || 0
        ];
        severityChart.update('none');
    }

    updateNavBadges();
}

async function loadRecentActivity(isBackground = false) {
    try {
        const [activityRes, foldersRes] = await Promise.all([
            fetch('/api/dashboard/activity'),
            fetch('/api/monitoring/folders')
        ]);

        const activityJson = await activityRes.json();
        const foldersJson = await foldersRes.json();

        if (foldersJson.status === 'success') {
            renderFoldersSummary(foldersJson.data);
        }

        if (activityJson.status === 'success') {
            renderAlertsSummary(activityJson.data.alerts);
        }
    } catch (e) {
        console.error('Error syncing recent activity:', e);
    }
}

function renderFoldersSummary(folders) {
    const tbody = document.getElementById('dashFoldersList');
    if (!tbody) return;

    if (!folders || folders.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-4">No monitored folders registered. Click 'Monitor Directory' to add one.</td></tr>`;
        return;
    }

    tbody.innerHTML = folders.slice(0, 5).map(f => `
        <tr>
            <td class="font-weight-600">${escapeHtml(f.name)}</td>
            <td class="font-mono text-muted" title="${escapeHtml(f.path)}">${escapeHtml(f.path.length > 30 ? '...' + f.path.slice(-28) : f.path)}</td>
            <td>
                ${f.is_running 
                    ? '<span class="badge badge-emerald">Surveillance Active</span>' 
                    : '<span class="badge badge-subtle">Paused</span>'}
            </td>
            <td><span class="badge badge-blue">${f.event_count || 0} events</span></td>
        </tr>
    `).join('');
}

function renderAlertsSummary(alerts) {
    const tbody = document.getElementById('dashAlertsList');
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-4">No security incidents flagged. All monitored nodes nominal.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.slice(0, 5).map(a => {
        let sevBadge = 'badge-subtle';
        if (a.severity === 'Critical') sevBadge = 'badge-danger';
        else if (a.severity === 'High') sevBadge = 'badge-amber';
        else if (a.severity === 'Medium') sevBadge = 'badge-blue';
        else if (a.severity === 'Low') sevBadge = 'badge-emerald';

        return `
            <tr>
                <td><span class="badge ${sevBadge}">${escapeHtml(a.severity)}</span></td>
                <td><span class="font-mono ${a.risk_score >= 80 ? 'text-crimson' : 'text-amber'}">${a.risk_score}/100</span></td>
                <td class="font-mono" title="${escapeHtml(a.file_path)}">${escapeHtml(a.file_path.length > 30 ? '...' + a.file_path.slice(-28) : a.file_path)}</td>
                <td><span class="badge badge-subtle">${escapeHtml(a.status)}</span></td>
            </tr>
        `;
    }).join('');
}
