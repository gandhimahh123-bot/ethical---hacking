/**
 * RansomShield AI — File Monitoring & Cryptographic Integrity Controller
 */

let activeIntegrityFolderId = null;
let eventsPollInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    loadMonitoredFolders();
    loadEvents();

    eventsPollInterval = setInterval(() => {
        loadEvents(true);
    }, 4000);
});

async function loadMonitoredFolders() {
    try {
        const res = await fetch('/api/monitoring/folders');
        const json = await res.json();
        if (json.status === 'success') {
            renderFoldersTable(json.data);
            const countEl = document.getElementById('foldersCountBadge');
            if (countEl) countEl.textContent = `${json.data.length} Registered`;
        }
    } catch (e) {
        showToast('Failed to load monitored folders', 'error');
    }
}

function renderFoldersTable(folders) {
    const tbody = document.getElementById('foldersTableBody');
    if (!tbody) return;

    if (!folders || folders.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">No monitored folders registered yet. Click 'Register Folder' above.</td></tr>`;
        return;
    }

    tbody.innerHTML = folders.map(f => `
        <tr>
            <td class="font-weight-600">${escapeHtml(f.name)}</td>
            <td class="font-mono text-muted" title="${escapeHtml(f.path)}">${escapeHtml(f.path)}</td>
            <td>
                ${f.is_running 
                    ? '<span class="badge badge-emerald">Surveillance Active</span>' 
                    : '<span class="badge badge-subtle">Observer Inactive</span>'}
            </td>
            <td>${f.recursive ? '<span class="text-cyan">Recursive</span>' : '<span class="text-muted">Top-level</span>'}</td>
            <td>${f.last_scan ? `<span class="font-mono text-muted">${escapeHtml(f.last_scan)}</span>` : '<span class="text-muted">No scans yet</span>'}</td>
            <td>
                <div class="flex-gap-2">
                    ${f.is_running 
                        ? `<button class="btn btn-secondary btn-sm" onclick="toggleMonitoring(${f.id}, false)">Pause</button>`
                        : `<button class="btn btn-emerald btn-sm" onclick="toggleMonitoring(${f.id}, true)">Start</button>`}
                    <button class="btn btn-outline-cyan btn-sm" onclick="createBaseline(${f.id})">Create Baseline</button>
                    <button class="btn btn-secondary btn-sm" onclick="runIntegrityCheck(${f.id})">Verify Integrity</button>
                    <button class="btn btn-danger btn-sm" onclick="confirmDeleteFolder(${f.id}, '${escapeHtml(f.name)}')">Remove</button>
                </div>
            </td>
        </tr>
    `).join('');
}

function openAddFolderModal() {
    const modal = document.getElementById('addFolderModal');
    if (modal) modal.style.display = 'flex';
}

function closeAddFolderModal() {
    const modal = document.getElementById('addFolderModal');
    if (modal) modal.style.display = 'none';
    document.getElementById('folderPathInput').value = '';
    document.getElementById('folderNameInput').value = '';
}

async function submitAddFolder() {
    const path = document.getElementById('folderPathInput').value.trim();
    const name = document.getElementById('folderNameInput').value.trim();
    const recursive = document.getElementById('folderRecursiveInput').checked;

    if (!path) {
        showToast('Directory path is required', 'error');
        return;
    }

    try {
        const res = await fetchWithCsrf('/api/monitoring/folders', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path, name, recursive })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            closeAddFolderModal();
            loadMonitoredFolders();
        } else {
            showToast(data.message || 'Failed to add folder', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

async function toggleMonitoring(folderId, start) {
    const endpoint = start ? '/api/monitoring/start' : '/api/monitoring/stop';
    try {
        const res = await fetchWithCsrf(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ folder_id: folderId })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            loadMonitoredFolders();
        } else {
            showToast(data.message || 'Operation failed', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

function confirmDeleteFolder(folderId, name) {
    showConfirmDialog(
        'Remove Monitored Folder',
        `Are you sure you want to remove <strong>${name}</strong> from active surveillance? Event histories and baselines will be pruned.`,
        async () => {
            try {
                const res = await fetchWithCsrf(`/api/monitoring/folders/${folderId}`, { method: 'DELETE' });
                const data = await res.json();
                if (data.status === 'success') {
                    showToast(data.message, 'success');
                    loadMonitoredFolders();
                } else {
                    showToast(data.message || 'Failed to remove folder', 'error');
                }
            } catch (e) {
                showToast('Connection error', 'error');
            }
        },
        'Remove Target',
        true
    );
}

// Integrity Baselines
async function createBaseline(folderId) {
    try {
        const res = await fetchWithCsrf('/api/integrity/baseline/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ folder_id: folderId })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
        } else {
            showToast(data.message || 'Failed to generate baseline', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

async function runIntegrityCheck(folderId) {
    activeIntegrityFolderId = folderId;
    const modal = document.getElementById('integrityModal');
    const modalBody = document.getElementById('integrityModalBody');
    const btnApprove = document.getElementById('btnApproveBaseline');
    btnApprove.style.display = 'none';

    modalBody.innerHTML = '<div class="text-center py-4"><span class="pulse-dot"></span> Performing cryptographic SHA-256 integrity verification...</div>';
    modal.style.display = 'flex';

    try {
        const res = await fetchWithCsrf('/api/integrity/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ folder_id: folderId })
        });
        const data = await res.json();

        if (data.status === 'success') {
            const check = data.data;
            const det = check.details || {};
            
            let statusBanner = '';
            if (check.status === 'clean') {
                statusBanner = '<div class="alert-box alert-info mb-3"><strong>Integrity Verified Clean:</strong> All current file checksums match baseline records perfectly.</div>';
            } else {
                statusBanner = '<div class="alert-box alert-warning mb-3"><strong>Anomalies Detected:</strong> Modifications, missing files, or newly created files detected relative to baseline.</div>';
                btnApprove.style.display = 'inline-flex';
            }

            let modifiedRows = '';
            if (det.modified_files && det.modified_files.length > 0) {
                modifiedRows = `
                    <h4 class="mt-3 text-amber font-sm font-weight-600">Modified Files (${det.modified_files.length})</h4>
                    <table class="data-table mt-1">
                        <thead><tr><th>File</th><th>Expected Hash (Baseline)</th><th>Current Hash</th></tr></thead>
                        <tbody>
                            ${det.modified_files.map(m => `
                                <tr>
                                    <td class="font-mono text-cyan">${escapeHtml(m.relative_path)}</td>
                                    <td class="font-mono text-muted">${escapeHtml(m.expected_hash ? m.expected_hash.slice(0, 16) + '...' : 'N/A')}</td>
                                    <td class="font-mono text-amber">${escapeHtml(m.current_hash ? m.current_hash.slice(0, 16) + '...' : 'N/A')}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
            }

            let missingRows = '';
            if (det.missing_files && det.missing_files.length > 0) {
                missingRows = `
                    <h4 class="mt-3 text-crimson font-sm font-weight-600">Missing / Deleted Files (${det.missing_files.length})</h4>
                    <ul class="font-mono font-sm text-muted mt-1" style="padding-left: 1.2rem;">
                        ${det.missing_files.map(f => `<li>${escapeHtml(f.relative_path)}</li>`).join('')}
                    </ul>
                `;
            }

            let newRows = '';
            if (det.new_files && det.new_files.length > 0) {
                newRows = `
                    <h4 class="mt-3 text-cyan font-sm font-weight-600">New Untracked Files (${det.new_files.length})</h4>
                    <ul class="font-mono font-sm text-muted mt-1" style="padding-left: 1.2rem;">
                        ${det.new_files.map(f => `<li>${escapeHtml(f.relative_path)} (Hash: ${f.sha256_hash ? f.sha256_hash.slice(0, 12) + '...' : ''})</li>`).join('')}
                    </ul>
                `;
            }

            modalBody.innerHTML = `
                ${statusBanner}
                <div class="stats-grid mb-3">
                    <div class="stat-card p-2"><div class="stat-title">SCANNED</div><div class="stat-value font-sm">${check.total_files}</div></div>
                    <div class="stat-card p-2"><div class="stat-title">MODIFIED</div><div class="stat-value font-sm text-amber">${check.modified_files}</div></div>
                    <div class="stat-card p-2"><div class="stat-title">MISSING</div><div class="stat-value font-sm text-crimson">${check.missing_files}</div></div>
                    <div class="stat-card p-2"><div class="stat-title">NEW</div><div class="stat-value font-sm text-cyan">${check.new_files}</div></div>
                </div>
                ${modifiedRows}
                ${missingRows}
                ${newRows}
            `;
            loadMonitoredFolders();
        } else {
            modalBody.innerHTML = `<div class="alert-box alert-warning">${escapeHtml(data.message)}</div>`;
        }
    } catch (e) {
        modalBody.innerHTML = `<div class="alert-box alert-warning">Connection error during verification check.</div>`;
    }
}

function closeIntegrityModal() {
    const modal = document.getElementById('integrityModal');
    if (modal) modal.style.display = 'none';
    activeIntegrityFolderId = null;
}

async function approveNewBaseline() {
    if (!activeIntegrityFolderId) return;
    try {
        const res = await fetchWithCsrf('/api/integrity/baseline/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ folder_id: activeIntegrityFolderId })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            closeIntegrityModal();
        } else {
            showToast(data.message || 'Failed to approve baseline', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

// Live Events Interception
async function loadEvents(isBackground = false) {
    const eventType = document.getElementById('filterEventType')?.value || '';
    const suspiciousOnly = document.getElementById('filterSuspiciousOnly')?.checked || false;

    let url = `/api/monitoring/events?limit=40`;
    if (eventType) url += `&event_type=${encodeURIComponent(eventType)}`;
    if (suspiciousOnly) url += `&suspicious_only=true`;

    try {
        const res = await fetch(url);
        const json = await res.json();
        if (json.status === 'success') {
            renderEventsTable(json.data);
        }
    } catch (e) {
        if (!isBackground) showToast('Failed to sync event stream', 'error');
    }
}

function renderEventsTable(events) {
    const tbody = document.getElementById('eventsTableBody');
    if (!tbody) return;

    if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-4">No file events recorded yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = events.map(e => {
        let evBadge = 'badge-subtle';
        if (e.event_type === 'created') evBadge = 'badge-emerald';
        else if (e.event_type === 'modified') evBadge = 'badge-blue';
        else if (e.event_type === 'deleted') evBadge = 'badge-danger';
        else if (e.event_type === 'moved') evBadge = 'badge-amber';

        return `
            <tr>
                <td class="font-mono font-sm text-muted">${escapeHtml(e.timestamp)}</td>
                <td><span class="badge ${evBadge}">${escapeHtml(e.event_type.toUpperCase())}</span></td>
                <td class="font-mono" title="${escapeHtml(e.file_path)}">${escapeHtml(e.file_path.length > 38 ? '...' + e.file_path.slice(-35) : e.file_path)}</td>
                <td class="font-mono text-muted">${e.old_path ? escapeHtml(e.old_path.length > 25 ? '...' + e.old_path.slice(-22) : e.old_path) : '—'}</td>
                <td>
                    ${e.is_suspicious 
                        ? '<span class="badge badge-danger">ANOMALOUS VELOCITY</span>' 
                        : '<span class="badge badge-subtle">Nominal</span>'}
                </td>
            </tr>
        `;
    }).join('');
}
