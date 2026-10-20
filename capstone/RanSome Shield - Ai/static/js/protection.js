/**
 * RansomShield AI — Protection, Backups & Quarantine Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    loadBackups();
    loadQuarantine();
    loadRecoveries();
});

function switchProtTab(tabKey) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');

    if (tabKey === 'backups') {
        document.getElementById('tabBtnBackups').classList.add('active');
        document.getElementById('tabBackups').style.display = 'block';
        loadBackups();
    } else if (tabKey === 'quarantine') {
        document.getElementById('tabBtnQuarantine').classList.add('active');
        document.getElementById('tabQuarantine').style.display = 'block';
        loadQuarantine();
    } else if (tabKey === 'recoveries') {
        document.getElementById('tabBtnRecoveries').classList.add('active');
        document.getElementById('tabRecoveries').style.display = 'block';
        loadRecoveries();
    }
}

// ---------------- BACKUPS ----------------

async function loadBackups() {
    try {
        const res = await fetch('/api/backups');
        const json = await res.json();
        if (json.status === 'success') {
            renderBackupsTable(json.data);
            const countEl = document.getElementById('backupsTabCount');
            if (countEl) countEl.textContent = json.data.length;
        }
    } catch (e) {
        showToast('Failed to load backup catalog', 'error');
    }
}

function renderBackupsTable(backups) {
    const tbody = document.getElementById('backupsTableBody');
    if (!tbody) return;

    if (!backups || backups.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No backup snapshots stored yet. Click 'Create Backup Snapshot' above.</td></tr>`;
        return;
    }

    tbody.innerHTML = backups.map(b => `
        <tr>
            <td class="font-mono text-muted">#${b.id}</td>
            <td class="font-mono text-cyan" title="${escapeHtml(b.original_path)}">${escapeHtml(b.original_path.length > 35 ? '...' + b.original_path.slice(-32) : b.original_path)}</td>
            <td>${formatBytes(b.file_size)}</td>
            <td class="font-mono text-muted" title="${escapeHtml(b.sha256_hash)}">${escapeHtml(b.sha256_hash.slice(0, 16))}...</td>
            <td class="font-mono text-muted font-sm">${escapeHtml(b.created_at)}</td>
            <td>
                ${b.is_valid 
                    ? '<span class="badge badge-emerald">SHA-256 Valid</span>' 
                    : '<span class="badge badge-danger">Tampered / Missing</span>'}
            </td>
            <td>
                <div class="flex-gap-2">
                    <button class="btn btn-secondary btn-sm" onclick="verifyBackup(${b.id})">Verify Checksum</button>
                    <button class="btn btn-emerald btn-sm" onclick="openRestoreModal(${b.id}, '${escapeHtml(b.original_path)}')">Restore</button>
                </div>
            </td>
        </tr>
    `).join('');
}

function openCreateBackupModal() {
    const modal = document.getElementById('createBackupModal');
    if (modal) modal.style.display = 'flex';
}

function closeCreateBackupModal() {
    const modal = document.getElementById('createBackupModal');
    if (modal) modal.style.display = 'none';
    document.getElementById('backupPathInput').value = '';
    document.getElementById('backupNotesInput').value = '';
}

async function submitCreateBackup() {
    const path = document.getElementById('backupPathInput').value.trim();
    const notes = document.getElementById('backupNotesInput').value.trim();
    const isFolder = document.getElementById('backupIsFolderInput').checked;

    if (!path) {
        showToast('Target path is required', 'error');
        return;
    }

    try {
        const res = await fetchWithCsrf('/api/backups', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path, notes, is_folder: isFolder })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            closeCreateBackupModal();
            loadBackups();
        } else {
            showToast(data.message || 'Failed to create backup', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

async function verifyBackup(backupId) {
    try {
        const res = await fetchWithCsrf(`/api/backups/${backupId}/verify`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'verified') {
            showToast(data.message, 'success');
        } else {
            showToast(data.message || 'Checksum verification failed', 'error');
        }
        loadBackups();
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

// Restore Modal
function openRestoreModal(backupId, origPath) {
    const modal = document.getElementById('restoreModal');
    if (!modal) return;
    document.getElementById('restoreBackupId').value = backupId;
    document.getElementById('restoreDestInput').value = origPath;
    modal.style.display = 'flex';
}

function closeRestoreModal() {
    const modal = document.getElementById('restoreModal');
    if (modal) modal.style.display = 'none';
}

async function submitRestoreBackup() {
    const backupId = document.getElementById('restoreBackupId').value;
    const dest = document.getElementById('restoreDestInput').value.trim();

    try {
        const res = await fetchWithCsrf(`/api/backups/${backupId}/restore`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ destination_path: dest })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            closeRestoreModal();
            loadRecoveries();
        } else {
            showToast(data.message || 'Restoration failed', 'error');
        }
    } catch (e) {
        showToast('Connection error during restore', 'error');
    }
}

// ---------------- QUARANTINE ----------------

async function loadQuarantine() {
    try {
        const res = await fetch('/api/quarantine');
        const json = await res.json();
        if (json.status === 'success') {
            renderQuarantineTable(json.data);
            const countEl = document.getElementById('quarantineTabCount');
            if (countEl) countEl.textContent = json.data.filter(q => q.status === 'Quarantined').length;
        }
    } catch (e) {
        showToast('Failed to load quarantine store', 'error');
    }
}

function renderQuarantineTable(records) {
    const tbody = document.getElementById('quarantineTableBody');
    if (!tbody) return;

    if (!records || records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No items in quarantine vault.</td></tr>`;
        return;
    }

    tbody.innerHTML = records.map(q => `
        <tr>
            <td class="font-mono text-muted">#${q.id}</td>
            <td class="font-mono text-amber" title="${escapeHtml(q.original_path)}">${escapeHtml(q.original_path.length > 35 ? '...' + q.original_path.slice(-32) : q.original_path)}</td>
            <td>${escapeHtml(q.reason)}</td>
            <td class="font-mono text-muted" title="${escapeHtml(q.sha256_hash)}">${escapeHtml(q.sha256_hash ? q.sha256_hash.slice(0, 14) + '...' : 'N/A')}</td>
            <td class="font-mono text-muted font-sm">${escapeHtml(q.quarantined_at)}</td>
            <td>
                ${q.status === 'Quarantined' 
                    ? '<span class="badge badge-amber">ISOLATED</span>' 
                    : '<span class="badge badge-subtle">RESTORED</span>'}
            </td>
            <td>
                ${q.status === 'Quarantined' 
                    ? `<button class="btn btn-secondary btn-sm" onclick="restoreQuarantinedFile(${q.id})">Unquarantine</button>` 
                    : '<span class="text-muted font-sm">Restored</span>'}
            </td>
        </tr>
    `).join('');
}

function openQuarantineModal() {
    const modal = document.getElementById('quarantineModal');
    if (modal) modal.style.display = 'flex';
}

function closeQuarantineModal() {
    const modal = document.getElementById('quarantineModal');
    if (modal) modal.style.display = 'none';
    document.getElementById('quarantinePathInput').value = '';
    document.getElementById('quarantineReasonInput').value = '';
}

async function submitQuarantineFile() {
    const path = document.getElementById('quarantinePathInput').value.trim();
    const reason = document.getElementById('quarantineReasonInput').value.trim();

    if (!path) {
        showToast('File path is required', 'error');
        return;
    }

    try {
        const res = await fetchWithCsrf('/api/quarantine', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path: path, reason: reason || 'Manual isolation' })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            closeQuarantineModal();
            loadQuarantine();
        } else {
            showToast(data.message || 'Quarantine failed', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

async function restoreQuarantinedFile(recordId) {
    showConfirmDialog(
        'Restore Quarantined File',
        'Are you sure you want to restore this file to its original path? Verify it is safe before continuing.',
        async () => {
            try {
                const res = await fetchWithCsrf(`/api/quarantine/${recordId}/restore`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
                const data = await res.json();
                if (data.status === 'success') {
                    showToast(data.message, 'success');
                    loadQuarantine();
                } else {
                    showToast(data.message || 'Failed to restore', 'error');
                }
            } catch (e) {
                showToast('Connection error', 'error');
            }
        },
        'Restore File'
    );
}

// ---------------- RECOVERIES ----------------

async function loadRecoveries() {
    try {
        const res = await fetch('/api/recoveries');
        const json = await res.json();
        if (json.status === 'success') {
            renderRecoveriesTable(json.data);
        }
    } catch (e) {
        console.error('Failed to load recoveries:', e);
    }
}

function renderRecoveriesTable(recs) {
    const tbody = document.getElementById('recoveriesTableBody');
    if (!tbody) return;

    if (!recs || recs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">No restoration operations performed yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = recs.map(r => `
        <tr>
            <td class="font-mono text-muted">#${r.id}</td>
            <td><span class="badge badge-blue">Backup #${r.backup_id || 'N/A'}</span></td>
            <td class="font-mono text-emerald" title="${escapeHtml(r.target_path)}">${escapeHtml(r.target_path.length > 35 ? '...' + r.target_path.slice(-32) : r.target_path)}</td>
            <td class="font-mono text-muted font-sm">${escapeHtml(r.recovered_at)}</td>
            <td class="font-mono text-muted" title="${escapeHtml(r.verified_hash)}">${escapeHtml(r.verified_hash ? r.verified_hash.slice(0, 14) + '...' : 'N/A')}</td>
            <td>
                ${r.status === 'Success' 
                    ? '<span class="badge badge-emerald">VERIFIED RESTORE</span>' 
                    : '<span class="badge badge-danger">MISMATCH</span>'}
            </td>
        </tr>
    `).join('');
}
