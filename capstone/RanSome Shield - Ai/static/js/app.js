/**
 * RansomShield AI — Core Application & Global Utilities
 */

// CSRF-enabled Fetch Wrapper
async function fetchWithCsrf(url, options = {}) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    const headers = options.headers || {};
    
    if (csrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes((options.method || 'GET').toUpperCase())) {
        headers['X-CSRF-Token'] = csrfToken;
    }
    
    options.headers = headers;
    return fetch(url, options);
}

// Live Clock
function initLiveClock() {
    const clockEl = document.getElementById('liveClock');
    if (!clockEl) return;
    
    function update() {
        const now = new Date();
        clockEl.textContent = now.toUTCString().slice(17, 25) + ' UTC';
    }
    update();
    setInterval(update, 1000);
}

// Toast Notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let iconSvg = '';
    if (type === 'success') {
        iconSvg = `<svg class="btn-icon text-emerald" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
    } else if (type === 'error') {
        iconSvg = `<svg class="btn-icon text-crimson" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
    } else {
        iconSvg = `<svg class="btn-icon text-cyan" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
    }

    toast.innerHTML = `${iconSvg} <span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.4s ease';
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

// Confirmation Modal Helper
let currentConfirmCallback = null;

function showConfirmDialog(title, message, onConfirm, confirmBtnText = 'Proceed', isDestructive = false) {
    const modal = document.getElementById('confirmModal');
    const titleEl = document.getElementById('confirmModalTitle');
    const msgEl = document.getElementById('confirmModalMessage');
    const btnEl = document.getElementById('confirmModalActionBtn');

    if (!modal || !titleEl || !msgEl || !btnEl) return;

    titleEl.textContent = title;
    msgEl.innerHTML = message;
    btnEl.textContent = confirmBtnText;
    btnEl.className = isDestructive ? 'btn btn-danger' : 'btn btn-primary';

    currentConfirmCallback = onConfirm;
    btnEl.onclick = () => {
        if (currentConfirmCallback) currentConfirmCallback();
        closeConfirmModal();
    };

    modal.style.display = 'flex';
}

function closeConfirmModal() {
    const modal = document.getElementById('confirmModal');
    if (modal) modal.style.display = 'none';
    currentConfirmCallback = null;
}

// Demo Simulation Modal
async function openDemoModal() {
    const modal = document.getElementById('demoModal');
    if (!modal) return;
    modal.style.display = 'flex';
    await refreshDemoStatus();
}

function closeDemoModal() {
    const modal = document.getElementById('demoModal');
    if (modal) modal.style.display = 'none';
}

async function refreshDemoStatus() {
    try {
        const res = await fetch('/api/demo/status');
        const json = await res.json();
        if (json.status === 'success') {
            document.getElementById('demoSandboxPath').textContent = json.data.sandbox_path;
            document.getElementById('demoFileCount').textContent = `${json.data.file_count} files (${json.data.is_monitored ? 'Monitored' : 'Idle'})`;
        }
    } catch (e) {
        console.error('Error fetching demo status:', e);
    }
}

async function prepareDemoSandbox() {
    const btn = document.getElementById('btnPrepDemo');
    btn.disabled = true;
    btn.textContent = 'Preparing...';
    try {
        const res = await fetchWithCsrf('/api/demo/prepare', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            await refreshDemoStatus();
        } else {
            showToast(data.message || 'Failed to prepare sandbox', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Prepare Sandbox';
    }
}

async function runSimulation() {
    showConfirmDialog(
        'Trigger Safe Simulation Burst',
        'This will simulate rapid modification and extension renaming on the harmless sample files in the demo sandbox to trigger behavioral detection rules. No real files or keys will be affected.',
        async () => {
            const btn = document.getElementById('btnRunSim');
            btn.disabled = true;
            btn.textContent = 'Simulating...';
            try {
                const res = await fetchWithCsrf('/api/demo/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: 'rapid_mod_rename' })
                });
                const data = await res.json();
                if (data.status === 'success') {
                    showToast(data.message, 'success');
                    await refreshDemoStatus();
                    // If on dashboard or monitoring, refresh telemetry
                    if (window.loadDashboardData) window.loadDashboardData();
                    if (window.loadEvents) window.loadEvents();
                } else {
                    showToast(data.message || 'Simulation error', 'error');
                }
            } catch (e) {
                showToast('Connection error during simulation', 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Trigger Burst Event';
            }
        },
        'Execute Simulation',
        true
    );
}

async function cleanDemoSandbox() {
    try {
        const res = await fetchWithCsrf('/api/demo/cleanup', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(data.message, 'success');
            await refreshDemoStatus();
        } else {
            showToast(data.message || 'Cleanup error', 'error');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

// Utility: Escape HTML
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Utility: Format File Size
function formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Global Nav Updates
async function updateNavBadges() {
    try {
        const res = await fetch('/api/dashboard/stats');
        const json = await res.json();
        if (json.status === 'success') {
            const data = json.data;
            const monCountEl = document.getElementById('navMonCount');
            if (monCountEl) monCountEl.textContent = data.active_monitors || '0';

            const alertCountEl = document.getElementById('navAlertCount');
            if (alertCountEl) {
                if (data.critical_alerts > 0) {
                    alertCountEl.textContent = data.critical_alerts;
                    alertCountEl.style.display = 'inline-flex';
                } else {
                    alertCountEl.style.display = 'none';
                }
            }
        }
    } catch (e) {
        // silent fail on background badge update
    }
}

// DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    initLiveClock();
    updateNavBadges();
    
    // Sidebar mobile toggle
    const toggleBtn = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
    }
});
