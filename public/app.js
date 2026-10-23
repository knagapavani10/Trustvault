// TrustVault Frontend Application State
let state = {
  token: localStorage.getItem('trustvault_token') || '',
  user: JSON.parse(localStorage.getItem('trustvault_user') || 'null'),
  currentTab: 'vault',
  activeDocForPerms: null,
  auditFilter: ''
};

// Initialize app on load
window.addEventListener('DOMContentLoaded', async () => {
  if (!state.token || !state.user) {
    // Default initial auto-login as Alice (Document Owner) for smooth demo evaluation
    await quickLogin('alice.owner@trustvault.local', 'AlicePass123!');
  } else {
    updateUserNav();
    loadCurrentTab();
  }
  verifyLedger(false);
});

// Toast notification helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  const colors = {
    info: 'bg-indigo-600 text-white',
    success: 'bg-emerald-600 text-white',
    error: 'bg-red-600 text-white',
    warning: 'bg-amber-600 text-white'
  };
  const icons = {
    info: 'fa-info-circle',
    success: 'fa-check-circle',
    error: 'fa-shield-xmark',
    warning: 'fa-triangle-exclamation'
  };

  toast.className = `${colors[type] || colors.info} px-4 py-3 rounded-xl shadow-2xl flex items-center space-x-3 text-xs font-semibold transform transition-all duration-300 ease-out translate-y-2 opacity-0 pointer-events-auto max-w-md`;
  toast.innerHTML = `
    <i class="fa-solid ${icons[type]} text-sm"></i>
    <span class="flex-1">${message}</span>
  `;

  container.appendChild(toast);
  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Update Top Bar User Information
function updateUserNav() {
  const nameEl = document.getElementById('navUserName');
  const roleEl = document.getElementById('navUserRole');
  const avatarEl = document.getElementById('userAvatar');
  const uploadBtn = document.getElementById('uploadDocBtn');

  if (state.user) {
    nameEl.textContent = state.user.name;
    roleEl.textContent = `Role: ${state.user.role.toUpperCase()}`;
    avatarEl.textContent = state.user.name.charAt(0);
    
    // Viewers cannot upload new documents
    if (state.user.role === 'viewer') {
      uploadBtn.classList.add('hidden');
    } else {
      uploadBtn.classList.remove('hidden');
    }
  } else {
    nameEl.textContent = 'Not Logged In';
    roleEl.textContent = 'Role: -';
    avatarEl.textContent = '?';
  }
}

// Quick Login switcher
async function quickLogin(email, password) {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || 'Authentication failed', 'error');
      return;
    }

    state.token = data.token;
    state.user = data.user;
    localStorage.setItem('trustvault_token', data.token);
    localStorage.setItem('trustvault_user', JSON.stringify(data.user));

    updateUserNav();
    showToast(`Logged in as ${data.user.name} (${data.user.role})`, 'success');
    loadCurrentTab();
    verifyLedger(false);
  } catch (err) {
    showToast(`Network or server error: ${err.message}`, 'error');
  }
}

function logout() {
  state.token = '';
  state.user = null;
  localStorage.removeItem('trustvault_token');
  localStorage.removeItem('trustvault_user');
  updateUserNav();
  showToast('Logged out. Please select an account from the switcher.', 'info');
  document.getElementById('documentTableBody').innerHTML = '<tr><td colspan="6" class="py-8 text-center text-slate-500">Please log in to access the vault.</td></tr>';
}

// Navigation Tabs
function switchTab(tabName) {
  state.currentTab = tabName;
  ['vault', 'audit', 'admin'].forEach(t => {
    const sec = document.getElementById(`tab-${t}`);
    const btn = document.getElementById(`tabBtn-${t}`);
    if (t === tabName) {
      sec.classList.remove('hidden');
      btn.className = 'py-3 px-2 border-b-2 border-indigo-500 text-indigo-400 font-medium text-sm flex items-center space-x-2 transition';
    } else {
      sec.classList.add('hidden');
      btn.className = 'py-3 px-2 border-b-2 border-transparent text-slate-400 hover:text-slate-200 font-medium text-sm flex items-center space-x-2 transition';
    }
  });
  loadCurrentTab();
}

function loadCurrentTab() {
  if (state.currentTab === 'vault') loadDocuments();
  if (state.currentTab === 'audit') loadAuditLogs();
  if (state.currentTab === 'admin') loadAdminUsers();
}

// -------------------------------------------------------------
// TAB 1: DOCUMENTS
// -------------------------------------------------------------
async function loadDocuments() {
  const tbody = document.getElementById('documentTableBody');
  if (!state.token) return;

  const search = document.getElementById('searchInput').value;
  const category = document.getElementById('categorySelect').value;

  try {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (category) params.append('category', category);

    const res = await fetch(`/api/documents?${params.toString()}`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-red-400">${data.error}</td></tr>`;
      return;
    }

    if (!data.documents || data.documents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="py-12 text-center text-slate-500">No documents found matching your permissions or search criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.documents.map(doc => {
      const isOwner = doc.user_permission === 'owner';
      const canEdit = doc.user_permission === 'edit' || isOwner;
      const canRead = doc.user_permission === 'read' || canEdit;

      const permBadge = isOwner
        ? `<span class="px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono text-[10px]">Owner</span>`
        : doc.user_permission === 'edit'
        ? `<span class="px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-mono text-[10px]">Edit & Read</span>`
        : doc.user_permission === 'read'
        ? `<span class="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono text-[10px]">Read Only</span>`
        : `<span class="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono text-[10px]">No Access</span>`;

      return `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="py-3 px-4">
            <div class="flex items-center space-x-3">
              <div class="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-indigo-400">
                <i class="fa-regular fa-file-lines"></i>
              </div>
              <div>
                <div class="font-semibold text-slate-200">${escapeHtml(doc.title)}</div>
                <div class="text-[11px] text-slate-400 font-mono">${escapeHtml(doc.original_name)} (${formatBytes(doc.file_size)})</div>
              </div>
            </div>
          </td>
          <td class="py-3 px-4 text-slate-300">${escapeHtml(doc.category)}</td>
          <td class="py-3 px-4 text-slate-300">
            <div>${escapeHtml(doc.owner_name)}</div>
            <div class="text-[10px] text-slate-500">${escapeHtml(doc.owner_email)}</div>
          </td>
          <td class="py-3 px-4 font-mono text-[10px] text-slate-400" title="${doc.sha256_checksum}">
            ${doc.sha256_checksum.slice(0, 12)}...
          </td>
          <td class="py-3 px-4">${permBadge}</td>
          <td class="py-3 px-4 text-right">
            <div class="flex items-center justify-end space-x-2">
              ${canRead ? `
                <button onclick="openViewModal('${doc.id}', '${escapeHtml(doc.title)}', '${escapeHtml(doc.original_name)}', '${doc.mime_type}')" class="px-2.5 py-1 rounded-lg bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/20 transition text-[11px] font-medium" title="View Document">
                  <i class="fa-solid fa-eye mr-1"></i> View
                </button>
                <button onclick="downloadDocument('${doc.id}', '${escapeHtml(doc.original_name)}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition text-[11px] font-medium" title="Authorized Download">
                  <i class="fa-solid fa-download mr-1"></i> Download
                </button>
              ` : `
                <button onclick="simulateIdorAttack('${doc.id}')" class="px-2 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition text-[10px] font-mono" title="Test IDOR: Attempt Unauthorized Access">
                  <i class="fa-solid fa-bug mr-1"></i> Probe (IDOR Test)
                </button>
              `}

              ${isOwner ? `
                <button onclick="openPermsModal('${doc.id}', '${escapeHtml(doc.title)}')" class="px-2.5 py-1 rounded-lg bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/20 transition text-[11px] font-medium" title="Manage Named Grants">
                  <i class="fa-solid fa-user-lock mr-1"></i> Share
                </button>
                <button onclick="deleteDoc('${doc.id}')" class="p-1.5 rounded-lg hover:bg-red-500/20 text-slate-400 hover:text-red-400 transition text-xs" title="Delete Document">
                  <i class="fa-regular fa-trash-can"></i>
                </button>
              ` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-red-400">Failed to load documents: ${err.message}</td></tr>`;
  }
}

// Download Document through authenticated server endpoint
async function downloadDocument(docId, filename) {
  try {
    const res = await fetch(`/api/documents/${docId}/download`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });

    if (!res.ok) {
      const err = await res.json();
      showToast(`Download Denied: ${err.error}`, 'error');
      // Refresh audit logs
      if (state.currentTab === 'audit') loadAuditLogs();
      verifyLedger(false);
      return;
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    showToast(`Downloaded "${filename}" safely.`, 'success');
    verifyLedger(false);
  } catch (err) {
    showToast(`Download error: ${err.message}`, 'error');
  }
}

// IDOR Simulation probe button
async function simulateIdorAttack(docId) {
  showToast('Simulating direct object reference bypass attempt against server...', 'warning');
  try {
    const res = await fetch(`/api/documents/${docId}/download`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (res.status === 403) {
      showToast(`SERVER BLOCKED (403): ${data.error}. Refusal logged to audit trail!`, 'error');
    } else {
      showToast(`Unexpected status: ${res.status}`, 'warning');
    }
    verifyLedger(false);
  } catch (err) {
    showToast(`Security probe finished: ${err.message}`, 'info');
  }
}

// Delete Document
async function deleteDoc(docId) {
  if (!confirm('Are you sure you want to delete this document? The deletion will be cryptographically audited.')) return;
  try {
    const res = await fetch(`/api/documents/${docId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to delete', 'error');
      return;
    }
    showToast('Document deleted and logged.', 'success');
    loadDocuments();
    verifyLedger(false);
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  }
}

// Upload Modal
function openUploadModal() {
  document.getElementById('uploadModal').classList.remove('hidden');
}

function closeUploadModal() {
  document.getElementById('uploadModal').classList.add('hidden');
  document.getElementById('uploadForm').reset();
}

async function handleUploadSubmit(e) {
  e.preventDefault();
  const fileInput = document.getElementById('uploadFileInput');
  const title = document.getElementById('uploadTitle').value;
  const category = document.getElementById('uploadCategory').value;
  const desc = document.getElementById('uploadDesc').value;

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast('Please select a file to upload.', 'error');
    return;
  }

  const formData = new FormData();
  formData.append('title', title);
  formData.append('category', category);
  formData.append('description', desc);
  formData.append('file', fileInput.files[0]);

  const submitBtn = document.getElementById('uploadSubmitBtn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Validating Magic Bytes...';

  try {
    const res = await fetch('/api/documents', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${state.token}` },
      body: formData
    });
    const data = await res.json();

    if (!res.ok) {
      showToast(`Upload Rejected: ${data.error}`, 'error');
      return;
    }

    showToast(`Document "${data.document.title}" validated and secured.`, 'success');
    closeUploadModal();
    loadDocuments();
    verifyLedger(false);
  } catch (err) {
    showToast(`Upload failed: ${err.message}`, 'error');
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<i class="fa-solid fa-shield-check"></i> <span>Validate & Deposit to Vault</span>';
  }
}

// -------------------------------------------------------------
// PERMISSIONS MANAGER MODAL
// -------------------------------------------------------------
async function openPermsModal(docId, docTitle) {
  state.activeDocForPerms = docId;
  document.getElementById('permModalDocTitle').textContent = `Document: ${docTitle}`;
  document.getElementById('permsModal').classList.remove('hidden');
  loadDocPermissions(docId);
}

function closePermsModal() {
  document.getElementById('permsModal').classList.add('hidden');
  state.activeDocForPerms = null;
}

async function loadDocPermissions(docId) {
  const tbody = document.getElementById('permListBody');
  try {
    const res = await fetch(`/api/documents/${docId}/permissions`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-red-400">${data.error}</td></tr>`;
      return;
    }

    if (!data.permissions || data.permissions.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-slate-500">No external grants active. Only owner currently has access.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.permissions.map(p => `
      <tr class="hover:bg-slate-900/60">
        <td class="py-2.5 px-3">
          <div class="font-medium text-slate-200">${escapeHtml(p.name)}</div>
          <div class="text-[10px] text-slate-500 font-mono">${escapeHtml(p.email)}</div>
        </td>
        <td class="py-2.5 px-3 text-slate-400 capitalize">${p.role}</td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-mono ${p.permission_level === 'edit' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}">
            ${p.permission_level.toUpperCase()}
          </span>
        </td>
        <td class="py-2.5 px-3 font-mono text-[10px] text-slate-400">${new Date(p.granted_at).toLocaleString()}</td>
        <td class="py-2.5 px-3 text-right">
          <button onclick="revokePerm('${p.user_id}', '${escapeHtml(p.name)}')" class="px-2.5 py-1 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 text-[11px] font-medium transition">
            <i class="fa-solid fa-ban mr-1"></i> Revoke Now
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-red-400">Failed to load grants: ${err.message}</td></tr>`;
  }
}

async function handleGrantSubmit(e) {
  e.preventDefault();
  const targetEmail = document.getElementById('grantTargetEmail').value;
  const permissionLevel = document.getElementById('grantLevel').value;

  if (!targetEmail || !state.activeDocForPerms) return;

  try {
    const res = await fetch(`/api/documents/${state.activeDocForPerms}/permissions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`
      },
      body: JSON.stringify({ targetEmail, permissionLevel })
    });
    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || 'Failed to grant permission', 'error');
      return;
    }

    showToast(`Granted ${permissionLevel.toUpperCase()} access to ${targetEmail}.`, 'success');
    document.getElementById('grantPermForm').reset();
    loadDocPermissions(state.activeDocForPerms);
    verifyLedger(false);
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  }
}

async function revokePerm(targetUserId, targetName) {
  if (!state.activeDocForPerms) return;
  try {
    const res = await fetch(`/api/documents/${state.activeDocForPerms}/permissions/${targetUserId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || 'Failed to revoke', 'error');
      return;
    }

    showToast(`IMMEDIATE REVOCATION ENFORCED: ${targetName}'s access halted instantly.`, 'warning');
    loadDocPermissions(state.activeDocForPerms);
    verifyLedger(false);
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  }
}

// -------------------------------------------------------------
// TAB 2: AUDIT LEDGER
// -------------------------------------------------------------
async function loadAuditLogs() {
  const tbody = document.getElementById('auditTableBody');
  if (!state.token) return;

  try {
    const params = new URLSearchParams();
    if (state.auditFilter) {
      if (state.auditFilter === 'ACCESS_DENIED') params.append('status', 'DENIED');
      else params.append('action', state.auditFilter);
    }

    const res = await fetch(`/api/audit?${params.toString()}`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="8" class="py-6 text-center text-red-400 font-sans">${data.error}</td></tr>`;
      return;
    }

    if (!data.logs || data.logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="py-8 text-center text-slate-500 font-sans">No audit events found.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.logs.map(log => {
      const isDenied = log.status === 'DENIED';
      const statusBadge = isDenied
        ? `<span class="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 text-[10px] font-bold">DENIED</span>`
        : `<span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">SUCCESS</span>`;

      return `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="py-2.5 px-4 font-bold text-slate-300">#${log.id}</td>
          <td class="py-2.5 px-4 text-slate-400">${new Date(log.timestamp).toISOString().replace('T', ' ').slice(0, 19)}</td>
          <td class="py-2.5 px-4">
            <span class="text-slate-200">${escapeHtml(log.actor_email)}</span>
            <span class="text-[10px] text-slate-500 block uppercase">${log.actor_role}</span>
          </td>
          <td class="py-2.5 px-4 font-semibold ${isDenied ? 'text-red-400' : 'text-indigo-300'}">${log.action}</td>
          <td class="py-2.5 px-4 text-slate-300 font-sans text-xs">
            ${escapeHtml(log.resource_name || log.resource_id || '-')}
          </td>
          <td class="py-2.5 px-4">${statusBadge}</td>
          <td class="py-2.5 px-4 text-slate-400">${log.ip_address}</td>
          <td class="py-2.5 px-4 text-[10px] text-indigo-400/80 cursor-pointer" title="Block Hash: ${log.hash}\nPrev Hash: ${log.prev_hash}">
            ${log.hash.slice(0, 16)}...
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="py-6 text-center text-red-400 font-sans">Failed to load ledger: ${err.message}</td></tr>`;
  }
}

function filterAuditLogs(filter) {
  state.auditFilter = filter;
  loadAuditLogs();
}

// Cryptographic Ledger Verification
async function verifyLedger(showExplicitSuccessToast = false) {
  const badgeText = document.getElementById('ledgerBadgeText');
  const verifyBtn = document.getElementById('verifyLedgerBtn');

  try {
    const res = await fetch('/api/audit/verify', {
      headers: state.token ? { 'Authorization': `Bearer ${state.token}` } : {}
    });
    const data = await res.json();

    if (data.verification && data.verification.valid) {
      badgeText.textContent = `Ledger: Verified (${data.verification.totalBlocks} Blocks)`;
      verifyBtn.className = 'flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20 transition text-xs font-mono font-medium';
      if (showExplicitSuccessToast) {
        showToast(`Cryptographic Audit Chain Integrity 100% Verified across all ${data.verification.totalBlocks} blocks! Head: ${data.verification.headHash.slice(0, 12)}...`, 'success');
      }
    } else {
      badgeText.textContent = 'ALERT: Tamper Detected!';
      verifyBtn.className = 'flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-red-500/20 border border-red-500/40 text-red-400 hover:bg-red-500/30 transition text-xs font-mono font-medium animate-pulse';
      showToast(`CRITICAL INTEGRITY FAILURE: ${data.verification.error}`, 'error');
    }
  } catch (err) {
    badgeText.textContent = 'Ledger Check Failed';
  }
}

// -------------------------------------------------------------
// TAB 3: SECURITY & ADMIN
// -------------------------------------------------------------
async function loadAdminUsers() {
  const tbody = document.getElementById('adminUsersTableBody');
  if (!state.token) return;

  try {
    const res = await fetch('/api/admin/users', {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-red-400">${data.error}</td></tr>`;
      return;
    }

    tbody.innerHTML = data.users.map(u => {
      const isActive = u.is_active === 1;
      const isAdmin = state.user?.role === 'admin';

      return `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="py-3 px-4">
            <div class="font-semibold text-slate-200">${escapeHtml(u.name)}</div>
            <div class="text-[11px] text-slate-400 font-mono">${escapeHtml(u.email)}</div>
          </td>
          <td class="py-3 px-4">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
              u.role === 'admin' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' :
              u.role === 'owner' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
              'bg-blue-500/10 text-blue-400 border border-blue-500/20'
            }">
              ${u.role}
            </span>
          </td>
          <td class="py-3 px-4">
            ${isActive 
              ? `<span class="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-mono">Active</span>`
              : `<span class="px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20 text-[10px] font-mono">Suspended</span>`
            }
          </td>
          <td class="py-3 px-4 text-[11px] text-slate-400">
            ${isActive ? 'Token version validated' : 'Sessions revoked immediately'}
          </td>
          <td class="py-3 px-4 text-right">
            ${isAdmin ? `
              <button onclick="toggleUserStatus('${u.id}', ${!isActive})" class="px-3 py-1 rounded-lg ${isActive ? 'bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20'} text-xs font-medium transition">
                ${isActive ? 'Suspend Account' : 'Activate Account'}
              </button>
            ` : '<span class="text-slate-500 text-xs">Admin Only</span>'}
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-red-400">Error: ${err.message}</td></tr>`;
  }
}

async function toggleUserStatus(userId, makeActive) {
  try {
    const res = await fetch(`/api/admin/users/${userId}/status`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`
      },
      body: JSON.stringify({ isActive: makeActive })
    });
    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || 'Failed to update user status', 'error');
      return;
    }

    showToast(`User status updated to ${makeActive ? 'ACTIVE' : 'SUSPENDED'}. All prior sessions revoked.`, 'info');
    loadAdminUsers();
    verifyLedger(false);
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  }
}

// Utilities
function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[m]));
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// -------------------------------------------------------------
// USER REGISTRATION & LOGIN MODAL
// -------------------------------------------------------------
function openAuthModal(mode = 'login') {
  document.getElementById('authModal').classList.remove('hidden');
  switchAuthMode(mode);
}

function closeAuthModal() {
  document.getElementById('authModal').classList.add('hidden');
}

function switchAuthMode(mode) {
  const regForm = document.getElementById('registerForm');
  const loginForm = document.getElementById('customLoginForm');
  const regBtn = document.getElementById('authTabRegisterBtn');
  const loginBtn = document.getElementById('authTabLoginBtn');

  if (mode === 'register') {
    regForm.classList.remove('hidden');
    loginForm.classList.add('hidden');
    regBtn.className = 'px-3 py-1.5 rounded-lg bg-indigo-600 text-white';
    loginBtn.className = 'px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white';
  } else {
    regForm.classList.add('hidden');
    loginForm.classList.remove('hidden');
    loginBtn.className = 'px-3 py-1.5 rounded-lg bg-indigo-600 text-white';
    regBtn.className = 'px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white';
  }
}

async function handleRegisterSubmit(e) {
  e.preventDefault();
  const name = document.getElementById('regName').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const role = document.getElementById('regRole').value;
  const password = document.getElementById('regPassword').value;

  const btn = document.getElementById('regSubmitBtn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Creating Account...';

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, role, password })
    });
    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || 'Registration failed', 'error');
      return;
    }

    state.token = data.token;
    state.user = data.user;
    localStorage.setItem('trustvault_token', data.token);
    localStorage.setItem('trustvault_user', JSON.stringify(data.user));

    updateUserNav();
    showToast(`Welcome ${data.user.name}! Account created as ${data.user.role}.`, 'success');
    closeAuthModal();
    loadCurrentTab();
    verifyLedger(false);
  } catch (err) {
    showToast(`Registration error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-user-plus"></i> <span>Create Account & Log In</span>';
  }
}

async function handleCustomLoginSubmit(e) {
  e.preventDefault();
  const email = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;
  await quickLogin(email, password);
  closeAuthModal();
}

// -------------------------------------------------------------
// SECURE IN-BROWSER DOCUMENT VIEWER
// -------------------------------------------------------------
async function openViewModal(docId, title, originalName, mimeType) {
  const modal = document.getElementById('viewDocModal');
  const titleEl = document.getElementById('viewDocModalTitle');
  const metaEl = document.getElementById('viewDocModalMeta');
  const contentEl = document.getElementById('viewDocContent');
  const downloadBtn = document.getElementById('viewDocDownloadBtn');

  titleEl.innerHTML = `<i class="fa-solid fa-file-shield text-indigo-400"></i> <span>${escapeHtml(title)}</span>`;
  metaEl.textContent = `${originalName} (${mimeType}) - Evaluating real-time permissions...`;
  contentEl.innerHTML = '<div class="text-center text-slate-500"><i class="fa-solid fa-spinner animate-spin text-2xl mb-2 text-indigo-400"></i><p>Verifying server authorization...</p></div>';
  downloadBtn.onclick = () => downloadDocument(docId, originalName);
  modal.classList.remove('hidden');

  try {
    const res = await fetch(`/api/documents/${docId}/view`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });

    if (!res.ok) {
      const err = await res.json();
      contentEl.innerHTML = `
        <div class="text-center text-red-400 p-8 space-y-3">
          <i class="fa-solid fa-shield-xmark text-4xl text-red-500"></i>
          <div class="font-bold text-sm">ACCESS DENIED (HTTP ${res.status})</div>
          <p class="text-xs max-w-md mx-auto text-slate-400">${escapeHtml(err.error || 'You lack permission to view this document.')}</p>
          <p class="text-[10px] font-mono text-amber-400">This unauthorized probe was recorded in the immutable audit ledger.</p>
        </div>
      `;
      metaEl.textContent = 'Access Blocked by Server';
      verifyLedger(false);
      return;
    }

    metaEl.textContent = `${originalName} (${mimeType}) • Authenticated Stream`;

    if (mimeType.includes('pdf')) {
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      contentEl.innerHTML = `<iframe src="${objectUrl}#toolbar=0" class="w-full h-full rounded-lg border-0 bg-slate-900"></iframe>`;
    } else if (mimeType.startsWith('image/')) {
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      contentEl.innerHTML = `<img src="${objectUrl}" alt="${escapeHtml(title)}" class="max-w-full max-h-full object-contain rounded-lg">`;
    } else {
      // Text / CSV / JSON
      const text = await res.text();
      contentEl.innerHTML = `<pre class="w-full h-full text-slate-200 whitespace-pre-wrap font-mono text-xs overflow-auto select-text">${escapeHtml(text)}</pre>`;
    }

    verifyLedger(false);
  } catch (err) {
    contentEl.innerHTML = `<div class="text-red-400 text-center">Failed to stream document: ${escapeHtml(err.message)}</div>`;
  }
}

function closeViewModal() {
  document.getElementById('viewDocModal').classList.add('hidden');
}
