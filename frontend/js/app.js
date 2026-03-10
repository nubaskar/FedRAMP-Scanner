/* ==========================================================================
   CMMC Cloud Compliance Scanner - Core Application
   Router, API helpers, Auth (Entra ID SSO), and shared utilities
   ========================================================================== */

(function () {
  'use strict';

  /* ---------- Configuration ---------- */
  const isBackendServed = window.location.port === '8000' || window.location.pathname.startsWith('/static/');
  const CONFIG = {
    API_BASE: isBackendServed ? window.location.origin + '/api' : 'https://cmmc-scanner-prod-api.whitecliff-57323604.eastus2.azurecontainerapps.io/api',
    TOKEN_KEY: 'cmmc_scanner_token',
    USER_KEY: 'cmmc_scanner_user',
    POLL_INTERVAL: 5000,
  };

  /* ---------- API Helper ---------- */
  const api = {
    _getHeaders() {
      const headers = { 'Content-Type': 'application/json' };
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      if (token) {
        headers['Authorization'] = 'Bearer ' + token;
      }
      return headers;
    },

    async _request(method, url, data) {
      const opts = {
        method: method,
        headers: this._getHeaders(),
      };
      if (data !== undefined && method !== 'GET') {
        opts.body = JSON.stringify(data);
      }
      const fullUrl = url.startsWith('http') ? url : CONFIG.API_BASE + url;
      try {
        const resp = await fetch(fullUrl, opts);
        if (resp.status === 401) {
          auth.logout();
          return null;
        }
        if (resp.status === 204) return null;
        const json = await resp.json();
        if (!resp.ok) {
          throw new Error(json.detail || json.message || 'Request failed');
        }
        return json;
      } catch (err) {
        if (err.message === 'Failed to fetch') {
          showToast('Unable to connect to server. Please check your connection.', 'error');
        }
        throw err;
      }
    },

    get(url) { return this._request('GET', url); },
    post(url, data) { return this._request('POST', url, data); },
    put(url, data) { return this._request('PUT', url, data); },
    delete(url) { return this._request('DELETE', url); },
  };

  /* ---------- Auth (dual mode: password for dev, SSO for prod) ---------- */
  var authMode = 'password'; // default, updated by /api/auth/config

  const auth = {
    loginSSO() {
      window.location.href = CONFIG.API_BASE + '/auth/login';
    },

    async loginPassword(username, password) {
      var data = await api.post('/auth/login', { username: username, password: password });
      if (data && data.access_token) {
        localStorage.setItem(CONFIG.TOKEN_KEY, data.access_token);
        // Decode JWT for user info
        try {
          var parts = data.access_token.split('.');
          var payload = JSON.parse(atob(parts[1]));
          var user = {
            name: payload.name || username,
            role: payload.role || 'Admin',
            email: payload.email || '',
            auth_method: payload.auth_method || 'password',
            username: payload.sub || username,
            exp: payload.exp || 0,
          };
          localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(user));
        } catch {
          localStorage.setItem(CONFIG.USER_KEY, JSON.stringify({ name: username, role: 'Admin', auth_method: 'password' }));
        }
        return true;
      }
      return false;
    },

    async logout() {
      try {
        var data = await api.post('/auth/logout');
        localStorage.removeItem(CONFIG.TOKEN_KEY);
        localStorage.removeItem(CONFIG.USER_KEY);
        if (data && data.auth_method === 'sso' && data.logout_url) {
          window.location.href = data.logout_url;
          return;
        }
      } catch {
        // If logout endpoint fails, just clear local state
      }
      localStorage.removeItem(CONFIG.TOKEN_KEY);
      localStorage.removeItem(CONFIG.USER_KEY);
      showLoginOverlay();
      window.location.hash = '#dashboard';
    },

    isAuthenticated() {
      return !!localStorage.getItem(CONFIG.TOKEN_KEY);
    },

    getUser() {
      try {
        return JSON.parse(localStorage.getItem(CONFIG.USER_KEY)) || { name: 'User', role: 'Assessor' };
      } catch {
        return { name: 'User', role: 'Assessor' };
      }
    },
  };

  /* ---------- SSO Callback Handler ---------- */
  function handleSSOCallback() {
    var hash = window.location.hash;

    // Handle SSO success: #sso-callback?token=...
    if (hash.startsWith('#sso-callback')) {
      var params = new URLSearchParams(hash.replace('#sso-callback?', ''));
      var token = params.get('token');
      if (token) {
        localStorage.setItem(CONFIG.TOKEN_KEY, token);

        // Decode JWT payload (base64) to extract user info
        try {
          var parts = token.split('.');
          var payload = JSON.parse(atob(parts[1]));
          var user = {
            name: payload.name || payload.sub || 'User',
            role: payload.role || 'Assessor',
            email: payload.email || '',
            auth_method: payload.auth_method || 'sso',
            username: payload.sub || '',
            exp: payload.exp || 0,
          };
          localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(user));
        } catch {
          localStorage.setItem(CONFIG.USER_KEY, JSON.stringify({ name: 'User', role: 'Assessor', auth_method: 'sso' }));
        }

        // Clear the SSO hash and navigate to dashboard
        window.location.hash = '#dashboard';
        return true;
      }
    }

    // Handle SSO error: #sso-error?message=...
    if (hash.startsWith('#sso-error')) {
      var errorParams = new URLSearchParams(hash.replace('#sso-error?', ''));
      var message = errorParams.get('m') || errorParams.get('message') || 'Authentication failed. Please try again.';
      var errorEl = document.getElementById('login-error');
      if (errorEl) {
        errorEl.textContent = message;
        errorEl.classList.add('show');
      }
      window.location.hash = '';
      return false;
    }

    return false;
  }

  /* ---------- Router ---------- */
  const routes = {
    dashboard: { title: 'Dashboard', breadcrumb: 'Home / Dashboard', render: null },
    clients: { title: 'Clients', breadcrumb: 'Home / Clients', render: null },
    scans: { title: 'Scans', breadcrumb: 'Home / Scans', render: null },
    reports: { title: 'Reports', breadcrumb: 'Home / Reports', render: null },
    help: { title: 'Help & Documentation', breadcrumb: 'Home / Help', render: null },
  };

  function getRoute() {
    const hash = window.location.hash.replace('#', '') || 'dashboard';
    const parts = hash.split('/');
    return { view: parts[0], id: parts[1] || null };
  }

  function navigate(hash) {
    window.location.hash = hash;
  }

  function handleRoute() {
    if (!auth.isAuthenticated()) {
      showLoginOverlay();
      return;
    }
    hideLoginOverlay();

    const route = getRoute();
    const contentEl = document.getElementById('content-area');
    if (!contentEl) return;

    // Stop scan polling when navigating away from scans view
    if (typeof window.cleanupScanPolling === 'function') window.cleanupScanPolling();

    updateActiveNav(route.view);

    // Handle scan detail as a sub-route
    if (route.view === 'scan' && route.id) {
      updateTopBar('Scan Detail', 'Home / Scans / Scan Detail');
      contentEl.innerHTML = '<div class="loading-overlay"><div class="spinner lg"></div><span>Loading scan details...</span></div>';
      if (typeof window.renderScanDetail === 'function') {
        window.renderScanDetail(contentEl, route.id);
      }
      return;
    }

    const config = routes[route.view];
    if (!config) {
      navigate('dashboard');
      return;
    }

    updateTopBar(config.title, config.breadcrumb);

    // Show loading state
    contentEl.innerHTML = '<div class="loading-overlay"><div class="spinner lg"></div><span>Loading...</span></div>';

    // Render the appropriate view
    switch (route.view) {
      case 'dashboard':
        if (typeof window.renderDashboard === 'function') window.renderDashboard(contentEl);
        break;
      case 'clients':
        if (typeof window.renderClients === 'function') window.renderClients(contentEl);
        break;
      case 'scans':
        if (typeof window.renderScans === 'function') window.renderScans(contentEl);
        break;
      case 'reports':
        if (typeof window.renderReports === 'function') window.renderReports(contentEl);
        break;
      case 'help':
        if (typeof window.renderHelp === 'function') window.renderHelp(contentEl);
        break;
      default:
        contentEl.innerHTML = '<div class="empty-state"><h3>Page not found</h3></div>';
    }
  }

  /* ---------- UI Helpers ---------- */
  function updateTopBar(title, breadcrumb) {
    const titleEl = document.getElementById('topbar-title');
    const breadcrumbEl = document.getElementById('topbar-breadcrumb');
    if (titleEl) titleEl.textContent = title;
    if (breadcrumbEl) {
      const parts = breadcrumb.split(' / ');
      breadcrumbEl.innerHTML = parts.map((p, i) => {
        if (i < parts.length - 1) {
          return '<a href="#' + p.toLowerCase() + '">' + escapeHtml(p) + '</a><span class="separator">/</span>';
        }
        return '<span>' + escapeHtml(p) + '</span>';
      }).join(' ');
    }
  }

  function updateActiveNav(viewName) {
    document.querySelectorAll('.nav-item').forEach(function (el) {
      el.classList.remove('active');
      if (el.dataset.view === viewName) {
        el.classList.add('active');
      }
    });
  }

  function showLoginOverlay() {
    const overlay = document.getElementById('login-overlay');
    if (overlay) overlay.classList.remove('hidden');
  }

  function hideLoginOverlay() {
    const overlay = document.getElementById('login-overlay');
    if (overlay) overlay.classList.add('hidden');
  }

  /* ---------- Toast Notifications ---------- */
  function showToast(message, type) {
    type = type || 'info';
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = {
      success: '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>',
      error: '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/></svg>',
      warning: '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>',
      info: '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/></svg>',
    };

    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.innerHTML =
      '<span class="toast-icon">' + (icons[type] || icons.info) + '</span>' +
      '<span class="toast-message">' + escapeHtml(message) + '</span>' +
      '<button class="toast-close" aria-label="Dismiss notification">' +
        '<svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>' +
      '</button>';

    container.appendChild(toast);

    // Trigger show animation
    requestAnimationFrame(function () {
      toast.classList.add('show');
    });

    const dismiss = function () {
      toast.classList.remove('show');
      setTimeout(function () { toast.remove(); }, 300);
    };

    toast.querySelector('.toast-close').addEventListener('click', dismiss);
    setTimeout(dismiss, 5000);
  }

  /* ---------- Modal Helpers ---------- */
  function openModal(id) {
    const el = document.getElementById(id);
    if (el) {
      el.classList.add('open');
      el.setAttribute('aria-hidden', 'false');
    }
  }

  function closeModal(id) {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove('open');
      el.setAttribute('aria-hidden', 'true');
    }
  }

  function closeAllModals() {
    document.querySelectorAll('.modal-overlay.open').forEach(function (el) {
      el.classList.remove('open');
      el.setAttribute('aria-hidden', 'true');
    });
  }

  /* ---------- Table Sorting ---------- */
  function makeSortable(tableEl) {
    const headers = tableEl.querySelectorAll('th[data-sort]');
    headers.forEach(function (th) {
      th.addEventListener('click', function () {
        const key = th.dataset.sort;
        const tbody = tableEl.querySelector('tbody');
        if (!tbody) return;

        const rows = Array.from(tbody.querySelectorAll('tr'));
        const isAsc = th.classList.contains('sorted-asc');

        // Clear all sort indicators
        headers.forEach(function (h) {
          h.classList.remove('sorted-asc', 'sorted-desc');
          const icon = h.querySelector('.sort-icon');
          if (icon) icon.textContent = '\u2195';
        });

        const dir = isAsc ? -1 : 1;
        th.classList.add(isAsc ? 'sorted-desc' : 'sorted-asc');
        const icon = th.querySelector('.sort-icon');
        if (icon) icon.textContent = isAsc ? '\u2193' : '\u2191';

        const colIndex = Array.from(th.parentNode.children).indexOf(th);
        rows.sort(function (a, b) {
          const aVal = a.children[colIndex] ? a.children[colIndex].textContent.trim() : '';
          const bVal = b.children[colIndex] ? b.children[colIndex].textContent.trim() : '';
          const aNum = parseFloat(aVal.replace(/[^0-9.-]/g, ''));
          const bNum = parseFloat(bVal.replace(/[^0-9.-]/g, ''));
          if (!isNaN(aNum) && !isNaN(bNum)) return (aNum - bNum) * dir;
          return aVal.localeCompare(bVal) * dir;
        });

        rows.forEach(function (row) { tbody.appendChild(row); });
      });
    });
  }

  /* ---------- Formatting Utilities ---------- */
  function formatDate(dateString) {
    if (!dateString) return '--';
    try {
      const d = new Date(dateString);
      if (isNaN(d.getTime())) return dateString;
      const opts = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' };
      return d.toLocaleDateString('en-US', opts);
    } catch {
      return dateString;
    }
  }

  function formatDateShort(dateString) {
    if (!dateString) return '--';
    try {
      const d = new Date(dateString);
      if (isNaN(d.getTime())) return dateString;
      return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' });
    } catch {
      return dateString;
    }
  }

  function formatDuration(seconds) {
    if (!seconds && seconds !== 0) return '--';
    if (seconds < 60) return seconds + 's';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return m + 'm ' + s + 's';
  }

  function formatPercent(value) {
    if (value === null || value === undefined) return '--';
    return Math.round(value * 10) / 10 + '%';
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function truncate(str, len) {
    if (!str) return '';
    len = len || 80;
    return str.length > len ? str.substring(0, len) + '...' : str;
  }

  /* ---------- Badge Helpers ---------- */
  function statusBadge(status) {
    const map = {
      met: '<span class="badge badge-met">Met</span>',
      'not-met': '<span class="badge badge-not-met">Not Met</span>',
      'not_met': '<span class="badge badge-not-met">Not Met</span>',
      manual: '<span class="badge badge-manual">Manual Review</span>',
      manual_review: '<span class="badge badge-manual">Manual Review</span>',
      error: '<span class="badge badge-error">Error</span>',
      pending: '<span class="badge badge-pending">Pending</span>',
      running: '<span class="badge badge-running">Running</span>',
      completed: '<span class="badge badge-completed">Completed</span>',
      passed: '<span class="badge badge-met">Passed</span>',
      failed: '<span class="badge badge-failed">Failed</span>',
    };
    const key = (status || '').toLowerCase().replace(/[\s]/g, '_');
    return map[key] || '<span class="badge badge-error">' + escapeHtml(status) + '</span>';
  }

  function levelBadge(level) {
    const l = (level || '').toUpperCase();
    if (l === 'L1' || l === 'LEVEL 1') return '<span class="badge badge-l1">L1</span>';
    if (l === 'L2' || l === 'LEVEL 2') return '<span class="badge badge-l2">L2</span>';
    if (l === 'L3' || l === 'LEVEL 3') return '<span class="badge badge-l3">L3</span>';
    return '<span class="badge badge-error">' + escapeHtml(l) + '</span>';
  }

  function envDisplay(env) {
    const map = {
      'aws_govcloud': { label: 'AWS GovCloud', cls: 'aws' },
      'aws_commercial': { label: 'AWS Commercial', cls: 'aws' },
      'azure_government': { label: 'Azure Government', cls: 'azure' },
      'azure_commercial': { label: 'Azure Commercial', cls: 'azure' },
      'gcp_assured_workloads': { label: 'GCP Assured', cls: 'gcp' },
      'gcp_commercial': { label: 'GCP Commercial', cls: 'gcp' },
    };
    const info = map[(env || '').toLowerCase()] || { label: env || '--', cls: '' };
    return '<span class="cloud-icon ' + info.cls + '"><span class="icon-dot"></span>' + escapeHtml(info.label) + '</span>';
  }

  function severityClass(severity) {
    const s = (severity || '').toLowerCase();
    if (s === 'critical') return 'severity-critical';
    if (s === 'high') return 'severity-high';
    if (s === 'medium') return 'severity-medium';
    if (s === 'low') return 'severity-low';
    return '';
  }

  /* ---------- Compliance Color ---------- */
  function complianceColor(pct) {
    if (pct >= 80) return 'var(--color-met)';
    if (pct >= 60) return 'var(--color-manual)';
    return 'var(--color-not-met)';
  }

  function complianceBarClass(pct) {
    if (pct >= 80) return 'green';
    if (pct >= 60) return 'amber';
    return 'red';
  }

  /* ---------- Skeleton Loaders ---------- */
  function skeletonCards(count) {
    let html = '<div class="stats-grid">';
    for (let i = 0; i < count; i++) {
      html += '<div class="skeleton skeleton-card"></div>';
    }
    html += '</div>';
    return html;
  }

  function skeletonTable(rows) {
    let html = '';
    for (let i = 0; i < rows; i++) {
      html += '<div class="skeleton skeleton-table-row"></div>';
    }
    return html;
  }

  /* ---------- Login Form (dual mode) ---------- */
  function initLoginForm() {
    // SSO button handler
    var ssoBtn = document.getElementById('sso-login-btn');
    if (ssoBtn) {
      ssoBtn.addEventListener('click', function () {
        ssoBtn.disabled = true;
        ssoBtn.innerHTML = '<span class="spinner sm"></span> Redirecting...';
        auth.loginSSO();
      });
    }

    // Password form handler
    var form = document.getElementById('login-form');
    if (form) {
      form.addEventListener('submit', async function (e) {
        e.preventDefault();
        var btn = form.querySelector('button[type="submit"]');
        var errorEl = document.getElementById('login-error');
        var username = form.querySelector('#login-username').value.trim();
        var password = form.querySelector('#login-password').value;

        if (!username || !password) {
          errorEl.textContent = 'Please enter both username and password.';
          errorEl.classList.add('show');
          return;
        }

        btn.disabled = true;
        btn.innerHTML = '<span class="spinner sm"></span> Signing in...';
        errorEl.classList.remove('show');

        try {
          var success = await auth.loginPassword(username, password);
          if (success) {
            hideLoginOverlay();
            updateUserMenu();
            handleRoute();
            showToast('Welcome back, ' + auth.getUser().name, 'success');
          } else {
            errorEl.textContent = 'Invalid credentials. Please try again.';
            errorEl.classList.add('show');
          }
        } catch (err) {
          errorEl.textContent = err.message || 'Login failed. Please try again.';
          errorEl.classList.add('show');
        } finally {
          btn.disabled = false;
          btn.innerHTML = 'Sign In';
        }
      });
    }

    // Fetch auth config from backend and show the right section
    detectAuthMode();
  }

  async function detectAuthMode() {
    var loadingEl = document.getElementById('login-loading-section');
    var passwordEl = document.getElementById('login-password-section');
    var ssoEl = document.getElementById('login-sso-section');
    var dividerEl = document.getElementById('login-divider');

    try {
      var data = await api.get('/auth/config');
      authMode = (data && data.mode) || 'password';
    } catch {
      // If config endpoint fails, default to password
      authMode = 'password';
    }

    var showSso = authMode === 'sso';
    if (loadingEl) loadingEl.style.display = 'none';
    if (ssoEl) ssoEl.style.display = showSso ? 'block' : 'none';
    if (dividerEl) dividerEl.style.display = showSso ? 'block' : 'none';
    if (passwordEl) passwordEl.style.display = 'block';
  }

  /* ---------- User Menu ---------- */
  function updateUserMenu() {
    const user = auth.getUser();
    const nameEl = document.getElementById('user-menu-name');
    const roleEl = document.getElementById('user-menu-role');
    const avatarEl = document.getElementById('user-avatar');
    if (nameEl) nameEl.textContent = user.name || 'User';
    if (roleEl) roleEl.textContent = user.role || 'Assessor';
    if (avatarEl) {
      const initials = (user.name || 'SB').split(' ').map(function (w) { return w[0]; }).join('').toUpperCase().substring(0, 2);
      avatarEl.textContent = initials;
    }
  }

  function initUserMenu() {
    const toggle = document.getElementById('user-menu-toggle');
    const dropdown = document.getElementById('user-dropdown');
    if (!toggle || !dropdown) return;

    // Only toggle dropdown when clicking the toggle area, not the dropdown items
    toggle.addEventListener('click', function (e) {
      e.stopPropagation();
      // Ignore clicks on dropdown items - they have their own handlers
      if (e.target.closest('.user-dropdown')) return;
      dropdown.classList.toggle('open');
    });

    document.addEventListener('click', function () {
      dropdown.classList.remove('open');
    });

    // Prevent dropdown item clicks from bubbling to the toggle handler
    dropdown.addEventListener('click', function (e) {
      e.stopPropagation();
    });

    var profileBtn = document.getElementById('profile-btn');
    if (profileBtn) {
      profileBtn.addEventListener('click', function () {
        var user = auth.getUser();
        var avatarEl = document.getElementById('profile-avatar-lg');
        var nameEl = document.getElementById('profile-name');
        var usernameEl = document.getElementById('profile-username');
        var emailEl = document.getElementById('profile-email');
        var roleEl = document.getElementById('profile-role');
        var authEl = document.getElementById('profile-auth');
        var sessionEl = document.getElementById('profile-session');

        var initials = (user.name || 'SB').split(' ').map(function (w) { return w[0]; }).join('').toUpperCase().substring(0, 2);
        if (avatarEl) avatarEl.textContent = initials;
        if (nameEl) nameEl.textContent = user.name || '--';
        if (usernameEl) usernameEl.textContent = user.username || user.name || '--';

        // Email row - hide if no email
        var emailRow = emailEl ? emailEl.closest('.profile-row') : null;
        if (emailRow) {
          if (user.email) {
            emailEl.textContent = user.email;
            emailRow.style.display = '';
          } else {
            emailRow.style.display = 'none';
          }
        }

        if (roleEl) {
          var roleLabel = (user.role || 'assessor').charAt(0).toUpperCase() + (user.role || 'assessor').slice(1);
          roleEl.textContent = roleLabel;
        }

        // Auth method - dynamic based on JWT claim
        if (authEl) {
          if (user.auth_method === 'sso') {
            authEl.innerHTML = '<span class="profile-auth-badge sso"><svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg> Microsoft Entra ID</span>';
          } else {
            authEl.innerHTML = '<span class="profile-auth-badge local"><svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 8a6 6 0 01-7.743 5.743L10 14l-1 1-1 1H6v2H2v-4l4.257-4.257A6 6 0 1118 8zm-6-4a1 1 0 100 2 2 2 0 012 2 1 1 0 102 0 4 4 0 00-4-4z" clip-rule="evenodd"/></svg> Local Password</span>';
          }
        }

        // Session expiry
        if (sessionEl && user.exp) {
          var expDate = new Date(user.exp * 1000);
          var now = new Date();
          var remaining = expDate - now;
          if (remaining > 0) {
            var hours = Math.floor(remaining / 3600000);
            var mins = Math.floor((remaining % 3600000) / 60000);
            sessionEl.textContent = hours + 'h ' + mins + 'm remaining';
          } else {
            sessionEl.textContent = 'Expired';
          }
        } else if (sessionEl) {
          sessionEl.textContent = '--';
        }

        dropdown.classList.remove('open');
        openModal('profile-modal');
      });
    }

    var settingsBtn = document.getElementById('settings-btn');
    if (settingsBtn) {
      settingsBtn.addEventListener('click', function () {
        dropdown.classList.remove('open');
        showToast('Settings will be available in a future release.', 'info');
      });
    }

    var logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', function () {
        auth.logout();
      });
    }
  }

  /* ---------- Notifications ---------- */
  function timeAgo(iso) {
    if (!iso) return '';
    var s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    if (s < 172800) return 'Yesterday';
    return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  function renderNotificationItem(n) {
    var cls = n.status === 'completed' ? 'completed' : 'failed';
    var icon = n.status === 'completed'
      ? '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>'
      : '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/></svg>';

    var envMap = {
      'aws_govcloud': 'AWS GovCloud', 'aws_commercial': 'AWS',
      'azure_government': 'Azure Gov', 'azure_commercial': 'Azure',
      'gcp_assured_workloads': 'GCP Assured', 'gcp_commercial': 'GCP',
    };
    var env = envMap[(n.environment || '').toLowerCase()] || n.environment || '';
    var row2 = '';
    if (n.status === 'completed') {
      row2 = escapeHtml(env) + ' &middot; ' + escapeHtml(n.cmmc_level || '') +
        ' &middot; <span class="ndi-pct">' + (n.compliance_pct != null ? n.compliance_pct + '%' : '--') + '</span>';
    } else {
      row2 = '<span class="ndi-pct">' + escapeHtml(n.error_message || 'Scan failed') + '</span>';
    }

    return '<div class="notification-dropdown-item ' + cls + '" data-scan-id="' + escapeHtml(n.scan_id) + '">' +
      '<div class="ndi-icon">' + icon + '</div>' +
      '<div class="ndi-body">' +
        '<div class="ndi-row1"><span class="ndi-client">' + escapeHtml(n.client_name) + '</span>' +
          '<span class="ndi-time">' + timeAgo(n.completed_at) + '</span></div>' +
        '<div class="ndi-row2">' + row2 + '</div>' +
      '</div>' +
    '</div>';
  }

  function updateNotificationDot(items) {
    var dot = document.getElementById('notification-dot');
    if (!dot) return;
    var lastSeen = localStorage.getItem('cmmc_notification_last_seen') || '';
    if (items.length > 0 && items[0].completed_at && items[0].completed_at > lastSeen) {
      dot.classList.remove('hidden');
    } else {
      dot.classList.add('hidden');
    }
  }

  async function fetchNotifications() {
    var listEl = document.getElementById('notification-list');
    if (!listEl) return;
    listEl.innerHTML = '<div class="notification-dropdown-empty"><span class="spinner sm"></span></div>';

    try {
      var data = await api.get('/reports/notifications');
      var items = (data && data.notifications) || [];
      if (items.length === 0) {
        listEl.innerHTML = '<div class="notification-dropdown-empty">No recent scan activity</div>';
      } else {
        listEl.innerHTML = items.map(renderNotificationItem).join('');
        listEl.querySelectorAll('.notification-dropdown-item').forEach(function (el) {
          el.addEventListener('click', function () {
            var id = el.dataset.scanId;
            if (id) {
              document.getElementById('notification-panel').style.display = 'none';
              navigate('scan/' + id);
            }
          });
        });
      }
      updateNotificationDot(items);
    } catch {
      listEl.innerHTML = '<div class="notification-dropdown-empty">Failed to load</div>';
    }
  }

  async function pollNotificationDot() {
    if (!auth.isAuthenticated()) return;
    try {
      var data = await api.get('/reports/notifications');
      var items = (data && data.notifications) || [];
      updateNotificationDot(items);
    } catch {
      // Silently ignore polling errors
    }
  }

  function initNotifications() {
    var bell = document.getElementById('notification-bell');
    var panel = document.getElementById('notification-panel');
    if (!bell || !panel) return;

    bell.addEventListener('click', function (e) {
      e.stopPropagation();
      var isOpen = panel.style.display !== 'none';
      if (isOpen) {
        panel.style.display = 'none';
      } else {
        panel.style.display = 'block';
        fetchNotifications();
        localStorage.setItem('cmmc_notification_last_seen', new Date().toISOString());
        var dot = document.getElementById('notification-dot');
        if (dot) dot.classList.add('hidden');
      }
    });

    document.addEventListener('click', function () {
      panel.style.display = 'none';
    });

    panel.addEventListener('click', function (e) {
      e.stopPropagation();
    });

    // Check for new notifications on load (after a short delay) and every 60s
    setTimeout(pollNotificationDot, 2000);
    setInterval(pollNotificationDot, 60000);
  }

  /* ---------- Navigation ---------- */
  function initNav() {
    document.querySelectorAll('.nav-item').forEach(function (el) {
      el.addEventListener('click', function (e) {
        e.preventDefault();
        const view = el.dataset.view;
        if (view) navigate(view);
      });
    });
  }

  /* ---------- Initialize Application ---------- */
  function init() {
    // Handle SSO callback before anything else
    var ssoHandled = handleSSOCallback();

    initNav();
    initLoginForm();
    initUserMenu();
    initNotifications();
    updateUserMenu();

    // Listen for hash changes
    window.addEventListener('hashchange', handleRoute);

    // Handle the initial route
    if (auth.isAuthenticated()) {
      hideLoginOverlay();
      handleRoute();
      if (ssoHandled) {
        showToast('Welcome, ' + auth.getUser().name, 'success');
      }
    } else {
      showLoginOverlay();
    }
  }

  // Run init when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  /* ---------- Export to window scope ---------- */
  window.app = {
    api: api,
    auth: auth,
    navigate: navigate,
    showToast: showToast,
    openModal: openModal,
    closeModal: closeModal,
    closeAllModals: closeAllModals,
    makeSortable: makeSortable,
    formatDate: formatDate,
    formatDateShort: formatDateShort,
    formatDuration: formatDuration,
    formatPercent: formatPercent,
    escapeHtml: escapeHtml,
    truncate: truncate,
    statusBadge: statusBadge,
    levelBadge: levelBadge,
    envDisplay: envDisplay,
    severityClass: severityClass,
    complianceColor: complianceColor,
    complianceBarClass: complianceBarClass,
    skeletonCards: skeletonCards,
    skeletonTable: skeletonTable,
    CONFIG: CONFIG,
    handleRoute: handleRoute,
  };

})();
