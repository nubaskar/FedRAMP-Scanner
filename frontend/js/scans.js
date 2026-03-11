/* ==========================================================================
   FedRAMP Cloud Compliance Scanner - Scans View & Scan Detail
   ========================================================================== */

(function () {
  'use strict';

  var pollTimer = null;
  var allScans = [];
  var scanClientList = [];
  var scanContainer = null;
  var scanSearchQuery = '';
  var scanEnvFilter = '';
  var scanStatusFilter = '';
  var scanLevelFilter = '';

  var ENVIRONMENTS = [
    { value: 'aws_govcloud', label: 'AWS GovCloud' },
    { value: 'aws_commercial', label: 'AWS Commercial' },
    { value: 'azure_government', label: 'Azure Government' },
    { value: 'azure_commercial', label: 'Azure Commercial' },
    { value: 'gcp_assured_workloads', label: 'GCP Assured Workloads' },
    { value: 'gcp_commercial', label: 'GCP Commercial' },
  ];

  var FEDRAMP_FAMILIES = [
    { code: 'AC', name: 'Access Control' },
    { code: 'AT', name: 'Awareness & Training' },
    { code: 'AU', name: 'Audit & Accountability' },
    { code: 'CA', name: 'Assessment, Authorization & Monitoring' },
    { code: 'CM', name: 'Configuration Management' },
    { code: 'CP', name: 'Contingency Planning' },
    { code: 'IA', name: 'Identification & Authentication' },
    { code: 'IR', name: 'Incident Response' },
    { code: 'MA', name: 'Maintenance' },
    { code: 'MP', name: 'Media Protection' },
    { code: 'PE', name: 'Physical & Environmental Protection' },
    { code: 'PL', name: 'Planning' },
    { code: 'PM', name: 'Program Management' },
    { code: 'PS', name: 'Personnel Security' },
    { code: 'PT', name: 'PII Processing & Transparency' },
    { code: 'RA', name: 'Risk Assessment' },
    { code: 'SA', name: 'System & Services Acquisition' },
    { code: 'SC', name: 'System & Communications Protection' },
    { code: 'SI', name: 'System & Information Integrity' },
    { code: 'SR', name: 'Supply Chain Risk Management' },
  ];

  /* ================================================================
     Scan List View
     ================================================================ */
  async function renderScans(container) {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    scanContainer = container;

    container.innerHTML = app.skeletonTable(8);

    var scans, clients;
    try {
      var results = await Promise.all([
        app.api.get('/scans?sort=-created_at'),
        app.api.get('/clients'),
      ]);
      scans = results[0];
      clients = results[1];
    } catch (err) {
      scans = [];
      clients = { clients: [], total: 0 };
    }

    var rawItems = scans.items || scans || [];
    var clientList = clients.clients || clients || [];
    scanClientList = clientList;

    // Build client name lookup
    var clientMap = {};
    clientList.forEach(function (c) { clientMap[c.id] = c.name; });

    // Enrich scan items with computed fields for display
    var items = rawItems.map(function (s) {
      var summary = s.summary || {};
      var totalChecks = (summary.met || 0) + (summary.not_met || 0) + (summary.manual || 0);
      return {
        id: s.id,
        client_id: s.client_id,
        client_name: clientMap[s.client_id] || 'Unknown',
        environment: s.environment,
        level: s.fedramp_baseline || s.level,
        status: s.status,
        created_at: s.started_at || s.created_at,
        duration: s.completed_at && s.started_at ? Math.round((new Date(s.completed_at) - new Date(s.started_at)) / 1000) : null,
        met: summary.met != null ? summary.met : null,
        not_met: summary.not_met != null ? summary.not_met : null,
        manual: summary.manual != null ? summary.manual : null,
        compliance_pct: totalChecks > 0 ? Math.round(((summary.met || 0) / totalChecks) * 1000) / 10 : null,
      };
    });
    allScans = items;

    container.innerHTML = buildScanListHeader(clientList) + buildScanSearchBar() +
      '<div id="scans-table-wrap">' + buildScanTable(items) + '</div>' +
      buildNewScanModal(clientList);

    var table = container.querySelector('.data-table');
    if (table) app.makeSortable(table);

    initScanListEvents(container);

    // Re-apply filters if they were active before re-render (e.g. poll re-render)
    if (scanSearchQuery || scanEnvFilter || scanStatusFilter || scanLevelFilter) {
      var searchInput = container.querySelector('#scan-search');
      var envSelect = container.querySelector('#scan-filter-env');
      var statusSelect = container.querySelector('#scan-filter-status');
      var levelSelect = container.querySelector('#scan-filter-level');
      if (searchInput) searchInput.value = scanSearchQuery;
      if (envSelect) envSelect.value = scanEnvFilter;
      if (statusSelect) statusSelect.value = scanStatusFilter;
      if (levelSelect) levelSelect.value = scanLevelFilter;
      applyScanFilters();
    }

    // Start polling if any scans are running
    var hasRunning = items.some(function (s) { return s.status === 'running' || s.status === 'pending'; });
    if (hasRunning) {
      pollTimer = setInterval(function () { renderScans(container); }, app.CONFIG.POLL_INTERVAL);
    }
  }

  function buildScanListHeader(clients) {
    return '<div class="flex items-center justify-between mb-lg">' +
      '<div>' +
        '<h2>Compliance Scans</h2>' +
        '<p class="text-secondary text-small mt-sm">Run and monitor FedRAMP compliance scans across client environments</p>' +
      '</div>' +
      '<button class="btn btn-primary" id="btn-new-scan" aria-label="Start a new compliance scan">' +
        '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L9 9.414V13a1 1 0 102 0V9.414l1.293 1.293a1 1 0 001.414-1.414z" clip-rule="evenodd"/></svg>' +
        ' New Scan' +
      '</button>' +
    '</div>';
  }

  function buildScanSearchBar() {
    if (allScans.length === 0) return '';

    var envOptions = '<option value="">Environment</option>';
    ENVIRONMENTS.forEach(function (e) {
      envOptions += '<option value="' + e.value + '">' + e.label + '</option>';
    });

    return '<div class="search-filter-bar">' +
      '<div class="search-input-wrap">' +
        '<svg class="search-input-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/></svg>' +
        '<input type="text" class="search-input" id="scan-search" placeholder="Search by client name..." aria-label="Search scans by client name" />' +
        '<button class="search-clear-btn hidden" id="scan-search-clear" aria-label="Clear search" type="button">&times;</button>' +
      '</div>' +
      '<div class="filter-pills">' +
        '<select class="filter-pill" id="scan-filter-env" aria-label="Filter by environment">' + envOptions + '</select>' +
        '<select class="filter-pill" id="scan-filter-status" aria-label="Filter by status">' +
          '<option value="">Status</option>' +
          '<option value="pending">Pending</option>' +
          '<option value="running">Running</option>' +
          '<option value="completed">Completed</option>' +
          '<option value="failed">Failed</option>' +
        '</select>' +
        '<select class="filter-pill" id="scan-filter-level" aria-label="Filter by FedRAMP baseline">' +
          '<option value="">Baseline</option>' +
          '<option value="Low">Low</option>' +
          '<option value="Moderate">Moderate</option>' +
          '<option value="High">High</option>' +
        '</select>' +
      '</div>' +
      '<span class="search-result-count" id="scan-result-count"></span>' +
    '</div>';
  }

  function buildScanTable(items) {
    if (items.length === 0 && allScans.length > 0) {
      return '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>' +
        '<h3>No matching scans</h3>' +
        '<p>Try adjusting your search or filter criteria.</p>' +
      '</div></div>';
    }

    if (items.length === 0) {
      return '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' +
        '<h3>No scans yet</h3>' +
        '<p>Run your first compliance scan to evaluate a client environment against FedRAMP requirements.</p>' +
        '<button class="btn btn-primary" id="btn-new-scan-empty" aria-label="Start first scan">Start Your First Scan</button>' +
      '</div></div>';
    }

    var rows = '';
    items.forEach(function (s) {
      var metDisplay = s.met !== null && s.met !== undefined ? s.met : '--';
      var notMetDisplay = s.not_met !== null && s.not_met !== undefined ? s.not_met : '--';
      var manualDisplay = s.manual !== null && s.manual !== undefined ? s.manual : '--';
      var durDisplay = app.formatDuration(s.duration);

      rows +=
        '<tr class="clickable" onclick="app.navigate(\'scan/' + app.escapeHtml(s.id) + '\')" role="link" tabindex="0" aria-label="View scan details for ' + app.escapeHtml(s.client_name) + '">' +
          '<td><strong>' + app.escapeHtml(s.client_name) + '</strong></td>' +
          '<td>' + app.envDisplay(s.environment) + '</td>' +
          '<td>' + app.levelBadge(s.level) + '</td>' +
          '<td>' + app.statusBadge(s.status) + '</td>' +
          '<td>' + app.formatDate(s.created_at) + '</td>' +
          '<td>' + durDisplay + '</td>' +
          '<td class="text-center"><span class="text-met font-bold">' + metDisplay + '</span></td>' +
          '<td class="text-center"><span class="text-not-met font-bold">' + notMetDisplay + '</span></td>' +
          '<td class="text-center"><span class="text-manual font-bold">' + manualDisplay + '</span></td>' +
        '</tr>';
    });

    return '<div class="card">' +
      '<div class="table-container">' +
        '<table class="data-table" aria-label="Compliance scans list">' +
          '<thead><tr>' +
            '<th data-sort="client">Client <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="env">Environment <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="level">Level <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="status">Status <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="started">Started <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="duration">Duration <span class="sort-icon">\u2195</span></th>' +
            '<th class="text-center" data-sort="met">Met <span class="sort-icon">\u2195</span></th>' +
            '<th class="text-center" data-sort="not-met">Not Met <span class="sort-icon">\u2195</span></th>' +
            '<th class="text-center" data-sort="manual">Manual <span class="sort-icon">\u2195</span></th>' +
          '</tr></thead>' +
          '<tbody>' + rows + '</tbody>' +
        '</table>' +
      '</div>' +
    '</div>';
  }

  function applyScanFilters() {
    var searchInput = document.getElementById('scan-search');
    var envSelect = document.getElementById('scan-filter-env');
    var statusSelect = document.getElementById('scan-filter-status');
    var levelSelect = document.getElementById('scan-filter-level');
    var clearBtn = document.getElementById('scan-search-clear');
    var countEl = document.getElementById('scan-result-count');

    var query = searchInput ? searchInput.value.trim().toLowerCase() : '';
    var envVal = envSelect ? envSelect.value : '';
    var statusVal = statusSelect ? statusSelect.value : '';
    var levelVal = levelSelect ? levelSelect.value : '';

    // Save state for re-render preservation (poll re-renders)
    scanSearchQuery = query;
    scanEnvFilter = envVal;
    scanStatusFilter = statusVal;
    scanLevelFilter = levelVal;

    // Toggle clear button visibility
    if (clearBtn) clearBtn.classList.toggle('hidden', !query);

    // Toggle active class on pills
    if (envSelect) envSelect.classList.toggle('active', !!envVal);
    if (statusSelect) statusSelect.classList.toggle('active', !!statusVal);
    if (levelSelect) levelSelect.classList.toggle('active', !!levelVal);

    // Filter
    var filtered = allScans.filter(function (s) {
      if (query && (s.client_name || '').toLowerCase().indexOf(query) === -1) return false;
      if (envVal && s.environment !== envVal) return false;
      if (statusVal && s.status !== statusVal) return false;
      if (levelVal && s.level !== levelVal) return false;
      return true;
    });

    // Re-render table wrap
    var wrap = document.getElementById('scans-table-wrap');
    if (wrap) {
      wrap.innerHTML = buildScanTable(filtered);
      var table = wrap.querySelector('.data-table');
      if (table) app.makeSortable(table);
    }

    // Update result count
    var isFiltered = query || envVal || statusVal || levelVal;
    if (countEl) {
      countEl.textContent = isFiltered ? filtered.length + ' of ' + allScans.length + ' scans' : '';
    }
  }

  function buildNewScanModal(clientList) {
    var clientOpts = '<option value="">Select a client...</option>';
    clientList.forEach(function (c) {
      clientOpts += '<option value="' + app.escapeHtml(c.id) + '">' + app.escapeHtml(c.name) + '</option>';
    });

    return '<div class="modal-overlay" id="new-scan-modal" aria-hidden="true" role="dialog" aria-labelledby="new-scan-modal-title">' +
      '<div class="modal">' +
        '<div class="modal-header">' +
          '<h3 id="new-scan-modal-title">Start New Scan</h3>' +
          '<button class="modal-close" id="new-scan-modal-close" aria-label="Close dialog">' +
            '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>' +
          '</button>' +
        '</div>' +
        '<div class="modal-body">' +
          '<div class="form-group">' +
            '<label class="form-label" for="scan-client">Client <span class="required">*</span></label>' +
            '<select class="form-select" id="scan-client" required aria-required="true">' + clientOpts + '</select>' +
          '</div>' +
          '<div id="scan-client-info" class="hidden" style="background:var(--color-bg);border-radius:var(--radius-md);padding:var(--spacing-md);margin-bottom:var(--spacing-md)">' +
            '<div class="flex items-center justify-between">' +
              '<span class="text-small font-bold">Environment</span>' +
              '<span id="scan-client-env" class="text-small"></span>' +
            '</div>' +
            '<div class="flex items-center justify-between mt-sm">' +
              '<span class="text-small font-bold">FedRAMP Baseline</span>' +
              '<span id="scan-client-level" class="text-small"></span>' +
            '</div>' +
          '</div>' +
          '<div class="form-hint" style="margin-top:8px">' +
            'The scan will evaluate all FedRAMP controls for the selected client\'s environment and level. This typically takes 3-8 minutes.' +
          '</div>' +
        '</div>' +
        '<div class="modal-footer">' +
          '<button class="btn btn-outline" id="btn-cancel-scan" type="button">Cancel</button>' +
          '<button class="btn btn-primary" id="btn-start-scan" type="button">Start Scan</button>' +
        '</div>' +
      '</div>' +
    '</div>' +

    /* Scan Progress Overlay */
    '<div class="modal-overlay" id="scan-progress-modal" aria-hidden="true" role="dialog" aria-labelledby="scan-progress-title">' +
      '<div class="modal">' +
        '<div class="modal-header">' +
          '<h3 id="scan-progress-title">Scan In Progress</h3>' +
        '</div>' +
        '<div class="modal-body text-center">' +
          '<div class="spinner lg" style="margin:0 auto var(--spacing-lg)"></div>' +
          '<p id="scan-progress-text" class="font-bold">Initializing scan...</p>' +
          '<p class="text-muted text-small mt-sm">This may take several minutes. You can close this dialog and check progress later.</p>' +
          '<div class="progress-bar lg mt-lg">' +
            '<div class="progress-bar-fill blue" id="scan-progress-bar" style="width:0%"></div>' +
          '</div>' +
          '<p class="text-xs text-muted mt-sm" id="scan-progress-pct">0%</p>' +
        '</div>' +
        '<div class="modal-footer justify-center">' +
          '<button class="btn btn-outline" id="btn-close-progress" type="button">Run in Background</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  function initScanListEvents(container) {
    var openNewScan = function () { app.openModal('new-scan-modal'); };
    var newScanBtn = container.querySelector('#btn-new-scan');
    if (newScanBtn) newScanBtn.addEventListener('click', openNewScan);

    // Event delegation for "Start Your First Scan" button inside empty state
    container.addEventListener('click', function (e) {
      var emptyBtn = e.target.closest('#btn-new-scan-empty');
      if (emptyBtn) {
        openNewScan();
      }
    });

    var closeNewScan = function () { app.closeModal('new-scan-modal'); };
    var closeBtn = container.querySelector('#new-scan-modal-close');
    var cancelBtn = container.querySelector('#btn-cancel-scan');
    if (closeBtn) closeBtn.addEventListener('click', closeNewScan);
    if (cancelBtn) cancelBtn.addEventListener('click', closeNewScan);

    // Client selection info
    var clientSelect = container.querySelector('#scan-client');
    if (clientSelect) {
      clientSelect.addEventListener('change', async function () {
        var infoDiv = container.querySelector('#scan-client-info');
        var envSpan = container.querySelector('#scan-client-env');
        var levelSpan = container.querySelector('#scan-client-level');
        if (!clientSelect.value) {
          if (infoDiv) infoDiv.classList.add('hidden');
          return;
        }
        try {
          var client = await app.api.get('/clients/' + clientSelect.value);
          if (envSpan) envSpan.innerHTML = app.envDisplay(client.environment);
          if (levelSpan) levelSpan.innerHTML = app.levelBadge(client.fedramp_baseline);
          if (infoDiv) infoDiv.classList.remove('hidden');
        } catch (err) {
          if (infoDiv) infoDiv.classList.add('hidden');
        }
      });
    }

    // Start Scan
    var startBtn = container.querySelector('#btn-start-scan');
    if (startBtn) {
      startBtn.addEventListener('click', async function () {
        var clientId = clientSelect ? clientSelect.value : '';
        if (!clientId) {
          app.showToast('Please select a client.', 'warning');
          return;
        }
        startBtn.disabled = true;
        startBtn.innerHTML = '<span class="spinner sm"></span> Starting...';

        try {
          var scan = await app.api.post('/scans', { client_id: clientId });
          app.closeModal('new-scan-modal');
          app.showToast('Scan started successfully.', 'success');

          // Show progress modal
          app.openModal('scan-progress-modal');
          pollScanProgress(scan.id || scan.scan_id, container);
        } catch (err) {
          app.showToast('Failed to start scan: ' + (err.message || 'Unknown error'), 'error');
        } finally {
          startBtn.disabled = false;
          startBtn.innerHTML = 'Start Scan';
        }
      });
    }

    // Close progress
    var closeProgressBtn = container.querySelector('#btn-close-progress');
    if (closeProgressBtn) {
      closeProgressBtn.addEventListener('click', function () {
        app.closeModal('scan-progress-modal');
      });
    }

    // Search & filter events
    var searchInput = container.querySelector('#scan-search');
    var clearBtn = container.querySelector('#scan-search-clear');
    var filterEnv = container.querySelector('#scan-filter-env');
    var filterStatus = container.querySelector('#scan-filter-status');
    var filterLevel = container.querySelector('#scan-filter-level');

    if (searchInput) {
      searchInput.addEventListener('input', applyScanFilters);
    }
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        if (searchInput) searchInput.value = '';
        applyScanFilters();
      });
    }
    if (filterEnv) {
      filterEnv.addEventListener('change', applyScanFilters);
    }
    if (filterStatus) {
      filterStatus.addEventListener('change', applyScanFilters);
    }
    if (filterLevel) {
      filterLevel.addEventListener('change', applyScanFilters);
    }

    // Close modals on overlay click
    container.querySelectorAll('.modal-overlay').forEach(function (overlay) {
      overlay.addEventListener('click', function (e) {
        if (e.target === overlay) {
          overlay.classList.remove('open');
          overlay.setAttribute('aria-hidden', 'true');
        }
      });
    });
  }

  function pollScanProgress(scanId, container) {
    var progressBar = document.getElementById('scan-progress-bar');
    var progressText = document.getElementById('scan-progress-text');
    var progressPct = document.getElementById('scan-progress-pct');
    var step = 0;
    // Stages are shown progressively.  Azure scans can take 8-10 min,
    // so we spread stages across ~120 steps (10 min at 5 s intervals).
    var stages = [
      { at: 1,  text: 'Connecting to cloud environment...' },
      { at: 4,  text: 'Pre-fetching cloud resource data...' },
      { at: 10, text: 'Scanning Access Control (AC)...' },
      { at: 16, text: 'Scanning Identity & Authentication (IA)...' },
      { at: 22, text: 'Scanning Audit & Accountability (AU)...' },
      { at: 28, text: 'Scanning Configuration Management (CM)...' },
      { at: 34, text: 'Scanning System & Communications (SC)...' },
      { at: 40, text: 'Scanning remaining domains...' },
      { at: 48, text: 'Scanning Security Center & Defender...' },
      { at: 56, text: 'Scanning identity and Graph API checks...' },
      { at: 64, text: 'Generating compliance report...' },
      { at: 72, text: 'Finalizing results...' },
    ];
    // Max steps before we give up polling (10 min)
    var maxSteps = 120;

    var interval = setInterval(async function () {
      step++;
      // Progress grows faster: reaches 95% at step ~76 (6.3 min)
      var pct = Math.min(Math.round(step * 1.25), 95);

      if (progressBar) progressBar.style.width = pct + '%';
      if (progressPct) progressPct.textContent = pct + '%';

      // Show the latest stage whose threshold we have passed
      if (progressText) {
        for (var i = stages.length - 1; i >= 0; i--) {
          if (step >= stages[i].at) {
            progressText.textContent = stages[i].text;
            break;
          }
        }
        // After all stages, show elapsed time
        if (step > stages[stages.length - 1].at + 5) {
          var elapsed = Math.round(step * app.CONFIG.POLL_INTERVAL / 1000);
          var mins = Math.floor(elapsed / 60);
          var secs = elapsed % 60;
          progressText.textContent = 'Still running... (' + mins + 'm ' + secs + 's elapsed)';
        }
      }

      try {
        var pollData = await app.api.get('/scans/' + scanId);
        var scanStatus = pollData.scan ? pollData.scan.status : pollData.status;
        if (scanStatus === 'completed' || scanStatus === 'failed') {
          clearInterval(interval);
          if (progressBar) progressBar.style.width = '100%';
          if (progressPct) progressPct.textContent = '100%';
          if (progressText) {
            progressText.textContent = scanStatus === 'completed' ? 'Scan completed!' : 'Scan failed.';
          }
          setTimeout(function () {
            app.closeModal('scan-progress-modal');
            app.navigate('scan/' + scanId);
          }, 1500);
        }
      } catch (err) {
        // Continue polling even on network error
      }

      if (step > maxSteps) {
        clearInterval(interval);
        if (progressText) {
          progressText.textContent = 'Scan is still running in the background. Check back shortly.';
        }
      }
    }, app.CONFIG.POLL_INTERVAL);
  }

  /* ================================================================
     Scan Detail View
     ================================================================ */
  async function renderScanDetail(container, scanId) {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

    var scan;
    try {
      var data = await app.api.get('/scans/' + scanId);
      var scanInfo = data.scan || data;
      var findings = data.findings || [];

      // Fetch client name
      var clientName = 'Unknown Client';
      try {
        var client = await app.api.get('/clients/' + scanInfo.client_id);
        clientName = client.name;
      } catch (e) { /* client may have been deleted */ }

      // Compute compliance_pct from summary
      var summary = scanInfo.summary || {};
      var totalChecks = (summary.met || 0) + (summary.not_met || 0) + (summary.manual || 0);
      var compliancePct = totalChecks > 0 ? Math.round(((summary.met || 0) / totalChecks) * 1000) / 10 : 0;

      // Compute duration in seconds
      var duration = null;
      if (scanInfo.started_at && scanInfo.completed_at) {
        duration = Math.round((new Date(scanInfo.completed_at) - new Date(scanInfo.started_at)) / 1000);
      }

      // Group findings by domain
      var domainMap = {};
      findings.forEach(function (f) {
        if (!domainMap[f.domain]) {
          domainMap[f.domain] = { met: 0, not_met: 0, manual: 0, error: 0, findings: [] };
        }
        var d = domainMap[f.domain];
        if (f.status === 'met') d.met++;
        else if (f.status === 'not_met') d.not_met++;
        else if (f.status === 'manual') d.manual++;
        else d.error++;
        d.findings.push({
          id: f.control_id,
          name: f.check_name,
          status: f.status,
          severity: f.severity,
          evidence: f.evidence || '',
          remediation: f.remediation || '',
        });
      });

      // Sort findings within each domain by control ID format (AC-2 style)
      function controlSort(a, b) {
        return (a.id || '').localeCompare(b.id || '', undefined, { numeric: true });
      }
      Object.keys(domainMap).forEach(function (key) {
        domainMap[key].findings.sort(controlSort);
      });

      var domains = [];
      FEDRAMP_FAMILIES.forEach(function (d) {
        var dd = domainMap[d.code];
        if (dd) {
          domains.push({
            code: d.code,
            name: d.name,
            total: dd.met + dd.not_met + dd.manual + dd.error,
            met: dd.met,
            not_met: dd.not_met,
            manual: dd.manual,
            findings: dd.findings,
          });
        }
      });

      // Ensure summary has total
      if (!summary.total) {
        summary.total = totalChecks;
      }

      // Build flat scan object for render functions
      scan = {
        id: scanInfo.id,
        client_name: clientName,
        environment: scanInfo.environment,
        level: scanInfo.fedramp_baseline,
        status: scanInfo.status,
        created_at: scanInfo.started_at,
        duration: duration,
        compliance_pct: compliancePct,
        summary: summary,
        domains: domains,
      };
    } catch (err) {
      scan = {
        id: scanId,
        client_name: 'Error loading scan',
        environment: '',
        level: '',
        status: 'error',
        created_at: null,
        duration: null,
        compliance_pct: 0,
        summary: { met: 0, not_met: 0, manual: 0, total: 0 },
        domains: [],
      };
    }

    container.innerHTML = buildDetailHeader(scan) +
      buildSummaryCards(scan) +
      '<div class="grid grid-sidebar mt-lg">' +
        buildDonutChart(scan) +
        buildExportSection(scan) +
      '</div>' +
      '<div class="mt-lg">' +
        buildDomainAccordion(scan) +
      '</div>' +
      /* Evidence Modal */
      '<div class="modal-overlay" id="evidence-modal" aria-hidden="true" role="dialog" aria-labelledby="evidence-modal-title">' +
        '<div class="modal modal-lg">' +
          '<div class="modal-header">' +
            '<h3 id="evidence-modal-title">API Evidence</h3>' +
            '<button class="modal-close" id="evidence-modal-close" aria-label="Close dialog">' +
              '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>' +
            '</button>' +
          '</div>' +
          '<div class="modal-body" id="evidence-modal-body"></div>' +
        '</div>' +
      '</div>';

    initDetailEvents(container, scan);
  }

  function generateDemoDomains() {
    var domains = [];
    var controlData = {
      AC: { total: 22, met: 18, not_met: 3, manual: 1, findings: [
        { id: 'AC-2', name: 'Account Management', status: 'met', severity: 'HIGH', evidence: 'IAM policies restrict access via role-based controls. MFA enforced on all console access.', remediation: '' },
        { id: 'AC-3', name: 'Access Enforcement', status: 'met', severity: 'HIGH', evidence: 'Service control policies limit API actions per role.', remediation: '' },
        { id: 'AC-4', name: 'Information Flow Enforcement', status: 'not_met', severity: 'CRITICAL', evidence: 'VPC flow logs show data traversing non-approved paths to commercial region.', remediation: 'Implement VPC endpoint policies and restrict data to GovCloud-only S3 buckets.' },
        { id: 'AC-5', name: 'Separation of Duties', status: 'met', severity: 'MEDIUM', evidence: 'Separate admin and operator roles defined in IAM.', remediation: '' },
        { id: 'AC-6', name: 'Least Privilege', status: 'met', severity: 'HIGH', evidence: 'IAM Access Analyzer confirms no wildcard permissions.', remediation: '' },
        { id: 'AC-7', name: 'Unsuccessful Logon Attempts', status: 'met', severity: 'MEDIUM', evidence: 'Account lockout after 5 failed attempts configured.', remediation: '' },
      ]},
      AT: { total: 3, met: 3, not_met: 0, manual: 0, findings: [
        { id: 'AT-2', name: 'Security Awareness Training', status: 'met', severity: 'MEDIUM', evidence: 'Annual security training records present for all users.', remediation: '' },
        { id: 'AT-3', name: 'Role-Based Security Training', status: 'met', severity: 'MEDIUM', evidence: 'Admin personnel completed security handling training.', remediation: '' },
        { id: 'AT-4', name: 'Security Training Records', status: 'met', severity: 'MEDIUM', evidence: 'Training documentation available.', remediation: '' },
      ]},
      AU: { total: 9, met: 7, not_met: 1, manual: 1, findings: [
        { id: 'AU-2', name: 'Audit Events', status: 'met', severity: 'HIGH', evidence: 'CloudTrail enabled in all regions with 365-day retention in S3.', remediation: '' },
        { id: 'AU-3', name: 'Content of Audit Records', status: 'met', severity: 'HIGH', evidence: 'CloudTrail records include user ARN and source IP.', remediation: '' },
        { id: 'AU-6', name: 'Audit Review, Analysis, and Reporting', status: 'not_met', severity: 'HIGH', evidence: 'Centralized log analysis tooling not deployed. Logs exist but are not correlated.', remediation: 'Deploy SIEM integration with CloudWatch and CloudTrail.' },
      ]},
      CM: { total: 9, met: 6, not_met: 2, manual: 1, findings: [] },
      IA: { total: 11, met: 9, not_met: 1, manual: 1, findings: [] },
      IR: { total: 3, met: 2, not_met: 1, manual: 0, findings: [] },
      MA: { total: 6, met: 5, not_met: 1, manual: 0, findings: [] },
      MP: { total: 9, met: 8, not_met: 0, manual: 1, findings: [] },
      PS: { total: 2, met: 2, not_met: 0, manual: 0, findings: [] },
      PE: { total: 6, met: 6, not_met: 0, manual: 0, findings: [] },
      RA: { total: 3, met: 2, not_met: 1, manual: 0, findings: [] },
      CA: { total: 4, met: 3, not_met: 1, manual: 0, findings: [] },
      SC: { total: 16, met: 12, not_met: 2, manual: 2, findings: [] },
      SI: { total: 7, met: 6, not_met: 1, manual: 0, findings: [] },
    };

    FEDRAMP_FAMILIES.forEach(function (d) {
      var pd = controlData[d.code] || { total: 5, met: 4, not_met: 1, manual: 0, findings: [] };
      domains.push({
        code: d.code,
        name: d.name,
        total: pd.total,
        met: pd.met,
        not_met: pd.not_met,
        manual: pd.manual,
        findings: pd.findings,
      });
    });

    return domains;
  }

  function buildDetailHeader(scan) {
    var summary = scan.summary || {};
    var statusDisplay;
    if (scan.status === 'completed') {
      var pct = scan.compliance_pct || 0;
      statusDisplay = pct >= 80 ? app.statusBadge('passed') : app.statusBadge('failed');
    } else {
      statusDisplay = app.statusBadge(scan.status);
    }

    return '<div class="flex items-center justify-between mb-lg">' +
      '<div>' +
        '<button class="btn btn-ghost btn-sm mb-sm" onclick="app.navigate(\'scans\')" aria-label="Back to scans list">' +
          '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/></svg>' +
          ' Back to Scans' +
        '</button>' +
        '<h2>' + app.escapeHtml(scan.client_name || 'Scan Detail') + '</h2>' +
        '<div class="flex items-center gap-md mt-sm">' +
          app.envDisplay(scan.environment) +
          app.levelBadge(scan.level) +
          statusDisplay +
          '<span class="text-small text-muted">' + app.formatDate(scan.created_at) + '</span>' +
          '<span class="text-small text-muted">Duration: ' + app.formatDuration(scan.duration) + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="flex gap-sm">' +
        '<button class="btn btn-outline btn-sm" id="btn-delete-scan" aria-label="Delete this scan">' +
          '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>' +
          ' Delete Scan' +
        '</button>' +
      '</div>' +
    '</div>';
  }

  function buildSummaryCards(scan) {
    var s = scan.summary || { met: 0, not_met: 0, manual: 0, error: 0, total: 0 };
    var errorCount = s.error || 0;
    var cols = errorCount > 0 ? 5 : 4;
    var html = '<div class="stats-grid" style="grid-template-columns:repeat(' + cols + ',1fr)">' +
      '<div class="stat-card">' +
        '<div class="stat-card-icon green">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value" style="color:var(--color-met)">' + (s.met || 0) + '</div>' +
          '<div class="stat-card-label">Met</div>' +
        '</div>' +
      '</div>' +
      '<div class="stat-card">' +
        '<div class="stat-card-icon red">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value" style="color:var(--color-not-met)">' + (s.not_met || 0) + '</div>' +
          '<div class="stat-card-label">Not Met</div>' +
        '</div>' +
      '</div>' +
      '<div class="stat-card">' +
        '<div class="stat-card-icon" style="background:var(--color-manual-bg);color:#b8860b">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value" style="color:#b8860b">' + (s.manual || 0) + '</div>' +
          '<div class="stat-card-label">Manual Review</div>' +
        '</div>' +
      '</div>';
    if (errorCount > 0) {
      html +=
      '<div class="stat-card">' +
        '<div class="stat-card-icon" style="background:#fef2f2;color:#dc2626">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value" style="color:#dc2626">' + errorCount + '</div>' +
          '<div class="stat-card-label">Error</div>' +
        '</div>' +
      '</div>';
    }
    html +=
      '<div class="stat-card">' +
        '<div class="stat-card-icon navy">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value">' + (s.total || 0) + '</div>' +
          '<div class="stat-card-label">Total Checks</div>' +
        '</div>' +
      '</div>' +
    '</div>';
    return html;
  }

  function buildDonutChart(scan) {
    var s = scan.summary || { met: 0, not_met: 0, manual: 0, total: 0 };
    var total = s.total || 1;
    var pct = scan.compliance_pct || Math.round((s.met / total) * 1000) / 10;
    var circumference = 2 * Math.PI * 60;
    var metArc = (s.met / total) * circumference;
    var notMetArc = (s.not_met / total) * circumference;
    var manualArc = (s.manual / total) * circumference;
    var metOffset = 0;
    var notMetOffset = metArc;
    var manualOffset = metArc + notMetArc;

    return '<div class="card">' +
      '<div class="card-header"><h4>Compliance Overview</h4></div>' +
      '<div class="card-body flex flex-col items-center">' +
        '<div class="donut-chart" role="img" aria-label="Compliance rate ' + pct + ' percent">' +
          '<svg viewBox="0 0 140 140">' +
            '<circle class="donut-bg" cx="70" cy="70" r="60"/>' +
            '<circle class="donut-met" cx="70" cy="70" r="60" stroke-dasharray="' + metArc + ' ' + (circumference - metArc) + '" stroke-dashoffset="0"/>' +
            '<circle class="donut-not-met" cx="70" cy="70" r="60" stroke-dasharray="' + notMetArc + ' ' + (circumference - notMetArc) + '" stroke-dashoffset="-' + notMetOffset + '"/>' +
            '<circle class="donut-manual" cx="70" cy="70" r="60" stroke-dasharray="' + manualArc + ' ' + (circumference - manualArc) + '" stroke-dashoffset="-' + manualOffset + '"/>' +
          '</svg>' +
          '<div class="donut-center">' +
            '<div class="donut-center-value" style="color:' + app.complianceColor(pct) + '">' + Math.round(pct) + '%</div>' +
            '<div class="donut-center-label">Compliant</div>' +
          '</div>' +
        '</div>' +
        '<div class="flex gap-lg mt-lg">' +
          '<div class="flex items-center gap-xs"><span class="badge-dot met"></span><span class="text-small">Met (' + s.met + ')</span></div>' +
          '<div class="flex items-center gap-xs"><span class="badge-dot not-met"></span><span class="text-small">Not Met (' + s.not_met + ')</span></div>' +
          '<div class="flex items-center gap-xs"><span class="badge-dot manual"></span><span class="text-small">Manual (' + s.manual + ')</span></div>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  function buildExportSection(scan) {
    return '<div class="card">' +
      '<div class="card-header"><h4>Export Report</h4></div>' +
      '<div class="card-body">' +
        '<p class="text-small text-secondary mb-lg">Download the compliance scan results in your preferred format for stakeholder distribution or audit documentation.</p>' +
        '<div class="export-group" style="flex-direction:column">' +
          '<button class="btn btn-secondary w-full" onclick="downloadReport(\'' + app.escapeHtml(scan.id) + '\', \'html\')" aria-label="Download HTML report">' +
            '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>' +
            ' Download HTML Report' +
          '</button>' +
          '<button class="btn btn-secondary w-full" onclick="downloadReport(\'' + app.escapeHtml(scan.id) + '\', \'xlsx\')" aria-label="Download XLSX report">' +
            '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>' +
            ' Download XLSX Report' +
          '</button>' +
        '</div>' +
        '<div class="mt-lg" style="border-top:1px solid var(--color-border-light);padding-top:var(--spacing-md)">' +
          '<h5 class="mb-sm">Scan Metadata</h5>' +
          '<div class="flex justify-between text-small mb-sm"><span class="text-muted">Scan ID</span><span class="font-mono">' + app.escapeHtml(scan.id) + '</span></div>' +
          '<div class="flex justify-between text-small mb-sm"><span class="text-muted">Engine Version</span><span>v1.0.0</span></div>' +
          '<div class="flex justify-between text-small mb-sm"><span class="text-muted">API Checks</span><span>496 NIST 800-53 Rev 5</span></div>' +
          '<div class="flex justify-between text-small"><span class="text-muted">Timestamp</span><span>' + app.formatDate(scan.created_at) + '</span></div>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  function buildDomainAccordion(scan) {
    var domains = scan.domains || [];
    if (domains.length === 0) {
      return '<div class="card"><div class="empty-state"><h3>No domain data available</h3><p>Domain-level findings will appear here once the scan completes.</p></div></div>';
    }

    var html = '<h3 class="mb-md">Findings by Domain</h3><div class="accordion">';
    domains.forEach(function (d, idx) {
      var metPct = d.total > 0 ? Math.round((d.met / d.total) * 100) : 0;
      var barColor = app.complianceBarClass(metPct);
      var isOpen = idx === 0 ? ' open' : '';

      html += '<div class="accordion-item' + isOpen + '" data-domain="' + app.escapeHtml(d.code) + '">' +
        '<div class="accordion-header" role="button" tabindex="0" aria-expanded="' + (idx === 0 ? 'true' : 'false') + '" aria-label="Toggle ' + app.escapeHtml(d.name) + ' findings">' +
          '<svg class="accordion-chevron" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd"/></svg>' +
          '<span class="accordion-title">' + app.escapeHtml(d.code) + ' - ' + app.escapeHtml(d.name) + '</span>' +
          '<div class="accordion-meta">' +
            '<span class="accordion-meta-item text-met"><strong>' + d.met + '</strong> met</span>' +
            '<span class="accordion-meta-item text-not-met"><strong>' + (d.not_met || 0) + '</strong> not met</span>' +
            '<span class="accordion-meta-item text-manual"><strong>' + (d.manual || 0) + '</strong> manual</span>' +
            '<div style="width:80px">' +
              '<div class="progress-bar sm">' +
                '<div class="progress-bar-fill ' + barColor + '" style="width:' + metPct + '%"></div>' +
              '</div>' +
            '</div>' +
            '<span class="text-small font-bold" style="width:36px;text-align:right;color:' + app.complianceColor(metPct) + '">' + metPct + '%</span>' +
          '</div>' +
        '</div>' +
        '<div class="accordion-body">' +
          '<div class="accordion-body-inner">' +
            buildFindingsTable(d.findings || [], scan.id) +
          '</div>' +
        '</div>' +
      '</div>';
    });
    html += '</div>';
    return html;
  }

  function textToBullets(text) {
    if (!text) return '';
    var lines = text.split('\n').filter(function (l) { return l.trim() !== ''; });
    if (lines.length <= 1) return '<p style="margin:4px 0">' + app.escapeHtml(lines[0] || '') + '</p>';
    var items = '';
    lines.forEach(function (line) {
      var clean = line.replace(/^\s*[-*]\s+/, '').trim();
      if (clean) items += '<li>' + app.escapeHtml(clean) + '</li>';
    });
    return '<ul style="margin:4px 0 0;padding-left:20px;list-style:disc">' + items + '</ul>';
  }

  /**
   * Format evidence text into structured cards.
   * Handles:
   *  - Aggregated sub-checks separated by \n\n with [Label] prefixes
   *  - Service/API/Expected key-value metadata
   *  - Semicolon-separated resource findings (sg-xxx, vpc-xxx, etc.)
   */
  function formatEvidence(text) {
    if (!text) return '';
    var blocks = text.split('\n\n').filter(function (b) { return b.trim() !== ''; });
    var cardStyle = 'background:var(--color-bg);border:1px solid var(--color-border-light);border-radius:6px;padding:10px 14px;margin:6px 0';

    var html = '';
    blocks.forEach(function (block) {
      var label = '';
      var body = block.trim();

      // Extract [Check Name] prefix
      var labelMatch = body.match(/^\[(.+?)\]\s*([\s\S]*)$/);
      if (labelMatch) {
        label = labelMatch[1];
        body = labelMatch[2];
      }

      // Extract key-value fields: Service: X. API: Y. Expected: Z.
      var kvFields = [];
      var message = body;
      var fieldPatterns = [
        { key: 'Service', regex: /\bService:\s*([^.]+)\./i },
        { key: 'API', regex: /\bAPI:\s*([^.]+)\./i },
        { key: 'Expected', regex: /\bExpected:\s*(.+)$/im },
      ];
      fieldPatterns.forEach(function (fp) {
        var m = message.match(fp.regex);
        if (m) {
          kvFields.push({ key: fp.key, value: m[1].trim().replace(/\.$/, '') });
          message = message.replace(m[0], '').trim();
        }
      });
      message = message.replace(/\.\s*\.\s*/g, '. ').replace(/\s+/g, ' ').trim();

      // Parse semicolon-separated resource findings from the message
      // Pattern: "Found N items: detail1; detail2; detail3"
      // or: "issue1; issue2; issue3"
      var summary = message;
      var resourceItems = [];
      var colonSplit = message.match(/^(.+?:\s*)(.+;.+)$/);
      if (colonSplit) {
        summary = colonSplit[1].trim();
        resourceItems = colonSplit[2].split(';').map(function (s) { return s.trim(); }).filter(Boolean);
      } else if (message.indexOf(';') !== -1 && !kvFields.length) {
        summary = '';
        resourceItems = message.split(';').map(function (s) { return s.trim(); }).filter(Boolean);
      }

      // Build card
      var card = '<div style="' + cardStyle + '">';
      if (label) {
        card += '<div style="font-weight:600;margin-bottom:6px;color:var(--color-text)">' + app.escapeHtml(label) + '</div>';
      }
      if (summary) {
        var mb = (kvFields.length || resourceItems.length) ? '8' : '0';
        card += '<div style="color:var(--color-text-secondary);margin-bottom:' + mb + 'px">' + app.escapeHtml(summary) + '</div>';
      }
      if (kvFields.length) {
        card += '<div style="display:grid;grid-template-columns:80px 1fr;gap:4px 12px;font-size:0.85em;margin-bottom:' + (resourceItems.length ? '8px' : '0') + '">';
        kvFields.forEach(function (kv) {
          card += '<span style="color:var(--color-text-muted);font-weight:500">' + app.escapeHtml(kv.key) + '</span>';
          card += '<span style="font-family:var(--font-mono);color:var(--color-text)">' + app.escapeHtml(kv.value) + '</span>';
        });
        card += '</div>';
      }
      if (resourceItems.length) {
        card += '<div style="display:flex;flex-direction:column;gap:4px">';
        resourceItems.forEach(function (item) {
          // Parse "resource_id (name): details" pattern
          var resMatch = item.match(/^([a-z]+-[a-f0-9]+)\s*\(([^)]+)\):\s*(.+)$/i);
          if (resMatch) {
            card += '<div style="display:grid;grid-template-columns:1fr;background:var(--color-bg-secondary,#fff);border:1px solid var(--color-border-light);border-radius:4px;padding:6px 10px;font-size:0.85em">' +
              '<div><span style="font-family:var(--font-mono);font-weight:600;color:var(--color-primary,#2E75B6)">' + app.escapeHtml(resMatch[1]) + '</span>' +
              ' <span style="color:var(--color-text-muted)">(' + app.escapeHtml(resMatch[2]) + ')</span></div>' +
              '<div style="color:var(--color-text-secondary);margin-top:2px">' + app.escapeHtml(resMatch[3]) + '</div>' +
            '</div>';
          } else {
            // Plain item (user names, simple issues, etc.)
            card += '<div style="background:var(--color-bg-secondary,#fff);border:1px solid var(--color-border-light);border-radius:4px;padding:6px 10px;font-size:0.85em;color:var(--color-text)">' +
              app.escapeHtml(item) +
            '</div>';
          }
        });
        card += '</div>';
      }
      card += '</div>';
      html += card;
    });
    return html;
  }

  function buildFindingsTable(findings, scanId) {
    if (findings.length === 0) {
      return '<p class="text-muted text-small" style="padding:16px 0">Detailed findings for this domain will populate from the scan engine.</p>';
    }

    var rows = '';
    findings.forEach(function (f, idx) {
      var hasDetail = f.evidence || f.remediation;
      var expandIcon = '<svg class="expand-icon" width="12" height="12" viewBox="0 0 20 20" fill="currentColor" style="vertical-align:middle;margin-right:6px;transition:transform 0.2s"><path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd"/></svg>';
      var evidenceBtn = (f.status !== 'manual')
        ? '<button class="btn-info-icon" data-practice-id="' + app.escapeHtml(f.id) + '" data-scan-id="' + app.escapeHtml(scanId || '') + '" title="More information on Evidence with CLI results">' +
              '<svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><circle cx="10" cy="10" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/><text x="10" y="14.5" text-anchor="middle" font-size="12" font-weight="bold" font-family="serif" fill="currentColor">i</text></svg>' +
            '</button>' +
            '<button class="btn btn-evidence btn-sm evidence-btn" data-practice-id="' + app.escapeHtml(f.id) + '" data-scan-id="' + app.escapeHtml(scanId || '') + '" title="View detailed API evidence and CLI commands">' +
              '<svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor" style="vertical-align:middle"><path d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z"/></svg>' +
              ' Evidence' +
            '</button>'
        : '';

      rows += '<tr class="finding-row" style="cursor:pointer" data-finding-idx="' + idx + '">' +
        '<td style="white-space:nowrap;width:110px">' + expandIcon + '<span class="font-mono font-bold text-small">' + app.escapeHtml(f.id) + '</span></td>' +
        '<td class="finding-name-cell">' + app.escapeHtml(f.name) + '</td>' +
        '<td style="white-space:nowrap;width:100px">' + app.statusBadge(f.status) + '</td>' +
        '<td style="white-space:nowrap;width:80px"><span class="' + app.severityClass(f.severity) + '">' + app.escapeHtml(f.severity) + '</span></td>' +
        '<td style="text-align:right;white-space:nowrap;width:140px">' + evidenceBtn + '</td>' +
      '</tr>';

      // Expandable detail row
      var evidenceHtml = f.evidence
        ? '<div class="finding-detail-section"><div class="finding-detail-label">Evidence</div>' + formatEvidence(f.evidence) + '</div>'
        : '';
      var remediationHtml = f.remediation
        ? '<div class="finding-detail-section"><div class="finding-detail-label">Remediation</div>' + textToBullets(f.remediation) + '</div>'
        : '';
      var detailContent = evidenceHtml + remediationHtml;
      if (!detailContent) {
        detailContent = '<p class="text-muted text-small">No additional details available for this control.</p>';
      }
      rows += '<tr class="finding-detail" data-finding-idx="' + idx + '" style="display:none">' +
        '<td colspan="5" style="padding:0;border-bottom:1px solid var(--color-border-light)">' +
          '<div class="finding-detail-body">' + detailContent + '</div>' +
        '</td>' +
      '</tr>';
    });

    return '<table class="data-table findings-table" style="width:100%;table-layout:fixed" aria-label="Control-level findings">' +
      '<colgroup>' +
        '<col style="width:110px">' +
        '<col>' +
        '<col style="width:120px">' +
        '<col style="width:90px">' +
        '<col style="width:140px">' +
      '</colgroup>' +
      '<thead><tr>' +
        '<th>Control ID</th>' +
        '<th>Control</th>' +
        '<th>Status</th>' +
        '<th>Severity</th>' +
        '<th></th>' +
      '</tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
    '</table>';
  }

  function showEvidenceModal(practiceId, data) {
    var title = document.getElementById('evidence-modal-title');
    var body = document.getElementById('evidence-modal-body');
    if (title) title.textContent = 'API Evidence - Control ' + practiceId;

    var checks = data.checks || [];
    if (checks.length === 0) {
      body.innerHTML = '<p class="text-muted">No automated checks with evidence available for this practice.</p>';
      app.openModal('evidence-modal');
      return;
    }

    var html = '<p class="text-small text-muted" style="margin-bottom:12px">Fetched at ' + app.escapeHtml(data.fetched_at || '') + '</p>';
    checks.forEach(function (chk) {
      var jsonStr = JSON.stringify(chk.raw_response || {}, null, 2);
      html += '<div class="evidence-check">' +
        '<div class="evidence-check-header">' +
          '<strong>' + app.escapeHtml(chk.check_name || chk.api_call || chk.check_id) + '</strong>' +
          app.statusBadge(chk.status) +
          '<button class="btn btn-ghost btn-sm copy-evidence-btn" data-json="' + app.escapeHtml(jsonStr) + '">Copy</button>' +
        '</div>' +
        // Query info metadata
        (chk.query_info && chk.query_info.api_method ?
          '<div class="evidence-query-info">' +
            '<span class="evidence-query-label">API:</span> ' + app.escapeHtml(chk.query_info.api_method) +
            (chk.query_info.region ? ' <span class="evidence-query-sep">|</span> <span class="evidence-query-label">Region:</span> ' + app.escapeHtml(chk.query_info.region) : '') +
            (chk.query_info.account_id ? ' <span class="evidence-query-sep">|</span> <span class="evidence-query-label">Account:</span> ' + app.escapeHtml(chk.query_info.account_id) : '') +
          '</div>' : '') +
        '<div class="evidence-check-summary">' + app.escapeHtml(chk.evidence_summary || '') + '</div>' +
        // Assessor guidance callout
        (chk.assessor_guidance ?
          '<div class="evidence-assessor-guidance">' +
            '<strong>What to look for:</strong> ' +
            app.escapeHtml(chk.assessor_guidance) +
          '</div>' : '') +
        // Corrective actions (CCA) by scenario
        (chk.corrective_actions && chk.corrective_actions.length ?
          '<div class="evidence-cca">' +
            '<div class="evidence-cca-title">Corrective Actions by Environment</div>' +
            chk.corrective_actions.map(function (cca) {
              var severityClass = cca.severity === 'warning' ? 'cca-warning'
                : cca.severity === 'success' ? 'cca-success' : 'cca-info';
              var altHtml = (cca.alternatives && cca.alternatives.length)
                ? '<ul class="cca-alternatives">' +
                    cca.alternatives.map(function (a) {
                      return '<li>' + app.escapeHtml(a) + '</li>';
                    }).join('') +
                  '</ul>'
                : '';
              return '<div class="cca-scenario ' + severityClass + '">' +
                '<div class="cca-scenario-header">' + app.escapeHtml(cca.scenario) + '</div>' +
                '<div class="cca-scenario-body">' + app.escapeHtml(cca.description) + '</div>' +
                altHtml +
              '</div>';
            }).join('') +
          '</div>' : '') +
        // CLI command block
        (chk.cli_command ?
          '<div class="evidence-cli">' +
            '<div class="evidence-cli-header">' +
              '<span class="evidence-cli-label">CLI Command</span>' +
              '<button class="btn btn-ghost btn-sm copy-cli-btn" data-cli="' + app.escapeHtml(chk.cli_command) + '">Copy</button>' +
            '</div>' +
            '<pre class="evidence-cli-code"><code>$ ' + app.escapeHtml(chk.cli_command) + '</code></pre>' +
          '</div>' : '') +
        '<pre class="evidence-json"><code>' + app.escapeHtml(jsonStr) + '</code></pre>' +
      '</div>';
    });
    body.innerHTML = html;

    // Bind copy buttons (JSON)
    body.querySelectorAll('.copy-evidence-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var text = btn.getAttribute('data-json');
        navigator.clipboard.writeText(text).then(function () {
          app.showToast('Copied to clipboard', 'success');
        }).catch(function () {
          app.showToast('Copy failed', 'error');
        });
      });
    });

    // Bind CLI copy buttons
    body.querySelectorAll('.copy-cli-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var text = btn.getAttribute('data-cli');
        navigator.clipboard.writeText(text).then(function () {
          app.showToast('CLI command copied', 'success');
        }).catch(function () {
          app.showToast('Copy failed', 'error');
        });
      });
    });

    app.openModal('evidence-modal');
  }

  function initDetailEvents(container, scan) {
    // Delete scan
    var deleteBtn = container.querySelector('#btn-delete-scan');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', async function () {
        if (!confirm('Delete this scan and all its findings? This cannot be undone.')) return;
        try {
          await app.api.delete('/scans/' + scan.id);
          app.showToast('Scan deleted.', 'success');
          app.navigate('scans');
        } catch (err) {
          app.showToast('Failed to delete scan: ' + (err.message || 'Unknown error'), 'error');
        }
      });
    }

    // Evidence button click (both </> Evidence and (i) info buttons)
    container.querySelectorAll('.evidence-btn, .btn-info-icon').forEach(function (btn) {
      btn.addEventListener('click', async function (e) {
        e.stopPropagation();
        var practiceId = btn.getAttribute('data-practice-id');
        var scanId = btn.getAttribute('data-scan-id') || scan.id;
        var originalHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner sm"></span>';
        try {
          var data = await app.api.get('/scans/' + scanId + '/evidence/' + practiceId);
          showEvidenceModal(practiceId, data);
        } catch (err) {
          app.showToast('Could not fetch evidence: ' + (err.message || 'Unknown error'), 'error');
        } finally {
          btn.disabled = false;
          btn.innerHTML = originalHtml;
        }
      });
    });

    // Evidence modal close
    var evidenceClose = container.querySelector('#evidence-modal-close');
    if (evidenceClose) {
      evidenceClose.addEventListener('click', function () {
        app.closeModal('evidence-modal');
      });
    }
    var evidenceOverlay = container.querySelector('#evidence-modal');
    if (evidenceOverlay) {
      evidenceOverlay.addEventListener('click', function (e) {
        if (e.target === evidenceOverlay) {
          app.closeModal('evidence-modal');
        }
      });
    }

    // Finding row expand/collapse
    container.querySelectorAll('.finding-row').forEach(function (row) {
      row.addEventListener('click', function (e) {
        // Don't expand if the click was on the evidence button
        if (e.target.closest('.evidence-btn') || e.target.closest('.btn-info-icon')) return;
        var idx = row.getAttribute('data-finding-idx');
        var detail = row.parentNode.querySelector('.finding-detail[data-finding-idx="' + idx + '"]');
        if (!detail) return;
        var isOpen = detail.style.display !== 'none';
        detail.style.display = isOpen ? 'none' : 'table-row';
        row.classList.toggle('expanded', !isOpen);
      });
    });

    // Accordion toggle
    container.querySelectorAll('.accordion-header').forEach(function (header) {
      header.addEventListener('click', function () {
        var item = header.closest('.accordion-item');
        if (item) {
          item.classList.toggle('open');
          var expanded = item.classList.contains('open');
          header.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        }
      });
      header.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          header.click();
        }
      });
    });
  }

  // Global report download function
  window.downloadReport = async function (scanId, format) {
    try {
      app.showToast('Preparing ' + format.toUpperCase() + ' report for download...', 'info');
      var resp = await fetch(app.CONFIG.API_BASE + '/reports/' + scanId + '/' + format, {
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem(app.CONFIG.TOKEN_KEY) },
      });
      if (!resp.ok) throw new Error('Download failed');
      var blob = await resp.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'fedramp-scan-' + scanId + '.' + format;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      app.showToast('Report downloaded successfully.', 'success');
    } catch (err) {
      app.showToast('Failed to download report: ' + (err.message || 'Unknown error'), 'error');
    }
  };

  window.renderScans = renderScans;
  window.renderScanDetail = renderScanDetail;
  window.cleanupScanPolling = function () {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  };

})();
