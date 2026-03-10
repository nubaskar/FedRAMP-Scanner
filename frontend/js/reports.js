/* ==========================================================================
   CMMC Cloud Compliance Scanner - Reports View
   ========================================================================== */

(function () {
  'use strict';

  var allReportClients = [];
  var reportContainer = null;
  var reportSearchQuery = '';
  var reportEnvFilter = '';
  var reportLevelFilter = '';

  var ENVIRONMENTS = [
    { value: 'aws_govcloud', label: 'AWS GovCloud' },
    { value: 'aws_commercial', label: 'AWS Commercial' },
    { value: 'azure_government', label: 'Azure Government' },
    { value: 'azure_commercial', label: 'Azure Commercial' },
    { value: 'gcp_assured_workloads', label: 'GCP Assured Workloads' },
    { value: 'gcp_commercial', label: 'GCP Commercial' },
  ];

  async function renderReports(container) {
    container.innerHTML = app.skeletonTable(6);

    var data;
    try {
      data = await app.api.get('/reports');
    } catch (err) {
      container.innerHTML = '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
        '<h3>Unable to load reports</h3>' +
        '<p>' + app.escapeHtml(err.message || 'Could not connect to the server.') + '</p>' +
        '<button class="btn btn-primary" onclick="app.navigate(\'reports\')" aria-label="Retry">Retry</button>' +
      '</div></div>';
      return;
    }

    var clients = data.clients || data || [];
    allReportClients = clients;
    reportContainer = container;

    container.innerHTML = buildReportsHeader() +
      '<div class="tabs mb-lg" role="tablist">' +
        '<div class="tab active" data-tab="history" role="tab" aria-selected="true" tabindex="0">Scan History</div>' +
        '<div class="tab" data-tab="compare" role="tab" aria-selected="false" tabindex="0">Compare Scans</div>' +
        '<div class="tab" data-tab="export" role="tab" aria-selected="false" tabindex="0">Export</div>' +
      '</div>' +
      '<div id="tab-content-history">' + buildHistoryTab(clients) + '</div>' +
      '<div id="tab-content-compare" class="hidden">' + buildCompareTab(clients) + '</div>' +
      '<div id="tab-content-export" class="hidden">' + buildExportTab(clients) + '</div>';

    initReportsEvents(container, clients);
  }

  function buildReportsHeader() {
    return '<div class="flex items-center justify-between mb-lg">' +
      '<div>' +
        '<h2>Reports & Analysis</h2>' +
        '<p class="text-secondary text-small mt-sm">Review historical scan data, compare results over time, and export compliance reports</p>' +
      '</div>' +
    '</div>';
  }

  /* ---------- History Tab ---------- */
  function buildHistoryTab(clients) {
    if (clients.length === 0) {
      return '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 17H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>' +
        '<h3>No completed scans</h3>' +
        '<p>Completed scans will appear here grouped by client. Run your first scan to see results.</p>' +
        '<button class="btn btn-primary" onclick="app.navigate(\'scans\')" aria-label="Go to scans page">Go to Scans</button>' +
      '</div></div>';
    }

    return buildReportSearchBar() +
      '<div id="report-history-wrap">' + buildReportCards(clients) + '</div>';
  }

  function buildReportSearchBar() {
    if (allReportClients.length === 0) return '';

    var envOptions = '<option value="">Environment</option>';
    ENVIRONMENTS.forEach(function (e) {
      envOptions += '<option value="' + e.value + '">' + e.label + '</option>';
    });

    return '<div class="search-filter-bar">' +
      '<div class="search-input-wrap">' +
        '<svg class="search-input-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/></svg>' +
        '<input type="text" class="search-input" id="report-search-input" placeholder="Search clients..." aria-label="Search reports by client name" />' +
        '<button class="search-clear-btn hidden" id="report-search-clear" aria-label="Clear search" type="button">&times;</button>' +
      '</div>' +
      '<div class="filter-pills">' +
        '<select class="filter-pill" id="report-env-filter" aria-label="Filter by environment">' + envOptions + '</select>' +
        '<select class="filter-pill" id="report-level-filter" aria-label="Filter by CMMC level">' +
          '<option value="">Level</option>' +
          '<option value="L1">L1</option>' +
          '<option value="L2">L2</option>' +
          '<option value="L3">L3</option>' +
        '</select>' +
      '</div>' +
      '<span class="search-result-count" id="report-result-count"></span>' +
    '</div>';
  }

  function buildReportCards(clients) {
    if (clients.length === 0 && allReportClients.length > 0) {
      return '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>' +
        '<h3>No matching scans</h3>' +
        '<p>Try adjusting your search or filter criteria.</p>' +
      '</div></div>';
    }

    var html = '';
    clients.forEach(function (c) {
      var rows = '';
      c.scans.forEach(function (s, idx) {
        var trendHtml = '';
        if (idx < c.scans.length - 1) {
          var prev = c.scans[idx + 1];
          var delta = Math.round((s.compliance_pct - prev.compliance_pct) * 10) / 10;
          if (delta > 0) {
            trendHtml = '<span class="stat-card-trend up">+' + delta + '%</span>';
          } else if (delta < 0) {
            trendHtml = '<span class="stat-card-trend down">' + delta + '%</span>';
          } else {
            trendHtml = '<span class="stat-card-trend neutral">0%</span>';
          }
        }

        rows += '<tr class="clickable" onclick="app.navigate(\'scan/' + app.escapeHtml(s.id) + '\')" role="link" tabindex="0">' +
          '<td>' + app.formatDateShort(s.created_at) + '</td>' +
          '<td>' + app.envDisplay(s.environment) + '</td>' +
          '<td>' + app.levelBadge(s.level) + '</td>' +
          '<td>' +
            '<div class="flex items-center gap-sm">' +
              '<div class="progress-bar" style="width:100px">' +
                '<div class="progress-bar-fill ' + app.complianceBarClass(s.compliance_pct) + '" style="width:' + s.compliance_pct + '%"></div>' +
              '</div>' +
              '<span class="font-bold text-small" style="color:' + app.complianceColor(s.compliance_pct) + '">' + app.formatPercent(s.compliance_pct) + '</span>' +
              trendHtml +
            '</div>' +
          '</td>' +
          '<td class="text-center text-met font-bold">' + s.met + '</td>' +
          '<td class="text-center text-not-met font-bold">' + s.not_met + '</td>' +
          '<td class="text-center" style="color:#b8860b;font-weight:600">' + s.manual + '</td>' +
        '</tr>';
      });

      html += '<div class="card mb-lg">' +
        '<div class="card-header">' +
          '<div class="flex items-center gap-sm">' +
            '<h4>' + app.escapeHtml(c.name) + '</h4>' +
            '<span class="badge badge-l2 text-xs">' + c.scans.length + ' scan' + (c.scans.length !== 1 ? 's' : '') + '</span>' +
          '</div>' +
        '</div>' +
        '<div class="table-container">' +
          '<table class="data-table" aria-label="Scan history for ' + app.escapeHtml(c.name) + '">' +
            '<thead><tr>' +
              '<th>Date</th>' +
              '<th>Environment</th>' +
              '<th>Level</th>' +
              '<th>Compliance</th>' +
              '<th class="text-center">Met</th>' +
              '<th class="text-center">Not Met</th>' +
              '<th class="text-center">Manual</th>' +
            '</tr></thead>' +
            '<tbody>' + rows + '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>';
    });

    return html;
  }

  function applyReportFilters() {
    var searchInput = document.getElementById('report-search-input');
    var envSelect = document.getElementById('report-env-filter');
    var levelSelect = document.getElementById('report-level-filter');
    var clearBtn = document.getElementById('report-search-clear');
    var countEl = document.getElementById('report-result-count');

    var query = searchInput ? searchInput.value.trim().toLowerCase() : '';
    var envVal = envSelect ? envSelect.value : '';
    var levelVal = levelSelect ? levelSelect.value : '';

    // Save state
    reportSearchQuery = query;
    reportEnvFilter = envVal;
    reportLevelFilter = levelVal;

    // Toggle clear button visibility
    if (clearBtn) clearBtn.classList.toggle('hidden', !query);

    // Toggle active class on pills
    if (envSelect) envSelect.classList.toggle('active', !!envVal);
    if (levelSelect) levelSelect.classList.toggle('active', !!levelVal);

    // Build filtered clients array
    var totalScans = 0;
    allReportClients.forEach(function (c) { totalScans += c.scans.length; });

    var filteredClients = [];
    var matchedScans = 0;
    allReportClients.forEach(function (c) {
      // Text search matches client name
      if (query && (c.name || '').toLowerCase().indexOf(query) === -1) return;

      // Filter individual scans by env + level
      var filteredScans = c.scans.filter(function (s) {
        if (envVal && s.environment !== envVal) return false;
        if (levelVal && s.level !== levelVal) return false;
        return true;
      });

      if (filteredScans.length > 0) {
        filteredClients.push({ id: c.id, name: c.name, scans: filteredScans });
        matchedScans += filteredScans.length;
      }
    });

    // Re-render cards
    var wrap = document.getElementById('report-history-wrap');
    if (wrap) {
      wrap.innerHTML = buildReportCards(filteredClients);
      wrap.querySelectorAll('.data-table').forEach(function (table) {
        app.makeSortable(table);
      });
    }

    // Update result count
    var isFiltered = query || envVal || levelVal;
    if (countEl) {
      if (isFiltered) {
        countEl.textContent = matchedScans + ' of ' + totalScans + ' scans across ' + filteredClients.length + ' client' + (filteredClients.length !== 1 ? 's' : '');
      } else {
        countEl.textContent = '';
      }
    }
  }

  /* ---------- Compare Tab ---------- */
  function buildCompareTab(clients) {
    var clientOpts = '<option value="">Select a client...</option>';
    clients.forEach(function (c) {
      if (c.scans.length >= 2) {
        clientOpts += '<option value="' + app.escapeHtml(c.id) + '">' + app.escapeHtml(c.name) + ' (' + c.scans.length + ' scans)</option>';
      }
    });

    var noClients = clients.every(function (c) { return c.scans.length < 2; });

    if (noClients) {
      return '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>' +
        '<h3>Not enough scans to compare</h3>' +
        '<p>Run at least two scans for the same client to enable side-by-side comparison.</p>' +
      '</div></div>';
    }

    return '<div class="card mb-lg">' +
      '<div class="card-body">' +
        '<div class="form-row">' +
          '<div class="form-group">' +
            '<label class="form-label" for="compare-client">Client</label>' +
            '<select class="form-select" id="compare-client">' + clientOpts + '</select>' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">Select Scans</label>' +
            '<div class="form-row">' +
              '<select class="form-select" id="compare-scan-a" disabled><option value="">Scan A</option></select>' +
              '<select class="form-select" id="compare-scan-b" disabled><option value="">Scan B</option></select>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<button class="btn btn-primary mt-sm" id="btn-compare" disabled>Compare Scans</button>' +
      '</div>' +
    '</div>' +
    '<div id="compare-results"></div>';
  }

  function populateScanDropdowns(clients, clientId) {
    var client = clients.find(function (c) { return c.id === clientId; });
    var selectA = document.getElementById('compare-scan-a');
    var selectB = document.getElementById('compare-scan-b');
    var btn = document.getElementById('btn-compare');

    if (!client || !selectA || !selectB) return;

    var opts = '<option value="">Select scan...</option>';
    client.scans.forEach(function (s) {
      opts += '<option value="' + app.escapeHtml(s.id) + '">' + app.formatDateShort(s.created_at) + ' (' + app.formatPercent(s.compliance_pct) + ')</option>';
    });

    selectA.innerHTML = opts;
    selectB.innerHTML = opts;
    selectA.disabled = false;
    selectB.disabled = false;
    if (btn) btn.disabled = false;

    // Auto-select most recent two
    if (client.scans.length >= 2) {
      selectA.value = client.scans[0].id;
      selectB.value = client.scans[1].id;
    }
  }

  function buildComparisonResults(scanA, scanB) {
    var pctA = scanA.compliance_pct || 0;
    var pctB = scanB.compliance_pct || 0;
    var delta = Math.round((pctA - pctB) * 10) / 10;
    var improved = delta > 0;

    var html = '<div class="card">' +
      '<div class="card-header">' +
        '<h4>Comparison Results</h4>' +
        '<span class="stat-card-trend ' + (improved ? 'up' : delta < 0 ? 'down' : 'neutral') + '">' +
          (improved ? '+' : '') + delta + '% overall' +
        '</span>' +
      '</div>' +
      '<div class="card-body">' +
        '<div class="comparison-grid">' +
          '<div class="comparison-column">' +
            '<div class="comparison-header">' +
              '<div class="flex justify-between items-center">' +
                '<span>Scan A: ' + app.formatDateShort(scanA.created_at) + '</span>' +
                '<span class="font-bold" style="color:' + app.complianceColor(pctA) + '">' + app.formatPercent(pctA) + '</span>' +
              '</div>' +
            '</div>' +
            '<div class="diff-row"><span>Met</span><span class="text-met font-bold">' + (scanA.met || 0) + '</span></div>' +
            '<div class="diff-row"><span>Not Met</span><span class="text-not-met font-bold">' + (scanA.not_met || 0) + '</span></div>' +
            '<div class="diff-row"><span>Manual Review</span><span style="color:#b8860b;font-weight:600">' + (scanA.manual || 0) + '</span></div>' +
          '</div>' +
          '<div class="comparison-column">' +
            '<div class="comparison-header">' +
              '<div class="flex justify-between items-center">' +
                '<span>Scan B: ' + app.formatDateShort(scanB.created_at) + '</span>' +
                '<span class="font-bold" style="color:' + app.complianceColor(pctB) + '">' + app.formatPercent(pctB) + '</span>' +
              '</div>' +
            '</div>' +
            '<div class="diff-row"><span>Met</span><span class="text-met font-bold">' + (scanB.met || 0) + '</span></div>' +
            '<div class="diff-row"><span>Not Met</span><span class="text-not-met font-bold">' + (scanB.not_met || 0) + '</span></div>' +
            '<div class="diff-row"><span>Manual Review</span><span style="color:#b8860b;font-weight:600">' + (scanB.manual || 0) + '</span></div>' +
          '</div>' +
        '</div>';

    // Delta summary
    var metDelta = (scanA.met || 0) - (scanB.met || 0);
    var notMetDelta = (scanA.not_met || 0) - (scanB.not_met || 0);
    var manualDelta = (scanA.manual || 0) - (scanB.manual || 0);

    html += '<div class="mt-lg">' +
      '<h5 class="mb-md">Change Summary</h5>' +
      buildDeltaRow('Newly Met', metDelta, true) +
      buildDeltaRow('Not Met Changes', notMetDelta, false) +
      buildDeltaRow('Manual Review Changes', manualDelta, false) +
    '</div>';

    html += '</div></div>';
    return html;
  }

  function buildDeltaRow(label, delta, positiveIsGood) {
    var cls = 'unchanged';
    var prefix = '';
    if (delta > 0) {
      cls = positiveIsGood ? 'improved' : 'regressed';
      prefix = '+';
    } else if (delta < 0) {
      cls = positiveIsGood ? 'regressed' : 'improved';
    }

    return '<div class="diff-row ' + cls + '" style="border-radius:var(--radius-sm);margin-bottom:4px">' +
      '<span>' + app.escapeHtml(label) + '</span>' +
      '<span class="font-bold">' + prefix + delta + '</span>' +
    '</div>';
  }

  /* ---------- Export Tab ---------- */
  function buildExportTab(clients) {
    var hasScans = clients.some(function (c) { return c.scans.length > 0; });

    if (!hasScans) {
      return '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>' +
        '<h3>No reports to export</h3>' +
        '<p>Complete a scan to generate exportable compliance reports.</p>' +
      '</div></div>';
    }

    var clientOpts = '<option value="">Select a client...</option>';
    clients.forEach(function (c) {
      if (c.scans.length > 0) {
        clientOpts += '<option value="' + app.escapeHtml(c.id) + '">' +
          app.escapeHtml(c.name) + ' (' + c.scans.length + ' scan' + (c.scans.length !== 1 ? 's' : '') + ')' +
        '</option>';
      }
    });

    return '<div class="card">' +
      '<div class="card-header"><h4>Export Compliance Report</h4></div>' +
      '<div class="card-body">' +
        '<div class="form-row">' +
          '<div class="form-group">' +
            '<label class="form-label" for="export-client">Client</label>' +
            '<select class="form-select" id="export-client">' + clientOpts + '</select>' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label" for="export-scan">Scan</label>' +
            '<select class="form-select" id="export-scan" disabled><option value="">Select a scan...</option></select>' +
          '</div>' +
        '</div>' +
        '<div id="export-preview" class="hidden"></div>' +
        '<div class="form-group">' +
          '<label class="form-label">Report Format</label>' +
          '<div class="flex gap-md">' +
            '<label class="flex items-center gap-sm" style="cursor:pointer">' +
              '<input type="radio" name="export-format" value="html" checked style="accent-color:var(--color-primary)" />' +
              '<span>HTML Report</span>' +
            '</label>' +
            '<label class="flex items-center gap-sm" style="cursor:pointer">' +
              '<input type="radio" name="export-format" value="xlsx" style="accent-color:var(--color-primary)" />' +
              '<span>XLSX Spreadsheet</span>' +
            '</label>' +
          '</div>' +
          '<p class="form-hint mt-sm">HTML reports are designed for stakeholder presentations. XLSX reports are suitable for data analysis and audit trails.</p>' +
        '</div>' +
        '<button class="btn btn-primary" id="btn-export-report" disabled>' +
          '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>' +
          ' Download Report' +
        '</button>' +
      '</div>' +
    '</div>';
  }

  function populateExportScans(clients, clientId) {
    var client = clients.find(function (c) { return c.id === clientId; });
    var scanSelect = document.getElementById('export-scan');
    if (!scanSelect) return;

    if (!client) {
      scanSelect.innerHTML = '<option value="">Select a scan...</option>';
      scanSelect.disabled = true;
      return;
    }

    var opts = '<option value="">Select a scan...</option>';
    client.scans.forEach(function (s) {
      opts += '<option value="' + app.escapeHtml(s.id) + '">' +
        app.formatDateShort(s.created_at) + ' (' + app.formatPercent(s.compliance_pct) + ')' +
      '</option>';
    });

    scanSelect.innerHTML = opts;
    scanSelect.disabled = false;

    // Auto-select the most recent scan
    if (client.scans.length > 0) {
      scanSelect.value = client.scans[0].id;
    }
  }

  function updateExportPreview(clients) {
    var previewEl = document.getElementById('export-preview');
    var exportBtn = document.getElementById('btn-export-report');
    if (!previewEl) return;

    var clientId = (document.getElementById('export-client') || {}).value || '';
    var scanId = (document.getElementById('export-scan') || {}).value || '';

    if (!clientId || !scanId) {
      previewEl.classList.add('hidden');
      previewEl.innerHTML = '';
      if (exportBtn) exportBtn.disabled = true;
      return;
    }

    var client = clients.find(function (c) { return c.id === clientId; });
    if (!client) return;
    var scan = client.scans.find(function (s) { return s.id === scanId; });
    if (!scan) return;

    var pct = scan.compliance_pct || 0;
    var met = scan.met || 0;
    var notMet = scan.not_met || 0;
    var manual = scan.manual || 0;

    // Duration calculation
    var durationHtml = '';
    if (scan.started_at && scan.completed_at) {
      var durMs = new Date(scan.completed_at) - new Date(scan.started_at);
      if (durMs > 0) {
        var durMin = Math.floor(durMs / 60000);
        var durSec = Math.floor((durMs % 60000) / 1000);
        durationHtml = '<span class="text-secondary text-small" style="margin-left:var(--spacing-md)">Duration: ' + durMin + 'm ' + durSec + 's</span>';
      }
    }

    previewEl.innerHTML =
      '<div style="background:var(--color-bg);border:1px solid var(--color-border-light);border-radius:var(--radius-md);padding:var(--spacing-lg);margin-bottom:var(--spacing-lg)">' +
        '<div class="flex items-center gap-sm mb-md" style="flex-wrap:wrap">' +
          '<span class="font-bold" style="font-size:1.05rem">' + app.escapeHtml(client.name) + '</span>' +
          app.envDisplay(scan.environment) +
          app.levelBadge(scan.level) +
        '</div>' +
        '<div class="flex items-center mb-md" style="flex-wrap:wrap">' +
          '<span class="text-secondary text-small">' + app.formatDateShort(scan.created_at) + '</span>' +
          durationHtml +
        '</div>' +
        '<div class="flex gap-md mb-md" style="flex-wrap:wrap">' +
          '<span class="badge" style="background:rgba(16,185,129,0.1);color:var(--color-met);font-weight:600">' + met + ' Met</span>' +
          '<span class="badge" style="background:rgba(239,68,68,0.1);color:var(--color-not-met);font-weight:600">' + notMet + ' Not Met</span>' +
          '<span class="badge" style="background:rgba(184,134,11,0.1);color:#b8860b;font-weight:600">' + manual + ' Manual</span>' +
        '</div>' +
        '<div class="flex items-center gap-sm">' +
          '<div class="progress-bar" style="flex:1">' +
            '<div class="progress-bar-fill ' + app.complianceBarClass(pct) + '" style="width:' + pct + '%"></div>' +
          '</div>' +
          '<span class="font-bold" style="color:' + app.complianceColor(pct) + '">' + app.formatPercent(pct) + '</span>' +
        '</div>' +
      '</div>';

    previewEl.classList.remove('hidden');
    if (exportBtn) exportBtn.disabled = false;
  }

  /* ---------- Event Handlers ---------- */
  function initReportsEvents(container, clients) {
    // Tab switching
    container.querySelectorAll('.tab').forEach(function (tab) {
      tab.addEventListener('click', function () {
        container.querySelectorAll('.tab').forEach(function (t) {
          t.classList.remove('active');
          t.setAttribute('aria-selected', 'false');
        });
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');

        var tabName = tab.dataset.tab;
        ['history', 'compare', 'export'].forEach(function (name) {
          var el = container.querySelector('#tab-content-' + name);
          if (el) {
            if (name === tabName) {
              el.classList.remove('hidden');
            } else {
              el.classList.add('hidden');
            }
          }
        });
      });
      tab.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          tab.click();
        }
      });
    });

    // Report history search & filter events
    var reportSearchInput = container.querySelector('#report-search-input');
    var reportClearBtn = container.querySelector('#report-search-clear');
    var reportFilterEnv = container.querySelector('#report-env-filter');
    var reportFilterLevel = container.querySelector('#report-level-filter');

    if (reportSearchInput) {
      reportSearchInput.addEventListener('input', applyReportFilters);
    }
    if (reportClearBtn) {
      reportClearBtn.addEventListener('click', function () {
        if (reportSearchInput) reportSearchInput.value = '';
        applyReportFilters();
      });
    }
    if (reportFilterEnv) {
      reportFilterEnv.addEventListener('change', applyReportFilters);
    }
    if (reportFilterLevel) {
      reportFilterLevel.addEventListener('change', applyReportFilters);
    }

    // Re-apply filters if they were active before (e.g. tab switch back)
    if (reportSearchQuery || reportEnvFilter || reportLevelFilter) {
      if (reportSearchInput) reportSearchInput.value = reportSearchQuery;
      if (reportFilterEnv) reportFilterEnv.value = reportEnvFilter;
      if (reportFilterLevel) reportFilterLevel.value = reportLevelFilter;
      applyReportFilters();
    }

    // Compare client selection
    var compareClient = container.querySelector('#compare-client');
    if (compareClient) {
      compareClient.addEventListener('change', function () {
        if (compareClient.value) {
          populateScanDropdowns(clients, compareClient.value);
        } else {
          var a = document.getElementById('compare-scan-a');
          var b = document.getElementById('compare-scan-b');
          if (a) { a.innerHTML = '<option value="">Scan A</option>'; a.disabled = true; }
          if (b) { b.innerHTML = '<option value="">Scan B</option>'; b.disabled = true; }
          var btn = document.getElementById('btn-compare');
          if (btn) btn.disabled = true;
        }
      });
    }

    // Compare button
    var compareBtn = container.querySelector('#btn-compare');
    if (compareBtn) {
      compareBtn.addEventListener('click', function () {
        var clientId = compareClient ? compareClient.value : '';
        var scanAId = document.getElementById('compare-scan-a') ? document.getElementById('compare-scan-a').value : '';
        var scanBId = document.getElementById('compare-scan-b') ? document.getElementById('compare-scan-b').value : '';

        if (!clientId || !scanAId || !scanBId) {
          app.showToast('Please select a client and two scans to compare.', 'warning');
          return;
        }

        if (scanAId === scanBId) {
          app.showToast('Please select two different scans to compare.', 'warning');
          return;
        }

        var client = clients.find(function (c) { return c.id === clientId; });
        if (!client) return;

        var scanA = client.scans.find(function (s) { return s.id === scanAId; });
        var scanB = client.scans.find(function (s) { return s.id === scanBId; });
        if (!scanA || !scanB) return;

        var resultsEl = document.getElementById('compare-results');
        if (resultsEl) {
          resultsEl.innerHTML = buildComparisonResults(scanA, scanB);
        }
      });
    }

    // Export - cascading client -> scan dropdowns
    var exportClient = container.querySelector('#export-client');
    if (exportClient) {
      exportClient.addEventListener('change', function () {
        if (exportClient.value) {
          populateExportScans(clients, exportClient.value);
          updateExportPreview(clients);
        } else {
          var scanSel = document.getElementById('export-scan');
          if (scanSel) { scanSel.innerHTML = '<option value="">Select a scan...</option>'; scanSel.disabled = true; }
          updateExportPreview(clients);
        }
      });
    }

    var exportScan = container.querySelector('#export-scan');
    if (exportScan) {
      exportScan.addEventListener('change', function () {
        updateExportPreview(clients);
      });
    }

    // Export download button
    var exportBtn = container.querySelector('#btn-export-report');
    if (exportBtn) {
      exportBtn.addEventListener('click', function () {
        var scanSelect = document.getElementById('export-scan');
        var scanId = scanSelect ? scanSelect.value : '';
        if (!scanId) {
          app.showToast('Please select a scan to export.', 'warning');
          return;
        }
        var formatEl = container.querySelector('input[name="export-format"]:checked');
        var format = formatEl ? formatEl.value : 'html';
        window.downloadReport(scanId, format);
      });
    }

    // Make tables sortable
    container.querySelectorAll('.data-table').forEach(function (table) {
      app.makeSortable(table);
    });
  }

  window.renderReports = renderReports;

})();
