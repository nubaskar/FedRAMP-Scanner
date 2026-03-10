/* ==========================================================================
   FedRAMP Cloud Compliance Scanner - Dashboard View
   ========================================================================== */

(function () {
  'use strict';

  const FEDRAMP_FAMILIES = [
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

  async function renderDashboard(container) {
    // Show skeleton while loading
    container.innerHTML =
      app.skeletonCards(4) +
      '<div class="grid grid-2 mt-lg">' +
        '<div class="skeleton skeleton-card" style="height:340px"></div>' +
        '<div class="skeleton skeleton-card" style="height:340px"></div>' +
      '</div>';

    let stats, recentScans, domainCompliance;

    // Fetch real data from existing APIs
    var clientsData, scansData;
    try {
      var results = await Promise.all([
        app.api.get('/clients'),
        app.api.get('/scans'),
      ]);
      clientsData = results[0];
      scansData = results[1];
    } catch (err) {
      clientsData = { clients: [], total: 0 };
      scansData = [];
    }

    var clientsList = clientsData.clients || clientsData || [];
    var scansList = scansData.items || scansData || [];

    // Build client name lookup
    var clientMap = {};
    clientsList.forEach(function (c) { clientMap[c.id] = c.name; });

    // Enrich scan items with computed fields for display
    scansList = scansList.map(function (s) {
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
        compliance_pct: totalChecks > 0 ? Math.round(((summary.met || 0) / totalChecks) * 1000) / 10 : null,
        summary: summary,
      };
    });

    // Build stats from real data
    var completedScans = scansList.filter(function (s) { return s.status === 'completed'; });
    var totalFindings = 0;
    completedScans.forEach(function (s) {
      if (s.summary && s.summary.not_met) totalFindings += s.summary.not_met;
    });

    stats = {
      total_clients: clientsList.length,
      total_scans: scansList.length,
      compliance_rate: 0,
      open_issues: totalFindings,
      clients_trend: 0,
      scans_trend: 0,
      compliance_trend: 0,
      issues_trend: 0,
    };

    // Calculate average compliance from completed scans
    if (completedScans.length > 0) {
      var totalMet = 0, totalChecks = 0;
      completedScans.forEach(function (s) {
        if (s.summary) {
          totalMet += (s.summary.met || 0);
          totalChecks += (s.summary.met || 0) + (s.summary.not_met || 0) + (s.summary.manual || 0);
        }
      });
      stats.compliance_rate = totalChecks > 0 ? Math.round((totalMet / totalChecks) * 1000) / 10 : 0;
    }

    recentScans = { items: scansList.slice(0, 10) };

    // Build domain compliance from the most recent completed scan's findings
    domainCompliance = { domains: [] };
    var latestCompleted = scansList.find(function (s) { return s.status === 'completed'; });
    if (latestCompleted) {
      try {
        var summaryData = await app.api.get('/scans/' + latestCompleted.id + '/summary');
        var byDomain = (summaryData && summaryData.by_domain) || {};
        domainCompliance.domains = FEDRAMP_FAMILIES.map(function (d) {
          var counts = byDomain[d.code] || {};
          var met = counts.met || 0;
          var total = (counts.met || 0) + (counts.not_met || 0) + (counts.manual || 0) + (counts.error || 0);
          return {
            code: d.code,
            name: d.name,
            met_pct: total > 0 ? Math.round((met / total) * 1000) / 10 : 0,
          };
        });
      } catch {
        // Fall through to empty domains - chart shows 0%
      }
    }

    const items = recentScans.items || recentScans || [];
    const domains = (domainCompliance && domainCompliance.domains) || domainCompliance || [];

    container.innerHTML = buildStatsRow(stats) +
      '<div class="flex gap-sm mb-lg">' +
        '<button class="btn btn-primary" onclick="app.navigate(\'scans\')" aria-label="Start a new scan">' +
          '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/></svg>' +
          ' New Scan' +
        '</button>' +
        '<button class="btn btn-outline" onclick="app.navigate(\'clients\')" aria-label="Add a new client">' +
          '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path d="M8 9a3 3 0 100-6 3 3 0 000 6zM8 11a6 6 0 016 6H2a6 6 0 016-6zM16 7a1 1 0 10-2 0v1h-1a1 1 0 100 2h1v1a1 1 0 102 0v-1h1a1 1 0 100-2h-1V7z"/></svg>' +
          ' Add Client' +
        '</button>' +
      '</div>' +
      '<div class="grid grid-2">' +
        buildRecentScansCard(items) +
        buildDomainChart(domains) +
      '</div>';

    // Initialize table sorting
    var table = container.querySelector('.data-table');
    if (table) app.makeSortable(table);
  }

  function buildStatsRow(s) {
    function trendHtml(val) {
      if (!val && val !== 0) return '';
      var cls = val > 0 ? 'up' : val < 0 ? 'down' : 'neutral';
      var arrow = val > 0 ? '\u2191' : val < 0 ? '\u2193' : '\u2192';
      return '<span class="stat-card-trend ' + cls + '">' + arrow + ' ' + Math.abs(val) + '</span>';
    }

    return '<div class="stats-grid">' +
      '<div class="stat-card">' +
        '<div class="stat-card-icon blue">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value">' + (s.total_clients || 0) + '</div>' +
          '<div class="stat-card-label">Total Clients</div>' +
          trendHtml(s.clients_trend) +
        '</div>' +
      '</div>' +
      '<div class="stat-card">' +
        '<div class="stat-card-icon navy">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value">' + (s.total_scans || 0) + '</div>' +
          '<div class="stat-card-label">Total Scans</div>' +
          trendHtml(s.scans_trend) +
        '</div>' +
      '</div>' +
      '<div class="stat-card">' +
        '<div class="stat-card-icon green">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"/><path d="M12 6v6l4 2"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value">' + app.formatPercent(s.compliance_rate) + '</div>' +
          '<div class="stat-card-label">Compliance Rate</div>' +
          trendHtml(s.compliance_trend) +
        '</div>' +
      '</div>' +
      '<div class="stat-card">' +
        '<div class="stat-card-icon red">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
        '</div>' +
        '<div class="stat-card-content">' +
          '<div class="stat-card-value">' + (s.open_issues || 0) + '</div>' +
          '<div class="stat-card-label">Open Issues</div>' +
          trendHtml(s.issues_trend) +
        '</div>' +
      '</div>' +
    '</div>';
  }

  function buildRecentScansCard(items) {
    var rows = '';
    if (items.length === 0) {
      rows = '<tr><td colspan="6" class="text-center text-muted" style="padding:32px">No scans yet. Start your first scan to see results here.</td></tr>';
    } else {
      items.forEach(function (s) {
        var pctDisplay = s.compliance_pct !== null && s.compliance_pct !== undefined
          ? '<span style="color:' + app.complianceColor(s.compliance_pct) + ';font-weight:600">' + app.formatPercent(s.compliance_pct) + '</span>'
          : '<span class="text-muted">--</span>';
        rows +=
          '<tr class="clickable" onclick="app.navigate(\'scan/' + app.escapeHtml(s.id) + '\')" role="link" tabindex="0" aria-label="View scan details for ' + app.escapeHtml(s.client_name) + '">' +
            '<td><strong>' + app.escapeHtml(s.client_name) + '</strong></td>' +
            '<td>' + app.envDisplay(s.environment) + '</td>' +
            '<td>' + app.levelBadge(s.level) + '</td>' +
            '<td>' + app.statusBadge(s.status) + '</td>' +
            '<td>' + app.formatDateShort(s.created_at) + '</td>' +
            '<td class="text-right">' + pctDisplay + '</td>' +
          '</tr>';
      });
    }

    return '<div class="card">' +
      '<div class="card-header">' +
        '<h4>Recent Scans</h4>' +
        '<a href="#scans" class="btn btn-ghost btn-sm">View All</a>' +
      '</div>' +
      '<div class="table-container">' +
        '<table class="data-table" aria-label="Recent compliance scans">' +
          '<thead><tr>' +
            '<th data-sort="client">Client <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="env">Environment <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="level">Level <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="status">Status <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="date">Date <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="compliance" class="text-right">Compliance <span class="sort-icon">\u2195</span></th>' +
          '</tr></thead>' +
          '<tbody>' + rows + '</tbody>' +
        '</table>' +
      '</div>' +
    '</div>';
  }

  function buildDomainChart(domains) {
    var bars = '';
    if (domains.length === 0) {
      domains = FEDRAMP_FAMILIES.map(function (d) { return { code: d.code, name: d.name, met_pct: 0 }; });
    }
    domains.forEach(function (d) {
      var pct = d.met_pct || 0;
      var color = app.complianceColor(pct);
      bars +=
        '<div class="domain-bar-row" title="' + app.escapeHtml(d.name) + ': ' + pct + '% compliant">' +
          '<span class="domain-bar-label">' + app.escapeHtml(d.code) + '</span>' +
          '<div class="domain-bar-track">' +
            '<div class="domain-bar-fill" style="width:' + pct + '%;background:' + color + '"></div>' +
          '</div>' +
          '<span class="domain-bar-pct" style="color:' + color + '">' + pct + '%</span>' +
        '</div>';
    });

    return '<div class="card">' +
      '<div class="card-header">' +
        '<h4>Compliance by Domain</h4>' +
        '<span class="text-small text-muted">20 FedRAMP Families</span>' +
      '</div>' +
      '<div class="card-body">' +
        '<div class="domain-chart">' + bars + '</div>' +
      '</div>' +
    '</div>';
  }

  // Export to global scope
  window.renderDashboard = renderDashboard;

})();
