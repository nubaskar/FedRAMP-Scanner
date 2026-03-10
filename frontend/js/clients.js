/* ==========================================================================
   CMMC Cloud Compliance Scanner - Clients View
   ========================================================================== */

(function () {
  'use strict';

  var ENVIRONMENTS = [
    { value: 'aws_govcloud', label: 'AWS GovCloud', levels: ['L1', 'L2', 'L3'] },
    { value: 'aws_commercial', label: 'AWS Commercial', levels: ['L1', 'L2'] },
    { value: 'azure_government', label: 'Azure Government', levels: ['L1', 'L2', 'L3'] },
    { value: 'azure_commercial', label: 'Azure Commercial', levels: ['L1', 'L2'] },
    { value: 'gcp_assured_workloads', label: 'GCP Assured Workloads', levels: ['L1', 'L2', 'L3'] },
    { value: 'gcp_commercial', label: 'GCP Commercial', levels: ['L1', 'L2'] },
  ];

  var CREDENTIAL_FIELDS = {
    'aws_govcloud': [
      { key: 'role_arn', label: 'Role ARN', type: 'text', placeholder: 'arn:aws-us-gov:iam::123456789012:role/CMMCScannerRole' },
      { key: 'external_id', label: 'External ID', type: 'text', placeholder: 'securitybricks-cmmc-scan' },
    ],
    'aws_commercial': [
      { key: 'role_arn', label: 'Role ARN', type: 'text', placeholder: 'arn:aws:iam::123456789012:role/CMMCScannerRole' },
      { key: 'external_id', label: 'External ID', type: 'text', placeholder: 'securitybricks-cmmc-scan' },
    ],
    'azure_government': [
      { key: 'tenant_id', label: 'Tenant ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
      { key: 'client_id', label: 'Client ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
      { key: 'client_secret', label: 'Client Secret', type: 'password', placeholder: 'Enter client secret' },
      { key: 'subscription_id', label: 'Subscription ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    ],
    'azure_commercial': [
      { key: 'tenant_id', label: 'Tenant ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
      { key: 'client_id', label: 'Client ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
      { key: 'client_secret', label: 'Client Secret', type: 'password', placeholder: 'Enter client secret' },
      { key: 'subscription_id', label: 'Subscription ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    ],
    'gcp_assured_workloads': [
      { key: 'project_id', label: 'Project ID', type: 'text', placeholder: 'my-assured-project-123' },
      { key: 'service_account_key', label: 'Service Account Key JSON', type: 'textarea', placeholder: 'Paste service account key JSON here' },
    ],
    'gcp_commercial': [
      { key: 'project_id', label: 'Project ID', type: 'text', placeholder: 'my-project-123' },
      { key: 'service_account_key', label: 'Service Account Key JSON', type: 'textarea', placeholder: 'Paste service account key JSON here' },
    ],
  };

  var currentEditId = null;
  var allClients = [];
  var currentContainer = null;
  var deleteClientId = null;
  var clientSearchQuery = '';
  var clientEnvFilter = '';
  var clientLevelFilter = '';

  async function renderClients(container) {
    container.innerHTML = app.skeletonTable(8);
    currentContainer = container;

    var clients;
    try {
      clients = await app.api.get('/clients');
    } catch (err) {
      clients = [];
    }

    var items = clients.clients || clients || [];
    allClients = items;

    container.innerHTML = buildHeader() + buildClientSearchBar() +
      '<div id="clients-table-wrap">' + buildClientTable(items) + '</div>' +
      buildClientModal();

    var table = container.querySelector('.data-table');
    if (table) app.makeSortable(table);

    initClientEvents(container);

    // Re-apply filters if they were active before re-render (e.g. after save/delete)
    if (clientSearchQuery || clientEnvFilter || clientLevelFilter) {
      var searchInput = container.querySelector('#client-search');
      var envSelect = container.querySelector('#client-filter-env');
      var levelSelect = container.querySelector('#client-filter-level');
      if (searchInput) searchInput.value = clientSearchQuery;
      if (envSelect) envSelect.value = clientEnvFilter;
      if (levelSelect) levelSelect.value = clientLevelFilter;
      applyClientFilters();
    }
  }

  function buildHeader() {
    return '<div class="flex items-center justify-between mb-lg">' +
      '<div>' +
        '<h2>Client Management</h2>' +
        '<p class="text-secondary text-small mt-sm">Manage your DIB contractor clients and their cloud environments</p>' +
      '</div>' +
      '<button class="btn btn-primary" id="btn-add-client" aria-label="Add a new client">' +
        '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/></svg>' +
        ' Add Client' +
      '</button>' +
    '</div>';
  }

  function buildClientSearchBar() {
    if (allClients.length === 0) return '';

    var envOptions = '<option value="">Environment</option>';
    ENVIRONMENTS.forEach(function (e) {
      envOptions += '<option value="' + e.value + '">' + e.label + '</option>';
    });

    return '<div class="search-filter-bar">' +
      '<div class="search-input-wrap">' +
        '<svg class="search-input-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/></svg>' +
        '<input type="text" class="search-input" id="client-search" placeholder="Search clients..." aria-label="Search clients by name" />' +
        '<button class="search-clear-btn hidden" id="client-search-clear" aria-label="Clear search" type="button">&times;</button>' +
      '</div>' +
      '<div class="filter-pills">' +
        '<select class="filter-pill" id="client-filter-env" aria-label="Filter by environment">' + envOptions + '</select>' +
        '<select class="filter-pill" id="client-filter-level" aria-label="Filter by CMMC level">' +
          '<option value="">Level</option>' +
          '<option value="L1">L1</option>' +
          '<option value="L2">L2</option>' +
          '<option value="L3">L3</option>' +
        '</select>' +
      '</div>' +
      '<span class="search-result-count" id="client-result-count"></span>' +
    '</div>';
  }

  function buildClientTable(items) {
    if (items.length === 0 && allClients.length > 0) {
      return '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>' +
        '<h3>No matching clients</h3>' +
        '<p>Try adjusting your search or filter criteria.</p>' +
      '</div></div>';
    }

    if (items.length === 0) {
      return '<div class="card"><div class="empty-state">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>' +
        '<h3>No clients yet</h3>' +
        '<p>Add your first client to start running CMMC compliance scans against their cloud environments.</p>' +
        '<button class="btn btn-primary" id="btn-add-client-empty" aria-label="Add first client">Add Your First Client</button>' +
      '</div></div>';
    }

    var rows = '';
    items.forEach(function (c) {
      var statusCls = 'badge-met';
      var statusLabel = 'Active';
      rows +=
        '<tr>' +
          '<td><strong class="clickable-text" data-client-id="' + app.escapeHtml(c.id) + '" tabindex="0" role="link" aria-label="View scan history for ' + app.escapeHtml(c.name) + '">' + app.escapeHtml(c.name) + '</strong></td>' +
          '<td>' + app.envDisplay(c.environment) + '</td>' +
          '<td>' + app.levelBadge(c.cmmc_level) + '</td>' +
          '<td>' + app.formatDateShort(c.updated_at) + '</td>' +
          '<td><span class="badge ' + statusCls + '">' + statusLabel + '</span></td>' +
          '<td class="cell-actions">' +
            '<button class="btn btn-ghost btn-icon btn-sm btn-edit-client" data-id="' + app.escapeHtml(c.id) + '" title="Edit client" aria-label="Edit ' + app.escapeHtml(c.name) + '">' +
              '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"/></svg>' +
            '</button>' +
            '<button class="btn btn-ghost btn-icon btn-sm btn-delete-client" data-id="' + app.escapeHtml(c.id) + '" data-name="' + app.escapeHtml(c.name) + '" title="Delete client" aria-label="Delete ' + app.escapeHtml(c.name) + '">' +
              '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>' +
            '</button>' +
          '</td>' +
        '</tr>';
    });

    return '<div class="card">' +
      '<div class="table-container">' +
        '<table class="data-table" aria-label="Clients list">' +
          '<thead><tr>' +
            '<th data-sort="name">Name <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="env">Environment <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="level">CMMC Level <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="scan">Last Scan <span class="sort-icon">\u2195</span></th>' +
            '<th data-sort="status">Status <span class="sort-icon">\u2195</span></th>' +
            '<th class="text-right">Actions</th>' +
          '</tr></thead>' +
          '<tbody>' + rows + '</tbody>' +
        '</table>' +
      '</div>' +
    '</div>';
  }

  function applyClientFilters() {
    var searchInput = document.getElementById('client-search');
    var envSelect = document.getElementById('client-filter-env');
    var levelSelect = document.getElementById('client-filter-level');
    var clearBtn = document.getElementById('client-search-clear');
    var countEl = document.getElementById('client-result-count');

    var query = searchInput ? searchInput.value.trim().toLowerCase() : '';
    var envVal = envSelect ? envSelect.value : '';
    var levelVal = levelSelect ? levelSelect.value : '';

    // Save state for re-render preservation
    clientSearchQuery = query;
    clientEnvFilter = envVal;
    clientLevelFilter = levelVal;

    // Toggle clear button visibility
    if (clearBtn) clearBtn.classList.toggle('hidden', !query);

    // Toggle active class on pills
    if (envSelect) envSelect.classList.toggle('active', !!envVal);
    if (levelSelect) levelSelect.classList.toggle('active', !!levelVal);

    // Filter
    var filtered = allClients.filter(function (c) {
      if (query && (c.name || '').toLowerCase().indexOf(query) === -1) return false;
      if (envVal && c.environment !== envVal) return false;
      if (levelVal && c.cmmc_level !== levelVal) return false;
      return true;
    });

    // Re-render table wrap
    var wrap = document.getElementById('clients-table-wrap');
    if (wrap) {
      wrap.innerHTML = buildClientTable(filtered);
      var table = wrap.querySelector('.data-table');
      if (table) app.makeSortable(table);
    }

    // Update result count
    var isFiltered = query || envVal || levelVal;
    if (countEl) {
      countEl.textContent = isFiltered ? filtered.length + ' of ' + allClients.length + ' clients' : '';
    }
  }

  function buildClientModal() {
    var envOptions = '<option value="">Select environment...</option>';
    ENVIRONMENTS.forEach(function (e) {
      envOptions += '<option value="' + e.value + '">' + e.label + '</option>';
    });

    return '<div class="modal-overlay" id="client-modal" aria-hidden="true" role="dialog" aria-labelledby="client-modal-title">' +
      '<div class="modal modal-lg">' +
        '<div class="modal-header">' +
          '<h3 id="client-modal-title">Add Client</h3>' +
          '<button class="modal-close" id="client-modal-close" aria-label="Close dialog">' +
            '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>' +
          '</button>' +
        '</div>' +
        '<div class="modal-body">' +
          '<form id="client-form">' +
            '<div class="form-group">' +
              '<label class="form-label" for="client-name">Client Name <span class="required">*</span></label>' +
              '<input class="form-input" id="client-name" type="text" placeholder="e.g., Northrop Grumman CUI Division" required aria-required="true" />' +
            '</div>' +
            '<div class="form-row">' +
              '<div class="form-group">' +
                '<label class="form-label" for="client-env">Environment <span class="required">*</span></label>' +
                '<select class="form-select" id="client-env" required aria-required="true">' + envOptions + '</select>' +
              '</div>' +
              '<div class="form-group">' +
                '<label class="form-label" for="client-level">CMMC Level <span class="required">*</span></label>' +
                '<select class="form-select" id="client-level" required aria-required="true">' +
                  '<option value="">Select level...</option>' +
                  '<option value="L1">Level 1 (Foundational)</option>' +
                  '<option value="L2">Level 2 (Advanced)</option>' +
                  '<option value="L3">Level 3 (Expert)</option>' +
                '</select>' +
              '</div>' +
            '</div>' +
            '<div id="credential-section">' +
              '<div style="margin-top:8px;border-top:1px solid var(--color-border-light);padding-top:16px">' +
                '<div class="form-label" style="margin-bottom:2px">Cloud Credentials</div>' +
                '<div class="form-hint" style="margin-bottom:12px">Credentials are encrypted and stored securely.</div>' +
              '</div>' +
              '<div id="credential-fields" class="credential-fields"></div>' +
            '</div>' +
          '</form>' +
        '</div>' +
        '<div class="modal-footer">' +
          '<button class="btn btn-outline" id="btn-test-connection" type="button" disabled>Test Connection</button>' +
          '<button class="btn btn-outline" id="btn-cancel-client" type="button">Cancel</button>' +
          '<button class="btn btn-primary" id="btn-save-client" type="button">Save Client</button>' +
        '</div>' +
      '</div>' +
    '</div>' +

    /* Delete Confirmation Modal */
    '<div class="modal-overlay" id="delete-modal" aria-hidden="true" role="dialog" aria-labelledby="delete-modal-title">' +
      '<div class="modal">' +
        '<div class="modal-header">' +
          '<h3 id="delete-modal-title">Delete Client</h3>' +
          '<button class="modal-close" id="delete-modal-close" aria-label="Close dialog">' +
            '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>' +
          '</button>' +
        '</div>' +
        '<div class="modal-body">' +
          '<p>Are you sure you want to delete <strong id="delete-client-name"></strong>? This action cannot be undone. All scan history for this client will be permanently removed.</p>' +
        '</div>' +
        '<div class="modal-footer">' +
          '<button class="btn btn-outline" id="btn-cancel-delete" type="button">Cancel</button>' +
          '<button class="btn btn-primary" id="btn-confirm-delete" type="button" style="background:var(--color-not-met);border-color:var(--color-not-met)">Delete Client</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  function updateCredentialFields(env) {
    var container = document.getElementById('credential-fields');
    var testBtn = document.getElementById('btn-test-connection');
    if (!container) return;

    var fields = CREDENTIAL_FIELDS[env];
    if (!fields) {
      container.innerHTML = '';
      container.classList.remove('visible');
      if (testBtn) testBtn.disabled = true;
      return;
    }

    var html = '';
    fields.forEach(function (f) {
      html += '<div class="form-group">';
      html += '<label class="form-label" for="cred-' + f.key + '">' + app.escapeHtml(f.label) + ' <span class="required">*</span></label>';
      if (f.type === 'textarea') {
        html += '<textarea class="form-textarea form-input" id="cred-' + f.key + '" placeholder="' + app.escapeHtml(f.placeholder) + '" rows="4" required aria-required="true"></textarea>';
      } else {
        html += '<input class="form-input" id="cred-' + f.key + '" type="' + f.type + '" placeholder="' + app.escapeHtml(f.placeholder) + '" required aria-required="true" />';
      }
      html += '</div>';
    });

    container.innerHTML = html;
    container.classList.add('visible');
    if (testBtn) testBtn.disabled = false;
  }

  function updateLevelOptions(env) {
    var levelSelect = document.getElementById('client-level');
    if (!levelSelect) return;

    var envConfig = ENVIRONMENTS.find(function (e) { return e.value === env; });
    var allowed = envConfig ? envConfig.levels : ['L1', 'L2', 'L3'];
    var labels = { L1: 'Level 1 (Foundational)', L2: 'Level 2 (Advanced)', L3: 'Level 3 (Expert)' };

    var currentVal = levelSelect.value;
    levelSelect.innerHTML = '<option value="">Select level...</option>';
    allowed.forEach(function (l) {
      var selected = l === currentVal ? ' selected' : '';
      levelSelect.innerHTML += '<option value="' + l + '"' + selected + '>' + labels[l] + '</option>';
    });
  }

  function gatherFormData() {
    var name = document.getElementById('client-name').value.trim();
    var env = document.getElementById('client-env').value;
    var level = document.getElementById('client-level').value;
    var credentials = {};

    var fields = CREDENTIAL_FIELDS[env] || [];
    fields.forEach(function (f) {
      var el = document.getElementById('cred-' + f.key);
      if (el) credentials[f.key] = el.value.trim();
    });

    return { name: name, environment: env, cmmc_level: level, credentials_config: credentials };
  }

  function validateForm(data) {
    if (!data.name) return 'Client name is required.';
    if (!data.environment) return 'Please select an environment.';
    if (!data.cmmc_level) return 'Please select a CMMC level.';

    var fields = CREDENTIAL_FIELDS[data.environment] || [];
    for (var i = 0; i < fields.length; i++) {
      if (!data.credentials_config[fields[i].key]) {
        return fields[i].label + ' is required.';
      }
    }
    return null;
  }

  function resetForm() {
    currentEditId = null;
    var form = document.getElementById('client-form');
    if (form) form.reset();
    var container = document.getElementById('credential-fields');
    if (container) {
      container.innerHTML = '';
      container.classList.remove('visible');
    }
    var title = document.getElementById('client-modal-title');
    if (title) title.textContent = 'Add Client';
    var testBtn = document.getElementById('btn-test-connection');
    if (testBtn) testBtn.disabled = true;
  }

  function populateForm(client) {
    currentEditId = client.id;
    var title = document.getElementById('client-modal-title');
    if (title) title.textContent = 'Edit Client';

    var nameEl = document.getElementById('client-name');
    var envEl = document.getElementById('client-env');
    var levelEl = document.getElementById('client-level');

    if (nameEl) nameEl.value = client.name || '';
    if (envEl) {
      envEl.value = client.environment || '';
      updateCredentialFields(client.environment);
      updateLevelOptions(client.environment);
    }
    if (levelEl) levelEl.value = client.cmmc_level || '';

    if (client.credentials_config) {
      Object.keys(client.credentials_config).forEach(function (key) {
        var el = document.getElementById('cred-' + key);
        if (el) el.value = client.credentials_config[key] || '';
      });
    }
  }

  async function handleEditClient(btn) {
    var id = btn.dataset.id;
    try {
      var client = await app.api.get('/clients/' + id);
      populateForm(client);
      app.openModal('client-modal');
    } catch (err) {
      var row = btn.closest('tr');
      if (row) {
        populateForm({
          id: id,
          name: row.querySelector('strong').textContent,
          environment: '',
          level: '',
          credentials_config: {},
        });
        app.openModal('client-modal');
      }
    }
  }

  function initClientEvents(container) {
    // Add Client button (header)
    var addBtn = container.querySelector('#btn-add-client');
    var openAdd = function () {
      resetForm();
      app.openModal('client-modal');
    };
    if (addBtn) addBtn.addEventListener('click', openAdd);

    // Close modal buttons
    var closeClientModal = function () { app.closeModal('client-modal'); };
    var closeBtn = container.querySelector('#client-modal-close');
    var cancelBtn = container.querySelector('#btn-cancel-client');
    if (closeBtn) closeBtn.addEventListener('click', closeClientModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeClientModal);

    // Environment change (in modal)
    var envSelect = container.querySelector('#client-env');
    if (envSelect) {
      envSelect.addEventListener('change', function () {
        updateCredentialFields(envSelect.value);
        updateLevelOptions(envSelect.value);
      });
    }

    // Test Connection
    var testBtn = container.querySelector('#btn-test-connection');
    if (testBtn) {
      testBtn.addEventListener('click', async function () {
        var data = gatherFormData();
        var error = validateForm(data);
        if (error) {
          app.showToast(error, 'warning');
          return;
        }
        testBtn.disabled = true;
        testBtn.innerHTML = '<span class="spinner sm"></span> Testing...';
        try {
          await app.api.post('/clients/verify', { environment: data.environment, credentials_config: data.credentials_config });
          app.showToast('Connection successful. Credentials are valid.', 'success');
        } catch (err) {
          app.showToast('Connection failed: ' + (err.message || 'Unable to verify credentials.'), 'error');
        } finally {
          testBtn.disabled = false;
          testBtn.innerHTML = 'Test Connection';
        }
      });
    }

    // Save Client
    var saveBtn = container.querySelector('#btn-save-client');
    if (saveBtn) {
      saveBtn.addEventListener('click', async function () {
        var data = gatherFormData();
        var error = validateForm(data);
        if (error) {
          app.showToast(error, 'warning');
          return;
        }
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<span class="spinner sm"></span> Saving...';
        try {
          if (currentEditId) {
            await app.api.put('/clients/' + currentEditId, data);
            app.showToast('Client updated successfully.', 'success');
          } else {
            await app.api.post('/clients', data);
            app.showToast('Client added successfully.', 'success');
          }
          app.closeModal('client-modal');
          renderClients(container);
        } catch (err) {
          app.showToast('Failed to save client: ' + (err.message || 'Unknown error'), 'error');
        } finally {
          saveBtn.disabled = false;
          saveBtn.innerHTML = 'Save Client';
        }
      });
    }

    // Delete modal buttons
    var closeDeleteModal = function () { app.closeModal('delete-modal'); };
    var deleteCloseBtn = container.querySelector('#delete-modal-close');
    var cancelDeleteBtn = container.querySelector('#btn-cancel-delete');
    if (deleteCloseBtn) deleteCloseBtn.addEventListener('click', closeDeleteModal);
    if (cancelDeleteBtn) cancelDeleteBtn.addEventListener('click', closeDeleteModal);

    var confirmDeleteBtn = container.querySelector('#btn-confirm-delete');
    if (confirmDeleteBtn) {
      confirmDeleteBtn.addEventListener('click', async function () {
        if (!deleteClientId) return;
        confirmDeleteBtn.disabled = true;
        confirmDeleteBtn.innerHTML = '<span class="spinner sm"></span> Deleting...';
        try {
          await app.api.delete('/clients/' + deleteClientId);
          app.showToast('Client deleted successfully.', 'success');
          app.closeModal('delete-modal');
          renderClients(container);
        } catch (err) {
          app.showToast('Failed to delete client: ' + (err.message || 'Unknown error'), 'error');
        } finally {
          confirmDeleteBtn.disabled = false;
          confirmDeleteBtn.innerHTML = 'Delete Client';
        }
      });
    }

    // Search & filter events
    var searchInput = container.querySelector('#client-search');
    var clearBtn = container.querySelector('#client-search-clear');
    var filterEnv = container.querySelector('#client-filter-env');
    var filterLevel = container.querySelector('#client-filter-level');

    if (searchInput) {
      searchInput.addEventListener('input', applyClientFilters);
    }
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        if (searchInput) searchInput.value = '';
        applyClientFilters();
      });
    }
    if (filterEnv) {
      filterEnv.addEventListener('change', applyClientFilters);
    }
    if (filterLevel) {
      filterLevel.addEventListener('change', applyClientFilters);
    }

    // Event delegation for table row actions
    container.addEventListener('click', function (e) {
      // "Add Your First Client" button inside empty state
      var addEmpty = e.target.closest('#btn-add-client-empty');
      if (addEmpty) {
        openAdd();
        return;
      }

      // Edit client button
      var editBtn = e.target.closest('.btn-edit-client');
      if (editBtn) {
        handleEditClient(editBtn);
        return;
      }

      // Delete client button
      var delBtn = e.target.closest('.btn-delete-client');
      if (delBtn) {
        deleteClientId = delBtn.dataset.id;
        var nameEl = document.getElementById('delete-client-name');
        if (nameEl) nameEl.textContent = delBtn.dataset.name || 'this client';
        app.openModal('delete-modal');
        return;
      }

      // Click client name to view scan history
      var clientLink = e.target.closest('.clickable-text[data-client-id]');
      if (clientLink) {
        app.navigate('scans');
        return;
      }
    });

    // Keyboard accessibility for client name links (delegation)
    container.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        var clientLink = e.target.closest('.clickable-text[data-client-id]');
        if (clientLink) {
          e.preventDefault();
          app.navigate('scans');
        }
      }
    });

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

  window.renderClients = renderClients;

})();
