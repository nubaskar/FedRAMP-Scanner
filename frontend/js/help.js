/* ==========================================================================
   FedRAMP Cloud Compliance Scanner  - Help & Documentation View
   Four tabs: User Guide + API Reference + Assessment Methodology + QA Validation
   ========================================================================== */

(function () {
  'use strict';

  var activeTab = 'guide';

  function renderHelp(container) {
    container.innerHTML =
      '<div class="help-tabs">' +
        '<div class="help-tab active" data-tab="guide">User Guide</div>' +
        '<div class="help-tab" data-tab="api">API Reference</div>' +
        '<div class="help-tab" data-tab="methodology">Assessment Methodology</div>' +
        '<div class="help-tab" data-tab="qa">QA Validation</div>' +
      '</div>' +
      '<div class="help-tab-content active" id="help-tab-guide">' + renderUserGuide() + '</div>' +
      '<div class="help-tab-content" id="help-tab-api">' + renderAPIReference() + '</div>' +
      '<div class="help-tab-content" id="help-tab-methodology">' + renderMethodology() + '</div>' +
      '<div class="help-tab-content" id="help-tab-qa">' + renderQAValidation() + '</div>';

    // Tab switching
    container.querySelectorAll('.help-tab').forEach(function (tab) {
      tab.addEventListener('click', function () {
        var target = tab.dataset.tab;
        if (target === activeTab) return;
        activeTab = target;

        container.querySelectorAll('.help-tab').forEach(function (t) { t.classList.remove('active'); });
        container.querySelectorAll('.help-tab-content').forEach(function (c) { c.classList.remove('active'); });
        tab.classList.add('active');
        var panel = document.getElementById('help-tab-' + target);
        if (panel) panel.classList.add('active');
      });
    });

    // Accordion toggle
    container.querySelectorAll('.help-accordion-header').forEach(function (header) {
      header.addEventListener('click', function () {
        var item = header.parentElement;
        item.classList.toggle('open');
      });
    });

    // Method toggle (Web Console / CLI)
    container.querySelectorAll('.help-method-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var toggleGroup = btn.parentElement;
        var wrapper = toggleGroup.parentElement;
        var method = btn.dataset.method;

        toggleGroup.querySelectorAll('.help-method-btn').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');

        wrapper.querySelectorAll('.help-method-content').forEach(function (c) { c.classList.remove('active'); });
        var target = wrapper.querySelector('.help-method-content[data-method="' + method + '"]');
        if (target) target.classList.add('active');
      });
    });

    // Copy CLI command
    container.querySelectorAll('.help-cli-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var cmd = btn.getAttribute('data-cmd');
        if (!cmd) return;
        navigator.clipboard.writeText(cmd).then(function () {
          var orig = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(function () { btn.textContent = orig; }, 1500);
        });
      });
    });
  }

  /* ---------- User Guide Tab ---------- */
  function renderUserGuide() {
    return '' +
      // Getting Started
      '<div class="card mb-lg">' +
        '<div class="card-body">' +
          '<h3 class="help-section-title">Getting Started</h3>' +
          '<p class="help-section-desc">' +
            'The FedRAMP Cloud Compliance Scanner evaluates your clients\u2019 cloud environments against ' +
            'FedRAMP requirements (NIST 800-53 Rev 5). The workflow is simple:' +
          '</p>' +
          '<div class="help-workflow">' +
            workflowStep('1', 'Add a Client', 'Configure cloud credentials for AWS, Azure, or GCP') +
            workflowStep('2', 'Run a Scan', 'Select the client and FedRAMP baseline, then start the scan') +
            workflowStep('3', 'View Results', 'Review findings by domain with live API evidence') +
            workflowStep('4', 'Download Reports', 'Export HTML or XLSX reports for the assessment') +
          '</div>' +
        '</div>' +
      '</div>' +

      // Step 1: Add a Client
      '<div class="card mb-lg">' +
        '<div class="card-body">' +
          '<h3 class="help-section-title">' +
            '<span class="help-step-number">1</span> Add a Client' +
          '</h3>' +
          '<p class="help-section-desc">' +
            'Navigate to <strong>Clients</strong> and click <strong>Add Client</strong>. ' +
            'Enter the client name, select the cloud environment and FedRAMP baseline, then provide ' +
            'the read-only credentials for the target cloud account.' +
          '</p>' +

          '<div class="help-accordion">' +
            // AWS
            '<div class="help-accordion-item">' +
              '<div class="help-accordion-header">' +
                '<svg class="help-accordion-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>' +
                '<span class="tag tag-aws">AWS</span>' +
                '<span class="help-accordion-title">AWS Commercial / GovCloud</span>' +
              '</div>' +
              '<div class="help-accordion-body">' +
                '<div class="help-accordion-body-inner">' +
                  '<p>Create a read-only IAM role in the client\u2019s AWS account with a trust policy that allows your scanner account to assume it.</p>' +
                  '<div class="help-info-box">' +
                    '<strong>Scope:</strong> Each client entry scans a single AWS account. If the client has multiple AWS accounts ' +
                    'in scope (e.g. production, staging, shared services), add each account as a separate client.' +
                  '</div>' +
                  methodToggle('aws') +
                  '<div class="help-method-content active" data-method="console">' +
                    '<ol class="help-steps-list">' +
                      '<li>In the client\u2019s AWS Console, go to <strong>IAM \u2192 Roles \u2192 Create Role</strong>.</li>' +
                      '<li>Select <strong>Another AWS account</strong> and enter your scanner account ID.</li>' +
                      '<li>Check <strong>Require external ID</strong> and enter a unique external ID.</li>' +
                      '<li>Attach the <code>SecurityAudit</code> and <code>ViewOnlyAccess</code> managed policies.</li>' +
                      '<li>Name the role (e.g. <code>FedRAMPScannerReadOnly</code>) and create it.</li>' +
                      '<li>Copy the <strong>Role ARN</strong> from the role summary page.</li>' +
                    '</ol>' +
                  '</div>' +
                  '<div class="help-method-content" data-method="cli">' +
                    '<p>Run these commands in the <strong>client\u2019s AWS account</strong> using the AWS CLI.</p>' +
                    '<ol class="help-steps-list">' +
                      '<li>Create the cross-account trust policy and IAM role:</li>' +
                    '</ol>' +
                    cliBlock('aws iam create-role --role-name FedRAMPScannerReadOnly \\\n  --assume-role-policy-document \'{\n    "Version": "2012-10-17",\n    "Statement": [{\n      "Effect": "Allow",\n      "Principal": {"AWS": "arn:aws:iam::<SCANNER_ACCOUNT_ID>:root"},\n      "Action": "sts:AssumeRole",\n      "Condition": {"StringEquals": {"sts:ExternalId": "<EXTERNAL_ID>"}}\n    }]\n  }\'') +
                    '<ol class="help-steps-list" start="2">' +
                      '<li>Attach the <code>SecurityAudit</code> managed policy:</li>' +
                    '</ol>' +
                    cliBlock('aws iam attach-role-policy --role-name FedRAMPScannerReadOnly \\\n  --policy-arn arn:aws:iam::aws:policy/SecurityAudit') +
                    '<ol class="help-steps-list" start="3">' +
                      '<li>Attach the <code>ViewOnlyAccess</code> managed policy:</li>' +
                    '</ol>' +
                    cliBlock('aws iam attach-role-policy --role-name FedRAMPScannerReadOnly \\\n  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess') +
                    '<ol class="help-steps-list" start="4">' +
                      '<li>Retrieve the Role ARN:</li>' +
                    '</ol>' +
                    cliBlock('aws iam get-role --role-name FedRAMPScannerReadOnly \\\n  --query "Role.Arn" --output text') +
                  '</div>' +
                  '<div class="help-cred-fields">' +
                    '<h5>Required Fields</h5>' +
                    credField('Role ARN', 'arn:aws:iam::123456789012:role/FedRAMPScannerReadOnly') +
                    credField('External ID', 'A unique string shared between you and the client') +
                    credField('Region', 'e.g. us-east-1, us-gov-west-1') +
                  '</div>' +
                '</div>' +
              '</div>' +
            '</div>' +

            // Azure
            '<div class="help-accordion-item">' +
              '<div class="help-accordion-header">' +
                '<svg class="help-accordion-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>' +
                '<span class="tag tag-azure">Azure</span>' +
                '<span class="help-accordion-title">Azure Commercial / Government</span>' +
              '</div>' +
              '<div class="help-accordion-body">' +
                '<div class="help-accordion-body-inner">' +
                  '<p>Register an App in Microsoft Entra ID (Azure AD) in the client\u2019s tenant and grant it read-only access to the target subscription.</p>' +
                  '<div class="help-info-box">' +
                    '<strong>Scope:</strong> Each client entry scans a single Azure subscription. If the client has multiple subscriptions ' +
                    'in scope (e.g. production, development, shared services), add each subscription as a separate client. ' +
                    'The same App registration can be reused across subscriptions \u2014 just assign the Reader and Security Reader roles ' +
                    'on each additional subscription and create a new client entry with the same Tenant ID, Client ID, and Client Secret ' +
                    'but a different Subscription ID.' +
                  '</div>' +
                  methodToggle('azure') +
                  '<div class="help-method-content active" data-method="console">' +
                    '<ol class="help-steps-list">' +
                      '<li>In the Azure Portal, go to <strong>Entra ID \u2192 App registrations \u2192 New registration</strong>.</li>' +
                      '<li>Name it (e.g. <code>FedRAMP Scanner</code>), set single-tenant, and register.</li>' +
                      '<li>Go to <strong>Certificates & secrets \u2192 New client secret</strong> and copy the value.</li>' +
                      '<li>Go to the target <strong>Subscription \u2192 Access control (IAM) \u2192 Add role assignment</strong>.</li>' +
                      '<li>Assign the <strong>Reader</strong> and <strong>Security Reader</strong> roles to the registered app.</li>' +
                      '<li>For full Entra ID checks, add <strong>Microsoft Graph API</strong> Application permissions:<br>' +
                        '<code>Directory.Read.All</code>, <code>Policy.Read.All</code>, <code>User.Read.All</code>, ' +
                        '<code>AuditLog.Read.All</code>, <code>Reports.Read.All</code>, ' +
                        '<code>IdentityRiskEvent.Read.All</code>, <code>IdentityRiskyUser.Read.All</code></li>' +
                      '<li>Click <strong>Grant admin consent</strong> for the tenant.</li>' +
                    '</ol>' +
                  '</div>' +
                  '<div class="help-method-content" data-method="cli">' +
                    '<p>Run these commands in the <strong>client\u2019s Azure tenant</strong> using the Azure CLI.</p>' +
                    '<ol class="help-steps-list">' +
                      '<li>Create the app registration:</li>' +
                    '</ol>' +
                    cliBlock('az ad app create --display-name "FedRAMP Scanner" \\\n  --sign-in-audience AzureADMyOrg') +
                    '<ol class="help-steps-list" start="2">' +
                      '<li>Create a service principal for the app:</li>' +
                    '</ol>' +
                    cliBlock('APP_ID=$(az ad app list --display-name "FedRAMP Scanner" \\\n  --query "[0].appId" -o tsv)\naz ad sp create --id $APP_ID') +
                    '<ol class="help-steps-list" start="3">' +
                      '<li>Create a client secret (save the output):</li>' +
                    '</ol>' +
                    cliBlock('az ad app credential reset --id $APP_ID --append \\\n  --display-name "fedramp-scanner-secret" --years 1') +
                    '<ol class="help-steps-list" start="4">' +
                      '<li>Assign <code>Reader</code> role on the subscription:</li>' +
                    '</ol>' +
                    cliBlock('SUB_ID=$(az account show --query id -o tsv)\naz role assignment create --assignee $APP_ID \\\n  --role "Reader" --scope /subscriptions/$SUB_ID') +
                    '<ol class="help-steps-list" start="5">' +
                      '<li>Assign <code>Security Reader</code> role:</li>' +
                    '</ol>' +
                    cliBlock('az role assignment create --assignee $APP_ID \\\n  --role "Security Reader" --scope /subscriptions/$SUB_ID') +
                    '<ol class="help-steps-list" start="6">' +
                      '<li>Add Microsoft Graph API permissions:</li>' +
                    '</ol>' +
                    cliBlock('GRAPH_ID=00000003-0000-0000-c000-000000000000\nfor PERM in 7ab1d382-f21e-4acd-a863-ba3e13f7da61 \\\n  246dd0d5-5bd0-4def-940b-0421030a5b68 \\\n  df021288-bdef-4463-88db-98f22de89214 \\\n  b0afded3-3588-46d8-8b3d-9842eff778da \\\n  230c1aed-a721-4c5d-9cb4-a90514e508ef \\\n  db06fb33-1953-4b7b-a2ac-f1e2c854f7ae \\\n  dc5007c0-2d7d-4c42-879c-2dab87571379; do\n  az ad app permission add --id $APP_ID \\\n    --api $GRAPH_ID --api-permissions $PERM=Role\ndone') +
                    '<ol class="help-steps-list" start="7">' +
                      '<li>Grant admin consent for the tenant:</li>' +
                    '</ol>' +
                    cliBlock('az ad app permission admin-consent --id $APP_ID') +
                  '</div>' +
                  '<div class="help-cred-fields">' +
                    '<h5>Required Fields</h5>' +
                    credField('Tenant ID', 'The Entra ID tenant GUID') +
                    credField('Client ID', 'The App registration Application (client) ID') +
                    credField('Client Secret', 'The secret value created in step 3') +
                    credField('Subscription ID', 'The target Azure subscription GUID') +
                  '</div>' +
                '</div>' +
              '</div>' +
            '</div>' +

            // GCP
            '<div class="help-accordion-item">' +
              '<div class="help-accordion-header">' +
                '<svg class="help-accordion-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>' +
                '<span class="tag tag-gcp">GCP</span>' +
                '<span class="help-accordion-title">GCP Commercial / Assured Workloads</span>' +
              '</div>' +
              '<div class="help-accordion-body">' +
                '<div class="help-accordion-body-inner">' +
                  '<p>Create a service account in the client\u2019s GCP project with the required roles and download the JSON key.</p>' +
                  '<div class="help-info-box">' +
                    '<strong>Scope:</strong> Each client entry scans a single GCP project. If the client has multiple projects ' +
                    'in scope, add each project as a separate client with its own service account key.' +
                  '</div>' +
                  methodToggle('gcp') +
                  '<div class="help-method-content active" data-method="console">' +
                    '<ol class="help-steps-list">' +
                      '<li>In the GCP Console, go to <strong>IAM & Admin \u2192 Service Accounts \u2192 Create Service Account</strong>.</li>' +
                      '<li>Name it (e.g. <code>fedramp-scanner</code>).</li>' +
                      '<li>Grant the following <strong>IAM roles</strong> at the project level:<br>' +
                        '<code>Viewer</code> (basic read access), ' +
                        '<code>Security Reviewer</code> (Security Command Center), ' +
                        '<code>Security Center Admin</code> (SCC findings &amp; notifications)</li>' +
                      '<li>For full coverage, also enable these <strong>APIs</strong> on the project:<br>' +
                        '<code>Cloud Asset API</code>, <code>Cloud Resource Manager API</code>, ' +
                        '<code>Security Command Center API</code>, <code>OS Config API</code>, ' +
                        '<code>Binary Authorization API</code>, <code>Container Analysis API</code>, ' +
                        '<code>Web Security Scanner API</code>, <code>Cloud DNS API</code>, ' +
                        '<code>Recommender API</code>, <code>SQL Admin API</code></li>' +
                      '<li>Go to <strong>Keys \u2192 Add Key \u2192 Create new key \u2192 JSON</strong>.</li>' +
                      '<li>Download the JSON key file and store it securely.</li>' +
                      '<li><em>Note:</em> Google Workspace checks (2SV, password policy, login challenges) require ' +
                        '<strong>domain-wide delegation</strong> with Admin SDK scopes. These checks return ' +
                        '\u201cmanual\u201d status if delegation is not configured.</li>' +
                    '</ol>' +
                  '</div>' +
                  '<div class="help-method-content" data-method="cli">' +
                    '<p>Run these commands in the <strong>client\u2019s GCP project</strong> using the gcloud CLI.</p>' +
                    '<ol class="help-steps-list">' +
                      '<li>Create the service account:</li>' +
                    '</ol>' +
                    cliBlock('PROJECT_ID=$(gcloud config get-value project)\ngcloud iam service-accounts create fedramp-scanner \\\n  --display-name="FedRAMP Scanner" \\\n  --project=$PROJECT_ID') +
                    '<ol class="help-steps-list" start="2">' +
                      '<li>Grant <code>Viewer</code> role:</li>' +
                    '</ol>' +
                    cliBlock('SA_EMAIL=fedramp-scanner@${PROJECT_ID}.iam.gserviceaccount.com\ngcloud projects add-iam-policy-binding $PROJECT_ID \\\n  --member="serviceAccount:$SA_EMAIL" \\\n  --role="roles/viewer"') +
                    '<ol class="help-steps-list" start="3">' +
                      '<li>Grant <code>Security Reviewer</code> role:</li>' +
                    '</ol>' +
                    cliBlock('gcloud projects add-iam-policy-binding $PROJECT_ID \\\n  --member="serviceAccount:$SA_EMAIL" \\\n  --role="roles/iam.securityReviewer"') +
                    '<ol class="help-steps-list" start="4">' +
                      '<li>Grant <code>Security Center Admin</code> role:</li>' +
                    '</ol>' +
                    cliBlock('gcloud projects add-iam-policy-binding $PROJECT_ID \\\n  --member="serviceAccount:$SA_EMAIL" \\\n  --role="roles/securitycenter.admin"') +
                    '<ol class="help-steps-list" start="5">' +
                      '<li>Enable required APIs:</li>' +
                    '</ol>' +
                    cliBlock('gcloud services enable \\\n  cloudasset.googleapis.com \\\n  cloudresourcemanager.googleapis.com \\\n  securitycenter.googleapis.com \\\n  osconfig.googleapis.com \\\n  binaryauthorization.googleapis.com \\\n  containeranalysis.googleapis.com \\\n  websecurityscanner.googleapis.com \\\n  dns.googleapis.com \\\n  recommender.googleapis.com \\\n  sqladmin.googleapis.com \\\n  --project=$PROJECT_ID') +
                    '<ol class="help-steps-list" start="6">' +
                      '<li>Create and download the JSON key:</li>' +
                    '</ol>' +
                    cliBlock('gcloud iam service-accounts keys create fedramp-scanner-key.json \\\n  --iam-account=$SA_EMAIL \\\n  --project=$PROJECT_ID') +
                    '<div class="help-info-box">' +
                      '<strong>Note:</strong> Google Workspace checks (2SV, password policy, login challenges) require ' +
                      'domain-wide delegation with Admin SDK scopes. These checks return "manual" status if delegation is not configured.' +
                    '</div>' +
                  '</div>' +
                  '<div class="help-cred-fields">' +
                    '<h5>Required Fields</h5>' +
                    credField('Project ID', 'The GCP project ID (not the project number)') +
                    credField('Service Account Key', 'The full JSON key file contents') +
                  '</div>' +
                '</div>' +
              '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      // Step 2: Run a Scan
      '<div class="card mb-lg">' +
        '<div class="card-body">' +
          '<h3 class="help-section-title">' +
            '<span class="help-step-number">2</span> Run a Scan' +
          '</h3>' +
          '<ol class="help-steps-list">' +
            '<li>Navigate to <strong>Scans</strong> in the sidebar.</li>' +
            '<li>Click <strong>New Scan</strong> and select the client from the dropdown.</li>' +
            '<li>Confirm the FedRAMP baseline and cloud environment, then click <strong>Start Scan</strong>.</li>' +
            '<li>The scan runs asynchronously. The status will update from <code>pending</code> \u2192 <code>running</code> \u2192 <code>completed</code>.</li>' +
            '<li>You can navigate away \u2014 the scan continues in the background.</li>' +
          '</ol>' +
          '<div class="help-info-box">' +
            '<strong>Scan scope:</strong> The scanner evaluates 496 automated checks across 20 FedRAMP control families. ' +
            'Policy/process controls that cannot be automated are flagged as "Manual Review Required." ' +
            'A full scan typically completes in 2\u20135 minutes depending on the cloud environment size.' +
          '</div>' +
        '</div>' +
      '</div>' +

      // Step 3: View Results
      '<div class="card mb-lg">' +
        '<div class="card-body">' +
          '<h3 class="help-section-title">' +
            '<span class="help-step-number">3</span> View Results & Evidence' +
          '</h3>' +
          '<ol class="help-steps-list">' +
            '<li>Click on a completed scan to open the detail view.</li>' +
            '<li>Findings are grouped by control family (AC, AU, CM, CP, etc.) in expandable accordions.</li>' +
            '<li>Each finding shows the control ID, check name, status (Met / Not Met / Manual Review), and severity.</li>' +
            '<li>Click the <strong>Evidence</strong> button on any finding to view live API evidence \u2014 the raw cloud configuration data that was evaluated.</li>' +
          '</ol>' +
        '</div>' +
      '</div>' +

      // Step 4: Download Reports
      '<div class="card mb-lg">' +
        '<div class="card-body">' +
          '<h3 class="help-section-title">' +
            '<span class="help-step-number">4</span> Download Reports' +
          '</h3>' +
          '<ol class="help-steps-list">' +
            '<li>Navigate to <strong>Reports</strong> or open a completed scan detail view.</li>' +
            '<li>Click <strong>Download HTML</strong> for a self-contained, printable report.</li>' +
            '<li>Click <strong>Download XLSX</strong> for a spreadsheet with all findings.</li>' +
          '</ol>' +
          '<div class="help-info-box">' +
            '<strong>Demo reports:</strong> To preview the report format without running a scan, visit ' +
            '<code>/api/reports/demo/html</code> or <code>/api/reports/demo/xlsx</code>. ' +
            'These contain realistic mock findings across all 20 families.' +
          '</div>' +
        '</div>' +
      '</div>';
  }

  /* ---------- API Reference Tab ---------- */
  function renderAPIReference() {
    var apiBase = (window.app && window.app.CONFIG) ? window.app.CONFIG.API_BASE : '/api';
    var baseUrl = apiBase;
    // Derive backend origin for Swagger UI link (strip /api suffix)
    var backendOrigin = apiBase.replace(/\/api$/, '');

    return '' +
      // Overview
      '<div class="card mb-lg">' +
        '<div class="card-body">' +
          '<h3 class="help-section-title">API Overview</h3>' +
          '<p class="help-section-desc">' +
            'The FedRAMP Scanner exposes a RESTful API for managing clients, scans, and reports. ' +
            'All endpoints are prefixed with <code>/api</code>.' +
          '</p>' +
          '<div class="help-api-details">' +
            '<div class="help-api-detail-row">' +
              '<span class="help-api-label">Base URL</span>' +
              '<code class="help-api-value">' + escapeHtml(baseUrl) + '</code>' +
            '</div>' +
            '<div class="help-api-detail-row">' +
              '<span class="help-api-label">Auth</span>' +
              '<span class="help-api-value">Bearer token via <code>Authorization: Bearer &lt;jwt&gt;</code></span>' +
            '</div>' +
            '<div class="help-api-detail-row">' +
              '<span class="help-api-label">Format</span>' +
              '<span class="help-api-value">JSON request/response bodies</span>' +
            '</div>' +
          '</div>' +
          '<div class="mt-md">' +
            '<a href="' + backendOrigin + '/api/docs" target="_blank" rel="noopener" class="btn btn-primary">' +
              '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>' +
              'Open Interactive API Docs' +
            '</a>' +
          '</div>' +
        '</div>' +
      '</div>' +

      // Auth endpoints
      endpointSection('Authentication', [
        { method: 'GET', path: '/api/auth/login', desc: 'Redirect to Microsoft Entra ID for SSO authentication' },
        { method: 'GET', path: '/api/auth/callback', desc: 'Handle Entra ID callback, exchange code for JWT' },
        { method: 'POST', path: '/api/auth/logout', desc: 'Logout and return Entra ID logout URL' },
        { method: 'GET', path: '/api/auth/me', desc: 'Get current user info from JWT claims' },
        { method: 'GET', path: '/api/auth/config', desc: 'Get authentication mode (SSO or password)' },
      ]) +

      // Clients endpoints
      endpointSection('Clients', [
        { method: 'POST', path: '/api/clients', desc: 'Create a new client with cloud credentials' },
        { method: 'GET', path: '/api/clients', desc: 'List all clients' },
        { method: 'GET', path: '/api/clients/{id}', desc: 'Get client details by ID' },
        { method: 'PUT', path: '/api/clients/{id}', desc: 'Update client configuration' },
        { method: 'DELETE', path: '/api/clients/{id}', desc: 'Delete client and all associated scan data' },
      ]) +

      // Scans endpoints
      endpointSection('Scans', [
        { method: 'POST', path: '/api/scans', desc: 'Start a new compliance scan (runs async)' },
        { method: 'GET', path: '/api/scans', desc: 'List scans (optional ?client_id= filter)' },
        { method: 'GET', path: '/api/scans/{id}', desc: 'Get scan details with all findings' },
        { method: 'GET', path: '/api/scans/{id}/summary', desc: 'Compliance summary grouped by status and domain' },
        { method: 'GET', path: '/api/scans/{id}/evidence/{control_id}', desc: 'Retrieve live API evidence for a specific control' },
        { method: 'DELETE', path: '/api/scans/{id}', desc: 'Delete scan and all findings' },
      ]) +

      // Reports endpoints
      endpointSection('Reports', [
        { method: 'GET', path: '/api/reports/{scan_id}/html', desc: 'Download HTML report for a completed scan' },
        { method: 'GET', path: '/api/reports/{scan_id}/xlsx', desc: 'Download XLSX report for a completed scan' },
        { method: 'GET', path: '/api/reports/demo/html', desc: 'Demo HTML report with 48 mock findings (no auth required)' },
        { method: 'GET', path: '/api/reports/demo/xlsx', desc: 'Demo XLSX report with 48 mock findings (no auth required)' },
      ]);
  }

  /* ---------- Helpers ---------- */
  function escapeHtml(str) {
    if (window.app && window.app.escapeHtml) return window.app.escapeHtml(str);
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function workflowStep(num, title, desc) {
    return '<div class="help-workflow-step">' +
      '<span class="help-step-number">' + num + '</span>' +
      '<div>' +
        '<strong>' + title + '</strong>' +
        '<div class="text-small text-muted">' + desc + '</div>' +
      '</div>' +
    '</div>';
  }

  function credField(label, hint) {
    return '<div class="help-cred-field">' +
      '<span class="help-cred-label">' + escapeHtml(label) + '</span>' +
      '<span class="help-cred-hint">' + escapeHtml(hint) + '</span>' +
    '</div>';
  }

  function methodToggle(id) {
    return '<div class="help-method-toggle" data-toggle-id="' + id + '">' +
      '<button class="help-method-btn active" data-method="console">Web Console</button>' +
      '<button class="help-method-btn" data-method="cli">CLI</button>' +
    '</div>';
  }

  function cliBlock(cmd) {
    var safeAttr = cmd.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return '<div class="help-cli-block">' +
      '<pre class="help-cli-pre">' + escapeHtml(cmd) + '</pre>' +
      '<button class="help-cli-copy" data-cmd="' + safeAttr + '">Copy</button>' +
    '</div>';
  }

  function endpointSection(title, endpoints) {
    var rows = endpoints.map(function (ep) {
      var methodClass = 'help-method-' + ep.method.toLowerCase();
      return '<tr>' +
        '<td><span class="help-method ' + methodClass + '">' + ep.method + '</span></td>' +
        '<td><code>' + escapeHtml(ep.path) + '</code></td>' +
        '<td>' + escapeHtml(ep.desc) + '</td>' +
      '</tr>';
    }).join('');

    return '<div class="card mb-lg">' +
      '<div class="card-header"><h4>' + escapeHtml(title) + '</h4></div>' +
      '<div class="table-container">' +
        '<table class="data-table help-endpoint-table">' +
          '<thead><tr>' +
            '<th style="width:80px">Method</th>' +
            '<th style="width:320px">Endpoint</th>' +
            '<th>Description</th>' +
          '</tr></thead>' +
          '<tbody>' + rows + '</tbody>' +
        '</table>' +
      '</div>' +
    '</div>';
  }

  /* ---------- Assessment Methodology Tab ---------- */
  function renderMethodology() {
    // Content loaded from methodology-data.js (auto-generated from config files)
    if (window._methodologyHTML) {
      return window._methodologyHTML;
    }
    return '<div class="card mb-lg"><div class="card-body">' +
      '<h3 class="help-section-title">Assessment Methodology</h3>' +
      '<p class="help-section-desc">' +
        'Methodology data not loaded. Ensure <code>methodology-data.js</code> is included before <code>help.js</code>.' +
      '</p>' +
    '</div></div>';
  }

  /* ---------- QA Validation Tab ---------- */
  function renderQAValidation() {
    // Content loaded from qa-validation-data.js (auto-generated from QA checks)
    if (window._qaValidationHTML) {
      return window._qaValidationHTML;
    }
    return '<div class="card mb-lg"><div class="card-body">' +
      '<h3 class="help-section-title">QA Validation</h3>' +
      '<p class="help-section-desc">' +
        'QA validation data not loaded. Ensure <code>qa-validation-data.js</code> is included before <code>help.js</code>.' +
      '</p>' +
    '</div></div>';
  }

  window.renderHelp = renderHelp;
})();
