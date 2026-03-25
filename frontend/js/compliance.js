/**
 * Cloud Compliance Module
 * Handles AWS (multi-service), Azure, GitHub compliance checks with Playwright + AI analysis
 */
const Compliance = (() => {
    let activeProvider = 'aws';
    let selectedAwsService = null;
    let selectedAwsCheck = null;
    let selectedDdService = null;
    let selectedDdCheck = null;
    const DD_SERVICE_ICONS = {
        monitors_alerts: '🚨', infrastructure: '🖥️', apm_traces: '📡',
        security: '🛡️', logs: '📋', organization: '👥', dashboards: '📊',
    };
    // Service icons (emoji) keyed by service id
    const SERVICE_ICONS = {
        ec2: '🖥️', s3: '🪣', iam: '👤', rds: '🗄️', vpc: '🌐',
        lambda: '⚡', cloudwatch: '📊', kms: '🔑', secretsmanager: '🔐',
        guardduty: '🛡️', securityhub: '🏰', dynamodb: '📦',
        cloudtrail: '📝', config: '⚙️', sns: '🔔', sqs: '📬',
        ecs: '🐳', eks: '☸️', route53: '🌍', cloudfront: '🌩️',
    };

    // ─── Lightbox ─────────────────────────────────────────────────────────────

    let _lbImages = [];  // [{src, caption}]
    let _lbIndex = 0;

    function _initLightbox() {
        const overlay = document.getElementById('lightbox-overlay');
        document.getElementById('lightbox-close').addEventListener('click', _closeLightbox);
        document.getElementById('lightbox-prev').addEventListener('click', () => _lbNav(-1));
        document.getElementById('lightbox-next').addEventListener('click', () => _lbNav(1));
        overlay.addEventListener('click', e => { if (e.target === overlay) _closeLightbox(); });
        document.addEventListener('keydown', e => {
            if (overlay.style.display === 'none') return;
            if (e.key === 'Escape') _closeLightbox();
            if (e.key === 'ArrowLeft') _lbNav(-1);
            if (e.key === 'ArrowRight') _lbNav(1);
        });
    }

    function _openLightbox(index) {
        _lbIndex = index;
        _lbRender();
        document.getElementById('lightbox-overlay').style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }

    function _closeLightbox() {
        document.getElementById('lightbox-overlay').style.display = 'none';
        document.body.style.overflow = '';
    }

    function _lbNav(dir) {
        _lbIndex = (_lbIndex + dir + _lbImages.length) % _lbImages.length;
        _lbRender();
    }

    function _lbRender() {
        const img = document.getElementById('lightbox-img');
        const caption = document.getElementById('lightbox-caption');
        const counter = document.getElementById('lightbox-counter');
        const prev = document.getElementById('lightbox-prev');
        const next = document.getElementById('lightbox-next');
        img.src = _lbImages[_lbIndex].src;
        img.alt = _lbImages[_lbIndex].caption;
        caption.textContent = _lbImages[_lbIndex].caption;
        counter.textContent = `${_lbIndex + 1} / ${_lbImages.length}`;
        prev.style.display = _lbImages.length > 1 ? 'flex' : 'none';
        next.style.display = _lbImages.length > 1 ? 'flex' : 'none';
    }

    function init() {
        _initLightbox();

        // Tab switching
        document.querySelectorAll('.cc-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                switchProvider(tab.getAttribute('data-provider'));
            });
        });

        // AWS three-step flow
        _setupAwsValidation();
        document.getElementById('btn-aws-next').addEventListener('click', _showServiceSelection);
        document.getElementById('btn-aws-back').addEventListener('click', _showCredentials);
        document.getElementById('btn-aws-back-checks').addEventListener('click', _showServiceSelectionFromChecks);
        document.getElementById('btn-run-aws').addEventListener('click', () => runAwsCheck());

        // Datadog three-step flow
        _setupDdValidation();
        document.getElementById('btn-dd-next').addEventListener('click', _ddShowServiceSelection);
        document.getElementById('btn-dd-back').addEventListener('click', _ddShowCredentials);
        document.getElementById('btn-dd-back-checks').addEventListener('click', _ddShowServiceSelectionFromChecks);
        document.getElementById('btn-run-datadog').addEventListener('click', () => runDatadogCheck());
        _loadDdServices();

        // Azure & GitHub
        _setupAzureValidation();
        _setupFormValidation('github', ['github-token']);
        document.getElementById('btn-run-azure').addEventListener('click', () => runAzureCheck());
        document.getElementById('btn-run-github').addEventListener('click', () => runGithubCheck());

        // New Check button
        document.getElementById('btn-new-compliance').addEventListener('click', () => resetCompliance());

        // Pre-load service list
        _loadAwsServices();
    }

    // ─── AWS Step 1: Credentials ───────────────────────────────────────────────

    function _setupAwsValidation() {
        const btn = document.getElementById('btn-aws-next');
        const apiFields = ['aws-access-key', 'aws-secret-key'];
        const consoleFields = ['aws-account-id', 'aws-iam-username', 'aws-iam-password'];

        const validate = () => {
            const hasApiKeys = apiFields.every(id => document.getElementById(id).value.trim() !== '');
            const hasConsoleCreds = consoleFields.every(id => document.getElementById(id).value.trim() !== '');
            btn.disabled = !(hasApiKeys || hasConsoleCreds);
        };

        [...apiFields, ...consoleFields].forEach(id =>
            document.getElementById(id).addEventListener('input', validate)
        );
    }

    // ─── AWS Step 2: Service Selection ────────────────────────────────────────

    async function _loadAwsServices() {
        try {
            const res = await fetch('/api/compliance/aws/services');
            const data = await res.json();
            if (data.success) _buildServiceGrid(data.services);
        } catch (_) {
            // Fall back to empty grid — will load on next open
        }
    }

    function _buildServiceGrid(services) {
        const grid = document.getElementById('aws-service-grid');
        grid.innerHTML = '';
        services.forEach(svc => {
            const icon = SERVICE_ICONS[svc.id] || '☁️';
            const card = document.createElement('div');
            card.className = 'aws-svc-card';
            card.dataset.service = svc.id;
            card.innerHTML = `
                <div class="aws-svc-icon">${icon}</div>
                <div class="aws-svc-name">${svc.name}</div>
                <div class="aws-svc-desc">${svc.description}</div>
            `;
            card.addEventListener('click', () => _selectService(svc.id, card));
            grid.appendChild(card);
        });
    }

    function _selectService(serviceId, cardEl) {
        document.querySelectorAll('.aws-svc-card').forEach(c => c.classList.remove('aws-svc-card--selected'));
        cardEl.classList.add('aws-svc-card--selected');
        selectedAwsService = serviceId;
        _showCheckSelection(serviceId);
    }

    function _showServiceSelection() {
        document.getElementById('aws-step-credentials').style.display = 'none';
        document.getElementById('aws-step-checks').style.display = 'none';
        document.getElementById('aws-step-service').style.display = 'block';
        // Re-load if grid is empty (first visit)
        if (document.getElementById('aws-service-grid').children.length === 0) {
            _loadAwsServices();
        }
    }

    function _showCredentials() {
        document.getElementById('aws-step-service').style.display = 'none';
        document.getElementById('aws-step-checks').style.display = 'none';
        document.getElementById('aws-step-credentials').style.display = 'block';
    }

    function _showServiceSelectionFromChecks() {
        document.getElementById('aws-step-checks').style.display = 'none';
        document.getElementById('aws-step-service').style.display = 'block';
        selectedAwsCheck = null;
        document.getElementById('btn-run-aws').disabled = true;
    }

    // ─── AWS Step 3: Check Selection ──────────────────────────────────────────

    async function _showCheckSelection(serviceId) {
        document.getElementById('aws-step-service').style.display = 'none';
        document.getElementById('aws-step-checks').style.display = 'block';
        document.getElementById('btn-run-aws').disabled = true;
        selectedAwsCheck = null;

        const grid = document.getElementById('aws-check-grid');
        grid.innerHTML = '<p style="color:rgba(255,255,255,0.4);font-size:0.85rem;">Loading checks…</p>';

        try {
            const res = await fetch(`/api/compliance/aws/checks/${serviceId}`);
            const data = await res.json();
            if (data.success) _buildCheckGrid(data.checks);
            else grid.innerHTML = '<p style="color:rgba(255,80,80,0.8);">Failed to load checks.</p>';
        } catch (_) {
            grid.innerHTML = '<p style="color:rgba(255,80,80,0.8);">Failed to load checks.</p>';
        }
    }

    function _buildCheckGrid(checks) {
        const grid = document.getElementById('aws-check-grid');
        grid.innerHTML = '';
        checks.forEach(chk => {
            const card = document.createElement('div');
            card.className = 'aws-check-card';
            card.dataset.check = chk.id;
            card.innerHTML = `
                <div class="aws-check-name">${chk.name}</div>
                <div class="aws-check-desc">${chk.description}</div>
            `;
            card.addEventListener('click', () => _selectCheck(chk.id, card));
            grid.appendChild(card);
        });
    }

    function _selectCheck(checkId, cardEl) {
        document.querySelectorAll('.aws-check-card').forEach(c => c.classList.remove('aws-check-card--selected'));
        cardEl.classList.add('aws-check-card--selected');
        selectedAwsCheck = checkId;
        document.getElementById('btn-run-aws').disabled = false;
    }

    // ─── Validation helpers ────────────────────────────────────────────────────

    function _setupFormValidation(provider, fieldIds) {
        const btn = document.getElementById(`btn-run-${provider}`);
        fieldIds.forEach(id => {
            document.getElementById(id).addEventListener('input', () => {
                btn.disabled = !fieldIds.every(fid => document.getElementById(fid).value.trim() !== '');
            });
        });
    }

    function _setupAzureValidation() {
        const btn = document.getElementById('btn-run-azure');
        const tokenField = document.getElementById('azure-access-token');
        const spFields = ['azure-tenant-id', 'azure-client-id', 'azure-client-secret'];

        const validate = () => {
            const hasToken = tokenField.value.trim() !== '';
            const hasAllSP = spFields.every(id => document.getElementById(id).value.trim() !== '');
            btn.disabled = !(hasToken || hasAllSP);
        };

        tokenField.addEventListener('input', validate);
        spFields.forEach(id => document.getElementById(id).addEventListener('input', validate));
    }

    function switchProvider(provider) {
        activeProvider = provider;
        document.querySelectorAll('.cc-tab').forEach(t => t.classList.remove('cc-tab--active'));
        document.querySelector(`.cc-tab[data-provider="${provider}"]`).classList.add('cc-tab--active');
        document.querySelectorAll('.cc-panel').forEach(p => { p.style.display = 'none'; });
        document.getElementById(`panel-${provider}`).style.display = 'block';
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('compliance-results').style.display = 'none';
        document.getElementById('cc-credentials-wrap').style.display = 'block';
        document.getElementById('cc-tabs').style.pointerEvents = '';
        document.getElementById('cc-tabs').style.opacity = '';
    }

    // ─── Processing UI ─────────────────────────────────────────────────────────

    function _showProcessing(providerName) {
        document.getElementById('cc-credentials-wrap').style.display = 'none';
        document.getElementById('cc-tabs').style.pointerEvents = 'none';
        document.getElementById('cc-tabs').style.opacity = '0.5';
        const processing = document.getElementById('compliance-processing');
        processing.style.display = 'block';
        document.getElementById('compliance-provider-name').textContent = providerName;
        document.querySelectorAll('.cc-step').forEach(s => s.setAttribute('data-status', 'waiting'));
    }

    function _updateStep(stepId, status) {
        const step = document.getElementById(stepId);
        if (step) step.setAttribute('data-status', status);
    }

    async function _simulateProgress() {
        _updateStep('step-auth', 'processing');
        await _delay(800);
        _updateStep('step-auth', 'completed');
        _updateStep('step-api', 'processing');
        await _delay(1500);
        _updateStep('step-api', 'completed');
        _updateStep('step-screenshot', 'processing');
        await _delay(2000);
        _updateStep('step-screenshot', 'completed');
        _updateStep('step-analysis', 'processing');
        _startElapsedTimer();
    }

    function _delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

    // Elapsed-time ticker shown while AI analysis runs (can take 30–120 s)
    let _elapsedInterval = null;
    let _elapsedSeconds = 0;

    function _startElapsedTimer() {
        _elapsedSeconds = 0;
        _elapsedInterval = setInterval(() => {
            _elapsedSeconds++;
            const step = document.getElementById('step-analysis');
            if (step) {
                const label = step.querySelector('.cc-step__label');
                if (label) label.textContent = `AI Analysis (${_elapsedSeconds}s\u2026)`;
            }
        }, 1000);
    }

    function _stopElapsedTimer() {
        if (_elapsedInterval) { clearInterval(_elapsedInterval); _elapsedInterval = null; }
        const step = document.getElementById('step-analysis');
        if (step) {
            const label = step.querySelector('.cc-step__label');
            if (label) label.textContent = 'AI Analysis';
        }
    }

    // Datadog processing animation helpers (alias to shared implementation)
    function _startProcessingAnimation() {
        document.querySelectorAll('.cc-step').forEach(s => s.setAttribute('data-status', 'waiting'));
        _simulateProgress();
    }

    function _stopProcessingAnimation() {
        _stopElapsedTimer();
        _updateStep('step-analysis', 'completed');
    }

    // ─── AWS ──────────────────────────────────────────────────────────────────

    async function runAwsCheck() {
        console.log('[AWS] runAwsCheck called');
        const accessKey = document.getElementById('aws-access-key').value.trim();
        const secretKey = document.getElementById('aws-secret-key').value.trim();
        const region = document.getElementById('aws-region').value;
        const accountId = document.getElementById('aws-account-id').value.trim();
        const iamUsername = document.getElementById('aws-iam-username').value.trim();
        const iamPassword = document.getElementById('aws-iam-password').value.trim();

        const serviceId = selectedAwsService;
        const serviceName = serviceId
            ? (document.querySelector(`.aws-svc-card[data-service="${serviceId}"] .aws-svc-name`)?.textContent || serviceId)
            : 'EBS Encryption';

        console.log('[AWS] service:', serviceId, 'check:', selectedAwsCheck, 'hasApiKeys:', !!(accessKey && secretKey), 'hasConsole:', !!(accountId && iamUsername && iamPassword));
        _showProcessing(`AWS — ${serviceName}`);
        console.log('[AWS] processing panel shown, starting fetch...');
        const progressPromise = _simulateProgress();

        const body = { region };
        if (accessKey && secretKey) { body.access_key = accessKey; body.secret_key = secretKey; }
        if (accountId && iamUsername && iamPassword) {
            body.account_id = accountId;
            body.iam_username = iamUsername;
            body.iam_password = iamPassword;
        }
        if (serviceId) body.service = serviceId;
        if (selectedAwsCheck) body.check_id = selectedAwsCheck;

        const controller = new AbortController();
        const fetchTimeout = setTimeout(() => controller.abort(), 180000);

        try {
            const response = await fetch('/api/compliance/aws', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                signal: controller.signal,
            });
            clearTimeout(fetchTimeout);

            await progressPromise;
            _stopElapsedTimer();
            _updateStep('step-analysis', 'completed');
            await _delay(500);

            const data = await response.json();
            console.log('[AWS] response received, success:', data.success, 'keys:', Object.keys(data));
            if (data.success) {
                try {
                    _showResults(data.result, 'aws');
                    console.log('[AWS] _showResults completed successfully');
                } catch (showErr) {
                    console.error('[AWS] _showResults CRASHED:', showErr);
                    App.showToast('Error displaying results: ' + showErr.message, 'error');
                    resetCompliance();
                }
            } else {
                console.warn('[AWS] check failed:', data.error);
                App.showToast(data.error || 'AWS compliance check failed', 'error');
                resetCompliance();
            }
        } catch (err) {
            clearTimeout(fetchTimeout);
            _stopElapsedTimer();
            console.error('[AWS] fetch error:', err);
            const msg = err.name === 'AbortError'
                ? 'Compliance check timed out (>3 min). The backend may still be running.'
                : 'Failed to connect to server';
            App.showToast(msg, 'error');
            resetCompliance();
        }
    }

    // ─── Datadog Step 1: Credentials ──────────────────────────────────────────

    function _setupDdValidation() {
        const btn = document.getElementById('btn-dd-next');
        const fields = ['dd-email', 'dd-password'];
        const validate = () => { btn.disabled = !fields.every(id => document.getElementById(id).value.trim()); };
        fields.forEach(id => document.getElementById(id).addEventListener('input', validate));
    }

    let _ddServices = [];

    async function _loadDdServices() {
        try {
            const resp = await fetch('/api/compliance/datadog/services');
            const data = await resp.json();
            if (data.success) _ddServices = data.services;
        } catch (e) { console.error('Failed to load Datadog services:', e); }
    }

    // ─── Datadog Step 2: Service Selection ────────────────────────────────────

    function _ddShowServiceSelection() {
        document.getElementById('dd-step-credentials').style.display = 'none';
        document.getElementById('dd-step-checks').style.display = 'none';
        document.getElementById('dd-step-service').style.display = 'block';
        _buildDdServiceGrid();
    }

    function _ddShowCredentials() {
        document.getElementById('dd-step-service').style.display = 'none';
        document.getElementById('dd-step-checks').style.display = 'none';
        document.getElementById('dd-step-credentials').style.display = 'block';
    }

    function _ddShowServiceSelectionFromChecks() {
        document.getElementById('dd-step-checks').style.display = 'none';
        document.getElementById('dd-step-credentials').style.display = 'none';
        document.getElementById('dd-step-service').style.display = 'block';
    }

    function _buildDdServiceGrid() {
        const grid = document.getElementById('dd-service-grid');
        grid.innerHTML = '';
        const services = _ddServices.length ? _ddServices : [
            {id:'monitors_alerts', name:'Monitors & Alerts', description:'Alert monitors and SLOs'},
            {id:'infrastructure', name:'Infrastructure', description:'Hosts, containers, processes'},
            {id:'apm_traces', name:'APM & Tracing', description:'Application performance'},
            {id:'security', name:'Security', description:'Signals, posture, vulnerabilities'},
            {id:'logs', name:'Log Management', description:'Pipelines, indexes, archives'},
            {id:'organization', name:'Organization Settings', description:'Users, roles, SSO'},
            {id:'dashboards', name:'Dashboards', description:'Dashboards and integrations'},
        ];
        services.forEach(svc => {
            const card = document.createElement('div');
            card.className = 'aws-svc-card' + (selectedDdService === svc.id ? ' aws-svc-card--selected' : '');
            card.innerHTML = `
                <div class="aws-svc-card__icon">${DD_SERVICE_ICONS[svc.id] || '🐶'}</div>
                <div class="aws-svc-card__name">${svc.name}</div>
                <div class="aws-svc-card__desc">${svc.description}</div>`;
            card.addEventListener('click', () => _selectDdService(svc.id, card));
            grid.appendChild(card);
        });
    }

    function _selectDdService(serviceId, cardEl) {
        selectedDdService = serviceId;
        document.querySelectorAll('#dd-service-grid .aws-svc-card').forEach(c => c.classList.remove('aws-svc-card--selected'));
        cardEl.classList.add('aws-svc-card--selected');
        _ddShowCheckSelection(serviceId);
    }

    // ─── Datadog Step 3: Check Selection ──────────────────────────────────────

    async function _ddShowCheckSelection(serviceId) {
        document.getElementById('dd-step-service').style.display = 'none';
        document.getElementById('dd-step-credentials').style.display = 'none';
        document.getElementById('dd-step-checks').style.display = 'block';
        selectedDdCheck = null;
        document.getElementById('btn-run-datadog').disabled = true;
        try {
            const resp = await fetch(`/api/compliance/datadog/checks/${serviceId}`);
            const data = await resp.json();
            if (data.success) _buildDdCheckGrid(data.checks);
        } catch (e) { console.error('Failed to load Datadog checks:', e); }
    }

    function _buildDdCheckGrid(checks) {
        const grid = document.getElementById('dd-check-grid');
        grid.innerHTML = '';
        checks.forEach(chk => {
            const card = document.createElement('div');
            card.className = 'aws-check-card';
            card.innerHTML = `<div class="aws-check-name">${chk.name}</div><div class="aws-check-desc">${chk.description}</div>`;
            card.addEventListener('click', () => _selectDdCheck(chk.id, card));
            grid.appendChild(card);
        });
    }

    function _selectDdCheck(checkId, cardEl) {
        selectedDdCheck = checkId;
        document.querySelectorAll('#dd-check-grid .aws-check-card').forEach(c => c.classList.remove('aws-check-card--selected'));
        cardEl.classList.add('aws-check-card--selected');
        document.getElementById('btn-run-datadog').disabled = false;
    }

    // ─── Datadog Run ───────────────────────────────────────────────────────────

    async function runDatadogCheck() {
        const email = document.getElementById('dd-email').value.trim();
        const password = document.getElementById('dd-password').value.trim();
        const site = document.getElementById('dd-site').value;
        const service = selectedDdService;
        const checkId = selectedDdCheck;
        console.log('[DD] runDatadogCheck called:', { email: !!email, password: !!password, service, checkId });
        if (!email || !password || !service || !checkId) {
            console.warn('[DD] Early return — missing:', { email: !!email, password: !!password, service, checkId });
            return;
        }

        document.getElementById('cc-credentials-wrap').style.display = 'none';
        document.getElementById('cc-tabs').style.pointerEvents = 'none';
        document.getElementById('cc-tabs').style.opacity = '0.5';
        document.getElementById('compliance-processing').style.display = 'flex';
        document.getElementById('compliance-provider-name').textContent = 'Datadog — ' + service.replace(/_/g, ' ');
        _startProcessingAnimation();

        try {
            const resp = await fetch('/api/compliance/datadog', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, service, check_id: checkId, site }),
            });
            const data = await resp.json();
            _stopProcessingAnimation();
            if (data.success) {
                _showResults(data.result, 'datadog');
            } else {
                alert('Datadog check failed: ' + (data.error || 'Unknown error'));
                resetCompliance();
            }
        } catch (e) {
            _stopProcessingAnimation();
            alert('Network error: ' + e.message);
            resetCompliance();
        }
    }

    // ─── Azure ────────────────────────────────────────────────────────────────

    async function runAzureCheck() {
        const accessToken = document.getElementById('azure-access-token').value.trim();
        const tenantId = document.getElementById('azure-tenant-id').value.trim();
        const clientId = document.getElementById('azure-client-id').value.trim();
        const clientSecret = document.getElementById('azure-client-secret').value.trim();

        _showProcessing('Azure SQL Encryption Check');
        const progressPromise = _simulateProgress();

        const body = {};
        if (accessToken) { body.access_token = accessToken; }
        else { body.tenant_id = tenantId; body.client_id = clientId; body.client_secret = clientSecret; }

        const controller = new AbortController();
        const fetchTimeout = setTimeout(() => controller.abort(), 180000);

        try {
            const response = await fetch('/api/compliance/azure', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                signal: controller.signal,
            });
            clearTimeout(fetchTimeout);

            await progressPromise;
            _stopElapsedTimer();
            _updateStep('step-analysis', 'completed');
            await _delay(500);

            const data = await response.json();
            if (data.success) {
                _showResults(data.result, 'azure');
            } else {
                App.showToast(data.error || 'Azure compliance check failed', 'error');
                resetCompliance();
            }
        } catch (err) {
            clearTimeout(fetchTimeout);
            _stopElapsedTimer();
            const msg = err.name === 'AbortError'
                ? 'Compliance check timed out (>3 min).'
                : 'Failed to connect to server';
            App.showToast(msg, 'error');
            resetCompliance();
        }
    }

    // ─── GitHub ───────────────────────────────────────────────────────────────

    async function runGithubCheck() {
        const apiToken = document.getElementById('github-token').value.trim();

        _showProcessing('GitHub MFA Check');
        const progressPromise = _simulateProgress();

        const controller = new AbortController();
        const fetchTimeout = setTimeout(() => controller.abort(), 60000);

        try {
            const response = await fetch('/api/compliance/github', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_token: apiToken }),
                signal: controller.signal,
            });
            clearTimeout(fetchTimeout);

            await progressPromise;
            _stopElapsedTimer();
            _updateStep('step-analysis', 'completed');
            await _delay(500);

            const data = await response.json();
            if (data.success) {
                _showResults(data.result, 'github');
            } else {
                App.showToast(data.error || 'GitHub compliance check failed', 'error');
                resetCompliance();
            }
        } catch (err) {
            clearTimeout(fetchTimeout);
            _stopElapsedTimer();
            const msg = err.name === 'AbortError'
                ? 'Compliance check timed out.'
                : 'Failed to connect to server';
            App.showToast(msg, 'error');
            resetCompliance();
        }
    }

    // ─── Results ──────────────────────────────────────────────────────────────

    function _showResults(result, provider) {
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('cc-tabs').style.pointerEvents = 'none';
        document.getElementById('cc-tabs').style.opacity = '0.5';
        document.getElementById('compliance-results').style.display = 'block';

        // Set report title
        if ((provider === 'aws' || provider === 'datadog') && result.service_name) {
            const prefix = provider === 'datadog' ? 'Datadog' : 'AWS';
            document.getElementById('compliance-results-title').textContent =
                `${prefix} ${result.service_name} — Analysis Report`;
        } else {
            const titles = {
                aws: 'AWS EBS Encryption — Compliance Report',
                azure: 'Azure SQL Encryption — Compliance Report',
                github: 'GitHub MFA — Compliance Report',
                datadog: 'Datadog — Compliance Report',
            };
            document.getElementById('compliance-results-title').textContent = titles[provider] || 'Compliance Report';
        }

        _renderStatusBanner(result, provider);
        _renderScreenshots(result.screenshots || []);
        _renderApiFindings(result.api_findings || {}, provider);
        _renderVisionAnalysis(result.vision_analysis || {}, result.service_name);
    }

    function _renderStatusBanner(result, provider) {
        const banner = document.getElementById('compliance-status-banner');
        const icon = document.getElementById('compliance-status-icon');
        const text = document.getElementById('compliance-status-text');
        const desc = document.getElementById('compliance-status-desc');

        // Generic service scan — always show as informational (no pass/fail)
        if ((provider === 'aws' || provider === 'datadog') && result.service_name && !result.encryption_enabled && result.encryption_enabled !== false) {
            banner.className = 'cc-status-banner status-info';
            icon.textContent = 'ℹ';
            text.textContent = `${result.service_name} — Analysis Complete`;
            desc.textContent = 'Review the screenshots and AI findings below for a full picture of this service\'s configuration.';
            return;
        }

        let isCompliant;
        if (provider === 'github') {
            isCompliant = result.mfa_enabled;
        } else {
            isCompliant = result.encryption_enabled;
        }

        if (isCompliant === true) {
            banner.className = 'cc-status-banner status-pass';
            icon.textContent = '\u2713';
            if (provider === 'aws') {
                text.textContent = 'EBS Encryption: ENABLED';
                desc.textContent = 'AWS EBS volume encryption policy is properly configured and active.';
            } else if (provider === 'azure') {
                text.textContent = 'SQL Encryption (TDE): ENABLED';
                desc.textContent = 'Azure SQL Database Transparent Data Encryption is active.';
            } else {
                text.textContent = 'MFA: ENABLED';
                desc.textContent = 'GitHub Multi-Factor Authentication is enabled for this account.';
            }
        } else if (isCompliant === false) {
            banner.className = 'cc-status-banner status-fail';
            icon.textContent = '\u2715';
            if (provider === 'aws') {
                text.textContent = 'EBS Encryption: NOT ENABLED';
                desc.textContent = 'AWS EBS volume encryption is not fully enabled. Immediate action recommended.';
            } else if (provider === 'azure') {
                text.textContent = 'SQL Encryption (TDE): NOT ENABLED';
                desc.textContent = 'Azure SQL encryption is not fully configured. Review database encryption settings.';
            } else {
                text.textContent = 'MFA: NOT ENABLED';
                desc.textContent = 'GitHub Multi-Factor Authentication is not enabled. Critical security risk.';
            }
        } else {
            banner.className = 'cc-status-banner status-unknown';
            icon.textContent = '?';
            text.textContent = 'Status: UNDETERMINED';
            desc.textContent = 'Could not definitively determine the compliance status. Review the findings below.';
        }
    }

    function _renderScreenshots(screenshots) {
        const card = document.getElementById('screenshots-card');
        const gallery = document.getElementById('screenshots-gallery');
        gallery.innerHTML = '';

        if (screenshots.length === 0) { card.style.display = 'none'; return; }

        card.style.display = 'block';

        // Build lightbox image list
        _lbImages = screenshots.map(ss => ({ src: ss.url_path, caption: ss.description }));

        screenshots.forEach((ss, idx) => {
            const item = document.createElement('div');
            item.className = 'screenshot-item';
            item.innerHTML = `
                <div class="screenshot-image-container screenshot-clickable" title="Click to expand">
                    <img src="${ss.url_path}" alt="${ss.description}" loading="lazy">
                    <div class="screenshot-expand-hint">🔍 Click to expand</div>
                    <div class="screenshot-click-overlay"></div>
                </div>
                <div class="screenshot-info">
                    <h4>${ss.description}</h4>
                    <span class="screenshot-label">${ss.label}</span>
                </div>
            `;
            item.querySelector('.screenshot-click-overlay').addEventListener('click', () => _openLightbox(idx));
            gallery.appendChild(item);
        });
    }

    function _renderApiFindings(findings, provider) {
        const container = document.getElementById('api-findings-content');
        container.innerHTML = '';

        if (Object.keys(findings).length === 0) {
            container.innerHTML = '<p class="empty-state">No API findings available.</p>';
            return;
        }

        if (provider === 'aws') _renderAwsFindings(container, findings);
        else if (provider === 'azure') _renderAzureFindings(container, findings);
        else _renderGithubFindings(container, findings);
    }

    function _renderAwsFindings(container, findings) {
        let html = '<div class="findings-grid">';

        if (findings.ebs_encryption_by_default !== undefined) {
            html += `
                <div class="finding-card ${findings.ebs_encryption_by_default ? 'finding-pass' : 'finding-fail'}">
                    <div class="finding-header">
                        <span class="finding-badge">${findings.ebs_encryption_by_default ? 'Enabled' : 'Disabled'}</span>
                        <h4>EBS Encryption by Default</h4>
                    </div>
                    <p>${findings.ebs_encryption_by_default ? 'New EBS volumes are encrypted by default' : 'EBS encryption by default is NOT enabled'}</p>
                </div>`;
        }

        if (findings.volumes) {
            html += `
                <div class="finding-card ${findings.volumes.unencrypted === 0 ? 'finding-pass' : 'finding-fail'}">
                    <div class="finding-header">
                        <span class="finding-badge">${findings.volumes.encrypted}/${findings.volumes.total}</span>
                        <h4>EBS Volumes Encrypted</h4>
                    </div>
                    <p>${findings.volumes.total} total volumes: ${findings.volumes.encrypted} encrypted, ${findings.volumes.unencrypted} unencrypted</p>
                </div>`;
        }

        if (findings.note) {
            html += `
                <div class="finding-card finding-info">
                    <div class="finding-header"><span class="finding-badge">Info</span><h4>Note</h4></div>
                    <p>${findings.note}</p>
                </div>`;
        }

        html += '</div>';
        container.innerHTML = html;
    }

    function _renderAzureFindings(container, findings) {
        let html = '<div class="findings-grid">';

        const authOk = findings.authentication && findings.authentication.startsWith('success');
        html += `
            <div class="finding-card ${authOk ? 'finding-pass' : 'finding-fail'}">
                <div class="finding-header">
                    <span class="finding-badge">${authOk ? 'OK' : 'Failed'}</span>
                    <h4>Authentication</h4>
                </div>
                <p>${authOk ? 'Successfully authenticated with Azure' : findings.authentication}</p>
            </div>`;

        if (findings.subscriptions) {
            html += `
                <div class="finding-card finding-info">
                    <div class="finding-header">
                        <span class="finding-badge">${findings.subscriptions.length}</span>
                        <h4>Azure Subscriptions</h4>
                    </div>
                    <p>${findings.subscriptions.map(s => s.name).join(', ')}</p>
                </div>`;
        }

        if (findings.sql_servers && findings.sql_servers.length > 0) {
            findings.sql_servers.forEach(srv => {
                html += `
                    <div class="finding-card ${srv.tde_enabled ? 'finding-pass' : 'finding-fail'}">
                        <div class="finding-header">
                            <span class="finding-badge">${srv.tde_enabled ? 'Enabled' : 'Disabled'}</span>
                            <h4>${srv.server} / ${srv.database}</h4>
                        </div>
                        <p>Transparent Data Encryption: ${srv.tde_enabled ? 'Enabled' : 'NOT Enabled'}</p>
                    </div>`;
            });
        } else if (findings.sql_servers_note) {
            html += `
                <div class="finding-card finding-info">
                    <div class="finding-header"><span class="finding-badge">N/A</span><h4>SQL Databases</h4></div>
                    <p>${findings.sql_servers_note}</p>
                </div>`;
        }

        html += '</div>';
        container.innerHTML = html;
    }

    function _renderGithubFindings(container, findings) {
        let html = '<div class="findings-grid">';

        if (findings.user) {
            html += `
                <div class="finding-card ${findings.user.two_factor_authentication ? 'finding-pass' : 'finding-fail'}">
                    <div class="finding-header">
                        <span class="finding-badge">${findings.user.two_factor_authentication ? 'Enabled' : 'Disabled'}</span>
                        <h4>Two-Factor Authentication</h4>
                    </div>
                    <p>User: ${findings.user.login} (${findings.user.name || 'N/A'})<br>
                    2FA: ${findings.user.two_factor_authentication ? 'Enabled' : 'NOT Enabled'}</p>
                </div>`;
        }

        if (findings.organizations && findings.organizations.length > 0) {
            findings.organizations.forEach(org => {
                html += `
                    <div class="finding-card ${org.two_factor_requirement_enabled ? 'finding-pass' : 'finding-warn'}">
                        <div class="finding-header">
                            <span class="finding-badge">${org.two_factor_requirement_enabled ? 'Required' : 'Optional'}</span>
                            <h4>Org: ${org.name}</h4>
                        </div>
                        <p>2FA Requirement: ${org.two_factor_requirement_enabled ? 'Enforced' : 'Not enforced'}
                        ${org.members_without_2fa !== undefined ? `<br>Members without 2FA: ${org.members_without_2fa}` : ''}</p>
                    </div>`;
            });
        }

        html += '</div>';
        container.innerHTML = html;
    }

    // ─── Vision Analysis ──────────────────────────────────────────────────────

    function _renderVisionAnalysis(visionResults, serviceName) {
        const card = document.getElementById('vision-card');
        const container = document.getElementById('vision-analysis-content');
        container.innerHTML = '';

        const entries = Object.entries(visionResults);
        if (entries.length === 0) { card.style.display = 'none'; return; }

        card.style.display = 'block';

        entries.forEach(([label, analysis]) => {
            const item = document.createElement('div');
            item.className = 'vision-analysis-item';

            if (analysis.error) {
                item.innerHTML = `
                    <h4>${label.replace(/_/g, ' ')}</h4>
                    <p class="vision-error">Analysis error: ${analysis.error}</p>`;
            } else if (analysis.page_summary !== undefined) {
                // Generic service analysis format
                const risk = analysis.risk_level || 'unknown';
                const riskClass = risk === 'low' ? 'status-pass' : risk === 'medium' ? 'status-unknown' : risk === 'high' || risk === 'critical' ? 'status-fail' : 'status-unknown';

                const _list = (arr) => arr && arr.length
                    ? '<ul class="vision-findings">' + arr.map(f => `<li>${f}</li>`).join('') + '</ul>'
                    : '';

                item.innerHTML = `
                    <div class="vision-header">
                        <h4>${label.replace(/_/g, ' ')}</h4>
                        <span class="vision-status ${riskClass}">Risk: ${risk.toUpperCase()}</span>
                    </div>
                    <p class="vision-assessment">${analysis.page_summary || ''}</p>
                    ${analysis.resources_found && analysis.resources_found.length ? `
                        <div class="vision-section">
                            <strong>Resources Found</strong>
                            ${_list(analysis.resources_found)}
                        </div>` : ''}
                    ${analysis.security_observations && analysis.security_observations.length ? `
                        <div class="vision-section">
                            <strong>Security Observations</strong>
                            ${_list(analysis.security_observations)}
                        </div>` : ''}
                    ${analysis.configuration_details && analysis.configuration_details.length ? `
                        <div class="vision-section">
                            <strong>Configuration Details</strong>
                            ${_list(analysis.configuration_details)}
                        </div>` : ''}
                    ${analysis.recommendations && analysis.recommendations.length ? `
                        <div class="vision-section vision-recommendations">
                            <strong>Recommendations</strong>
                            ${_list(analysis.recommendations)}
                        </div>` : ''}
                    ${analysis.confidence ? `<span class="vision-confidence">Confidence: ${(analysis.confidence * 100).toFixed(0)}%</span>` : ''}
                `;
            } else {
                // Legacy EBS / encryption format
                const status = analysis.encryption_status || analysis.mfa_status || 'unknown';
                const statusClass = status === 'enabled' ? 'status-pass' : status === 'disabled' ? 'status-fail' : 'status-unknown';

                let findingsHtml = '';
                if (analysis.findings && analysis.findings.length > 0) {
                    findingsHtml = '<ul class="vision-findings">' +
                        analysis.findings.map(f => `<li>${f}</li>`).join('') + '</ul>';
                }

                item.innerHTML = `
                    <div class="vision-header">
                        <h4>${label.replace(/_/g, ' ')}</h4>
                        <span class="vision-status ${statusClass}">${status.toUpperCase()}</span>
                    </div>
                    <p class="vision-assessment">${analysis.compliance_assessment || ''}</p>
                    ${findingsHtml}
                    ${analysis.confidence ? `<span class="vision-confidence">Confidence: ${(analysis.confidence * 100).toFixed(0)}%</span>` : ''}
                `;
            }

            container.appendChild(item);
        });
    }

    // ─── Reset ────────────────────────────────────────────────────────────────

    function resetCompliance() {
        _stopElapsedTimer();
        document.getElementById('cc-credentials-wrap').style.display = 'block';
        document.getElementById('cc-tabs').style.pointerEvents = '';
        document.getElementById('cc-tabs').style.opacity = '';
        document.querySelectorAll('.cc-panel').forEach(p => { p.style.display = 'none'; });
        document.getElementById(`panel-${activeProvider}`).style.display = 'block';
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('compliance-results').style.display = 'none';

        // Reset AWS to step 1
        if (activeProvider === 'aws') {
            _showCredentials();
            selectedAwsService = null;
            selectedAwsCheck = null;
            document.querySelectorAll('.aws-svc-card').forEach(c => c.classList.remove('aws-svc-card--selected'));
            document.querySelectorAll('.aws-check-card').forEach(c => c.classList.remove('aws-check-card--selected'));
            document.getElementById('btn-run-aws').disabled = true;
        }

        // Reset Datadog to step 1
        if (activeProvider === 'datadog') {
            _ddShowCredentials();
            selectedDdService = null;
            selectedDdCheck = null;
            document.querySelectorAll('#dd-service-grid .aws-svc-card').forEach(c => c.classList.remove('aws-svc-card--selected'));
            document.querySelectorAll('#dd-check-grid .aws-check-card').forEach(c => c.classList.remove('aws-check-card--selected'));
            document.getElementById('btn-run-datadog').disabled = true;
        }
    }

    return { init, switchProvider, resetCompliance };
})();
