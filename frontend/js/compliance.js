/**
 * Cloud Compliance Module
 * Env-backed provider health, service navigation, and compliance dashboards.
 */
const Compliance = (() => {
    let activeProvider = 'aws';
    let providerStatuses = {};
    let servicesByProvider = {};
    let selectedServiceByProvider = {};
    let activeDashboardKey = null;
    let providerResults = {};

    let _lbImages = [];
    let _lbIndex = 0;

    const PROVIDER_LABELS = {
        aws: 'AWS',
        azure: 'Azure',
        github: 'GitHub',
    };

    function init() {
        _initLightbox();

        document.querySelectorAll('.cc-tab').forEach(tab => {
            tab.addEventListener('click', () => switchProvider(tab.dataset.provider));
        });
        document.getElementById('btn-run-selected-service').addEventListener('click', runSelectedService);
        document.getElementById('btn-new-compliance').addEventListener('click', resetCompliance);

        loadProviderStatuses().then(() => {
            switchProvider(activeProvider);
        });
    }

    async function loadProviderStatuses() {
        try {
            const response = await fetch('/api/compliance/providers/status');
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'Failed to load provider statuses');
            providerStatuses = data.providers || {};
            _renderProviderStatuses();
        } catch (err) {
            console.error('Provider status load failed:', err);
            App.showToast('Failed to load provider statuses', 'error');
        }
    }

    function _renderProviderStatuses() {
        Object.entries(providerStatuses).forEach(([provider, status]) => {
            const tab = document.getElementById(`tab-${provider}`);
            const label = document.getElementById(`tab-${provider}-status`);
            if (!tab || !label) return;

            tab.classList.remove('cc-tab--healthy', 'cc-tab--unhealthy');
            tab.classList.add(status.healthy ? 'cc-tab--healthy' : 'cc-tab--unhealthy');
            label.textContent = status.message || (status.healthy ? 'Configured' : 'Not configured');
        });
    }

    async function switchProvider(provider) {
        activeProvider = provider;
        document.querySelectorAll('.cc-tab').forEach(tab => tab.classList.toggle('cc-tab--active', tab.dataset.provider === provider));
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('cc-credentials-wrap').style.display = 'block';
        document.getElementById('cc-tabs').style.pointerEvents = '';
        document.getElementById('cc-tabs').style.opacity = '';

        _renderProviderHero();
        if (!servicesByProvider[provider]) {
            await _loadServices(provider);
        } else {
            _renderServiceList(provider);
        }

        if (provider === 'github') {
            if (providerResults.github) {
                _renderCachedGithubResult();
            } else if (providerStatuses.github?.healthy) {
                runSelectedService({ auto: true });
            }
        } else {
            document.getElementById('compliance-results').style.display = providerResults[provider] ? 'block' : 'none';
        }
    }

    function _renderProviderHero() {
        const status = providerStatuses[activeProvider] || {};
        document.getElementById('cc-provider-eyebrow').textContent = status.healthy ? 'Credentials Verified' : 'Provider Attention Needed';
        document.getElementById('cc-provider-title').textContent = PROVIDER_LABELS[activeProvider] || activeProvider;
        document.getElementById('cc-provider-description').textContent =
            `Service inventory for ${PROVIDER_LABELS[activeProvider] || activeProvider}. Select a service to inspect the configured environment.`;

        const banner = document.getElementById('cc-provider-health-banner');
        banner.className = `cc-service-stage__meta ${status.healthy ? 'cc-service-stage__meta--healthy' : 'cc-service-stage__meta--unhealthy'}`;
        banner.textContent = status.message || 'Provider status unavailable';
    }

    async function _loadServices(provider) {
        try {
            const response = await fetch(`/api/compliance/services/${provider}`);
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'Failed to load services');
            servicesByProvider[provider] = data.services || [];
            if (!selectedServiceByProvider[provider] && servicesByProvider[provider].length) {
                selectedServiceByProvider[provider] = servicesByProvider[provider][0].id;
            }
            _renderServiceList(provider);
        } catch (err) {
            console.error('Service load failed:', err);
            App.showToast(`Failed to load ${provider} services`, 'error');
        }
    }

    function _renderServiceList(provider) {
        const wrap = document.getElementById('cc-service-list');
        const services = servicesByProvider[provider] || [];
        wrap.innerHTML = '';

        services.forEach(service => {
            const item = document.createElement('button');
            item.type = 'button';
            item.className = 'cc-service-item';
            item.dataset.serviceId = service.id;
            item.classList.toggle('cc-service-item--active', selectedServiceByProvider[provider] === service.id);
            item.innerHTML = `
                <span class="cc-service-item__name">${service.name}</span>
                <span class="cc-service-item__desc">${service.description}</span>
            `;
            item.addEventListener('click', () => selectService(service.id));
            wrap.appendChild(item);
        });

        _renderSelectedServiceState();
    }

    function selectService(serviceId) {
        selectedServiceByProvider[activeProvider] = serviceId;
        _renderServiceList(activeProvider);
        if (activeProvider === 'github' && providerResults.github) {
            _renderCachedGithubResult();
        }
    }

    function _renderSelectedServiceState() {
        const services = servicesByProvider[activeProvider] || [];
        const service = services.find(item => item.id === selectedServiceByProvider[activeProvider]);
        document.getElementById('cc-selected-service-title').textContent = service ? service.name : 'Select a service';
        document.getElementById('cc-selected-service-desc').textContent = service
            ? service.description
            : 'Choose a provider service from the left rail to inspect the configured environment.';

        const providerHealthy = providerStatuses[activeProvider]?.healthy;
        document.getElementById('btn-run-selected-service').disabled = !(service && providerHealthy);
    }

    async function runSelectedService(options = {}) {
        const service = selectedServiceByProvider[activeProvider];
        if (!service) return;

        _showProcessing(`${PROVIDER_LABELS[activeProvider]} — ${service.replace(/_/g, ' ')}`);
        const progressPromise = _simulateProgress();
        const controller = new AbortController();
        const fetchTimeout = setTimeout(() => controller.abort(), 300000);

        try {
            const response = await fetch('/api/compliance/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider: activeProvider, service }),
                signal: controller.signal,
            });
            clearTimeout(fetchTimeout);

            await progressPromise;
            _stopElapsedTimer();
            _updateStep('step-analysis', 'completed');
            await _delay(500);

            const data = await response.json();
            if (data.success) {
                providerResults[activeProvider] = data.result;
                _showResults(data.result, activeProvider);
            } else {
                if (!options.auto) App.showToast(data.error || 'Compliance analysis failed', 'error');
                _showInlineError(data.error || 'Compliance analysis failed');
            }
        } catch (err) {
            clearTimeout(fetchTimeout);
            _stopElapsedTimer();
            const msg = err.name === 'AbortError' ? 'Compliance check timed out.' : 'Failed to connect to server';
            if (!options.auto) App.showToast(msg, 'error');
            _showInlineError(msg);
        }
    }

    function _showProcessing(providerName) {
        document.getElementById('cc-tabs').style.pointerEvents = 'none';
        document.getElementById('cc-tabs').style.opacity = '0.5';
        document.getElementById('compliance-results').style.display = 'none';
        const processing = document.getElementById('compliance-processing');
        processing.style.display = 'block';
        document.getElementById('compliance-provider-name').textContent = providerName;
        document.getElementById('cc-processing-bar-fill').style.width = '8%';
        document.querySelectorAll('.cc-step').forEach(step => step.setAttribute('data-status', 'waiting'));
    }

    function _updateStep(stepId, status) {
        const step = document.getElementById(stepId);
        if (step) step.setAttribute('data-status', status);
    }

    async function _simulateProgress() {
        _updateStep('step-auth', 'processing');
        _setProcessingBar(18);
        await _delay(800);
        _updateStep('step-auth', 'completed');
        _updateStep('step-api', 'processing');
        _setProcessingBar(42);
        await _delay(1500);
        _updateStep('step-api', 'completed');
        _updateStep('step-screenshot', 'processing');
        _setProcessingBar(68);
        await _delay(2000);
        _updateStep('step-screenshot', 'completed');
        _updateStep('step-analysis', 'processing');
        _setProcessingBar(86);
        _startElapsedTimer();
    }

    function _delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    let _elapsedInterval = null;
    let _elapsedSeconds = 0;

    function _startElapsedTimer() {
        _elapsedSeconds = 0;
        _elapsedInterval = setInterval(() => {
            _elapsedSeconds += 1;
            const label = document.querySelector('#step-analysis .cc-step__label');
            if (label) label.textContent = `AI Analysis (${_elapsedSeconds}s...)`;
        }, 1000);
    }

    function _stopElapsedTimer() {
        if (_elapsedInterval) clearInterval(_elapsedInterval);
        _elapsedInterval = null;
        const label = document.querySelector('#step-analysis .cc-step__label');
        if (label) label.textContent = 'AI Analysis';
        _setProcessingBar(100);
    }

    function _showResults(result, provider) {
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('cc-tabs').style.pointerEvents = '';
        document.getElementById('cc-tabs').style.opacity = '';
        document.getElementById('compliance-results').style.display = 'block';

        const providerLabel = PROVIDER_LABELS[provider] || provider;
        const serviceLabel = result.service_name || result.check || result.selected_service || 'Service';
        document.getElementById('compliance-results-title').textContent = `${providerLabel} ${serviceLabel} — Analysis Report`;

        _renderStatusBanner(result, provider);
        _renderUnifiedDashboard(result, provider);
        _renderScreenshots(result.screenshots || []);
        _renderApiFindings(result.api_findings || {}, provider);
        _renderVisionAnalysis(result.vision_analysis || {}, result.service_name);
    }

    function _renderCachedGithubResult() {
        const result = { ...providerResults.github, selected_service: selectedServiceByProvider.github };
        _showResults(result, 'github');
    }

    function _showInlineError(message) {
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('cc-tabs').style.pointerEvents = '';
        document.getElementById('cc-tabs').style.opacity = '';
        const banner = document.getElementById('cc-provider-health-banner');
        banner.className = 'cc-service-stage__meta cc-service-stage__meta--unhealthy';
        banner.textContent = message;
    }

    function _setProcessingBar(value) {
        const fill = document.getElementById('cc-processing-bar-fill');
        if (fill) fill.style.width = `${Math.max(0, Math.min(100, value))}%`;
    }

    function _renderStatusBanner(result, provider) {
        const banner = document.getElementById('compliance-status-banner');
        const icon = document.getElementById('compliance-status-icon');
        const text = document.getElementById('compliance-status-text');
        const desc = document.getElementById('compliance-status-desc');

        if (provider === 'github') {
            const summary = result.github_summary || {};
            const status = summary.overall_status || 'unknown';
            banner.className = `cc-status-banner ${_statusToBannerClass(status)}`;
            icon.textContent = _statusToSymbol(status);
            text.textContent = `GitHub posture score: ${summary.score ?? '--'}`;
            const counts = summary.status_counts || {};
            desc.textContent = `${counts.pass || 0} passed, ${counts.warn || 0} warnings, ${counts.fail || 0} failures, ${counts.unknown || 0} unknown.`;
            return;
        }

        const genericStatus = result.status === 'error'
            ? 'fail'
            : result.encryption_enabled === true
                ? 'pass'
                : result.encryption_enabled === false
                    ? 'fail'
                    : 'warn';

        banner.className = `cc-status-banner ${_statusToBannerClass(genericStatus)}`;
        icon.textContent = _statusToSymbol(genericStatus);
        text.textContent = `${PROVIDER_LABELS[provider]} ${result.service_name || result.check || 'Service'} — ${genericStatus.toUpperCase()}`;
        desc.textContent = result.error || result.check_description || 'Review the findings and metadata below for the current service.';
    }

    function _renderUnifiedDashboard(result, provider) {
        const card = document.getElementById('github-dashboard-card');
        card.style.display = 'block';

        if (provider === 'github') {
            _renderGithubDashboard(result);
            return;
        }

        _renderGenericDashboard(result, provider);
    }

    function _renderGenericDashboard(result, provider) {
        const model = _buildGenericServiceModel(result, provider);
        document.querySelector('.github-dashboard-kicker').textContent = `${PROVIDER_LABELS[provider]} Service Overview`;
        document.querySelector('.github-dashboard-title').textContent = `${result.service_name || result.check || 'Service'} posture`;
        document.getElementById('github-dashboard-copy').textContent = model.copy;
        document.getElementById('github-score-value').textContent = model.score;
        document.getElementById('github-passed-count').textContent = model.counts.pass;
        document.getElementById('github-warn-count').textContent = model.counts.warn;
        document.getElementById('github-fail-count').textContent = model.counts.fail;
        document.getElementById('github-unknown-count').textContent = model.counts.unknown;

        const cardsWrap = document.getElementById('github-service-cards');
        const barsWrap = document.getElementById('github-bargraph');
        const tabsWrap = document.getElementById('github-metadata-tabs');
        cardsWrap.innerHTML = '';
        barsWrap.innerHTML = '';
        tabsWrap.innerHTML = '';

        model.entries.forEach(entry => {
            const cardEl = document.createElement('button');
            cardEl.type = 'button';
            cardEl.dataset.serviceKey = entry.key;
            cardEl.className = `github-service-card github-service-card--${entry.status}`;
            cardEl.innerHTML = `
                <div class="github-service-card__top">
                    <span class="github-service-card__name">${entry.name}</span>
                    <span class="github-service-card__badge">${entry.status.toUpperCase()}</span>
                </div>
                <div class="github-service-card__score">${entry.score}</div>
                <p class="github-service-card__summary">${entry.summary}</p>
                <div class="github-service-card__metrics">${entry.metrics || 'Review metadata for full detail.'}</div>
            `;
            cardEl.addEventListener('click', () => _selectDashboardEntry(entry.key, model));
            cardsWrap.appendChild(cardEl);

            const bar = document.createElement('div');
            bar.className = 'github-bar';
            bar.innerHTML = `
                <div class="github-bar__label">
                    <span>${entry.name}</span>
                    <strong>${entry.score}</strong>
                </div>
                <div class="github-bar__track">
                    <div class="github-bar__fill github-bar__fill--${entry.status}" style="width:${entry.score}%"></div>
                </div>
            `;
            barsWrap.appendChild(bar);

            const tab = document.createElement('button');
            tab.type = 'button';
            tab.className = 'github-metadata-tab';
            tab.dataset.serviceKey = entry.key;
            tab.textContent = entry.name;
            tab.addEventListener('click', () => _selectDashboardEntry(entry.key, model));
            tabsWrap.appendChild(tab);
        });

        _selectDashboardEntry(model.entries[0]?.key, model);
    }

    function _buildGenericServiceModel(result, provider) {
        const entries = [];
        entries.push({
            key: 'overview',
            name: 'API Overview',
            status: result.status === 'error' ? 'fail' : 'pass',
            score: result.status === 'error' ? 28 : result.encryption_enabled === false ? 36 : 82,
            summary: result.error || result.check_description || 'Provider API response and captured service metadata.',
            metrics: `${Object.keys(result.api_findings || {}).length} API sections`,
            metadata: result.api_findings || {},
            findingsHtml: _renderGenericFindings(result.api_findings || {}),
        });

        Object.entries(result.vision_analysis || {}).forEach(([label, analysis]) => {
            const risk = analysis.risk_level || analysis.encryption_status || analysis.mfa_status || 'unknown';
            const status = risk === 'low' || risk === 'enabled' ? 'pass' : risk === 'medium' || risk === 'partial' ? 'warn' : risk === 'high' || risk === 'critical' || risk === 'disabled' ? 'fail' : 'unknown';
            entries.push({
                key: label,
                name: label.replace(/_/g, ' '),
                status,
                score: _statusScore(status),
                summary: analysis.page_summary || analysis.compliance_assessment || 'Screenshot analysis',
                metrics: analysis.confidence ? `Confidence ${(analysis.confidence * 100).toFixed(0)}%` : '',
                metadata: analysis,
                findingsHtml: _renderGenericAnalysisFindings(analysis),
            });
        });

        const counts = _countStatuses(entries);
        const score = Math.round(entries.reduce((sum, entry) => sum + entry.score, 0) / Math.max(entries.length, 1));
        return {
            score,
            counts,
            copy: `Score, findings, and metadata for the selected ${PROVIDER_LABELS[provider]} service.`,
            entries,
        };
    }

    function _renderGithubDashboard(result) {
        const services = result.services || {};
        const summary = result.github_summary || {};
        const counts = summary.status_counts || {};
        const serviceEntries = Object.entries(services);

        document.querySelector('.github-dashboard-kicker').textContent = 'GitHub Service Overview';
        document.querySelector('.github-dashboard-title').textContent = 'Security posture across five GitHub surfaces';
        document.getElementById('github-dashboard-copy').textContent =
            `A visual summary modeled around service status, backlog, and security coverage for ${serviceEntries.length} GitHub surfaces.`;
        document.getElementById('github-score-value').textContent = summary.score ?? '--';
        document.getElementById('github-passed-count').textContent = counts.pass || 0;
        document.getElementById('github-warn-count').textContent = counts.warn || 0;
        document.getElementById('github-fail-count').textContent = counts.fail || 0;
        document.getElementById('github-unknown-count').textContent = counts.unknown || 0;

        const cardsWrap = document.getElementById('github-service-cards');
        const barsWrap = document.getElementById('github-bargraph');
        const tabsWrap = document.getElementById('github-metadata-tabs');
        cardsWrap.innerHTML = '';
        barsWrap.innerHTML = '';
        tabsWrap.innerHTML = '';

        serviceEntries.forEach(([key, service]) => {
            const cardEl = document.createElement('button');
            cardEl.type = 'button';
            cardEl.className = `github-service-card github-service-card--${service.status}`;
            cardEl.dataset.serviceKey = key;
            cardEl.innerHTML = `
                <div class="github-service-card__top">
                    <span class="github-service-card__name">${service.name}</span>
                    <span class="github-service-card__badge">${service.status.toUpperCase()}</span>
                </div>
                <div class="github-service-card__score">${service.score}</div>
                <p class="github-service-card__summary">${service.summary}</p>
                <div class="github-service-card__metrics">${_formatGithubMetrics(service.metrics)}</div>
            `;
            cardEl.addEventListener('click', () => _selectDashboardEntry(key, { type: 'github', services }));
            cardsWrap.appendChild(cardEl);

            const bar = document.createElement('div');
            bar.className = 'github-bar';
            bar.innerHTML = `
                <div class="github-bar__label">
                    <span>${service.name}</span>
                    <strong>${service.score}</strong>
                </div>
                <div class="github-bar__track">
                    <div class="github-bar__fill github-bar__fill--${service.status}" style="width:${service.score}%"></div>
                </div>
            `;
            barsWrap.appendChild(bar);

            const tab = document.createElement('button');
            tab.type = 'button';
            tab.className = 'github-metadata-tab';
            tab.dataset.serviceKey = key;
            tab.textContent = service.name;
            tab.addEventListener('click', () => _selectDashboardEntry(key, { type: 'github', services }));
            tabsWrap.appendChild(tab);
        });

        const defaultKey = result.selected_service && services[result.selected_service]
            ? result.selected_service
            : serviceEntries[0]?.[0];
        _selectDashboardEntry(defaultKey, { type: 'github', services });
    }

    function _selectDashboardEntry(entryKey, model) {
        activeDashboardKey = entryKey;
        document.querySelectorAll('.github-metadata-tab').forEach(tab => {
            tab.classList.toggle('github-metadata-tab--active', tab.dataset.serviceKey === entryKey);
        });
        document.querySelectorAll('.github-service-card').forEach(card => {
            card.classList.toggle('github-service-card--active', card.dataset.serviceKey === entryKey);
        });

        if (model.type === 'github') {
            const service = model.services[entryKey] || {};
            document.getElementById('github-metadata-json').textContent = JSON.stringify(service.metadata || {}, null, 2);
            _renderGithubServiceFindings(entryKey, service);
            return;
        }

        const entry = (model.entries || []).find(item => item.key === entryKey) || model.entries?.[0];
        document.getElementById('github-metadata-json').textContent = JSON.stringify(entry?.metadata || {}, null, 2);
        document.getElementById('github-findings-list').innerHTML = entry?.findingsHtml || '<p class="empty-state">No findings available.</p>';
    }

    function _renderScreenshots(screenshots) {
        const card = document.getElementById('screenshots-card');
        const gallery = document.getElementById('screenshots-gallery');
        gallery.innerHTML = '';

        if (!screenshots.length) {
            card.style.display = 'none';
            return;
        }

        card.style.display = 'block';
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
        if (provider === 'github') {
            container.innerHTML = _renderGithubApiFindings(findings);
            return;
        }
        container.innerHTML = _renderGenericFindings(findings);
    }

    function _renderGenericFindings(findings) {
        const entries = Object.entries(findings || {});
        if (!entries.length) return '<p class="empty-state">No API findings available.</p>';
        return `<div class="findings-grid">${entries.map(([key, value]) => `
            <div class="finding-card finding-info">
                <div class="finding-header">
                    <span class="finding-badge">${Array.isArray(value) ? value.length : typeof value === 'object' ? 'JSON' : 'Info'}</span>
                    <h4>${key.replace(/_/g, ' ')}</h4>
                </div>
                <p>${_summarizeValue(value)}</p>
            </div>`).join('')}</div>`;
    }

    function _renderGithubApiFindings(findings) {
        let html = '<div class="findings-grid">';
        if (findings.summary) {
            html += `
                <div class="finding-card finding-info">
                    <div class="finding-header">
                        <span class="finding-badge">${findings.summary.score}</span>
                        <h4>Overall GitHub Score</h4>
                    </div>
                    <p>Status: ${findings.summary.overall_status}<br>Five GitHub service surfaces were analyzed.</p>
                </div>`;
        }
        if (findings.user) {
            html += `
                <div class="finding-card ${findings.user.two_factor_authentication ? 'finding-pass' : 'finding-fail'}">
                    <div class="finding-header">
                        <span class="finding-badge">${findings.user.two_factor_authentication ? 'Enabled' : 'Disabled'}</span>
                        <h4>Two-Factor Authentication</h4>
                    </div>
                    <p>User: ${findings.user.login} (${findings.user.name || 'N/A'})<br>2FA: ${findings.user.two_factor_authentication ? 'Enabled' : 'Not Enabled'}</p>
                </div>`;
        }
        if (findings.organizations?.length) {
            findings.organizations.forEach(org => {
                html += `
                    <div class="finding-card ${org.two_factor_requirement_enabled ? 'finding-pass' : 'finding-warn'}">
                        <div class="finding-header">
                            <span class="finding-badge">${org.two_factor_requirement_enabled ? 'Required' : 'Optional'}</span>
                            <h4>Org: ${org.login || org.name}</h4>
                        </div>
                        <p>2FA Requirement: ${org.two_factor_requirement_enabled ? 'Enforced' : 'Not enforced'}</p>
                    </div>`;
            });
        }
        html += '</div>';
        return html;
    }

    function _renderVisionAnalysis(visionResults) {
        const card = document.getElementById('vision-card');
        const container = document.getElementById('vision-analysis-content');
        const entries = Object.entries(visionResults || {});
        if (!entries.length) {
            card.style.display = 'none';
            return;
        }

        card.style.display = 'block';
        container.innerHTML = '';
        entries.forEach(([label, analysis]) => {
            const status = analysis.risk_level || analysis.encryption_status || analysis.mfa_status || 'unknown';
            const statusClass = status === 'low' || status === 'enabled' ? 'status-pass'
                : status === 'medium' || status === 'partial' ? 'status-unknown'
                    : status === 'high' || status === 'critical' || status === 'disabled' ? 'status-fail'
                        : 'status-unknown';

            const item = document.createElement('div');
            item.className = 'vision-analysis-item';
            item.innerHTML = `
                <div class="vision-header">
                    <h4>${label.replace(/_/g, ' ')}</h4>
                    <span class="vision-status ${statusClass}">${String(status).toUpperCase()}</span>
                </div>
                <p class="vision-assessment">${analysis.page_summary || analysis.compliance_assessment || ''}</p>
                ${_renderList(analysis.resources_found || analysis.findings)}
                ${_renderList(analysis.security_observations)}
                ${_renderList(analysis.recommendations)}
                ${analysis.confidence ? `<span class="vision-confidence">Confidence: ${(analysis.confidence * 100).toFixed(0)}%</span>` : ''}
            `;
            container.appendChild(item);
        });
    }

    function _renderList(items) {
        return items && items.length ? `<ul class="vision-findings">${items.map(item => `<li>${item}</li>`).join('')}</ul>` : '';
    }

    function _renderGithubServiceFindings(serviceKey, service) {
        const wrap = document.getElementById('github-findings-list');
        const metadata = service?.metadata || {};

        if (serviceKey === 'repositories') {
            wrap.innerHTML = _renderGithubRepositoriesFindings(metadata);
        } else if (serviceKey === 'pull_requests') {
            wrap.innerHTML = _renderGithubPullRequestFindings(metadata);
        } else if (serviceKey === 'settings') {
            wrap.innerHTML = _renderGithubSettingsFindings(metadata);
        } else if (serviceKey === 'vulnerabilities') {
            wrap.innerHTML = _renderGithubVulnerabilityFindings(metadata);
        } else if (serviceKey === 'issues') {
            wrap.innerHTML = _renderGithubIssueFindings(metadata);
        } else {
            wrap.innerHTML = '<p class="empty-state">No findings renderer is available for this service.</p>';
        }
    }

    function _renderGithubRepositoriesFindings(metadata) {
        const repos = metadata.repositories || [];
        if (!repos.length) return '<p class="empty-state">No repositories available.</p>';
        return repos.map(repo => `
            <article class="github-finding-item">
                <div class="github-finding-item__header">
                    <div>
                        <h5>${repo.full_name}</h5>
                        <p>${repo.language || 'No primary language'} · default branch ${repo.default_branch || 'n/a'} · updated ${_shortDate(repo.updated_at)}</p>
                    </div>
                    <div class="github-finding-badges">
                        <span class="github-chip">${repo.visibility || (repo.private ? 'private' : 'public')}</span>
                        ${repo.archived ? '<span class="github-chip github-chip--warn">archived</span>' : ''}
                        ${repo.has_issues ? '<span class="github-chip github-chip--pass">issues on</span>' : '<span class="github-chip github-chip--fail">issues off</span>'}
                    </div>
                </div>
                <div class="github-finding-stats">
                    <span>Open issues <strong>${repo.open_issues_count ?? 0}</strong></span>
                    <span>Forks <strong>${repo.forks_count ?? 0}</strong></span>
                    <span>Stars <strong>${repo.stargazers_count ?? 0}</strong></span>
                    <span>Watchers <strong>${repo.watchers_count ?? 0}</strong></span>
                </div>
                <div class="github-branch-list">
                    ${(repo.branches || []).length
                        ? repo.branches.map(branch => `<div class="github-branch-pill"><span>${branch.name}</span><em>${branch.protected ? 'protected' : 'standard'}</em></div>`).join('')
                        : '<span class="github-empty-inline">No branch data returned.</span>'}
                    ${repo.branches_error ? `<div class="github-inline-warning">Branch lookup unavailable: ${repo.branches_error}</div>` : ''}
                </div>
            </article>`).join('');
    }

    function _renderGithubPullRequestFindings(metadata) {
        const openItems = metadata.open_results?.items || [];
        const mergedItems = metadata.merged_results?.items || [];
        const list = [...openItems.map(item => ({ ...item, __kind: 'open' })), ...mergedItems.map(item => ({ ...item, __kind: 'merged' }))];
        if (!list.length) return '<p class="empty-state">No pull requests available.</p>';
        return list.map(item => `
            <article class="github-finding-item">
                <div class="github-finding-item__header">
                    <div>
                        <h5>${item.title}</h5>
                        <p>${item.repository_url ? item.repository_url.split('/').slice(-2).join('/') : 'Unknown repository'} · #${item.number} · updated ${_shortDate(item.updated_at)}</p>
                    </div>
                    <div class="github-finding-badges">
                        <span class="github-chip ${item.__kind === 'open' ? 'github-chip--warn' : 'github-chip--pass'}">${item.__kind}</span>
                        ${item.state ? `<span class="github-chip">${item.state}</span>` : ''}
                    </div>
                </div>
                <div class="github-finding-stats">
                    <span>Author <strong>${item.user?.login || 'n/a'}</strong></span>
                    <span>Comments <strong>${item.comments ?? 0}</strong></span>
                    <span>Created <strong>${_shortDate(item.created_at)}</strong></span>
                </div>
                ${item.body ? `<p class="github-finding-body">${_truncate(item.body, 240)}</p>` : ''}
            </article>`).join('');
    }

    function _renderGithubSettingsFindings(metadata) {
        const orgs = metadata.organizations || [];
        const repoSecurity = metadata.repository_security || [];
        return `
            <section class="github-findings-section">
                <div class="github-findings-section__title">Organization Policies</div>
                ${orgs.length ? orgs.map(org => `
                    <article class="github-finding-item github-finding-item--compact">
                        <div class="github-finding-item__header">
                            <div><h5>${org.name || org.login}</h5><p>${org.login}</p></div>
                            <div class="github-finding-badges">
                                <span class="github-chip ${org.two_factor_requirement_enabled ? 'github-chip--pass' : 'github-chip--warn'}">${org.two_factor_requirement_enabled ? '2FA required' : '2FA optional'}</span>
                            </div>
                        </div>
                    </article>`).join('') : '<p class="empty-state">No organization settings returned.</p>'}
            </section>
            <section class="github-findings-section">
                <div class="github-findings-section__title">Repository Security Controls</div>
                ${repoSecurity.length ? repoSecurity.map(repo => {
                    const sec = repo.security_and_analysis || {};
                    return `<article class="github-finding-item github-finding-item--compact">
                        <div class="github-finding-item__header"><div><h5>${repo.full_name}</h5><p>Repository security controls</p></div></div>
                        <div class="github-control-grid">
                            ${_githubControlPill('Dependabot', sec.dependabot_security_updates?.status)}
                            ${_githubControlPill('Secret scanning', sec.secret_scanning?.status)}
                            ${_githubControlPill('Push protection', sec.secret_scanning_push_protection?.status)}
                            ${_githubControlPill('Code scanning', sec.code_scanning?.status)}
                        </div>
                    </article>`;
                }).join('') : '<p class="empty-state">No repository security settings returned.</p>'}
            </section>`;
    }

    function _renderGithubVulnerabilityFindings(metadata) {
        const repos = metadata.repositories || [];
        if (!repos.length) return '<p class="empty-state">No vulnerability findings available.</p>';
        return repos.map(repo => `
            <article class="github-finding-item">
                <div class="github-finding-item__header">
                    <div><h5>${repo.full_name}</h5><p>Dependabot and repository security coverage</p></div>
                    <div class="github-finding-badges">
                        <span class="github-chip ${(repo.open_dependabot_alerts || 0) > 0 ? 'github-chip--fail' : 'github-chip--pass'}">${repo.open_dependabot_alerts || 0} alerts</span>
                    </div>
                </div>
                <div class="github-control-grid">
                    ${Object.entries(repo.feature_states || {}).map(([label, value]) => _githubControlPill(label.replace(/_/g, ' '), value)).join('')}
                </div>
                ${(repo.dependabot_alerts || []).length ? `<div class="github-subfinding-list">${repo.dependabot_alerts.map(alert => `
                    <div class="github-subfinding">
                        <strong>${alert.security_vulnerability?.package?.name || 'package'}</strong>
                        <span>${alert.security_advisory?.severity || 'unknown'} severity · ${alert.state || 'open'}</span>
                    </div>`).join('')}</div>` : ''}
                ${repo.dependabot_alerts_error ? `<div class="github-inline-warning">Alert lookup unavailable: ${repo.dependabot_alerts_error}</div>` : ''}
            </article>`).join('');
    }

    function _renderGithubIssueFindings(metadata) {
        const items = metadata.search_results?.items || [];
        if (!items.length) return '<p class="empty-state">No issues available.</p>';
        return items.map(item => `
            <article class="github-finding-item">
                <div class="github-finding-item__header">
                    <div><h5>${item.title}</h5><p>${item.repository_url ? item.repository_url.split('/').slice(-2).join('/') : 'Unknown repository'} · #${item.number}</p></div>
                    <div class="github-finding-badges">
                        <span class="github-chip ${item.state === 'open' ? 'github-chip--warn' : 'github-chip--pass'}">${item.state || 'unknown'}</span>
                    </div>
                </div>
                <div class="github-finding-stats">
                    <span>Author <strong>${item.user?.login || 'n/a'}</strong></span>
                    <span>Comments <strong>${item.comments ?? 0}</strong></span>
                    <span>Updated <strong>${_shortDate(item.updated_at)}</strong></span>
                </div>
                ${item.labels?.length ? `<div class="github-branch-list">${item.labels.map(label => `<div class="github-branch-pill"><span>${label.name}</span></div>`).join('')}</div>` : ''}
                ${item.body ? `<p class="github-finding-body">${_truncate(item.body, 240)}</p>` : ''}
            </article>`).join('');
    }

    function _renderGenericAnalysisFindings(analysis) {
        const blocks = [];
        if (analysis.resources_found?.length) blocks.push(`<div class="github-subfinding-list">${analysis.resources_found.map(item => `<div class="github-subfinding"><strong>Resource</strong><span>${item}</span></div>`).join('')}</div>`);
        if (analysis.security_observations?.length) blocks.push(`<div class="github-subfinding-list">${analysis.security_observations.map(item => `<div class="github-subfinding"><strong>Observation</strong><span>${item}</span></div>`).join('')}</div>`);
        if (analysis.recommendations?.length) blocks.push(`<div class="github-subfinding-list">${analysis.recommendations.map(item => `<div class="github-subfinding"><strong>Recommendation</strong><span>${item}</span></div>`).join('')}</div>`);
        return blocks.join('') || '<p class="empty-state">No detailed findings available.</p>';
    }

    function _githubControlPill(label, status) {
        const normalizedStatus = status === null || status === undefined ? 'not_configured' : status;
        const className = normalizedStatus === 'enabled' ? 'github-chip--pass' : normalizedStatus === 'disabled' ? 'github-chip--fail' : 'github-chip--warn';
        const labelText = normalizedStatus === 'not_configured' ? 'Not Configured' : normalizedStatus.replace(/_/g, ' ');
        return `<div class="github-control-pill ${className}"><span>${label}</span><strong>${labelText}</strong></div>`;
    }

    function _countStatuses(entries) {
        const counts = { pass: 0, warn: 0, fail: 0, unknown: 0 };
        entries.forEach(entry => {
            counts[entry.status] = (counts[entry.status] || 0) + 1;
        });
        return counts;
    }

    function _statusScore(status) {
        return { pass: 94, warn: 63, fail: 26, unknown: 45 }[status] || 45;
    }

    function _statusToBannerClass(status) {
        if (status === 'pass') return 'status-pass';
        if (status === 'fail') return 'status-fail';
        if (status === 'warn') return 'status-unknown';
        return 'status-info';
    }

    function _statusToSymbol(status) {
        if (status === 'pass') return '\u2713';
        if (status === 'fail') return '\u2715';
        if (status === 'warn') return '!';
        return '?';
    }

    function _formatGithubMetrics(metrics) {
        if (!metrics || Object.keys(metrics).length === 0) return 'No metrics';
        return Object.entries(metrics).slice(0, 4).map(([key, value]) => `${key.replace(/_/g, ' ')}: ${value}`).join(' · ');
    }

    function _summarizeValue(value) {
        if (Array.isArray(value)) return `${value.length} item(s)`;
        if (value && typeof value === 'object') return JSON.stringify(value).slice(0, 180);
        return String(value);
    }

    function _shortDate(value) {
        if (!value) return 'n/a';
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString();
    }

    function _truncate(text, max) {
        return text && text.length > max ? `${text.slice(0, max)}...` : (text || '');
    }

    function resetCompliance() {
        _stopElapsedTimer();
        document.getElementById('cc-credentials-wrap').style.display = 'block';
        document.getElementById('cc-tabs').style.pointerEvents = '';
        document.getElementById('cc-tabs').style.opacity = '';
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('compliance-results').style.display = activeProvider === 'github' && providerResults.github ? 'block' : 'none';
        document.getElementById('github-dashboard-card').style.display = 'none';
        activeDashboardKey = null;
        _renderProviderHero();
        _renderSelectedServiceState();
        if (activeProvider === 'github' && providerResults.github) {
            _renderCachedGithubResult();
        }
    }

    function _initLightbox() {
        const overlay = document.getElementById('lightbox-overlay');
        document.getElementById('lightbox-close').addEventListener('click', _closeLightbox);
        document.getElementById('lightbox-prev').addEventListener('click', () => _lbNav(-1));
        document.getElementById('lightbox-next').addEventListener('click', () => _lbNav(1));
        overlay.addEventListener('click', event => { if (event.target === overlay) _closeLightbox(); });
        document.addEventListener('keydown', event => {
            if (overlay.style.display === 'none') return;
            if (event.key === 'Escape') _closeLightbox();
            if (event.key === 'ArrowLeft') _lbNav(-1);
            if (event.key === 'ArrowRight') _lbNav(1);
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
        if (!_lbImages.length) return;
        document.getElementById('lightbox-img').src = _lbImages[_lbIndex].src;
        document.getElementById('lightbox-img').alt = _lbImages[_lbIndex].caption;
        document.getElementById('lightbox-caption').textContent = _lbImages[_lbIndex].caption;
        document.getElementById('lightbox-counter').textContent = `${_lbIndex + 1} / ${_lbImages.length}`;
        document.getElementById('lightbox-prev').style.display = _lbImages.length > 1 ? 'flex' : 'none';
        document.getElementById('lightbox-next').style.display = _lbImages.length > 1 ? 'flex' : 'none';
    }

    return { init, switchProvider, resetCompliance };
})();
