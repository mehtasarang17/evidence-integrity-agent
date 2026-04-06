/**
 * Service monitoring module.
 * Env-backed provider health, service navigation, and monitoring dashboards.
 */
const Compliance = (() => {
    let activeProvider = 'aws';
    let providerStatuses = {};
    let servicesByProvider = {};
    let selectedServiceByProvider = {};
    let serviceSearchByProvider = {};
    let visibleServiceCountByProvider = {};
    let regionFilterByProvider = {};
    let activeDashboardKey = null;
    let providerResults = {};
    let providerSnapshotMeta = {};
    let _autoRefreshTimer = null;

    let _lbImages = [];
    let _lbIndex = 0;

    const PROVIDER_LABELS = {
        aws: 'AWS',
        azure: 'Azure',
        github: 'GitHub',
        gitlab: 'GitLab',
    };
    const SERVICE_PAGE_SIZE = 10;

    function init() {
        _initLightbox();

        document.querySelectorAll('.cc-tab').forEach(tab => {
            tab.addEventListener('click', () => switchProvider(tab.dataset.provider));
        });
        document.getElementById('btn-run-selected-service').addEventListener('click', runSelectedService);
        document.getElementById('btn-new-compliance').addEventListener('click', resetCompliance);
        document.getElementById('cc-service-search').addEventListener('input', event => {
            serviceSearchByProvider[activeProvider] = event.target.value || '';
            visibleServiceCountByProvider[activeProvider] = SERVICE_PAGE_SIZE;
            _renderServiceList(activeProvider);
        });
        document.getElementById('cc-service-more').addEventListener('click', () => {
            visibleServiceCountByProvider[activeProvider] = (visibleServiceCountByProvider[activeProvider] || SERVICE_PAGE_SIZE) + SERVICE_PAGE_SIZE;
            _renderServiceList(activeProvider);
        });
        document.getElementById('cc-region-select').addEventListener('change', event => {
            regionFilterByProvider[activeProvider] = event.target.value || 'all';
            _rerenderActiveProvider();
        });

        _startAutoRefresh();
        loadProviderStatuses().then(() => {
            switchProvider(activeProvider);
        });
    }

    async function loadProviderStatuses() {
        try {
            const response = await fetch('/api/monitoring/providers/status');
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'Failed to load provider connections');
            providerStatuses = data.providers || {};
            _renderProviderStatuses();
        } catch (err) {
            console.error('Provider status load failed:', err);
            App.showToast('Failed to load provider connections', 'error');
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
        _renderHeroPanel();
    }

    function _formatRelativeSnapshot(value) {
        if (!value) return 'Awaiting cache';
        const date = _parseTimestamp(value);
        if (Number.isNaN(date.getTime())) return value;
        const diffMinutes = Math.max(0, Math.round((Date.now() - date.getTime()) / 60000));
        if (diffMinutes < 1) return 'Just refreshed';
        if (diffMinutes < 60) return `${diffMinutes}m ago`;
        const diffHours = Math.round(diffMinutes / 60);
        if (diffHours < 24) return `${diffHours}h ago`;
        return _shortDateTime(value);
    }

    function _renderHeroPanel() {
        const heroProvider = document.getElementById('cc-hero-provider');
        const onlineCount = document.getElementById('cc-hero-online-count');
        const serviceCount = document.getElementById('cc-hero-service-count');
        const refreshLabel = document.getElementById('cc-hero-refresh');
        const providerList = document.getElementById('cc-hero-provider-list');
        if (!heroProvider || !onlineCount || !serviceCount || !refreshLabel || !providerList) return;

        const activeLabel = PROVIDER_LABELS[activeProvider] || activeProvider;
        const healthyCount = Object.values(providerStatuses).filter(status => status?.healthy).length;
        const totalProviders = Object.keys(PROVIDER_LABELS).length;
        const activeServices = (servicesByProvider[activeProvider] || []).length;
        const activeSnapshot = providerSnapshotMeta[activeProvider] || {};

        heroProvider.textContent = `${activeLabel} monitoring fabric`;
        onlineCount.textContent = `${healthyCount}/${totalProviders}`;
        serviceCount.textContent = activeServices ? `${activeServices} services` : 'Loading';
        refreshLabel.textContent = _formatRelativeSnapshot(activeSnapshot.collected_at);

        providerList.innerHTML = Object.entries(PROVIDER_LABELS).map(([provider, label]) => {
            const status = providerStatuses[provider] || {};
            const serviceTotal = servicesByProvider[provider]?.length || 0;
            const isActive = provider === activeProvider ? ' cc-hero-provider-row--active' : '';
            const stateClass = status.healthy ? 'cc-hero-provider-row__dot--healthy' : 'cc-hero-provider-row__dot--unhealthy';
            const summary = status.message || 'Awaiting configuration';
            return `
                <div class="cc-hero-provider-row${isActive}">
                    <span class="cc-hero-provider-row__dot ${stateClass}"></span>
                    <div class="cc-hero-provider-row__body">
                        <strong>${label}</strong>
                        <span>${summary}</span>
                    </div>
                    <em>${serviceTotal ? `${serviceTotal} svc` : '—'}</em>
                </div>
            `;
        }).join('');
    }

    async function switchProvider(provider) {
        activeProvider = provider;
        const monitoringSection = document.getElementById('section-compliance');
        if (monitoringSection) {
            monitoringSection.dataset.provider = provider;
        }
        if (provider !== 'aws' && provider !== 'azure') {
            _hideRegionFilter();
        }
        document.querySelectorAll('.cc-tab').forEach(tab => tab.classList.toggle('cc-tab--active', tab.dataset.provider === provider));
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('cc-credentials-wrap').style.display = 'block';
        document.getElementById('cc-tabs').style.pointerEvents = '';
        document.getElementById('cc-tabs').style.opacity = '';

        _renderProviderHero();
        if (!servicesByProvider[provider]) {
            await _loadServices(provider);
        } else {
            _syncServiceSearchInput(provider);
            _renderServiceList(provider);
        }
        await _loadLatestSnapshot(provider);

        if (provider === 'github') {
            if (providerResults.github) {
                _renderCachedGithubResult();
            } else {
                document.getElementById('compliance-results').style.display = 'none';
            }
        } else if (provider === 'aws') {
            if (providerResults.aws) {
                _renderCachedAwsResult();
            } else {
                document.getElementById('compliance-results').style.display = 'none';
            }
        } else if (provider === 'azure') {
            if (providerResults.azure) {
                _renderCachedAzureResult();
            } else {
                document.getElementById('compliance-results').style.display = 'none';
            }
        } else if (provider === 'gitlab') {
            if (providerResults.gitlab) {
                _renderCachedGitlabResult();
            } else {
                document.getElementById('compliance-results').style.display = 'none';
            }
        } else {
            document.getElementById('compliance-results').style.display = providerResults[provider] ? 'block' : 'none';
        }
    }

    function _renderProviderHero() {
        const status = providerStatuses[activeProvider] || {};
        document.getElementById('cc-provider-eyebrow').textContent = status.healthy ? 'Connection Verified' : 'Provider Attention Needed';
        document.getElementById('cc-provider-title').textContent = PROVIDER_LABELS[activeProvider] || activeProvider;
        document.getElementById('cc-provider-description').textContent =
            `Connected ${PROVIDER_LABELS[activeProvider] || activeProvider} environment. Choose a service to inspect its live activity, inventory, and current operating state.`;

        const banner = document.getElementById('cc-provider-health-banner');
        banner.className = `cc-service-stage__meta ${status.healthy ? 'cc-service-stage__meta--healthy' : 'cc-service-stage__meta--unhealthy'}`;
        banner.textContent = status.message || 'Provider status unavailable';
        _renderHeroPanel();
    }

    async function _loadServices(provider) {
        try {
            const response = await fetch(`/api/monitoring/services/${provider}`);
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'Failed to load services');
            servicesByProvider[provider] = data.services || [];
            if (typeof serviceSearchByProvider[provider] !== 'string') {
                serviceSearchByProvider[provider] = '';
            }
            if (!visibleServiceCountByProvider[provider]) {
                visibleServiceCountByProvider[provider] = SERVICE_PAGE_SIZE;
            }
            if (!selectedServiceByProvider[provider] && servicesByProvider[provider].length) {
                selectedServiceByProvider[provider] = servicesByProvider[provider][0].id;
            }
            _syncServiceSearchInput(provider);
            _renderServiceList(provider);
            _renderHeroPanel();
        } catch (err) {
            console.error('Service load failed:', err);
            App.showToast(`Failed to load ${provider} services`, 'error');
        }
    }

    async function _loadLatestSnapshot(provider, options = {}) {
        try {
            const response = await fetch(`/api/monitoring/providers/${provider}/latest`);
            const data = await response.json();
            if (!data.success || !data.result) return false;

            const nextMeta = data.snapshot || {};
            const prevMeta = providerSnapshotMeta[provider] || {};
            const changed = nextMeta.id && nextMeta.id !== prevMeta.id;
            providerSnapshotMeta[provider] = nextMeta;
            providerResults[provider] = data.result;
            _renderHeroPanel();

            if (provider === activeProvider && (changed || options.forceRender)) {
                if (provider === 'github') _renderCachedGithubResult();
                if (provider === 'aws') _renderCachedAwsResult();
                if (provider === 'azure') _renderCachedAzureResult();
                if (provider === 'gitlab') _renderCachedGitlabResult();
            }
            return changed;
        } catch (err) {
            console.error(`Latest snapshot load failed for ${provider}:`, err);
            return false;
        }
    }

    function _startAutoRefresh() {
        if (_autoRefreshTimer) clearInterval(_autoRefreshTimer);
        _autoRefreshTimer = setInterval(() => {
            const complianceSection = document.getElementById('section-compliance');
            if (!complianceSection?.classList.contains('active')) return;
            _loadLatestSnapshot(activeProvider, { forceRender: Boolean(providerResults[activeProvider]) });
        }, 30000);
    }

    function _syncServiceSearchInput(provider) {
        const searchInput = document.getElementById('cc-service-search');
        if (searchInput) {
            searchInput.value = serviceSearchByProvider[provider] || '';
        }
    }

    function _renderServiceList(provider) {
        const wrap = document.getElementById('cc-service-list');
        const moreButton = document.getElementById('cc-service-more');
        const services = servicesByProvider[provider] || [];
        const searchTerm = (serviceSearchByProvider[provider] || '').trim().toLowerCase();
        const filteredServices = searchTerm
            ? services.filter(service => (service.name || '').toLowerCase().includes(searchTerm))
            : services;
        const visibleCount = visibleServiceCountByProvider[provider] || SERVICE_PAGE_SIZE;
        const visibleServices = filteredServices.slice(0, visibleCount);
        wrap.innerHTML = '';

        visibleServices.forEach(service => {
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

        if (!visibleServices.length) {
            wrap.innerHTML = '<p class="cc-service-list__empty">No services match your search.</p>';
        }

        if (moreButton) {
            const remaining = filteredServices.length - visibleServices.length;
            moreButton.hidden = remaining <= 0;
            moreButton.textContent = remaining > 0 ? `Show more (${remaining} left)` : 'Show more';
        }

        _renderSelectedServiceState();
    }

    function selectService(serviceId) {
        selectedServiceByProvider[activeProvider] = serviceId;
        regionFilterByProvider[activeProvider] = 'all';
        _renderServiceList(activeProvider);
        _rerenderActiveProvider();
    }

    function _rerenderActiveProvider() {
        if (activeProvider === 'github' && providerResults.github) {
            _renderCachedGithubResult();
        }
        if (activeProvider === 'aws' && providerResults.aws) {
            _renderCachedAwsResult();
        }
        if (activeProvider === 'azure' && providerResults.azure) {
            _renderCachedAzureResult();
        }
        if (activeProvider === 'gitlab' && providerResults.gitlab) {
            _renderCachedGitlabResult();
        }
    }

    function _renderSelectedServiceState() {
        const services = servicesByProvider[activeProvider] || [];
        const service = services.find(item => item.id === selectedServiceByProvider[activeProvider]);
        document.getElementById('cc-selected-service-title').textContent = service ? service.name : 'Select a service';
        document.getElementById('cc-selected-service-desc').textContent = service
            ? service.description
            : 'Choose a provider service to inspect the configured environment.';

        const providerHealthy = providerStatuses[activeProvider]?.healthy;
        document.getElementById('btn-run-selected-service').disabled = !(service && providerHealthy);
    }

    async function runSelectedService(options = {}) {
        const service = selectedServiceByProvider[activeProvider];
        if (!service) return;

        _showProcessing(PROVIDER_LABELS[activeProvider] || activeProvider, service);
        const progressPromise = _simulateProgress();
        const controller = new AbortController();
        const fetchTimeout = setTimeout(() => controller.abort(), 300000);

        try {
            const response = await fetch('/api/monitoring/analyze', {
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
                regionFilterByProvider[activeProvider] = 'all';
                providerSnapshotMeta[activeProvider] = {
                    id: data.result.snapshot_id,
                    collected_at: data.result.snapshot_collected_at,
                    source: data.result.snapshot_source,
                };
                providerResults[activeProvider] = data.result;
                _renderHeroPanel();
                _showResults(data.result, activeProvider);
            } else {
                if (!options.auto) App.showToast(data.error || 'Service monitoring failed', 'error');
                _showInlineError(data.error || 'Service monitoring failed');
            }
        } catch (err) {
            clearTimeout(fetchTimeout);
            _stopElapsedTimer();
            const msg = err.name === 'AbortError' ? 'Service monitoring timed out.' : 'Failed to connect to server';
            if (!options.auto) App.showToast(msg, 'error');
            _showInlineError(msg);
        }
    }

    function _showProcessing(providerLabel, serviceId) {
        document.getElementById('cc-tabs').style.pointerEvents = 'none';
        document.getElementById('cc-tabs').style.opacity = '0.5';
        document.getElementById('compliance-results').style.display = 'none';
        const processing = document.getElementById('compliance-processing');
        processing.style.display = 'block';
        document.getElementById('compliance-processing-title').textContent = `${providerLabel} Analysis`;
        document.getElementById('compliance-provider-name').textContent = `${providerLabel} Services`;
        document.getElementById('cc-processing-bar-fill').style.width = '8%';
        document.querySelectorAll('.cc-step').forEach(step => step.setAttribute('data-status', 'waiting'));
    }

    function _updateStep(stepId, status) {
        const step = document.getElementById(stepId);
        if (step) step.setAttribute('data-status', status);
    }

    async function _simulateProgress() {
        _updateStep('step-auth', 'processing');
        _setProcessingBar(24);
        await _delay(800);
        _updateStep('step-auth', 'completed');
        _updateStep('step-api', 'processing');
        _setProcessingBar(58);
        await _delay(1500);
        _updateStep('step-api', 'completed');
        _updateStep('step-analysis', 'processing');
        _setProcessingBar(82);
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
        document.getElementById('compliance-results').dataset.provider = provider;
        document.getElementById('github-dashboard-card').dataset.provider = provider;

        const providerLabel = PROVIDER_LABELS[provider] || provider;
        const serviceLabel = result.service_name || result.check || result.selected_service || 'Service';
        document.getElementById('compliance-results-title').textContent = `${providerLabel} ${serviceLabel} — Monitoring Report`;

        _renderStatusBanner(result, provider);
        _renderUnifiedDashboard(result, provider);
    }

    function _renderCachedGithubResult() {
        const result = { ...providerResults.github, selected_service: selectedServiceByProvider.github };
        _showResults(result, 'github');
    }

    function _renderCachedAwsResult() {
        const cache = providerResults.aws;
        if (!cache?.services || !Object.keys(cache.services).length) {
            _showProviderSnapshotState('aws', cache);
            return;
        }
        const serviceKey = selectedServiceByProvider.aws && cache.services[selectedServiceByProvider.aws]
            ? selectedServiceByProvider.aws
            : cache.selected_service || Object.keys(cache.services)[0];
        if (!serviceKey || !cache.services[serviceKey]) {
            _showProviderSnapshotState('aws', cache);
            return;
        }

        selectedServiceByProvider.aws = serviceKey;
        const selected = cache.services[serviceKey].metadata || {};
        _showResults({
            ...selected,
            selected_service: serviceKey,
            aws_summary: cache.aws_summary,
            aws_services: cache.services,
            check: cache.check,
        }, 'aws');
    }

    function _renderCachedAzureResult() {
        const cache = providerResults.azure;
        if (!cache?.services || !Object.keys(cache.services).length) {
            _showProviderSnapshotState('azure', cache);
            return;
        }
        const serviceKey = selectedServiceByProvider.azure && cache.services[selectedServiceByProvider.azure]
            ? selectedServiceByProvider.azure
            : cache.selected_service || Object.keys(cache.services)[0];
        if (!serviceKey || !cache.services[serviceKey]) {
            _showProviderSnapshotState('azure', cache);
            return;
        }

        selectedServiceByProvider.azure = serviceKey;
        const selected = cache.services[serviceKey].metadata || {};
        _showResults({
            ...selected,
            selected_service: serviceKey,
            azure_summary: cache.azure_summary,
            azure_services: cache.services,
            check: cache.check,
        }, 'azure');
    }

    function _renderCachedGitlabResult() {
        const cache = providerResults.gitlab;
        if (!cache?.services || !Object.keys(cache.services).length) {
            _showProviderSnapshotState('gitlab', cache);
            return;
        }
        const serviceKey = selectedServiceByProvider.gitlab && cache.services[selectedServiceByProvider.gitlab]
            ? selectedServiceByProvider.gitlab
            : cache.selected_service || Object.keys(cache.services)[0];
        if (!serviceKey || !cache.services[serviceKey]) {
            _showProviderSnapshotState('gitlab', cache);
            return;
        }

        selectedServiceByProvider.gitlab = serviceKey;
        const selected = cache.services[serviceKey].metadata || {};
        _showResults({
            ...selected,
            selected_service: serviceKey,
            gitlab_summary: cache.gitlab_summary,
            gitlab_services: cache.services,
            check: cache.check,
        }, 'gitlab');
    }

    function _showProviderSnapshotState(provider, cache) {
        _hideRegionFilter();
        document.getElementById('compliance-processing').style.display = 'none';
        document.getElementById('cc-tabs').style.pointerEvents = '';
        document.getElementById('cc-tabs').style.opacity = '';
        document.getElementById('compliance-results').style.display = 'block';
        document.getElementById('github-dashboard-card').style.display = 'block';
        document.getElementById('compliance-results').dataset.provider = provider;
        document.getElementById('github-dashboard-card').dataset.provider = provider;

        const providerLabel = PROVIDER_LABELS[provider] || provider;
        document.getElementById('compliance-results-title').textContent = `${providerLabel} Monitoring Report`;
        document.querySelector('.github-dashboard-kicker').textContent = `${providerLabel} Service Monitor`;
        document.querySelector('.github-dashboard-title').textContent = `${providerLabel} monitoring is unavailable`;
        document.getElementById('github-dashboard-copy').textContent = cache?.error
            || `No cached ${providerLabel} monitoring snapshot is available yet.`;
        document.getElementById('github-findings-subtitle').textContent = `Latest ${providerLabel} monitor state.`;
        document.getElementById('github-findings-list').innerHTML = `
            <div class="github-findings-list">
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Provider State</div>
                    <article class="github-finding-item">
                        <div class="github-finding-item__header">
                            <div>
                                <h5>${providerLabel}</h5>
                                <p>${cache?.error || 'No monitoring data is available for this provider yet.'}</p>
                            </div>
                            <div class="github-finding-badges">
                                <span class="github-chip github-chip--warn">${String(cache?.status || 'unknown').toUpperCase()}</span>
                            </div>
                        </div>
                    </article>
                </section>
            </div>
        `;
        document.getElementById('github-graph-title').textContent = `${providerLabel} Realtime Overview`;
        document.getElementById('github-graph-subtitle').textContent = 'No graphable metrics are available for the current provider state.';
        document.getElementById('github-graph-panel').innerHTML = '<p class="empty-state">No graphable realtime metrics are available for this provider.</p>';
        _updateMetadataHeading(provider, providerLabel);
        document.getElementById('github-metadata-json').textContent = JSON.stringify(cache || {}, null, 2);
        _renderStatusBanner(cache || { status: 'error', error: `No ${providerLabel} data available.` }, provider);
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
            const status = summary.overall_status === 'fail' ? 'fail' : 'info';
            banner.className = `cc-status-banner ${_statusToBannerClass(status)}`;
            icon.textContent = _statusToSymbol(status);
            text.textContent = 'GitHub monitoring summary';
            const counts = summary.status_counts || {};
            desc.textContent = `${counts.pass || 0} healthy, ${counts.fail || 0} blocked, ${counts.unknown || 0} unknown across ${Object.keys(result.services || {}).length || 0} services.`;
            return;
        }

        const genericStatus = result.status === 'error'
            ? 'fail'
            : result.encryption_enabled === true
                ? 'pass'
                : result.encryption_enabled === false
                    ? 'fail'
                    : 'info';

        banner.className = `cc-status-banner ${_statusToBannerClass(genericStatus)}`;
        icon.textContent = _statusToSymbol(genericStatus);
        text.textContent = `${PROVIDER_LABELS[provider]} ${result.service_name || result.check || 'Service'} monitor`;
        desc.textContent = result.error || result.check_description || 'Review the live findings and metadata below for the current service.';
    }

    function _renderUnifiedDashboard(result, provider) {
        const card = document.getElementById('github-dashboard-card');
        card.style.display = 'block';
        card.dataset.provider = provider;

        if (provider === 'github') {
            _renderGithubDashboard(result);
            return;
        }

        _renderGenericDashboard(result, provider);
    }

    function _renderGenericDashboard(result, provider) {
        const model = _buildGenericServiceModel(result, provider);
        document.querySelector('.github-dashboard-kicker').textContent = `${PROVIDER_LABELS[provider]} Service Monitor`;
        const providerSummary = provider === 'aws'
            ? result.aws_summary || {}
            : provider === 'azure'
                ? result.azure_summary || {}
                : provider === 'gitlab'
                    ? result.gitlab_summary || {}
                : null;
        document.querySelector('.github-dashboard-title').textContent = (provider === 'aws' || provider === 'azure' || provider === 'gitlab')
            ? `Realtime monitoring across ${PROVIDER_LABELS[provider]} integrations`
            : `${result.service_name || result.check || 'Service'} monitor`;
        document.getElementById('github-dashboard-copy').textContent = (provider === 'aws' || provider === 'azure' || provider === 'gitlab')
            ? `One cached ${PROVIDER_LABELS[provider]} monitoring run is used to inspect ${providerSummary.service_count || Object.keys(result[`${provider}_services`] || {}).length || 0} integrations without re-running collection when the service changes.`
            : model.copy;
        _renderRegionFilter(provider, result);
        _updateMetadataHeading(provider, result.service_name || 'selected service');
        _renderRealtimeGraph(provider, result);
        document.getElementById('github-findings-subtitle').textContent = `Detailed findings for ${result.service_name || 'the selected service'}.`;
        document.getElementById('github-metadata-json').textContent = JSON.stringify(result || {}, null, 2);
        document.getElementById('github-findings-list').innerHTML = model.entries[0]?.findingsHtml || '<p class="empty-state">No findings available.</p>';
    }

    function _buildGenericServiceModel(result, provider) {
        const entries = [];
        const overviewFindings = provider === 'aws'
            ? _renderAwsDetailedFindings(result.api_findings || {}, result)
            : provider === 'azure'
                ? _renderAzureDetailedFindings(result.api_findings || {}, result)
                : provider === 'gitlab'
                    ? _renderGitlabDetailedFindings(result.api_findings || {}, result)
                : _renderGenericFindings(result.api_findings || {});
        entries.push({
            key: 'overview',
            name: 'API Overview',
            status: result.status === 'error' ? 'fail' : 'pass',
            score: result.status === 'error' ? 28 : result.encryption_enabled === false ? 36 : 82,
            summary: result.error || result.check_description || 'Provider API response and captured service metadata.',
            metrics: `${Object.keys(result.api_findings || {}).length} API sections`,
            metadata: result.api_findings || {},
            findingsHtml: overviewFindings,
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

        return {
            counts: _countStatuses(entries),
            copy: `Live findings and metadata for the selected ${PROVIDER_LABELS[provider]} service.`,
            entries,
        };
    }

    function _renderGithubDashboard(result) {
        const services = result.services || {};

        document.querySelector('.github-dashboard-kicker').textContent = 'GitHub Service Monitor';
        document.querySelector('.github-dashboard-title').textContent = 'Live monitoring across GitHub services';
        document.getElementById('github-dashboard-copy').textContent =
            `A visual summary of service activity, backlog, and repository operations across ${Object.keys(services).length} GitHub surfaces.`;

        const defaultKey = result.selected_service && services[result.selected_service]
            ? result.selected_service
            : Object.entries(services)[0]?.[0];
        _selectDashboardEntry(defaultKey, { type: 'github', services });
    }

    function _selectDashboardEntry(entryKey, model) {
        activeDashboardKey = entryKey;

        if (model.type === 'github') {
            selectedServiceByProvider.github = entryKey;
            const service = model.services[entryKey] || {};
            _hideRegionFilter();
            _updateMetadataHeading('github', service.name || 'selected service');
            _renderRealtimeGraph('github', service.metadata || {}, service);
            document.getElementById('github-findings-subtitle').textContent = `Inventory view for ${service.name || 'the selected GitHub service'}.`;
            document.getElementById('github-metadata-json').textContent = JSON.stringify(service.metadata || {}, null, 2);
            _renderGithubServiceFindings(entryKey, service);
            return;
        }

        const entry = (model.entries || []).find(item => item.key === entryKey) || model.entries?.[0];
        _renderRegionFilter(activeProvider, entry?.metadata || {});
        _updateMetadataHeading(activeProvider, entry?.name || 'selected service');
        _renderRealtimeGraph(activeProvider, entry?.metadata || {}, null);
        document.getElementById('github-findings-subtitle').textContent = `Detailed findings for ${entry?.name || 'the selected service'}.`;
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

    function _updateMetadataHeading(provider, serviceName) {
        const providerLabel = PROVIDER_LABELS[provider] || provider || 'Service';
        const title = document.getElementById('github-metadata-title');
        const subtitle = document.getElementById('github-metadata-subtitle');
        if (title) {
            title.textContent = `${providerLabel} Metadata`;
        }
        if (subtitle) {
            subtitle.textContent = `Raw JSON metadata captured for ${serviceName || 'the selected service'}.`;
        }
    }

    function _renderRegionFilter(provider, result) {
        const wrap = document.getElementById('cc-region-filter');
        const select = document.getElementById('cc-region-select');
        if (!wrap || !select) return;

        const model = _getRegionFilterModel(provider, result);
        if (!model.visible) {
            _hideRegionFilter();
            return;
        }

        const currentValue = model.regions.includes(regionFilterByProvider[provider]) ? regionFilterByProvider[provider] : 'all';
        regionFilterByProvider[provider] = currentValue;
        wrap.hidden = false;
        select.innerHTML = `<option value="all">All regions</option>${model.regions.map(region => `
            <option value="${region}">${_formatRegionLabel(region)}${model.counts[region] ? ` (${model.counts[region]})` : ''}</option>
        `).join('')}`;
        select.value = currentValue;
    }

    function _hideRegionFilter() {
        const wrap = document.getElementById('cc-region-filter');
        const select = document.getElementById('cc-region-select');
        if (wrap) wrap.hidden = true;
        if (select) select.innerHTML = '<option value="all">All regions</option>';
    }

    function _getRegionFilterModel(provider, result) {
        if (provider !== 'aws' && provider !== 'azure') {
            return { visible: false, regions: [], counts: {} };
        }
        const integration = result.api_findings?.integration || {};
        const inventory = result.api_findings?.inventory || {};
        const regions = (integration.available_regions || inventory.available_regions || []).filter(Boolean);
        const counts = inventory.regional_resource_counts || {};
        const visible = integration.region_scope === 'regional' && regions.length > 0;
        return { visible, regions, counts };
    }

    function _formatRegionLabel(region) {
        return String(region || '')
            .split(/[-_ ]+/)
            .filter(Boolean)
            .map(part => part.charAt(0).toUpperCase() + part.slice(1))
            .join(' ');
    }

    function _humanizeFieldName(value) {
        return String(value || '')
            .replace(/([A-Z])/g, ' $1')
            .replace(/_/g, ' ')
            .trim();
    }

    function _applyRegionFilterToInventory(provider, inventory) {
        if (!inventory || (provider !== 'aws' && provider !== 'azure')) {
            return inventory || {};
        }

        const selectedRegion = regionFilterByProvider[provider] || 'all';
        if (selectedRegion === 'all') {
            return inventory || {};
        }

        const matchesRegion = item => {
            if (!item || typeof item !== 'object') return false;
            const itemRegion = item._region || item.region || item.Region || item.location;
            return String(itemRegion || '').toLowerCase() === selectedRegion.toLowerCase();
        };

        const regionalCounts = inventory.regional_resource_counts || {};
        return {
            ...inventory,
            resource_count: Number(regionalCounts[selectedRegion] || 0),
            sample: (inventory.sample || []).filter(matchesRegion),
            items_preview: (inventory.items_preview || []).filter(matchesRegion),
        };
    }

    function _describeSelectedRegion(provider, integration = {}) {
        const selectedRegion = regionFilterByProvider[provider] || 'all';
        if (selectedRegion !== 'all') {
            return _formatRegionLabel(selectedRegion);
        }
        if (integration.region_scope === 'global') {
            return 'the global service scope';
        }
        return provider === 'aws' ? 'all enabled regions' : 'all available regions';
    }

    function _renderOverviewSection(title, stats, note = '') {
        const visibleStats = (stats || []).filter(item => item && item.value !== undefined && item.value !== null && String(item.value).trim() !== '');
        if (!visibleStats.length && !note) return '';
        return `
            <section class="github-findings-section">
                <div class="github-findings-section__title">${title}</div>
                <article class="github-finding-item github-finding-item--compact">
                    ${visibleStats.length ? `<div class="github-control-grid">
                        ${visibleStats.map(item => `
                            <div class="github-control-pill">
                                <span>${item.label}</span>
                                <strong>${item.value}</strong>
                            </div>
                        `).join('')}
                    </div>` : ''}
                    ${note ? `<p class="github-finding-body">${note}</p>` : ''}
                </article>
            </section>
        `;
    }

    function _renderSimpleListSection(title, items, label = 'Detail') {
        const visibleItems = (items || []).filter(Boolean);
        if (!visibleItems.length) return '';
        return `
            <section class="github-findings-section">
                <div class="github-findings-section__title">${title}</div>
                ${visibleItems.map(item => `
                    <article class="github-finding-item github-finding-item--compact">
                        <div class="github-finding-item__header">
                            <div>
                                <h5>${label}</h5>
                                <p>${item}</p>
                            </div>
                        </div>
                    </article>
                `).join('')}
            </section>
        `;
    }

    function _renderCountMapSection(title, map) {
        const entries = Object.entries(map || {}).filter(([, value]) => Number(value) > 0);
        if (!entries.length) return '';
        return `
            <section class="github-findings-section">
                <div class="github-findings-section__title">${title}</div>
                <article class="github-finding-item github-finding-item--compact">
                    <div class="github-control-grid">
                        ${entries.map(([key, value]) => `
                            <div class="github-control-pill">
                                <span>${_formatRegionLabel(key)}</span>
                                <strong>${value}</strong>
                            </div>
                        `).join('')}
                    </div>
                </article>
            </section>
        `;
    }

    function _renderRealtimeGraph(provider, result, githubService = null) {
        const panel = document.getElementById('github-graph-panel');
        const title = document.getElementById('github-graph-title');
        const subtitle = document.getElementById('github-graph-subtitle');
        if (!panel || !title || !subtitle) return;

        const graph = _buildRealtimeGraphModel(provider, result, githubService);
        title.textContent = graph.title;
        subtitle.textContent = graph.subtitle;

        if (!graph.items.length) {
            panel.innerHTML = '<p class="empty-state">No graphable realtime metrics are available for this service.</p>';
            return;
        }

        const maxValue = Math.max(...graph.items.map(item => item.value), 1);
        panel.innerHTML = `
            <div class="github-realtime-graph">
                ${graph.items.map(item => `
                    <div class="github-realtime-row">
                        <div class="github-realtime-row__label">
                            <span>${item.label}</span>
                            <strong>${item.value}</strong>
                        </div>
                        <div class="github-realtime-row__track">
                            <div class="github-realtime-row__fill" style="width:${Math.max((item.value / maxValue) * 100, item.value > 0 ? 8 : 0)}%"></div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    function _buildRealtimeGraphModel(provider, result, githubService = null) {
        if (provider === 'github') {
            const service = githubService || {};
            const metrics = service.metrics || {};
            const items = Object.entries(metrics)
                .filter(([, value]) => typeof value === 'number')
                .slice(0, 6)
                .map(([key, value]) => ({ label: key.replace(/_/g, ' '), value }));
            return {
                title: `${service.name || 'GitHub'} Realtime Overview`,
                subtitle: 'Live GitHub metrics from the selected service surface.',
                items,
            };
        }

        const inventory = _applyRegionFilterToInventory(provider, result.api_findings?.inventory || {});
        const health = result.api_findings?.health || {};
        const subscriptions = result.api_findings?.subscriptions || [];
        const metrics = [
            { label: 'Resources', value: Number(inventory.resource_count || 0) },
            { label: 'Observations', value: Number((health.observations || []).length) },
            { label: 'Sample Items', value: Number((inventory.sample || []).length) },
            { label: 'Detailed Items', value: Number((inventory.items_preview || []).length) },
        ];

        if (provider === 'azure') {
            metrics.push({ label: 'Subscriptions', value: Number(subscriptions.length || 0) });
        }

        return {
            title: `${PROVIDER_LABELS[provider]} Realtime Overview`,
            subtitle: _buildRegionGraphSubtitle(provider, result),
            items: metrics.filter(item => item.value > 0),
        };
    }

    function _buildRegionGraphSubtitle(provider, result) {
        const selectedRegion = regionFilterByProvider[provider] || 'all';
        if ((provider === 'aws' || provider === 'azure') && selectedRegion !== 'all') {
            return `Live inventory metrics for ${_formatRegionLabel(selectedRegion)}.`;
        }
        return 'Live inventory metrics from the selected service scan.';
    }

    function _renderApiFindings(findings, provider) {
        const container = document.getElementById('api-findings-content');
        if (provider === 'github') {
            container.innerHTML = _renderGithubApiFindings(findings);
            return;
        }
        if (provider === 'aws') {
            container.innerHTML = _renderAwsApiFindings(findings);
            return;
        }
        if (provider === 'azure') {
            container.innerHTML = _renderAzureApiFindings(findings);
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

    function _renderAwsApiFindings(findings) {
        const integration = findings.integration || {};
        const inventory = findings.inventory || {};
        const health = findings.health || {};
        const errors = findings.errors?.messages || [];
        const sample = inventory.sample || [];
        const observations = health.observations || [];

        const cards = [];

        cards.push(`
            <div class="finding-card ${health.status === 'pass' ? 'finding-pass' : health.status === 'warn' ? 'finding-warn' : 'finding-info'}">
                <div class="finding-header">
                    <span class="finding-badge">${health.score ?? '--'}</span>
                    <h4>${integration.service_name || 'AWS Service'} Summary</h4>
                </div>
                <p>${health.summary || 'Realtime AWS API monitoring completed for the selected service.'}</p>
            </div>
        `);

        cards.push(`
            <div class="finding-card finding-info">
                <div class="finding-header">
                    <span class="finding-badge">${inventory.resource_count ?? 0}</span>
                    <h4>Resource Inventory</h4>
                </div>
                <p>${_buildAwsInventoryNarrative(integration, inventory)}</p>
            </div>
        `);

        if (observations.length) {
            cards.push(`
                <div class="finding-card finding-info">
                    <div class="finding-header">
                        <span class="finding-badge">${observations.length}</span>
                        <h4>Security Interpretation</h4>
                    </div>
                    <p>${observations.join(' ')}</p>
                </div>
            `);
        }

        if (sample.length) {
            cards.push(`
                <div class="finding-card finding-info">
                    <div class="finding-header">
                        <span class="finding-badge">${sample.length}</span>
                        <h4>What Was Observed</h4>
                    </div>
                    <p>${_buildAwsSampleNarrative(sample)}</p>
                </div>
            `);
        }

        if (errors.length) {
            cards.push(`
                <div class="finding-card finding-warn">
                    <div class="finding-header">
                        <span class="finding-badge">${errors.length}</span>
                        <h4>Access Limitations</h4>
                    </div>
                    <p>${errors.join(' ')}</p>
                </div>
            `);
        }

        return `<div class="findings-grid">${cards.join('')}</div>`;
    }

    function _renderAzureApiFindings(findings) {
        const integration = findings.integration || {};
        const inventory = findings.inventory || {};
        const health = findings.health || {};
        const errors = findings.errors?.messages || [];
        const sample = inventory.sample || [];
        const observations = health.observations || [];
        const subscriptions = findings.subscriptions || [];

        const cards = [];

        cards.push(`
            <div class="finding-card ${health.status === 'pass' ? 'finding-pass' : health.status === 'warn' ? 'finding-warn' : 'finding-info'}">
                <div class="finding-header">
                    <span class="finding-badge">${health.score ?? '--'}</span>
                    <h4>${integration.service_name || 'Azure Service'} Summary</h4>
                </div>
                <p>${health.summary || 'Realtime Azure API monitoring completed for the selected service.'}</p>
            </div>
        `);

        cards.push(`
            <div class="finding-card finding-info">
                <div class="finding-header">
                    <span class="finding-badge">${inventory.resource_count ?? 0}</span>
                    <h4>Resource Inventory</h4>
                </div>
                <p>${_buildAzureInventoryNarrative(integration, inventory, subscriptions)}</p>
            </div>
        `);

        if (observations.length) {
            cards.push(`
                <div class="finding-card finding-info">
                    <div class="finding-header">
                        <span class="finding-badge">${observations.length}</span>
                        <h4>Security Interpretation</h4>
                    </div>
                    <p>${observations.join(' ')}</p>
                </div>
            `);
        }

        if (sample.length) {
            cards.push(`
                <div class="finding-card finding-info">
                    <div class="finding-header">
                        <span class="finding-badge">${sample.length}</span>
                        <h4>What Was Observed</h4>
                    </div>
                    <p>${_buildAzureSampleNarrative(sample)}</p>
                </div>
            `);
        }

        if (errors.length) {
            cards.push(`
                <div class="finding-card finding-warn">
                    <div class="finding-header">
                        <span class="finding-badge">${errors.length}</span>
                        <h4>Access Limitations</h4>
                    </div>
                    <p>${errors.join(' ')}</p>
                </div>
            `);
        }

        return `<div class="findings-grid">${cards.join('')}</div>`;
    }

    function _renderAwsDetailedFindings(findings, result = {}) {
        const integration = findings.integration || {};
        const inventory = _applyRegionFilterToInventory('aws', findings.inventory || {});
        const health = findings.health || {};
        const errors = findings.errors?.messages || [];
        const detailedItems = inventory.items_preview || [];
        const sample = inventory.sample || [];
        const observations = health.observations || [];
        const serviceName = integration.service_name || result.service_name || 'AWS service';
        const region = _describeSelectedRegion('aws', integration);
        const count = inventory.resource_count ?? 0;

        let html = '<div class="github-findings-list">';

        html += `
            <section class="github-findings-section">
                <div class="github-findings-section__title">Service Narrative</div>
                <article class="github-finding-item">
                    <div class="github-finding-item__header">
                        <div>
                            <h5>${serviceName}</h5>
                            <p>Realtime AWS API monitor</p>
                        </div>
                        <div class="github-finding-badges">
                            <span class="github-chip ${health.status === 'pass' ? 'github-chip--pass' : health.status === 'warn' ? 'github-chip--warn' : 'github-chip--fail'}">${String(health.status || 'unknown').toUpperCase()}</span>
                            <span class="github-chip">${count} resources</span>
                        </div>
                    </div>
                    <p class="github-finding-body">${_buildAwsServiceNarrative(serviceName, count, region, health.summary)}</p>
                </article>
            </section>
        `;

        html += _renderOverviewSection('Monitoring Scope', [
            { label: 'Mode', value: integration.mode || 'API-only' },
            { label: 'Scope', value: integration.region_scope === 'global' ? 'Global' : 'Regional' },
            { label: 'Selected region', value: region },
            { label: 'Visible regions', value: (findings.inventory?.available_regions || []).length || 0 },
            { label: 'Resources', value: count },
            { label: 'Checked at', value: _shortDateTime(integration.checked_at) },
        ]);
        html += _renderCountMapSection('Regional Coverage', findings.inventory?.regional_resource_counts || {});

        if (observations.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Security Interpretation</div>
                    ${observations.map(item => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>Observation</h5>
                                    <p>${item}</p>
                                </div>
                            </div>
                        </article>
                    `).join('')}
                </section>
            `;
        }

        if (detailedItems.length || sample.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Observed Resources</div>
                    ${(detailedItems.length ? detailedItems : sample).map((item, index) => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>${_buildAwsResourceTitle(item, index)}</h5>
                                    <p>${_buildAwsSampleNarrative([item])}</p>
                                </div>
                            </div>
                            ${_renderAwsResourceStats(item)}
                        </article>
                    `).join('')}
                </section>
            `;
        }

        if (errors.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Access Limitations</div>
                    ${errors.map(item => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>Permission Gap</h5>
                                    <p>${item}</p>
                                </div>
                                <div class="github-finding-badges">
                                    <span class="github-chip github-chip--warn">attention</span>
                                </div>
                            </div>
                        </article>
                    `).join('')}
                </section>
            `;
        }

        html += '</div>';
        return html;
    }

    function _renderAzureDetailedFindings(findings, result = {}) {
        const integration = findings.integration || {};
        const inventory = _applyRegionFilterToInventory('azure', findings.inventory || {});
        const health = findings.health || {};
        const errors = findings.errors?.messages || [];
        const detailedItems = inventory.items_preview || [];
        const sample = inventory.sample || [];
        const observations = health.observations || [];
        const subscriptions = findings.subscriptions || [];
        const serviceName = integration.service_name || result.service_name || 'Azure service';
        const count = inventory.resource_count ?? 0;

        let html = '<div class="github-findings-list">';

        html += `
            <section class="github-findings-section">
                <div class="github-findings-section__title">Service Narrative</div>
                <article class="github-finding-item">
                    <div class="github-finding-item__header">
                        <div>
                            <h5>${serviceName}</h5>
                            <p>Realtime Azure Resource Manager monitor</p>
                        </div>
                        <div class="github-finding-badges">
                            <span class="github-chip ${health.status === 'pass' ? 'github-chip--pass' : health.status === 'warn' ? 'github-chip--warn' : 'github-chip--fail'}">${String(health.status || 'unknown').toUpperCase()}</span>
                            <span class="github-chip">${count} resources</span>
                        </div>
                    </div>
                    <p class="github-finding-body">${_buildAzureServiceNarrative(serviceName, count, subscriptions, health.summary)}</p>
                </article>
            </section>
        `;

        const resourceGroups = new Set((inventory.items_preview || []).map(item => item?.resourceGroup).filter(Boolean));
        html += _renderOverviewSection('Monitoring Scope', [
            { label: 'Mode', value: integration.mode || 'API-only' },
            { label: 'Scope', value: integration.region_scope === 'global' ? 'Global' : 'Regional' },
            { label: 'Selected region', value: _describeSelectedRegion('azure', integration) },
            { label: 'Subscriptions', value: subscriptions.length || 0 },
            { label: 'Resource groups', value: resourceGroups.size || 0 },
            { label: 'Checked at', value: _shortDateTime(integration.checked_at) },
        ]);
        html += _renderCountMapSection('Regional Coverage', findings.inventory?.regional_resource_counts || {});

        if (observations.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Security Interpretation</div>
                    ${observations.map(item => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>Observation</h5>
                                    <p>${item}</p>
                                </div>
                            </div>
                        </article>
                    `).join('')}
                </section>
            `;
        }

        if (detailedItems.length || sample.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Observed Resources</div>
                    ${(detailedItems.length ? detailedItems : sample).map((item, index) => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>${_buildAzureResourceTitle(item, index)}</h5>
                                    <p>${_buildAzureSampleNarrative([item])}</p>
                                </div>
                            </div>
                            ${_renderAzureResourceStats(item)}
                        </article>
                    `).join('')}
                </section>
            `;
        }

        if (errors.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Access Limitations</div>
                    ${errors.map(item => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>Permission Gap</h5>
                                    <p>${item}</p>
                                </div>
                                <div class="github-finding-badges">
                                    <span class="github-chip github-chip--warn">attention</span>
                                </div>
                            </div>
                        </article>
                    `).join('')}
                </section>
            `;
        }

        html += '</div>';
        return html;
    }

    function _buildAwsInventoryNarrative(integration, inventory) {
        const serviceName = integration.service_name || 'service';
        const count = inventory.resource_count ?? 0;
        const region = _describeSelectedRegion('aws', integration);
        if (count === 0) {
            return `The realtime AWS API check did not return any ${serviceName} resources in ${region}. This can mean the service is currently unused in that region, or that the credentials do not have visibility into the relevant resources.`;
        }
        if (count === 1) {
            return `The realtime AWS API check discovered 1 ${serviceName} resource in ${region}. The monitor captured a live inventory snapshot and prepared metadata so the service can be reviewed without opening the AWS console.`;
        }
        return `The realtime AWS API check discovered ${count} ${serviceName} resources in ${region}. The monitor captured a live inventory snapshot and prepared metadata so the service can be reviewed in one place without opening the AWS console.`;
    }

    function _buildAwsSampleNarrative(sample) {
        const summaries = sample.slice(0, 3).map(item => {
            if (!item || typeof item !== 'object') {
                return `Observed item: ${String(item)}`;
            }
            const pairs = Object.entries(item).slice(0, 4).map(([key, value]) => `${_humanizeFieldName(key)} ${value}`);
            return pairs.length ? pairs.join(', ') : 'Observed resource metadata was returned';
        });
        return summaries.join('. ') + '.';
    }

    function _buildAwsResourceTitle(item, index) {
        if (!item || typeof item !== 'object') {
            return `Sample ${index + 1}`;
        }
        return _resolveAwsResourceIdentity(item) || `AWS Resource ${index + 1}`;
    }

    function _resolveAwsResourceIdentity(item) {
        if (typeof item.display_name === 'string' && item.display_name.trim()) {
            return item.display_name;
        }
        const directKeys = [
            'Name', 'InstanceId', 'VpcId', 'SubnetId', 'GroupId', 'NetworkInterfaceId',
            'InternetGatewayId', 'NatGatewayId', 'RouteTableId', 'VpcPeeringConnectionId',
            'TransitGatewayId', 'VolumeId', 'SnapshotId', 'ImageId', 'LaunchTemplateId',
            'AllocationId', 'EgressOnlyInternetGatewayId', 'PrefixListId', 'VpnGatewayId',
            'VpnConnectionId', 'CustomerGatewayId', 'UserName', 'RoleName',
            'DBInstanceIdentifier', 'DBClusterIdentifier', 'DBSubnetGroupName',
            'FunctionName', 'BucketName', 'TableName', 'QueueName', 'QueueUrl',
            'TopicName', 'TopicArn', 'ClusterName', 'RepositoryName', 'SecretName',
            'KeyId', 'AliasName', 'DistributionId', 'HostedZoneId', 'LoadBalancerArn',
            'LoadBalancerName', 'TargetGroupArn', 'AutoScalingGroupName', 'CertificateArn',
            'RestApiId', 'ApiId', 'StackName', 'CacheClusterId', 'FileSystemId',
            'VaultName', 'WorkGroup', 'Name', 'Id', 'Arn'
        ];

        for (const key of directKeys) {
            const value = item[key];
            if (typeof value === 'string' && value.trim()) {
                return _prettifyAwsIdentityValue(key, value);
            }
        }

        if (Array.isArray(item.Tags)) {
            const nameTag = item.Tags.find(tag => tag && tag.Key === 'Name' && tag.Value);
            if (nameTag?.Value) return nameTag.Value;
        }

        return null;
    }

    function _prettifyAwsIdentityValue(key, value) {
        if (key === 'QueueUrl') {
            const parts = value.split('/');
            return parts[parts.length - 1] || value;
        }
        if (key === 'TopicArn' || key === 'Arn' || key.endsWith('Arn')) {
            const arnParts = value.split(':');
            return arnParts[arnParts.length - 1] || value;
        }
        return value;
    }

    function _renderAwsResourceStats(item) {
        if (!item || typeof item !== 'object') {
            return '';
        }
        const preferredKeys = [
            'Name', 'InstanceId', 'ReservationId', '_region', 'StateName', 'InstanceType', 'PrivateIpAddress', 'PublicIpAddress',
            'UserName', 'Arn', 'Path', 'CreateDate', 'PasswordLastUsed',
            'DBInstanceIdentifier', 'Engine', 'EngineVersion', 'DBInstanceStatus',
            'FunctionName', 'Runtime', 'LastModified',
            'BucketName', 'CreationDate',
            'VpcId', 'CidrBlock', 'State',
            'KeyId', 'Description',
        ];
        const seen = new Set();
        const stats = [];

        preferredKeys.forEach(key => {
            if (item[key] !== undefined && item[key] !== null && !seen.has(key)) {
                seen.add(key);
                stats.push(`<span>${_humanizeFieldName(key)} <strong>${item[key]}</strong></span>`);
            }
        });

        Object.entries(item).forEach(([key, value]) => {
            if (stats.length >= 6 || seen.has(key) || value === undefined || value === null || typeof value === 'object') {
                return;
            }
            stats.push(`<span>${_humanizeFieldName(key)} <strong>${value}</strong></span>`);
        });

        return stats.length ? `<div class="github-finding-stats">${stats.join('')}</div>` : '';
    }

    function _buildAwsServiceNarrative(serviceName, count, region, summary) {
        const lead = summary || `${serviceName} was checked through the AWS API monitor.`;
        if (count === 0) {
            return `${lead} No live resources were returned in ${region}, which usually means this service is not currently in use there or the credentials do not have the necessary read permissions.`;
        }
        if (count === 1) {
            return `${lead} The monitor found 1 live ${serviceName} resource in ${region} and converted that metadata into a reviewable service snapshot for this report.`;
        }
        return `${lead} The monitor found ${count} live ${serviceName} resources in ${region} and converted that metadata into a reviewable service snapshot for this report.`;
    }

    function _buildAzureInventoryNarrative(integration, inventory, subscriptions) {
        const serviceName = integration.service_name || 'service';
        const count = inventory.resource_count ?? 0;
        const subscriptionCount = subscriptions.length || 0;
        const region = _describeSelectedRegion('azure', integration);
        if (count === 0) {
            return `The realtime Azure API check did not return any ${serviceName} resources in ${region} across ${subscriptionCount || 'the connected'} subscription scope. This usually means the service is not yet in use or the token does not have read access to those resources.`;
        }
        if (count === 1) {
            return `The realtime Azure API check discovered 1 ${serviceName} resource in ${region} across ${subscriptionCount || 1} subscription scope. The monitor captured a live ARM inventory snapshot so the service can be reviewed without signing into the Azure portal.`;
        }
        return `The realtime Azure API check discovered ${count} ${serviceName} resources in ${region} across ${subscriptionCount || 'the connected'} subscription scope. The monitor captured a live ARM inventory snapshot so the service can be reviewed in one place without signing into the Azure portal.`;
    }

    function _buildAzureSampleNarrative(sample) {
        const summaries = sample.slice(0, 3).map(item => {
            if (!item || typeof item !== 'object') {
                return `Observed item: ${String(item)}`;
            }
            const pairs = Object.entries(item).slice(0, 4).map(([key, value]) => `${_humanizeFieldName(key)} ${value}`);
            return pairs.length ? pairs.join(', ') : 'Observed resource metadata was returned';
        });
        return summaries.join('. ') + '.';
    }

    function _buildAzureResourceTitle(item, index) {
        if (!item || typeof item !== 'object') {
            return `Resource ${index + 1}`;
        }
        return item.name
            || item.displayName
            || item.id
            || item.resourceGroup
            || item.subscriptionId
            || `Resource ${index + 1}`;
    }

    function _renderAzureResourceStats(item) {
        if (!item || typeof item !== 'object') {
            return '';
        }
        const preferredKeys = [
            'name', 'displayName', 'type', 'location', 'subscriptionId',
            'resourceGroup', 'kind', 'id', 'tenantId', 'state',
            'addressPrefix', 'vnet', 'provisioningState',
        ];
        const seen = new Set();
        const stats = [];

        preferredKeys.forEach(key => {
            if (item[key] !== undefined && item[key] !== null && !seen.has(key) && typeof item[key] !== 'object') {
                seen.add(key);
                stats.push(`<span>${_humanizeFieldName(key)} <strong>${item[key]}</strong></span>`);
            }
        });

        Object.entries(item).forEach(([key, value]) => {
            if (stats.length >= 6 || seen.has(key) || value === undefined || value === null || typeof value === 'object') {
                return;
            }
            stats.push(`<span>${_humanizeFieldName(key)} <strong>${value}</strong></span>`);
        });

        return stats.length ? `<div class="github-finding-stats">${stats.join('')}</div>` : '';
    }

    function _buildAzureServiceNarrative(serviceName, count, subscriptions, summary) {
        const lead = summary || `${serviceName} was checked through the Azure API monitor.`;
        const scope = subscriptions.length ? `${subscriptions.length} subscription${subscriptions.length === 1 ? '' : 's'}` : 'the connected Azure scope';
        const region = _describeSelectedRegion('azure', {});
        if (count === 0) {
            return `${lead} No live resources were returned in ${region} across ${scope}, which usually means this service is not currently in use there or the token does not have the necessary read permissions.`;
        }
        if (count === 1) {
            return `${lead} The monitor found 1 live ${serviceName} resource in ${region} across ${scope} and converted that metadata into a reviewable service snapshot for this report.`;
        }
        return `${lead} The monitor found ${count} live ${serviceName} resources in ${region} across ${scope} and converted that metadata into a reviewable service snapshot for this report.`;
    }

    function _renderGitlabDetailedFindings(findings, result = {}) {
        const integration = findings.integration || {};
        const inventory = findings.inventory || {};
        const health = findings.health || {};
        const access = findings.access || {};
        const detailedItems = inventory.items_preview || [];
        const sample = inventory.sample || [];
        const observations = health.observations || [];
        const notes = access.notes || [];
        const errors = access.errors || [];
        const scope = findings.scope || {};
        const serviceName = integration.service_name || result.service_name || 'GitLab service';
        const serviceKey = integration.service_id || result.service || '';
        const count = inventory.resource_count ?? 0;

        let html = '<div class="github-findings-list">';

        html += `
            <section class="github-findings-section">
                <div class="github-findings-section__title">Service Narrative</div>
                <article class="github-finding-item">
                    <div class="github-finding-item__header">
                        <div>
                            <h5>${serviceName}</h5>
                            <p>Realtime GitLab API monitor</p>
                        </div>
                        <div class="github-finding-badges">
                            <span class="github-chip ${health.status === 'pass' ? 'github-chip--pass' : health.status === 'warn' ? 'github-chip--warn' : 'github-chip--fail'}">${String(health.status || 'unknown').toUpperCase()}</span>
                            <span class="github-chip">${count} resources</span>
                        </div>
                    </div>
                    <p class="github-finding-body">${_buildGitlabServiceNarrative(serviceName, count, scope, integration.base_url, health.summary)}</p>
                </article>
            </section>
        `;

        html += _renderOverviewSection('Scope Overview', [
            { label: 'GitLab host', value: integration.base_url || 'Configured host' },
            { label: 'Projects in scope', value: scope.project_count || 0 },
            { label: 'Groups in scope', value: scope.group_count || 0 },
            { label: 'Resources returned', value: count },
            { label: 'User', value: integration.user?.username || integration.user?.name || '' },
            { label: 'Checked at', value: _shortDateTime(integration.checked_at) },
        ]);
        html += _renderGitlabServiceOverview(serviceKey, detailedItems.length ? detailedItems : sample);
        html += _renderSimpleListSection('Sampled Projects', scope.sampled_projects || [], 'Project');
        html += _renderSimpleListSection('Sampled Groups', scope.sampled_groups || [], 'Group');

        if (observations.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Security Interpretation</div>
                    ${observations.map(item => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>Observation</h5>
                                    <p>${item}</p>
                                </div>
                            </div>
                        </article>
                    `).join('')}
                </section>
            `;
        }

        if (detailedItems.length || sample.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Observed Resources</div>
                    ${(detailedItems.length ? detailedItems : sample).map((item, index) => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>${_buildGitlabResourceTitle(item, index)}</h5>
                                    <p>${_buildGitlabSampleNarrative([item])}</p>
                                </div>
                            </div>
                            ${_renderGitlabResourceStats(item)}
                        </article>
                    `).join('')}
                </section>
            `;
        }

        if (notes.length || errors.length) {
            html += `
                <section class="github-findings-section">
                    <div class="github-findings-section__title">Access Limitations</div>
                    ${notes.map(item => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>Scope Note</h5>
                                    <p>${item}</p>
                                </div>
                            </div>
                        </article>
                    `).join('')}
                    ${errors.map(item => `
                        <article class="github-finding-item github-finding-item--compact">
                            <div class="github-finding-item__header">
                                <div>
                                    <h5>Permission Gap</h5>
                                    <p>${item}</p>
                                </div>
                            </div>
                            <div class="github-finding-badges">
                                <span class="github-chip github-chip--warn">attention</span>
                            </div>
                        </article>
                    `).join('')}
                </section>
            `;
        }

        html += '</div>';
        return html;
    }

    function _buildGitlabServiceNarrative(serviceName, count, scope, baseUrl, summary) {
        const lead = summary || `${serviceName} was checked through the GitLab API monitor.`;
        const projects = scope.project_count || 0;
        const groups = scope.group_count || 0;
        const footprint = `${projects} project${projects === 1 ? '' : 's'} and ${groups} group${groups === 1 ? '' : 's'}`;
        if (count === 0) {
            return `${lead} No live resources were returned from ${baseUrl || 'the configured GitLab host'} within the authenticated scope of ${footprint}, which usually means the service is not currently in use there or the token cannot read those records.`;
        }
        if (count === 1) {
            return `${lead} The monitor found 1 live ${serviceName} record from ${baseUrl || 'the configured GitLab host'} and converted that metadata into a reviewable service snapshot across ${footprint}.`;
        }
        return `${lead} The monitor found ${count} live ${serviceName} records from ${baseUrl || 'the configured GitLab host'} and converted that metadata into a reviewable service snapshot across ${footprint}.`;
    }

    function _buildGitlabSampleNarrative(sample) {
        const summaries = sample.slice(0, 3).map(item => {
            if (!item || typeof item !== 'object') {
                return `Observed item: ${String(item)}`;
            }
            const pairs = Object.entries(item).slice(0, 4).map(([key, value]) => `${_humanizeFieldName(key)} ${value}`);
            return pairs.length ? pairs.join(', ') : 'Observed GitLab metadata was returned';
        });
        return summaries.join('. ') + '.';
    }

    function _buildGitlabResourceTitle(item, index) {
        if (!item || typeof item !== 'object') {
            return `Resource ${index + 1}`;
        }
        return item.title
            || item.name
            || item.ref
            || item.key
            || item.environment_scope
            || item.path_with_namespace
            || item.full_path
            || item.project_name
            || item.source_name
            || item.username
            || item.web_url
            || `Resource ${index + 1}`;
    }

    function _renderGitlabResourceStats(item) {
        if (!item || typeof item !== 'object') {
            return '';
        }
        const preferredKeys = [
            'title', 'name', 'key', 'project_name', 'source_name', 'path_with_namespace', 'full_path', 'username',
            'state', 'status', 'visibility', 'ref', 'environment_scope', 'protected',
            'masked', 'raw', 'web_url', 'created_at', 'last_activity_at',
        ];
        const seen = new Set();
        const stats = [];

        preferredKeys.forEach(key => {
            if (item[key] !== undefined && item[key] !== null && !seen.has(key) && typeof item[key] !== 'object') {
                seen.add(key);
                stats.push(`<span>${key.replace(/([A-Z])/g, ' $1').replace(/_/g, ' ').trim()} <strong>${item[key]}</strong></span>`);
            }
        });

        Object.entries(item).forEach(([key, value]) => {
            if (stats.length >= 6 || seen.has(key) || value === undefined || value === null || typeof value === 'object') {
                return;
            }
            stats.push(`<span>${key.replace(/_/g, ' ')} <strong>${value}</strong></span>`);
        });

        return stats.length ? `<div class="github-finding-stats">${stats.join('')}</div>` : '';
    }

    function _renderGitlabServiceOverview(serviceKey, items) {
        const visibleItems = (items || []).filter(item => item && typeof item === 'object');
        if (!visibleItems.length) return '';

        if (serviceKey === 'branches' || serviceKey === 'protected_branches') {
            const protectedCount = visibleItems.filter(item => item.protected).length;
            const projectCount = new Set(visibleItems.map(item => item.project_name).filter(Boolean)).size;
            return _renderOverviewSection('Branch Overview', [
                { label: 'Branches shown', value: visibleItems.length },
                { label: 'Protected branches', value: protectedCount },
                { label: 'Projects represented', value: projectCount },
            ], 'Branch monitoring highlights which repositories have protected refs and how branch coverage is distributed across sampled projects.');
        }

        if (serviceKey === 'pipelines' || serviceKey === 'jobs') {
            const statusCounts = {};
            visibleItems.forEach(item => {
                const key = item.status || 'unknown';
                statusCounts[key] = (statusCounts[key] || 0) + 1;
            });
            return _renderCountMapSection('Execution Status', statusCounts);
        }

        if (serviceKey === 'environments' || serviceKey === 'deployments') {
            const stateCounts = {};
            visibleItems.forEach(item => {
                const key = item.state || item.status || 'unknown';
                stateCounts[key] = (stateCounts[key] || 0) + 1;
            });
            return _renderCountMapSection('Environment State', stateCounts);
        }

        if (serviceKey === 'groups' || serviceKey === 'projects') {
            const visibilityCounts = {};
            visibleItems.forEach(item => {
                const key = item.visibility || 'unknown';
                visibilityCounts[key] = (visibilityCounts[key] || 0) + 1;
            });
            return _renderCountMapSection('Visibility Breakdown', visibilityCounts);
        }

        if (serviceKey === 'variables') {
            const maskedCount = visibleItems.filter(item => item.masked).length;
            const protectedCount = visibleItems.filter(item => item.protected).length;
            return _renderOverviewSection('Variable Overview', [
                { label: 'Variables shown', value: visibleItems.length },
                { label: 'Masked', value: maskedCount },
                { label: 'Protected', value: protectedCount },
            ], 'CI/CD variables are summarized here by protection and masking posture so secrets exposure is easier to spot.');
        }

        return '';
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
        const overview = _renderGithubServiceOverview(serviceKey, metadata);

        if (serviceKey === 'repositories') {
            wrap.innerHTML = overview + _renderGithubRepositoriesFindings(metadata);
        } else if (serviceKey === 'pull_requests') {
            wrap.innerHTML = overview + _renderGithubPullRequestFindings(metadata);
        } else if (serviceKey === 'settings') {
            wrap.innerHTML = overview + _renderGithubSettingsFindings(metadata);
        } else if (serviceKey === 'vulnerabilities') {
            wrap.innerHTML = overview + _renderGithubVulnerabilityFindings(metadata);
        } else if (serviceKey === 'issues') {
            wrap.innerHTML = overview + _renderGithubIssueFindings(metadata);
        } else {
            wrap.innerHTML = '<p class="empty-state">No findings renderer is available for this service.</p>';
        }
    }

    function _renderGithubServiceOverview(serviceKey, metadata) {
        if (serviceKey === 'repositories') {
            const repos = metadata.repositories || [];
            return _renderOverviewSection('Repository Overview', [
                { label: 'Accessible repositories', value: metadata.total_repositories || repos.length },
                { label: 'Private in sample', value: repos.filter(repo => repo.private).length },
                { label: 'Archived in sample', value: repos.filter(repo => repo.archived).length },
                { label: 'Sample size', value: repos.length },
            ], 'Repository details below come from the latest GitHub API snapshot, including branch and visibility metadata where available.');
        }
        if (serviceKey === 'pull_requests') {
            const openItems = metadata.open_results?.items || [];
            const mergedItems = metadata.merged_results?.items || [];
            return _renderOverviewSection('Pull Request Overview', [
                { label: 'Open pull requests', value: openItems.length },
                { label: 'Merged pull requests', value: mergedItems.length },
                { label: 'Rendered items', value: openItems.length + mergedItems.length },
            ], 'The monitor combines open and recently merged pull requests so reviewers can inspect backlog and delivery activity together.');
        }
        if (serviceKey === 'settings') {
            return _renderOverviewSection('Settings Overview', [
                { label: 'Organizations', value: (metadata.organizations || []).length },
                { label: 'Repositories reviewed', value: (metadata.repository_security || []).length },
                { label: 'User', value: metadata.user?.login || 'Authenticated user' },
                { label: '2FA', value: metadata.user?.two_factor_authentication ? 'Enabled' : 'Disabled' },
            ], 'This view combines account, organization, and repository security metadata into one operational overview.');
        }
        if (serviceKey === 'vulnerabilities') {
            const repos = metadata.repositories || [];
            return _renderOverviewSection('Vulnerability Overview', [
                { label: 'Repositories reviewed', value: repos.length },
                { label: 'Open alerts', value: repos.reduce((sum, repo) => sum + Number(repo.open_dependabot_alerts || 0), 0) },
                { label: 'Coverage gaps', value: repos.filter(repo => repo.dependabot_alerts_error).length },
            ], 'Vulnerability detail is sourced from Dependabot and repository security settings returned by GitHub.');
        }
        if (serviceKey === 'issues') {
            const items = metadata.search_results?.items || [];
            return _renderOverviewSection('Issue Overview', [
                { label: 'Open issues returned', value: items.length },
                { label: 'Query scope', value: metadata.query_scope || 'Configured GitHub scope' },
            ], 'Issue results below come from the latest GitHub search snapshot for the authenticated namespace.');
        }
        return '';
    }

    function _renderGithubRepositoriesFindings(metadata) {
        const repos = metadata.repositories || [];
        if (!repos.length) return '<p class="empty-state">No repositories available.</p>';
        const total = metadata.total_repositories || repos.length;
        const privateCount = repos.filter(repo => repo.private).length;
        const archivedCount = repos.filter(repo => repo.archived).length;
        return `
            ${_renderOverviewSection('Repository Overview', [
                { label: 'Accessible repositories', value: total },
                { label: 'Private in sample', value: privateCount },
                { label: 'Archived in sample', value: archivedCount },
                { label: 'Sample size', value: repos.length },
            ], 'Repository details below come from the latest GitHub API snapshot, including branch and visibility metadata where available.')}
            ${repos.map(repo => `
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
            </article>`).join('')}`;
    }

    function _renderGithubPullRequestFindings(metadata) {
        const openItems = metadata.open_results?.items || [];
        const mergedItems = metadata.merged_results?.items || [];
        const list = [...openItems.map(item => ({ ...item, __kind: 'open' })), ...mergedItems.map(item => ({ ...item, __kind: 'merged' }))];
        if (!list.length) return '<p class="empty-state">No pull requests available.</p>';
        return `
            ${_renderOverviewSection('Pull Request Overview', [
                { label: 'Open pull requests', value: openItems.length },
                { label: 'Merged pull requests', value: mergedItems.length },
                { label: 'Rendered items', value: list.length },
            ], 'The monitor combines open and recently merged pull requests so reviewers can inspect backlog and delivery activity together.')}
            ${list.map(item => `
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
            </article>`).join('')}`;
    }

    function _renderGithubSettingsFindings(metadata) {
        const orgs = metadata.organizations || [];
        const repoSecurity = metadata.repository_security || [];
        return `
            ${_renderOverviewSection('Settings Overview', [
                { label: 'Organizations', value: orgs.length },
                { label: 'Repositories reviewed', value: repoSecurity.length },
                { label: 'User', value: metadata.user?.login || 'Authenticated user' },
                { label: '2FA', value: metadata.user?.two_factor_authentication ? 'Enabled' : 'Disabled' },
            ], 'This view combines account, organization, and repository security metadata into one operational overview.')}
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
        return 'i';
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
        const date = _parseTimestamp(value);
        return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString();
    }

    function _shortDateTime(value) {
        if (!value) return 'n/a';
        const date = _parseTimestamp(value);
        return Number.isNaN(date.getTime()) ? value : `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    }

    function _parseTimestamp(value) {
        if (!value) return new Date(NaN);
        if (value instanceof Date) return value;
        if (typeof value !== 'string') return new Date(value);
        const normalized = /(?:Z|[+-]\d{2}:\d{2})$/.test(value) ? value : `${value}Z`;
        return new Date(normalized);
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
        document.getElementById('compliance-results').style.display =
            (activeProvider === 'github' && providerResults.github)
            || (activeProvider === 'gitlab' && providerResults.gitlab)
                ? 'block'
                : 'none';
        document.getElementById('github-dashboard-card').style.display = 'none';
        activeDashboardKey = null;
        _renderProviderHero();
        _renderSelectedServiceState();
        if (activeProvider === 'aws' && providerResults.aws) {
            _renderCachedAwsResult();
        }
        if (activeProvider === 'azure' && providerResults.azure) {
            _renderCachedAzureResult();
        }
        if (activeProvider === 'github' && providerResults.github) {
            _renderCachedGithubResult();
        }
        if (activeProvider === 'gitlab' && providerResults.gitlab) {
            _renderCachedGitlabResult();
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
