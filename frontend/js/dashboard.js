/**
 * Dashboard Module
 * Renders analysis results with animated gauge, findings, indicators
 */
const Dashboard = (() => {

    function showResults(analysis) {
        if (!analysis) return;

        renderScore(analysis.authenticity_score, analysis.tamper_risk);
        renderSummary(analysis);
        renderIndicators(analysis.report);
        renderFindings(analysis.report);
        renderRecommendations(analysis.report);
    }

    function renderScore(score, risk) {
        const scoreEl = document.getElementById('score-value');
        const gaugeCircle = document.getElementById('gauge-circle');
        const riskBadge = document.getElementById('risk-badge');
        const riskText = document.getElementById('risk-text');

        // Animated counter
        if (window.animateCounter) {
            window.animateCounter(scoreEl, Math.round(score), 2000);
        } else {
            scoreEl.textContent = Math.round(score);
        }

        // Animate gauge circle
        const circumference = 2 * Math.PI * 85; // r = 85
        const offset = circumference - (score / 100) * circumference;

        // Add SVG gradient if not exists
        ensureGaugeGradient(score);

        setTimeout(() => {
            gaugeCircle.style.strokeDashoffset = offset;
        }, 100);

        // Risk badge
        const riskLower = (risk || 'unknown').toLowerCase();
        riskBadge.className = `risk-badge risk-${riskLower}`;
        riskText.textContent = `${risk} Risk`;

        // Update gauge color based on score
        const color = getScoreColor(score);
        gaugeCircle.style.stroke = color;
    }

    function ensureGaugeGradient(score) {
        const svg = document.querySelector('.gauge-svg');
        if (!svg) return;

        // Remove existing defs
        const existingDefs = svg.querySelector('defs');
        if (existingDefs) existingDefs.remove();

        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        const gradient = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
        gradient.setAttribute('id', 'gauge-gradient');

        const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');

        if (score >= 80) {
            stop1.setAttribute('stop-color', '#10b981');
            stop2.setAttribute('stop-color', '#00f0ff');
        } else if (score >= 60) {
            stop1.setAttribute('stop-color', '#f59e0b');
            stop2.setAttribute('stop-color', '#10b981');
        } else if (score >= 40) {
            stop1.setAttribute('stop-color', '#ef4444');
            stop2.setAttribute('stop-color', '#f59e0b');
        } else {
            stop1.setAttribute('stop-color', '#ec4899');
            stop2.setAttribute('stop-color', '#ef4444');
        }

        stop1.setAttribute('offset', '0%');
        stop2.setAttribute('offset', '100%');
        gradient.appendChild(stop1);
        gradient.appendChild(stop2);
        defs.appendChild(gradient);
        svg.insertBefore(defs, svg.firstChild);
    }

    function getScoreColor(score) {
        if (score >= 80) return '#10b981';
        if (score >= 60) return '#f59e0b';
        if (score >= 40) return '#ef4444';
        return '#ec4899';
    }

    function renderSummary(analysis) {
        const summaryText = document.getElementById('summary-text');
        const filename = document.getElementById('result-filename');
        const sha256 = document.getElementById('result-sha256');
        const timestamp = document.getElementById('result-timestamp');

        const report = analysis.report || {};
        summaryText.textContent = report.executive_summary || 'Analysis completed.';
        filename.textContent = analysis.original_filename || '--';
        sha256.textContent = analysis.sha256 || '--';

        if (analysis.completed_at) {
            timestamp.textContent = new Date(analysis.completed_at).toLocaleString();
        } else {
            timestamp.textContent = new Date().toLocaleString();
        }
    }

    function renderIndicators(report) {
        if (!report) return;

        const positiveList = document.getElementById('positive-indicators');
        const negativeList = document.getElementById('negative-indicators');

        const indicators = report.integrity_indicators || {};
        const positives = indicators.positive || ['No specific positive indicators identified'];
        const negatives = indicators.negative || ['No suspicious indicators identified'];

        positiveList.innerHTML = positives.map(i => `<li>${escapeHtml(i)}</li>`).join('');
        negativeList.innerHTML = negatives.map(i => `<li>${escapeHtml(i)}</li>`).join('');
    }

    function renderFindings(report) {
        if (!report) return;

        const container = document.getElementById('findings-list');
        const findings = report.detailed_findings || [];

        if (findings.length === 0) {
            container.innerHTML = '<p class="empty-state">No specific findings to report.</p>';
            return;
        }

        container.innerHTML = findings.map(f => `
            <div class="finding-item">
                <span class="finding-agent">${escapeHtml(f.agent || 'Agent')}</span>
                <div class="finding-content">
                    <h4>${escapeHtml(f.category || 'Finding')}</h4>
                    <p>${escapeHtml(f.finding || '')}</p>
                    ${f.recommendation ? `<p style="margin-top:6px;color:var(--accent-cyan);font-size:0.78rem;">💡 ${escapeHtml(f.recommendation)}</p>` : ''}
                </div>
                <span class="finding-severity severity-${(f.severity || 'low').toLowerCase()}">${escapeHtml(f.severity || 'info')}</span>
            </div>
        `).join('');
    }

    function renderRecommendations(report) {
        if (!report) return;

        const list = document.getElementById('recommendations-list');
        const recommendations = report.recommendations || ['No specific recommendations at this time.'];

        list.innerHTML = recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ── History ──
    async function loadHistory() {
        try {
            const res = await fetch('/api/history?limit=20');
            if (!res.ok) return;

            const data = await res.json();
            renderHistory(data.analyses || []);
        } catch (err) {
            console.error('Failed to load history:', err);
        }
    }

    function renderHistory(analyses) {
        const tbody = document.getElementById('history-body');

        if (analyses.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="7">No analyses yet. Upload evidence to get started.</td>
                </tr>`;
            return;
        }

        tbody.innerHTML = analyses.map(a => {
            const score = a.authenticity_score || 0;
            const risk = (a.tamper_risk || 'Unknown').toLowerCase();
            const color = getScoreColor(score);
            const date = a.created_at ? new Date(a.created_at).toLocaleDateString() : '--';
            const status = a.status || 'unknown';

            return `
                <tr>
                    <td>
                        <strong style="font-size:0.85rem;">${escapeHtml(a.original_filename || '--')}</strong>
                    </td>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--text-muted);">
                        ${escapeHtml(a.file_type || '--')}
                    </td>
                    <td>
                        <span class="score-mini">
                            <span class="score-mini-bar">
                                <span class="score-mini-fill" style="width:${score}%;background:${color};"></span>
                            </span>
                            ${Math.round(score)}
                        </span>
                    </td>
                    <td>
                        <span class="badge-sm risk-badge risk-${risk}" style="font-size:0.7rem;">
                            ${escapeHtml(a.tamper_risk || '--')}
                        </span>
                    </td>
                    <td>
                        <span class="badge-sm badge-${status}">${status}</span>
                    </td>
                    <td style="font-size:0.8rem;color:var(--text-muted);">${date}</td>
                    <td>
                        <button class="btn btn-ghost btn-sm" onclick="Dashboard.viewResult('${a.id}')">
                            View
                        </button>
                    </td>
                </tr>`;
        }).join('');
    }

    async function viewResult(analysisId) {
        try {
            const res = await fetch(`/api/results/${analysisId}`);
            if (!res.ok) throw new Error('Not found');

            const data = await res.json();
            showResults(data.analysis);
            App.showSection('results');
        } catch (err) {
            App.showToast('Failed to load analysis', 'error');
        }
    }

    return { showResults, loadHistory, viewResult };
})();
