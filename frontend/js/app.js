/**
 * Main Application Module
 * Handles SPA navigation, API health checks, toast notifications
 */
const App = (() => {
    let currentSection = 'upload';

    function init() {
        // Initialize modules
        Upload.init();
        Compliance.init();

        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = link.getAttribute('data-section');
                if (section) showSection(section);
            });
        });

        // New Analysis button
        const newBtn = document.getElementById('btn-new-analysis');
        if (newBtn) {
            newBtn.addEventListener('click', () => {
                Upload.removeFile();
                Upload.resetPipeline();
                showSection('upload');
            });
        }

        // Refresh history
        const refreshBtn = document.getElementById('btn-refresh-history');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => Dashboard.loadHistory());
        }

        // Check API health
        checkApiHealth();
        setInterval(checkApiHealth, 30000);
    }

    function showSection(sectionName) {
        // Hide all sections
        document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));

        // Show target section
        const target = document.getElementById(`section-${sectionName}`);
        if (target) {
            target.classList.add('active');
        }

        // Update nav
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        const navLink = document.querySelector(`.nav-link[data-section="${sectionName}"]`);
        if (navLink) navLink.classList.add('active');

        currentSection = sectionName;

        // Load history if needed
        if (sectionName === 'history') {
            Dashboard.loadHistory();
        }
    }

    async function checkApiHealth() {
        const dot = document.getElementById('api-status');
        const text = document.getElementById('api-status-text');

        try {
            const res = await fetch('/api/health');
            if (res.ok) {
                dot.className = 'status-dot connected';
                text.textContent = 'Connected';
            } else {
                dot.className = 'status-dot error';
                text.textContent = 'API Error';
            }
        } catch {
            dot.className = 'status-dot error';
            text.textContent = 'Disconnected';
        }
    }

    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icons = { success: '✓', error: '✕', info: 'ℹ' };
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || 'ℹ'}</span>
            <span class="toast-message">${message}</span>
        `;

        container.appendChild(toast);

        // Auto-dismiss
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    return { init, showSection, showToast };
})();

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', App.init);
