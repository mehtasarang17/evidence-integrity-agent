/**
 * File Upload Module
 * Handles drag-and-drop, file selection, preview, and upload to backend
 */
const Upload = (() => {
    let selectedFile = null;
    let fileInfo = null;

    const ALLOWED_TYPES = [
        'image/png', 'image/jpeg', 'image/gif', 'image/bmp',
        'image/tiff', 'image/webp', 'application/pdf',
        'text/plain', 'text/csv', 'application/json', 'application/xml',
    ];

    const ALLOWED_EXTENSIONS = [
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp',
        'pdf', 'log', 'txt', 'csv', 'json', 'xml',
    ];

    function init() {
        const zone = document.getElementById('upload-zone');
        const input = document.getElementById('file-input');
        const removeBtn = document.getElementById('btn-remove-file');
        const analyzeBtn = document.getElementById('btn-analyze');

        if (!zone || !input) return;

        // Click to upload
        zone.addEventListener('click', () => input.click());
        input.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });

        // Drag and drop
        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.add('drag-over');
        });
        zone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.remove('drag-over');
        });
        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.remove('drag-over');
            if (e.dataTransfer.files.length > 0) {
                handleFile(e.dataTransfer.files[0]);
            }
        });

        // Remove file
        if (removeBtn) {
            removeBtn.addEventListener('click', removeFile);
        }

        // Analyze button
        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', startAnalysis);
        }
    }

    function handleFile(file) {
        // Validate file
        const ext = file.name.split('.').pop().toLowerCase();
        if (!ALLOWED_EXTENSIONS.includes(ext)) {
            App.showToast(`Unsupported file type: .${ext}`, 'error');
            return;
        }

        if (file.size > 50 * 1024 * 1024) {
            App.showToast('File too large (max 50MB)', 'error');
            return;
        }

        selectedFile = file;
        showPreview(file);
    }

    function showPreview(file) {
        const zone = document.getElementById('upload-zone');
        const preview = document.getElementById('file-preview');
        const imgContainer = document.getElementById('preview-image-container');
        const img = document.getElementById('preview-image');
        const icon = document.getElementById('preview-icon');
        const filename = document.getElementById('preview-filename');
        const size = document.getElementById('preview-size');
        const type = document.getElementById('preview-type');

        // Hide upload zone, show preview
        zone.style.display = 'none';
        preview.style.display = 'block';

        // Set file info
        filename.textContent = file.name;
        size.textContent = formatFileSize(file.size);
        type.textContent = file.type || 'unknown';

        // Show image preview if applicable
        if (file.type.startsWith('image/')) {
            icon.style.display = 'none';
            imgContainer.style.display = 'flex';
            const reader = new FileReader();
            reader.onload = (e) => {
                img.src = e.target.result;
            };
            reader.readAsDataURL(file);
        } else {
            imgContainer.style.display = 'none';
            icon.style.display = 'block';
            icon.textContent = getFileIcon(file.name);
        }
    }

    function removeFile() {
        selectedFile = null;
        fileInfo = null;

        const zone = document.getElementById('upload-zone');
        const preview = document.getElementById('file-preview');
        const input = document.getElementById('file-input');

        zone.style.display = 'block';
        preview.style.display = 'none';
        input.value = '';
    }

    async function startAnalysis() {
        if (!selectedFile) {
            App.showToast('No file selected', 'error');
            return;
        }

        const analyzeBtn = document.getElementById('btn-analyze');
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<span class="processing-spinner" style="width:16px;height:16px;border-width:2px;"></span> Uploading...';

        try {
            // Step 1: Upload the file
            const formData = new FormData();
            formData.append('file', selectedFile);

            const uploadRes = await fetch('/api/upload', {
                method: 'POST',
                body: formData,
            });

            if (!uploadRes.ok) {
                const err = await uploadRes.json();
                throw new Error(err.error || 'Upload failed');
            }

            const uploadData = await uploadRes.json();
            fileInfo = uploadData.file;

            App.showToast('File uploaded successfully', 'success');

            // Step 2: Show processing view and start analysis
            App.showSection('processing');
            document.getElementById('processing-filename').textContent = fileInfo.original_filename;

            // Animate pipeline agents
            await animatePipeline();

            // Step 3: Trigger analysis
            const analyzeRes = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    file_id: fileInfo.file_id,
                    original_filename: fileInfo.original_filename,
                    file_type: fileInfo.file_type,
                    mime_type: fileInfo.mime_type,
                }),
            });

            if (!analyzeRes.ok) {
                const err = await analyzeRes.json();
                throw new Error(err.error || 'Analysis failed');
            }

            const analysisData = await analyzeRes.json();

            // Complete all pipeline agents
            completePipeline();

            // Short delay for visual effect
            await sleep(800);

            // Step 4: Show results
            Dashboard.showResults(analysisData.analysis);
            App.showSection('results');
            App.showToast('Analysis complete!', 'success');

        } catch (error) {
            console.error('Analysis error:', error);
            App.showToast(`Error: ${error.message}`, 'error');
            App.showSection('upload');
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = '<span class="btn-icon">🔬</span> Analyze Evidence';
        }
    }

    async function animatePipeline() {
        const agents = ['metadata', 'hash', 'visual', 'rag', 'report'];
        const log = document.getElementById('processing-log');
        const connectors = document.querySelectorAll('.pipeline-connector');

        const messages = [
            'Extracting file metadata and EXIF data...',
            'Computing cryptographic hashes (SHA-256, MD5)...',
            'Running visual tampering detection with Amazon Nova Lite...',
            'Querying knowledge base for known patterns...',
            'Generating comprehensive integrity report...',
        ];

        for (let i = 0; i < agents.length; i++) {
            const agentEl = document.getElementById(`agent-${agents[i]}`);
            agentEl.setAttribute('data-status', 'processing');
            agentEl.querySelector('.agent-status-text').textContent = 'Processing';

            addLogEntry(log, messages[i]);

            // Activate connector before this agent (if not first)
            if (i > 0 && connectors[i - 1]) {
                connectors[i - 1].classList.add('active');
            }

            await sleep(600);
        }
    }

    function completePipeline() {
        const agents = ['metadata', 'hash', 'visual', 'rag', 'report'];
        const connectors = document.querySelectorAll('.pipeline-connector');

        agents.forEach(name => {
            const el = document.getElementById(`agent-${name}`);
            el.setAttribute('data-status', 'completed');
            el.querySelector('.agent-status-text').textContent = 'Done';
        });

        connectors.forEach(c => c.classList.add('active'));

        const log = document.getElementById('processing-log');
        addLogEntry(log, '✓ All agents completed. Preparing results...');
    }

    function resetPipeline() {
        const agents = ['metadata', 'hash', 'visual', 'rag', 'report'];
        const connectors = document.querySelectorAll('.pipeline-connector');

        agents.forEach(name => {
            const el = document.getElementById(`agent-${name}`);
            el.setAttribute('data-status', 'waiting');
            el.querySelector('.agent-status-text').textContent = 'Waiting';
        });

        connectors.forEach(c => c.classList.remove('active'));

        const log = document.getElementById('processing-log');
        log.innerHTML = '<div class="log-entry">Initializing analysis pipeline...</div>';
    }

    function addLogEntry(log, message) {
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        const time = new Date().toLocaleTimeString();
        entry.textContent = `[${time}] ${message}`;
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }

    function formatFileSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB'];
        let i = 0;
        while (bytes >= 1024 && i < units.length - 1) {
            bytes /= 1024;
            i++;
        }
        return `${bytes.toFixed(1)} ${units[i]}`;
    }

    function getFileIcon(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const icons = {
            pdf: '📕', log: '📝', txt: '📄', csv: '📊',
            json: '📋', xml: '📰',
        };
        return icons[ext] || '📄';
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    return { init, removeFile, resetPipeline };
})();
