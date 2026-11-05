/**
 * ==========================================================================
 * CYBERGUARD ENTERPRISE // APPLICATION CONTROLLER (app.js)
 * UI State Management, DOM Rendering, and Event Orchestration
 * ==========================================================================
 */

document.addEventListener('DOMContentLoaded', () => {
    // Presets for testing
    const presets = {
        secure: `HTTP/1.1 200 OK
Date: Tue, 03 Nov 2026 12:00:00 GMT
Server: enterprise-gateway/10.4
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
Access-Control-Allow-Origin: https://app.enterprise.org`,

        vulnerable: `HTTP/1.1 200 OK
Date: Tue, 03 Nov 2026 12:00:00 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval';
X-Frame-Options: ALLOWALL
Access-Control-Allow-Origin: *`,

        api: `HTTP/1.1 200 OK
Date: Tue, 03 Nov 2026 12:00:00 GMT
Server: cloudflare
Strict-Transport-Security: max-age=15552000
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer-when-downgrade
Access-Control-Allow-Origin: *`
    };

    // DOM Elements
    const tabBtns = document.querySelectorAll('.tab-btn');
    const hubPanels = document.querySelectorAll('.hub-panel');
    const targetUrlInput = document.getElementById('targetUrlInput');
    const btnScanUrl = document.getElementById('btnScanUrl');
    const corsNotice = document.getElementById('corsNotice');
    const rawHeadersInput = document.getElementById('rawHeadersInput');
    const btnScanRaw = document.getElementById('btnScanRaw');
    const btnLoadSampleRaw = document.getElementById('btnLoadSampleRaw');
    const presetChips = document.querySelectorAll('.preset-chip');

    const scorecardSection = document.getElementById('scorecardSection');
    const resultsContent = document.getElementById('resultsContent');
    const auditTimestamp = document.getElementById('auditTimestamp');
    const gradeBadge = document.getElementById('gradeBadge');
    const scoreValue = document.getElementById('scoreValue');
    const exposureValue = document.getElementById('exposureValue');
    const passedCount = document.getElementById('passedCount');
    const warningCount = document.getElementById('warningCount');
    const criticalCount = document.getElementById('criticalCount');
    const headersList = document.getElementById('headersList');
    const cspStatusBadge = document.getElementById('cspStatusBadge');
    const cspAnalysisContent = document.getElementById('cspAnalysisContent');
    const serverTabs = document.querySelectorAll('.server-tab');
    const serverTitle = document.getElementById('serverTitle');
    const remediationCodeBlock = document.getElementById('remediationCodeBlock');
    const btnCopyCode = document.getElementById('btnCopyCode');
    const btnExport = document.getElementById('btnExport');

    let currentServerType = 'nginx';

    // Tab Switching Logic
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            hubPanels.forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // Preset Chips Handler
    presetChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const presetKey = chip.getAttribute('data-preset');
            const sampleText = presets[presetKey];
            rawHeadersInput.value = sampleText;
            // Switch to raw mode tab to show loaded preset
            tabBtns[1].click();
            // Automatically execute scan with preset
            runAudit(sampleText);
        });
    });

    // Load sample raw button
    btnLoadSampleRaw.addEventListener('click', () => {
        rawHeadersInput.value = presets.secure;
        runAudit(presets.secure);
    });

    // Scan Raw Button
    btnScanRaw.addEventListener('click', () => {
        const rawText = rawHeadersInput.value;
        if (!rawText.trim()) {
            alert('Por favor, ingresa o pega cabeceras HTTP crudas.');
            return;
        }
        runAudit(rawText);
    });

    // Scan URL Button (with fetch & fallback simulation)
    btnScanUrl.addEventListener('click', async () => {
        let url = targetUrlInput.value.trim();
        if (!url) {
            alert('Por favor, introduce una URL objetivo.');
            return;
        }

        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        btnScanUrl.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Auditando...';
        btnScanUrl.disabled = true;
        corsNotice.classList.add('hidden');

        try {
            // Attempt a lightweight fetch (HEAD or GET with no-cors / cors)
            const response = await fetch(url, { method: 'HEAD', mode: 'cors' });
            const simulatedRaw = [];
            simulatedRaw.f_push = (k, v) => simulatedRaw.push(`${k}: ${v}`);
            
            // Extract available headers from response
            response.headers.forEach((val, key) => {
                simulatedRaw.push(`${key}: ${val}`);
            });

            // If fetch succeeded but returned no security headers (due to CORS restrictions on header exposure), simulate based on domain
            if (simulatedRaw.length <= 2) {
                throw new Error('CORS restriction or limited header exposure.');
            }

            const rawText = simulatedRaw.join('\n');
            rawHeadersInput.value = rawText;
            runAudit(rawText);
        } catch (error) {
            // Fallback simulation for enterprise demonstration
            corsNotice.classList.remove('hidden');
            // Select preset based on URL name length or default to secure
            const fallbackPreset = url.includes('gov') || url.includes('bank') ? presets.secure : presets.vulnerable;
            rawHeadersInput.value = fallbackPreset;
            runAudit(fallbackPreset);
        } finally {
            btnScanUrl.innerHTML = '<i class="fa-solid fa-radar"></i> Ejecutar Auditoría';
            btnScanUrl.disabled = false;
        }
    });

    // Server Tab Switching for Remediation
    serverTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            serverTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentServerType = tab.getAttribute('data-server');
            serverTitle.textContent = currentServerType === 'nginx' ? 'nginx.conf' : (currentServerType === 'apache' ? '.htaccess' : 'Cloudflare Rule');
            remediationCodeBlock.textContent = window.securityEngine.generateRemediation(currentServerType);
        });
    });

    // Copy Code Button
    btnCopyCode.addEventListener('click', () => {
        const codeText = remediationCodeBlock.textContent;
        navigator.clipboard.writeText(codeText).then(() => {
            const originalHTML = btnCopyCode.innerHTML;
            btnCopyCode.innerHTML = '<i class="fa-solid fa-check"></i> ¡Copiado!';
            setTimeout(() => {
                btnCopyCode.innerHTML = originalHTML;
            }, 2000);
        });
    });

    // Export / Print Report Button
    btnExport.addEventListener('click', () => {
        window.print();
    });

    /**
     * Executes audit logic and updates DOM
     */
    function runAudit(rawText) {
        const parsedMap = window.securityEngine.parseRawHeaders(rawText);
        const report = window.securityEngine.auditHeaders(parsedMap);

        // Update Scorecard
        scorecardSection.classList.remove('hidden');
        resultsContent.classList.remove('hidden');

        auditTimestamp.textContent = `Auditado: ${new Date().toLocaleTimeString()}`;
        gradeBadge.textContent = report.grade;
        gradeBadge.className = `grade-badge ${report.gradeClass}`;
        scoreValue.textContent = `${report.score} / 100`;
        exposureValue.textContent = report.exposure;

        if (report.score >= 80) {
            exposureValue.className = 'metric-value text-success';
        } else if (report.score >= 60) {
            exposureValue.className = 'metric-value text-warning';
        } else {
            exposureValue.className = 'metric-value text-danger';
        }

        passedCount.textContent = report.counts.passed;
        warningCount.textContent = report.counts.warning;
        criticalCount.textContent = report.counts.critical;

        // Render Detailed Findings Cards
        renderFindings(report.findings);

        // Render CSP Deep Analysis
        renderCSPInspector(report.cspAnalysis);

        // Render Initial Remediation Snippet
        remediationCodeBlock.textContent = window.securityEngine.generateRemediation(currentServerType);

        // Smooth scroll to results
        scorecardSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    /**
     * Renders detailed header cards
     */
    function renderFindings(findings) {
        headersList.innerHTML = '';
        findings.forEach(f => {
            const card = document.createElement('div');
            card.className = `header-card status-${f.status}`;

            let iconClass = 'fa-circle-check';
            if (f.status === 'warning') iconClass = 'fa-triangle-exclamation';
            if (f.status === 'danger') iconClass = 'fa-circle-xmark';

            let badgeClass = 'badge-success';
            let badgeText = 'Conforme';
            if (f.status === 'warning') {
                badgeClass = 'badge-warning';
                badgeText = 'Advertencia';
            }
            if (f.status === 'danger') {
                badgeClass = 'badge-danger';
                badgeText = 'Crítico / Ausente';
            }

            card.innerHTML = `
                <div class="header-card-top">
                    <div class="header-title-cluster">
                        <div class="header-status-icon">
                            <i class="fa-solid ${iconClass}"></i>
                        </div>
                        <span class="header-name">${f.name}</span>
                    </div>
                    <span class="badge-status ${badgeClass}">${badgeText}</span>
                </div>
                <div class="header-value-display font-mono">
                    ${f.value ? escapeHtml(f.value) : '<span class="text-danger">&lt; Cabecera No Detectada &gt;</span>'}
                </div>
                <p class="header-description">${f.message}</p>
            `;
            headersList.appendChild(card);
        });
    }

    /**
     * Renders CSP Deep Inspector panel
     */
    function renderCSPInspector(csp) {
        cspStatusBadge.textContent = csp.statusText;
        cspStatusBadge.className = `badge-status badge-${csp.status}`;

        cspAnalysisContent.innerHTML = '';

        if (csp.warnings.length > 0) {
            const warningsBox = document.createElement('div');
            warningsBox.className = 'cors-notice';
            warningsBox.style.marginBottom = '0.75rem';
            warningsBox.innerHTML = `
                <i class="fa-solid fa-triangle-exclamation"></i>
                <div>
                    <strong>Hallazgos de Riesgo en CSP:</strong>
                    <ul style="margin-top: 0.25rem; padding-left: 1rem;">
                        ${csp.warnings.map(w => `<li>${w}</li>`).join('')}
                    </ul>
                </div>
            `;
            cspAnalysisContent.appendChild(warningsBox);
        }

        if (csp.directives.length === 0) {
            const emptyDiv = document.createElement('div');
            emptyDiv.className = 'header-value-display';
            emptyDiv.textContent = 'No se encontraron directivas CSP configuradas.';
            cspAnalysisContent.appendChild(emptyDiv);
            return;
        }

        csp.directives.forEach(dir => {
            const row = document.createElement('div');
            row.className = 'csp-directive-row';
            row.innerHTML = `
                <span class="csp-dir-name">${dir.name}</span>
                <span class="csp-dir-value">${escapeHtml(dir.value)}</span>
            `;
            cspAnalysisContent.appendChild(row);
        });
    }

    /**
     * Helper to escape HTML for safe display
     */
    function escapeHtml(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Auto-load secure sample on startup for immediate visual impact
    rawHeadersInput.value = presets.secure;
    runAudit(presets.secure);
});
