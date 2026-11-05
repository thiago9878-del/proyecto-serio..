/**
 * ==========================================================================
 * CYBERGUARD ENTERPRISE // SECURITY ENGINE (securityEngine.js)
 * OWASP Secure Headers Analysis & CSP Intelligence Core
 * ==========================================================================
 */

class SecurityEngine {
    constructor() {
        // Definition of critical headers audited by OWASP standards
        this.ruleDefinitions = {
            'strict-transport-security': {
                name: 'Strict-Transport-Security (HSTS)',
                weight: 20,
                description: 'Fuerza conexiones cifradas (HTTPS) y previene ataques de suplantación de identidad (SSL stripping).',
                evaluator: (val) => {
                    if (!val) return { status: 'danger', message: 'Cabecera HSTS ausente. Alto riesgo de ataques Man-in-the-Middle.' };
                    const hasMaxAge = /max-age=(\d+)/i.exec(val);
                    const maxAgeSeconds = hasMaxAge ? parseInt(hasMaxAge[1], 10) : 0;
                    const includeSubDomains = /includesubdomains/i.test(val);
                    const preload = /preload/i.test(val);

                    if (maxAgeSeconds < 31536000) {
                        return { status: 'warning', message: `HSTS max-age (${maxAgeSeconds}s) es menor a 1 año recomendado (31536000s).` };
                    }
                    if (!includeSubDomains) {
                        return { status: 'warning', message: 'HSTS configurado pero falta la directiva includeSubDomains.' };
                    }
                    return { status: 'passed', message: `HSTS óptimo (max-age=${maxAgeSeconds}, includeSubDomains${preload ? ', preload' : ''}).` };
                }
            },
            'content-security-policy': {
                name: 'Content-Security-Policy (CSP)',
                weight: 25,
                description: 'Mitiga ataques de Inyección de Código (XSS) y Clickjacking controlando los recursos ejecutables.',
                evaluator: (val) => {
                    if (!val) return { status: 'danger', message: 'Política CSP ausente. La aplicación está expuesta a XSS y ejecución de scripts maliciosos.' };
                    if (val.includes("'unsafe-inline'") || val.includes("'unsafe-eval'")) {
                        return { status: 'warning', message: 'CSP contiene directivas inseguras (\'unsafe-inline\' o \'unsafe-eval\').' };
                    }
                    if (val.includes('*') && !val.includes("default-src 'self'")) {
                        return { status: 'warning', message: 'CSP contiene comodines permisivos sin aislamiento estricto de origen.' };
                    }
                    return { status: 'passed', message: 'Política CSP robusta y configurada correctamente.' };
                }
            },
            'x-frame-options': {
                name: 'X-Frame-Options',
                weight: 15,
                description: 'Protege contra ataques de Clickjacking impidiendo que el sitio sea embebido en iframes maliciosos.',
                evaluator: (val) => {
                    if (!val) return { status: 'danger', message: 'X-Frame-Options ausente. El sitio es vulnerable a ataques de enmarcado (Clickjacking).' };
                    const upper = val.trim().toUpperCase();
                    if (upper === 'DENY' || upper === 'SAMEORIGIN') {
                        return { status: 'passed', message: `Protección anti-clickjacking activa (${upper}).` };
                    }
                    return { status: 'warning', message: `Valor inusual o débil (${val}). Se recomienda DENY o SAMEORIGIN.` };
                }
            },
            'x-content-type-options': {
                name: 'X-Content-Type-Options',
                weight: 15,
                description: 'Previene ataques de "MIME-sniffing" forzando al navegador a respetar el tipo MIME declarado.',
                evaluator: (val) => {
                    if (!val) return { status: 'danger', message: 'Cabecera ausente. Los navegadores pueden interpretar incorrectamente los tipos MIME.' };
                    if (val.trim().toLowerCase() === 'nosniff') {
                        return { status: 'passed', message: 'Protección MIME-sniffing activa (nosniff).' };
                    }
                    return { status: 'warning', message: `Valor no estándar (${val}). Se esperaba 'nosniff'.` };
                }
            },
            'referrer-policy': {
                name: 'Referrer-Policy',
                weight: 10,
                description: 'Controla cuánta información de referencia (URLs sensibles) se incluye en las solicitudes salientes.',
                evaluator: (val) => {
                    if (!val) return { status: 'warning', message: 'Referrer-Policy ausente. Puede haber fugas de URLs sensibles hacia orígenes externos.' };
                    const securePolicies = [
                        'no-referrer', 
                        'no-referrer-when-downgrade', 
                        'origin', 
                        'origin-when-cross-origin', 
                        'same-origin', 
                        'strict-origin', 
                        'strict-origin-when-cross-origin'
                    ];
                    if (securePolicies.includes(val.trim().toLowerCase())) {
                        return { status: 'passed', message: `Política de referencia segura (${val}).` };
                    }
                    return { status: 'warning', message: `Política configurada (${val}) puede ser demasiado permisiva.` };
                }
            },
            'permissions-policy': {
                name: 'Permissions-Policy',
                weight: 10,
                description: 'Restringe el acceso del sitio y de scripts embebidos a APIs del navegador (cámara, micrófono, geolocalización).',
                evaluator: (val) => {
                    if (!val) return { status: 'warning', message: 'Permissions-Policy ausente. APIs sensibles (cámara, GPS) quedan con permisos por defecto del navegador.' };
                    return { status: 'passed', message: 'Permissions-Policy configurada correctamente.' };
                }
            },
            'access-control-allow-origin': {
                name: 'Access-Control-Allow-Origin (CORS)',
                weight: 5,
                description: 'Controla qué dominios externos tienen permiso para consultar recursos mediante CORS.',
                evaluator: (val) => {
                    if (!val) return { status: 'passed', message: 'Sin restricciones CORS globales expuestas (o estrictamente restringido).' };
                    if (val.trim() === '*') {
                        return { status: 'warning', message: 'CORS comodín (*) detectado. Permite solicitudes desde cualquier origen externo.' };
                    }
                    return { status: 'passed', message: `CORS configurado para origen específico (${val}).` };
                }
            }
        };
    }

    /**
     * Parses raw response headers text into a key-value dictionary (case-insensitive keys).
     */
    parseRawHeaders(rawText) {
        const headers = {};
        const lines = rawText.split(/\r?\n/);
        for (const line of lines) {
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                const key = line.substring(0, colonIndex).trim().toLowerCase();
                const value = line.substring(colonIndex + 1).trim();
                headers[key] = value;
            }
        }
        return headers;
    }

    /**
     * Performs a complete security audit on a dictionary of headers.
     */
    auditHeaders(headersMap) {
        let totalScore = 100;
        let maxPossibleScore = 0;
        let earnedScore = 0;
        
        const results = [];
        let passed = 0;
        let warning = 0;
        let critical = 0;

        for (const [key, def] of Object.entries(this.ruleDefinitions)) {
            maxPossibleScore += def.weight;
            const headerValue = headersMap[key] || null;
            const evaluation = def.evaluator(headerValue);

            let scoreContribution = 0;
            if (evaluation.status === 'passed') {
                scoreContribution = def.weight;
                passed++;
            } else if (evaluation.status === 'warning') {
                scoreContribution = def.weight * 0.5;
                warning++;
            } else {
                scoreContribution = 0;
                critical++;
            }

            earnedScore += scoreContribution;

            results.push({
                id: key,
                name: def.name,
                description: def.description,
                value: headerValue,
                status: evaluation.status,
                message: evaluation.message,
                weight: def.weight
            });
        }

        const finalScore = Math.round((earnedScore / maxPossibleScore) * 100);
        const grade = this.calculateGrade(finalScore, critical);

        // Deep CSP Analysis
        const cspValue = headersMap['content-security-policy'] || null;
        const cspAnalysis = this.analyzeCSP(cspValue);

        return {
            score: finalScore,
            grade: grade.grade,
            gradeClass: grade.cssClass,
            exposure: grade.exposure,
            counts: { passed, warning, critical },
            findings: results,
            cspAnalysis: cspAnalysis,
            rawMap: headersMap
        };
    }

    /**
     * Maps numerical score and critical count to letter grades (A+ to F).
     */
    calculateGrade(score, criticalCount) {
        if (score >= 95 && criticalCount === 0) return { grade: 'A+', cssClass: 'grade-aplus', exposure: 'Mínimo / Conforme' };
        if (score >= 90) return { grade: 'A', cssClass: 'grade-a', exposure: 'Bajo' };
        if (score >= 80) return { grade: 'B', cssClass: 'grade-b', exposure: 'Moderado' };
        if (score >= 70) return { grade: 'C', cssClass: 'grade-c', exposure: 'Elevado' };
        if (score >= 60) return { grade: 'D', cssClass: 'grade-d', exposure: 'Alto' };
        return { grade: 'F', cssClass: 'grade-f', exposure: 'Crítico / Vulnerable' };
    }

    /**
     * Deep analysis of CSP directives.
     */
    analyzeCSP(cspValue) {
        if (!cspValue) {
            return {
                status: 'danger',
                statusText: 'Ausente',
                directives: [],
                warnings: ['Falta la política Content-Security-Policy (CSP).']
            };
        }

        const directives = [];
        const warnings = [];
        const parts = cspValue.split(';');

        for (const part of parts) {
            const trimmed = part.trim();
            if (!trimmed) continue;
            const spaceIdx = trimmed.indexOf(' ');
            const dirName = spaceIdx > 0 ? trimmed.substring(0, spaceIdx) : trimmed;
            const dirVal = spaceIdx > 0 ? trimmed.substring(spaceIdx + 1) : '';

            directives.push({ name: dirName, value: dirVal });

            if (dirVal.includes("'unsafe-inline'")) {
                warnings.push(`Directiva '${dirName}' permite 'unsafe-inline' (riesgo de XSS).`);
            }
            if (dirVal.includes("'unsafe-eval'")) {
                warnings.push(`Directiva '${dirName}' permite 'unsafe-eval' (ejecución de código dinámico).`);
            }
            if (dirVal.includes('*') && !dirName.includes('report')) {
                warnings.push(`Directiva '${dirName}' utiliza comodines ('*') permisivos.`);
            }
        }

        const status = warnings.length === 0 ? 'success' : (warnings.length > 2 ? 'danger' : 'warning');
        const statusText = warnings.length === 0 ? 'Óptimo' : 'Con Riesgos';

        return {
            status,
            statusText,
            directives,
            warnings
        };
    }

    /**
     * Generates executive remediation code snippets for Nginx, Apache, and Cloudflare.
     */
    generateRemediation(serverType) {
        switch (serverType) {
            case 'nginx':
                return `# Configuración optimizada para Nginx (nginx.conf)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;`;

            case 'apache':
                return `# Configuración optimizada para Apache (.htaccess)
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>`;

            case 'cloudflare':
                return `# Cloudflare Transform Rules / Response Header Modifications
# Aplicar reglas de respuesta HTTP en Cloudflare Dashboard:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()`;

            default:
                return `# Seleccione un servidor válido.`;
        }
    }
}

// Global instance of SecurityEngine
window.securityEngine = new SecurityEngine();
