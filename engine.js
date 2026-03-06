const MITRE_RULES = [
    {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        pattern: /(powershell|cmd\.exe|sh|bash) (-enc|-e |bypass|windowstyle hidden)/i,
        severity: 40,
        description: "Suspicious shell execution with obfuscation flags.",
        recommendation: "Review the script content, terminate the parent process, and check for unauthorized user account activity."
    },
    {
        id: "T1112",
        name: "Modify Registry",
        pattern: /(reg add|HKLM|HKCU).*CurrentVersion\\Run/i,
        severity: 60,
        description: "Persistence mechanism: program set to run on startup.",
        recommendation: "Audit registry changes, check for suspicious keys, and revert unauthorized modifications."
    },
    {
        id: "T1071",
        name: "C2 Communication",
        pattern: /(curl|wget|nc -l|netcat).*(http|https|ftp|:\d{4})/i,
        severity: 50,
        description: "Potential Command & Control (C2) outbound traffic.",
        recommendation: "Block malicious IPs/Domains and check for data exfiltration patterns."
    },
    {
        id: "T1003",
        name: "OS Credential Dumping",
        pattern: /(mimikatz|procdump|lsass\.exe|samlib)/i,
        severity: 95,
        description: "CRITICAL: Attempt to dump credentials from memory.",
        recommendation: "Reset compromised passwords and enable Multi-Factor Authentication (MFA)."
    },
    {
        id: "T1486",
        name: "Data Encrypted for Impact",
        pattern: /(vssadmin delete shadows|cipher \/w|.crypt|.locked)/i,
        severity: 100,
        description: "RANSOMWARE ACTIVITY: Shadow copy deletion or encryption detected.",
        recommendation: "Isolate the machine immediately and restore from offline backups."
    }
];

// --- 1. File Upload Handler ---
document.getElementById('file-input').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const content = e.target.result;
        const lines = content.split('\n');
        processLogs(lines);
    };
    reader.readAsText(file);
});

// --- 2. Core Detection Engine ---
function processLogs(lines) {
    let totalRisk = 0;
    const detections = [];

    lines.forEach(line => {
        MITRE_RULES.forEach(rule => {
            if (rule.pattern.test(line)) {
                // Store detection and update risk
                detections.push({ ...rule, line: line.trim() });
                totalRisk += rule.severity;
            }
        });
    });

    const finalScore = Math.min(totalRisk, 100);
    updateDashboard(finalScore, detections);
}

// --- 3. UI Update Logic ---
function updateDashboard(score, detections) {
    const riskVal = document.getElementById('risk-value');
    const riskFill = document.getElementById('risk-fill');
    const feed = document.getElementById('threat-feed');

    // Update Score and Color
    riskVal.innerText = score;
    riskFill.style.width = score + '%';
    
    const statusColor = score > 75 ? "#ff4d4d" : (score > 40 ? "#ffbd3d" : "#00ff9d");
    riskVal.style.color = statusColor;
    riskFill.style.background = statusColor;

    // Clear Feed
    feed.innerHTML = ''; 

    if (detections.length === 0) {
        feed.innerHTML = '<p class="placeholder-text">✅ No threats detected in this log file.</p>';
        updateTimeline([]); // Clear timeline
        return;
    }

    // Build Threat Feed
    detections.forEach(item => {
        const div = document.createElement('div');
        div.className = 'threat-item';
        div.innerHTML = `
            <div class="threat-header" style="display: flex; justify-content: space-between; align-items:center;">
                <strong>[${item.id}] ${item.name}</strong>
                <span class="severity-badge" style="background:${item.severity >= 80 ? '#ff4d4d' : '#ffbd3d'}; color: black; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight:bold;">
                    ${item.severity >= 80 ? 'CRITICAL' : 'WARNING'}
                </span>
            </div>
            <p class="threat-desc" style="color: #8b949e; font-size: 0.9rem; margin: 10px 0;">${item.description}</p>
            <div class="playbook" style="background: rgba(0, 255, 157, 0.1); border: 1px dashed #00ff9d; padding: 10px; font-size: 0.85rem; color: #00ff9d; border-radius: 4px;">
                <strong>🛡️ Response Playbook:</strong> ${item.recommendation}
            </div>
        `;
        feed.appendChild(div);
    });

    // Update the Timeline view
    updateTimeline(detections);
}

// --- 4. Timeline Visualizer ---
function updateTimeline(detections) {
    const timeline = document.getElementById('timeline-flow');
    timeline.innerHTML = ''; 

    if (detections.length === 0) {
        timeline.innerHTML = '<p class="placeholder-text">Waiting for events...</p>';
        return;
    }

    detections.forEach((det, index) => {
        const step = document.createElement('div');
        step.className = 'timeline-step';
        step.innerHTML = `
            <div class="step-num">${index + 1}</div>
            <div class="step-content">
                <strong style="color:#00ff9d">${det.id}</strong><br>
                <small style="font-size:0.7rem; color:#8b949e">${det.name}</small>
            </div>
        `;
        timeline.appendChild(step);
    });
}

// --- 5. Report Export Logic ---
document.getElementById('download-btn').onclick = function() {
    const score = document.getElementById('risk-value').innerText;
    const threats = Array.from(document.querySelectorAll('.threat-item')).map(t => {
        // Clean up the text for a clean .txt file
        return t.innerText.replace(/\n\s+/g, '\n');
    }).join('\n' + '-'.repeat(30) + '\n');
    
    if (score === "0" && threats === "") {
        alert("No analysis data available to download.");
        return;
    }

    const reportText = `
=========================================
      MALWARE ANALYSIS AI REPORT
=========================================
Generated: ${new Date().toLocaleString()}
Overall Risk Score: ${score}%
System Status: ${score > 70 ? 'CRITICAL' : 'STABLE'}

DETECTION DETAILS:
-----------------------------------------
${threats || "No malicious patterns identified."}

=========================================
END OF REPORT
=========================================`;
    
    const blob = new Blob([reportText], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `Threat_Report_${Date.now()}.txt`;
    link.click();
};