/* ════════════════════════════════════════════════════════════════
   BENFET v3 — Enhanced Dashboard JavaScript
   - Fixed capture flow with auto-stop and clear completion feedback
   - Cleaner state management and async handling
   ════════════════════════════════════════════════════════════════ */

let currentAnalysisId = null;
let capturePollingInterval = null;
let isCaptureActive = false;

// ─── Utilities ──────────────────────────────────────────────────

function fmtBytes(b) {
    if (!b) return '0 B';
    const u = ['B','KB','MB','GB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return `${b.toFixed(1)} ${u[i]}`;
}

function showToast(msg, type = 'info') {
    const container = document.getElementById('toast');
    const t = document.createElement('div');
    t.className = `toast-item toast-${type}`;
    t.textContent = msg;
    container.appendChild(t);
    
    setTimeout(() => {
        t.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => t.remove(), 300);
    }, 4000);
}

// NOTE: safeFetch is for JSON API calls ONLY.
// File uploads MUST use fetch() directly — never safeFetch() — because
// safeFetch hard-codes Content-Type: application/json, which destroys the
// multipart/form-data boundary that the browser sets for FormData payloads.
async function safeFetch(url, options = {}) {
    try {
        const res = await fetch(url, {
            ...options,
            headers: { 'Content-Type': 'application/json', ...options.headers }
        });
        
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        
        return await res.json();
    } catch (error) {
        console.error(`Fetch error for ${url}:`, error);
        showToast(`⚠️ ${error.message || 'Request failed'}`, 'error');
        throw error;
    }
}

// ─── Tab Navigation ─────────────────────────────────────────────

function selectTab(tabName) {
    document.querySelectorAll('.tabs-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.toggle('active', pane.id === `tab-${tabName}`);
    });
    
    if (tabName === 'topology' && currentAnalysisId) {
        loadTopology(currentAnalysisId);
    } else if (tabName === 'behavioral') {
        loadBehavioralConsistency();
    }
}

// ─── Dashboard Loading ──────────────────────────────────────────

async function loadDashboard() {
    showToast('Refreshing dashboard...', 'info');
    try {
        const data = await safeFetch('/api/summary');
        
        document.getElementById('analyses-count').textContent = data.total_analyses || 0;
        document.getElementById('profiles-count').textContent = data.total_profiles || 8;
        document.getElementById('features-count').textContent = data.total_features || 78;
        
        // Update navbar badge
        const badge = document.getElementById('model-badge');
        // Update stats row model status
        const modelVal = document.getElementById('model-status-val');
        
        if (data.model_exists && data.model) {
            const acc = data.model.train_accuracy 
                ? `${(data.model.train_accuracy * 100).toFixed(0)}%` 
                : '✅';
            const modelDisplay = `✅ ${acc}`;
            
            badge.textContent = `✅ Model Ready (${acc} accuracy)`;
            badge.className = 'badge success';
            
            modelVal.textContent = modelDisplay;
            modelVal.style.color = 'var(--accent-green)';
        } else {
            badge.textContent = '⚠️ No Model';
            badge.className = 'badge warning';
            
            modelVal.textContent = '—';
            modelVal.style.color = 'var(--text-muted)';
        }
        
        showToast('Dashboard updated', 'success');
    } catch (error) {
        console.error('Dashboard load failed:', error);
        showToast('Failed to load dashboard', 'error');
    }
}

// ─── Network Interfaces ─────────────────────────────────────────

async function loadInterfaces() {
    try {
        const data = await safeFetch('/api/capture/interfaces');
        const select = document.getElementById('iface');
        
        if (!select) return;
        
        (data.interfaces || []).forEach(iface => {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = `${iface.name} (${iface.description || 'Unknown'})`;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load interfaces:', error);
    }
}

// ─── Live Capture Flow (FIXED) ──────────────────────────────────

async function startLiveCapture() {
    const iface = document.getElementById('iface').value;
    const duration = parseInt(document.getElementById('dur').value) || 30;
    const maxPkts = parseInt(document.getElementById('maxpkts').value) || 5000;
    
    if (!iface) {
        showToast('⚠️ Please select a network interface', 'warning');
        return;
    }
    
    const btn = document.getElementById('capture-btn');
    const msgBox = document.getElementById('capture-msg');
    
    messageBox(msgBox, 'info', `📡 Starting capture on ${iface} for ${duration}s...`);
    btn.disabled = true;
    isCaptureActive = true;
    
    try {
        const startRes = await safeFetch('/api/capture/start', {
            method: 'POST',
            body: JSON.stringify({
                interface: iface,
                duration: duration,
                packet_count: maxPkts
            })
        });
        
        if (startRes.error) {
            showToast(`❌ Capture failed: ${startRes.error}`, 'error');
            messageBox(msgBox, 'error', `❌ ${startRes.error}`);
            isCaptureActive = false;
            btn.disabled = false;
            return;
        }
        
        showToast('📡 Capture started! Waiting for completion...', 'info');
        
        //  Start polling
        pollCaptureStatus(duration, msgBox, btn, maxPkts);
        
    } catch (error) {
        console.error('Capture start error:', error);
        messageBox(msgBox, 'error', `❌ ${error.message}`);
        isCaptureActive = false;
        btn.disabled = false;
    }
}

async function pollCaptureStatus(totalDuration, msgBox, btn, targetMaxPkts) {
    let pollCount = 0;
    const maxPolls = Math.ceil((totalDuration + 30) * 1000 / 500); // Duration + 30s buffer, polling every 500ms
    
    capturePollingInterval = setInterval(async () => {
        pollCount++;
        
        // Safety timeout - if polling exceeds max attempts, stop and notify
        if (pollCount > maxPolls) {
            clearInterval(capturePollingInterval);
            capturePollingInterval = null;
            isCaptureActive = false;
            messageBox(msgBox, 'error', 
                `⚠️ CAPTURE TIMEOUT\n\nCapture did not complete within expected time.\nPlease refresh the page and try again.`);
            showToast(`⚠️ Capture timeout - exceeded ${totalDuration + 30} seconds`, 'warning');
            btn.disabled = false;
            return;
        }
        
        try {
            const status = await safeFetch('/api/capture/status');
            
            if (status.is_capturing) {
                const timeProgress = (status.elapsed_seconds / totalDuration) * 100;
                const pktProgress = targetMaxPkts ? (status.packets_captured / targetMaxPkts) * 100 : 0;
                const progress = Math.min(100, Math.round(Math.max(timeProgress, pktProgress)));

                const progressBar = '█'.repeat(Math.floor(progress / 5)) + '░'.repeat(20 - Math.floor(progress / 5));
                messageBox(msgBox, 'capturing', 
                    `📡 Capturing: ${status.packets_captured} packets | ${status.elapsed_seconds}s / ${totalDuration}s\n[${progressBar}] ${progress}%`);
            } else {
                // Capture completed natively via thread finish
                clearInterval(capturePollingInterval);
                capturePollingInterval = null;
                isCaptureActive = false;
                
                await completeCaptureWorkflow(status, msgBox, btn);
            }
        } catch (error) {
            console.error('Poll status error:', error);
            clearInterval(capturePollingInterval);
            capturePollingInterval = null;
            isCaptureActive = false;
            messageBox(msgBox, 'error', `⚠️ Connection issue during capture: ${error.message}`);
            btn.disabled = false;
        }
    }, 500);
}

async function completeCaptureWorkflow(status, msgBox, btn) {
    try {
        const stopRes = await safeFetch('/api/capture/stop', { method: 'POST' });
        
        // Check for capture errors first
        if (stopRes.error) {
            messageBox(msgBox, 'error', `❌ CAPTURE FAILED\n\n${stopRes.error}`);
            showToast(`❌ Capture failed: ${stopRes.error}`, 'error');
            btn.disabled = false;
            return;
        }
        
        const packetsCount = stopRes.packets_captured || status.packets_captured || 0;
        
        // Success case
        if (packetsCount > 0 && stopRes.analysis_id) {
            messageBox(msgBox, 'success', 
                `✅ CAPTURE COMPLETE!\n${packetsCount} packets captured\n\nAnalysis ID: ${stopRes.analysis_id}`);
            
            currentAnalysisId = stopRes.analysis_id;
            showToast(`✅ Capture complete: ${packetsCount} packets`, 'success');
            
            const actionBtn = document.createElement('button');
            actionBtn.className = 'btn btn-accent';
            actionBtn.style.marginTop = '12px';
            actionBtn.textContent = '⚡ Run Analysis';
            actionBtn.onclick = () => runAnalysis(stopRes.analysis_id);
            msgBox.appendChild(actionBtn);
        } else if (packetsCount > 0) {
            // Packets captured but no analysis_id (odd case)
            messageBox(msgBox, 'info', 
                `✅ Capture complete!\n${packetsCount} packets captured\n\nAnalysis ID saved. Refreshing data...`);
            showToast(`✅ ${packetsCount} packets captured`, 'success');
            currentAnalysisId = stopRes.analysis_id;
        } else {
            // No packets captured
            messageBox(msgBox, 'warning', 
                `⚠️ CAPTURE COMPLETE\nBut no packets were captured.\n\nEnsure network is active and try again.`);
            showToast(`⚠️ No packets captured (check interface/network)`, 'warning');
        }
        
        await loadDashboard();
        
    } catch (error) {
        console.error('Completion error:', error);
        messageBox(msgBox, 'error', `❌ Error finalizing capture: ${error.message}`);
    } finally {
        btn.disabled = false;
    }
}

function messageBox(el, type, text) {
    el.className = `msg-box msg-${type}`;
    el.style.display = 'block';
    el.innerHTML = text.replace(/\n/g, '<br>');
}

// ─── File Upload ────────────────────────────────────────────

function handleUpload(e) {
    e.preventDefault();
    e.stopPropagation();
    const files = e.dataTransfer?.files;
    if (files?.length) {
        uploadPCAP(files[0]);
    }
}

async function uploadPCAP(file) {
    if (!file) return;
    
    // Validate file type
    const allowed = ['pcap', 'pcapng', 'cap'];
    const ext = file.name.split('.').pop().toLowerCase();
    
    if (!allowed.includes(ext)) {
        showToast(`❌ Invalid file type. Allowed: ${allowed.join(', ')}`, 'error');
        return;
    }
    
    showToast(`📤 Uploading ${file.name}...`, 'info');
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        const data = await res.json();
        if (data.error) {
            showToast(`❌ ${data.error}`, 'error');
            return;
        }
        
        currentAnalysisId = data.analysis_id;
        showToast(`✅ File uploaded successfully!`, 'success');
        
        // Show the Run Analysis button
        const actionBox = document.getElementById('upload-actions');
        const statusText = document.getElementById('upload-status');
        statusText.textContent = `💾 File: ${file.name} | ID: ${data.analysis_id}`;
        actionBox.style.display = 'block';
        
        await loadDashboard();
        
    } catch (error) {
        console.error('Upload error:', error);
        showToast(`❌ Upload failed: ${error.message}`, 'error');
    }
}

async function runAnalysisFromUpload() {
    if (!currentAnalysisId) {
        showToast('❌ No file uploaded. Please upload a PCAP first.', 'error');
        return;
    }
    await runAnalysis(currentAnalysisId);
}

async function runAnalysis(id) {
    showToast('Running feature extraction & analysis (20-30 seconds)...', 'info');
    let timeoutHandle;
    try {
        const controller = new AbortController();
        timeoutHandle = setTimeout(() => controller.abort(), 240000);  // 240 seconds timeout for analysis
        
        const res = await fetch(`/api/analyze/${id}`, { signal: controller.signal });
        clearTimeout(timeoutHandle);
        
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        const data = await res.json();
        if (data.error) { showToast(`Analysis failed: ${data.error}`, 'error'); return; }

        currentAnalysisId = id;
        showToast('Feature extraction complete!', 'success');

        // Fetch full data for detailed view
        try {
            const flowRes = await fetch(`/api/flows/${id}`);
            if (!flowRes.ok) throw new Error(`Failed to fetch flows: HTTP ${flowRes.status}`);
            const flowData = await flowRes.json();
            renderResults(data, flowData);
        } catch (flowErr) {
            console.warn('Could not fetch flows:', flowErr);
            renderResults(data, {});
        }
        
        await loadDashboard();
        selectTab('analysis');
    } catch (e) { 
        if (timeoutHandle) clearTimeout(timeoutHandle);
        console.error('Analysis error:', e);
        const msg = e.name === 'AbortError' ? 'Request timed out (feature extraction took too long)' : e.message;
        showToast(`Error: ${msg}`, 'error'); 
    }
}

async function viewResults(id) {
    currentAnalysisId = id;
    try {
        const analyzeRes = await fetch(`/api/analyze/${id}`).then(r => r.ok ? r.json() : Promise.reject(new Error('Analysis failed'))).catch(() => ({analysis_id: id}));
        const flowRes = await fetch(`/api/flows/${id}`).then(r => r.ok ? r.json() : Promise.reject(new Error('Flows failed'))).catch(() => ({}));
        
        renderResults(analyzeRes, flowRes);
        selectTab('analysis');
    } catch (e) { 
        console.error('View results error:', e);
        showToast(`Error: ${e.message}`, 'error'); 
    }
}

function renderResults(data, flowData) {
    const el = document.getElementById('analysis-content');
    // Download button removed from this version
    const aid = data.analysis_id || currentAnalysisId;

    let html = `
        <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:16px;">
            <div class="stat-card"><div class="stat-label">Total Flows</div><div class="stat-value" style="font-size:22px">${data.total_flows || flowData?.features?.length || 0}</div></div>
            <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value" style="font-size:16px">✅</div><div class="stat-sub">${data.status || 'analyzed'}</div></div>
            <div class="stat-card"><div class="stat-label">Analysis ID</div><div class="stat-value" style="font-size:14px;word-break:break-all;">${aid}</div></div>
            <div class="stat-card"><div class="stat-label">Timestamp</div><div class="stat-value" style="font-size:12px">${new Date().toLocaleTimeString()}</div></div>
        </div>`;

    // Metadata section
    const metadata = data.metadata || flowData?.metadata || {};
    if (metadata && Object.keys(metadata).length > 0) {
        html += `<h3 style="margin:16px 0 8px">📋 Capture Metadata</h3>
            <table class="data-table"><thead><tr>
                <th>Metric</th><th>Value</th>
            </tr></thead><tbody>`;
        for (const [key, val] of Object.entries(metadata)) {
            let displayVal = val;
            if (key === 'total_bytes') displayVal = fmtBytes(val);
            else if (typeof val === 'number' && val > 1000) displayVal = val.toLocaleString();
            html += `<tr><td><strong>${key}</strong></td><td>${displayVal || '—'}</td></tr>`;
        }
        html += `</tbody></table>`;
    }

    // Protocol distribution
    const protos = data.protocol_distribution || flowData?.flow_analysis?.protocol_distribution || [];
    if (protos.length) {
        html += `<h3 style="margin:16px 0 8px">📊 Protocol Distribution</h3>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px;margin-bottom:12px;">`;
        protos.forEach(p => {
            const pktPct = ((p.packet_ratio||0)*100).toFixed(1);
            const bytePct = ((p.byte_ratio||0)*100).toFixed(1);
            html += `<div class="protocol-card">
                <div style="font-weight:600;color:var(--accent-blue);margin-bottom:4px">${p.protocol}</div>
                <div style="font-size:12px;color:var(--text-secondary);">
                    🔹 Packets: <strong>${(p.packet_count||0).toLocaleString()}</strong> (${pktPct}%)<br>
                    🔹 Bytes: <strong>${fmtBytes(p.byte_count||0)}</strong> (${bytePct}%)
                </div>
            </div>`;
        });
        html += `</div>`;
    }

    // Flow summaries - Top flows
    const flows = flowData?.flow_analysis?.flow_summaries || [];
    if (flows.length) {
        html += `<h3 style="margin:16px 0 8px">🔗 Top Flows (by bytes)</h3>
            <div style="overflow-x:auto;">
            <table class="data-table"><thead><tr>
                <th>Flow</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Duration</th><th>Avg Pkt</th><th>Flags</th>
            </tr></thead><tbody>`;
        flows.slice(0, 25).forEach(f => {
            const flags = f.tcp_flags ? f.tcp_flags.join(', ') : 'N/A';
            html += `<tr>
                <td style="font-family:monospace;font-size:11px">${f.flow}</td>
                <td><strong>${f.protocol}</strong></td>
                <td>${f.total_packets.toLocaleString()}</td>
                <td>${fmtBytes(f.total_bytes)}</td>
                <td>${f.duration.toFixed(3)}s</td>
                <td>${f.avg_packet_size} B</td>
                <td style="font-size:11px">${flags}</td>
            </tr>`;
        });
        html += `</tbody></table></div>`;
    }

    // Feature details with collapsible sections
    const features = flowData?.features || [];
    if (features.length) {
        html += `<h3 style="margin:16px 0 8px">🔬 Behavioral Features (${features.length} flows)</h3>
            <div style="background:var(--bg);border-radius:8px;padding:12px;margin-bottom:12px;font-size:12px;color:var(--text-secondary);">
                Showing detailed feature extraction for first 10 flows. Each flow analyzed on 77 behavioral dimensions (temporal, spatial, volumetric, TCP/IP, TLS).
            </div>`;
        features.slice(0, 10).forEach((feat, idx) => {
            const flowKey = feat.flow_key || `${feat.src_ip}:${feat.src_port} → ${feat.dst_ip}:${feat.dst_port}`;
            html += `<details style="margin-bottom:8px;"><summary style="cursor:pointer;font-weight:600;font-size:13px;color:var(--accent-blue);padding:8px;background:var(--bg);border-radius:6px;border:1px solid var(--border);">
                📊 Flow #${idx+1}: ${flowKey}</summary>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:6px;padding:10px;font-size:11px;background:var(--bg);border-radius:6px;margin-top:4px;border:1px solid var(--border);">`;

            const skip = ['flow_key','src_ip','dst_ip','protocol','src_port','dst_port'];
            const entries = Object.entries(feat).filter(([k]) => !skip.includes(k));
            
            // Show temporal features
            const temporalFeats = entries.filter(([k]) => k.includes('iat') || k.includes('duration') || k.includes('time') || k.includes('active') || k.includes('idle'));
            if (temporalFeats.length) {
                html += `<div style="grid-column:1/-1;color:var(--accent-cyan);font-weight:600;margin-top:4px;">⏱️ Temporal Features</div>`;
                temporalFeats.slice(0, 6).forEach(([k,v]) => {
                    const val = typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(4)) : v;
                    html += `<div><span style="color:var(--text-muted)">${k}:</span> <strong style="color:var(--accent-blue)">${val}</strong></div>`;
                });
            }

            // Show spatial features
            const spatialFeats = entries.filter(([k]) => k.includes('size') || k.includes('length') || k.includes('pkt') || k.includes('spl'));
            if (spatialFeats.length) {
                html += `<div style="grid-column:1/-1;color:var(--accent-purple);font-weight:600;margin-top:4px;">📐 Spatial Features</div>`;
                spatialFeats.slice(0, 6).forEach(([k,v]) => {
                    const val = typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(4)) : v;
                    html += `<div><span style="color:var(--text-muted)">${k}:</span> <strong style="color:var(--accent-purple)">${val}</strong></div>`;
                });
            }

            // Show other features
            const otherFeats = entries.filter(([k]) => 
                !k.includes('iat') && !k.includes('duration') && !k.includes('time') && 
                !k.includes('active') && !k.includes('idle') && !k.includes('size') && 
                !k.includes('length') && !k.includes('pkt') && !k.includes('spl'));
            if (otherFeats.length) {
                html += `<div style="grid-column:1/-1;color:var(--accent-green);font-weight:600;margin-top:4px;">📊 Additional Features</div>`;
                otherFeats.slice(0, 6).forEach(([k,v]) => {
                    const val = typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(4)) : v;
                    html += `<div><span style="color:var(--text-muted)">${k}:</span> <strong style="color:var(--accent-green)">${val}</strong></div>`;
                });
            }

            html += `</div></details>`;
        });
    }

    // Connection frequency
    const connFreq = flowData?.flow_analysis?.connection_frequency || {};
    const connEntries = Object.entries(connFreq);
    if (connEntries.length) {
        html += `<h3 style="margin:16px 0 8px">📡 Connection Frequency by Source IP</h3>
            <div style="overflow-x:auto;">
            <table class="data-table"><thead><tr>
                <th>Source IP</th><th>Unique Destinations</th><th>Top Destinations</th>
            </tr></thead><tbody>`;
        connEntries.slice(0, 20).forEach(([ip, info]) => {
            const topDests = (info.destinations || []).slice(0, 8).map(d => `<span style="padding:2px 6px;background:rgba(96,165,250,0.1);border-radius:4px;color:var(--accent-blue);">${d.ip}:${d.port}</span>`).join(' ');
            html += `<tr><td style="font-family:monospace;font-weight:600">${ip}</td><td><strong>${info.unique_destinations}</strong></td><td style="font-size:11px;display:flex;flex-wrap:wrap;gap:4px;">${topDests}</td></tr>`;
        });
        html += `</tbody></table></div>`;
    }

    html += `<div style="margin-top:20px; display:flex; gap:8px;flex-wrap:wrap;">
        <button class="btn btn-accent" onclick="runPredictions('${aid}')">🎯 Run Predictions</button>
        <button class="btn btn-secondary" onclick="loadTopology('${aid}')">🌐 View Topology</button>
        <button class="btn btn-secondary" onclick="downloadReportById('${aid}')">📄 PDF Report</button>
    </div>`;

    el.innerHTML = html;
}

// ─── Predictions & XAI ──────────────────────────────────────────

async function runPredictions(id) {
    // First verify model exists
    try {
        const modelRes = await fetch('/api/models');
        if (!modelRes.ok) throw new Error('Could not check model status');
        const modelData = await modelRes.json();
        if (!modelData.model_exists) {
            showToast('No trained model. Train first via Model panel.', 'warning');
            return;
        }
    } catch (e) {
        showToast('Model check failed: ' + e.message, 'error');
        return;
    }

    showToast('Running predictions (20-30 seconds)...', 'info');
    let timeoutHandle;
    try {
        const controller = new AbortController();
        timeoutHandle = setTimeout(() => controller.abort(), 240000);  // 240 seconds timeout for predictions
        
        const res = await fetch(`/api/predict/${id}`, { signal: controller.signal });
        clearTimeout(timeoutHandle);
        
        if (!res.ok) {
            const errData = await res.json();
            throw new Error(errData.error || `HTTP ${res.status}`);
        }
        
        const data = await res.json();
        if (!data.predictions) {
            showToast('No predictions returned', 'warning');
            return;
        }

        currentAnalysisId = id;
        renderPredictions(data.predictions || []);
        renderXAI(data.explanations || []);
        
        showToast('Predictions complete!', 'success');
        await loadDashboard();
        selectTab('predict');
    } catch (e) { 
        if (timeoutHandle) clearTimeout(timeoutHandle);
        console.error('Prediction error:', e);
        const msg = e.name === 'AbortError' ? 'Request timed out' : e.message;
        showToast(`Prediction failed: ${msg}`, 'error'); 
    }
}

function renderPredictions(preds) {
    const el = document.getElementById('predict-content');

    if (!preds.length) { el.innerHTML = '<p class="placeholder-text">No predictions.</p>'; return; }

    // Summary counts
    const counts = {};
    preds.forEach(p => { counts[p.prediction] = (counts[p.prediction]||0) + 1; });

    let html = `<div style="margin-bottom:16px;">
        <div style="font-size:13px;color:var(--text-secondary);margin-bottom:10px;">
            <strong>${preds.length}</strong> flows analyzed | <strong>${Object.keys(counts).length}</strong> unique behavioral profiles detected
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;">`;
    
    const THREAT_PROFILES = ['malware_c2_beacon', 'data_exfiltration', 'port_scan', 'brute_force', 'ddos_bot', 'cryptominer'];

    for (const [label, count] of Object.entries(counts).sort((a,b) => b[1]-a[1])) {
        const isAlert = THREAT_PROFILES.includes(label);
        const percentage = ((count / preds.length) * 100).toFixed(1);
        html += `<div style="padding:8px 14px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid ${isAlert ? 'var(--accent-red)' : 'var(--accent-blue)'};
            background:${isAlert ? 'rgba(248,113,113,0.1)' : 'rgba(99,102,241,0.1)'};
            color:${isAlert ? 'var(--accent-red)' : 'var(--accent-blue)'};">
            ${isAlert ? '⚠️ ' : ''}${label}: <strong>${count}</strong> (${percentage}%)</div>`;
    }
    html += `</div></div><hr style="border:none;border-top:1px solid var(--border);margin:16px 0;">`;

    preds.forEach((p, i) => {
        const conf = (p.confidence * 100).toFixed(1);
        const isAlert = THREAT_PROFILES.includes(p.prediction);
        const confColor = p.confidence > 0.8 ? 'var(--accent-green)' : p.confidence > 0.5 ? 'var(--accent-orange)' : 'var(--accent-red)';
        const confLabel = p.confidence > 0.8 ? 'High Confidence' : p.confidence > 0.5 ? 'Medium Confidence' : 'Low Confidence';

        html += `<div class="prediction-card ${isAlert ? 'threat' : ''}">
            <div style="display:flex;align-items:center;justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:12px;flex:1;">
                    <span style="font-size:11px;color:var(--text-muted);min-width:40px;text-align:right;">#${i+1}</span>
                    <span class="prediction-label" style="flex:1;">${isAlert ? '⚠️ ' : ''}${p.prediction}</span>
                    ${isAlert ? '<span style="font-size:11px;color:var(--accent-red);font-weight:600;padding:3px 8px;background:rgba(248,113,113,0.2);border-radius:4px;">THREAT</span>' : ''}
                </div>
                <div style="display:flex;align-items:center;gap:10px;min-width:200px;">
                    <div style="flex:1;">
                        <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px;">
                            <span style="font-size:12px;font-weight:600;color:${confColor};">${conf}%</span>
                            <span style="font-size:10px;color:var(--text-muted);">(${confLabel})</span>
                        </div>
                        <div class="confidence-bar"><div class="confidence-fill" style="width:${conf}%;background:${confColor}"></div></div>
                    </div>
                </div>
            </div>
        </div>`;
    });

    el.innerHTML = html;
}

function renderXAI(explanations) {
    const el = document.getElementById('predict-content');
    if (!explanations.length) { el.innerHTML = '<p class="placeholder-text">No explanations.</p>'; return; }

    let html = `<div style="font-size:13px;color:var(--text-secondary);margin-bottom:12px;">
        Feature importance analysis for <strong>${explanations.length}</strong> flows. 
        Each feature's contribution to the behavioral prediction is shown below (higher = more important).
    </div>`;

    const THREAT_PROFILES = ['malware_c2_beacon', 'data_exfiltration', 'port_scan', 'brute_force', 'ddos_bot', 'cryptominer'];

    explanations.slice(0, 10).forEach((exp, i) => {
        const isAlert = THREAT_PROFILES.includes(exp.prediction);
        html += `<div class="xai-sample" style="${isAlert ? 'border-color:var(--accent-red);border-width:2px;' : ''}">
            <div class="xai-title">
                <span style="font-size:13px;color:var(--text-muted);">Sample #${i+1}</span>
                <span style="color:${isAlert ? 'var(--accent-red)' : 'var(--accent-blue)'}; font-weight:600;margin-left:8px;">${exp.prediction}</span>
                <span style="color:var(--text-muted);font-size:12px;margin-left:8px;">(${(exp.confidence*100).toFixed(1)}% confidence)</span>
                ${isAlert ? '<span style="color:var(--accent-red);font-weight:600;font-size:11px;margin-left:auto;">⚠️ THREAT</span>' : ''}
            </div>
            <div style="margin-top:10px;">
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px;">Top Contributing Features</div>`;

        (exp.top_features || []).slice(0, 10).forEach((f, idx) => {
            const importance = Math.min((f.importance || 0) * 100, 100);
            const impColor = importance > 60 ? 'var(--accent-red)' : importance > 40 ? 'var(--accent-orange)' : 'var(--accent-blue)';
            html += `<div class="xai-bar-row">
                <div class="xai-bar-label">${idx+1}. ${f.feature}</div>
                <div class="xai-bar-track"><div class="xai-bar-fill" style="width:${importance}%;background:${impColor};"></div></div>
                <div class="xai-bar-value" style="color:${impColor};">${importance.toFixed(1)}%</div>
            </div>`;
        });

        if (exp.explanation_text) {
            html += `<div style="margin-top:12px;padding:10px;background:var(--bg);border-radius:6px;border-left:3px solid ${isAlert ? 'var(--accent-red)' : 'var(--accent-blue)'};font-size:12px;color:var(--text-secondary);line-height:1.6;">
                <strong>Analysis:</strong> ${exp.explanation_text.replace(/\n/g, '<br>')}
            </div>`;
        }
        html += '</div>';
    });

    el.innerHTML = html;
}

// ─── Topology (D3.js Force Graph) ───────────────────────────────

async function loadTopology(id) {
    if (!id) {
        showToast('No analysis ID selected', 'error');
        return;
    }
    
    showToast('Loading topology...', 'info');
    try {
        const res = await fetch(`/api/topology/${id}`);
        
        if (res.status === 400) {
            const data = await res.json();
            showToast('Run analysis first before viewing topology', 'warning');
            return;
        }
        
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        
        const data = await res.json();
        if (data.error) { 
            showToast(`Topology error: ${data.error}`, 'error'); 
            return; 
        }
        
        if (!data.nodes || data.nodes.length === 0) {
            showToast('No topology data available', 'warning');
            return;
        }
        
        renderTopology(data);
        showToast('Topology loaded', 'success');
    } catch (e) { 
        console.error('Topology error:', e);
        showToast(`Topology error: ${e.message}`, 'error'); 
    }
}

function renderTopology(data) {
    const container = document.getElementById('topology-svg');
    
    if (!container) {
        console.error('Topology container not found');
        return;
    }

    // Clear previous rendering
    container.innerHTML = '';

    if (!data.nodes?.length) {
        container.innerHTML = '<p class="placeholder-text">No topology data.</p>';
        return;
    }

    // Stats row (displayed as title)
    const s = data.stats || {};

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 500;

    const svg = d3.select(container).append('svg')
        .attr('width', width).attr('height', height);

    // Add zoom behavior
    const g = svg.append('g');
    svg.call(d3.zoom().scaleExtent([0.2, 5]).on('zoom', (e) => g.attr('transform', e.transform)));

    // Simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => (d.size || 10) + 5));

    // Links
    const links = g.append('g').selectAll('line')
        .data(data.links).enter().append('line')
        .attr('class', 'link')
        .attr('stroke', d => {
            const protos = d.protocols || [];
            if (protos.includes('TCP')) return 'rgba(96,165,250,0.4)';
            if (protos.includes('UDP')) return 'rgba(52,211,153,0.4)';
            return 'rgba(148,163,184,0.3)';
        })
        .attr('stroke-width', d => d.thickness || 1);

    // Link labels (protocol)
    const linkLabels = g.append('g').selectAll('text')
        .data(data.links).enter().append('text')
        .attr('fill', 'var(--text-muted)').attr('font-size', '8px')
        .attr('text-anchor', 'middle')
        .text(d => (d.protocols || []).join('/'));

    // Nodes
    const nodes = g.append('g').selectAll('g')
        .data(data.nodes).enter().append('g')
        .call(d3.drag()
            .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
            .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
            .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
        );

    nodes.append('circle')
        .attr('class', 'node-circle')
        .attr('r', d => d.size || 10)
        .attr('fill', d => {
            if (d.is_hub) return '#a78bfa';
            if (d.degree > 2) return '#60a5fa';
            return '#22d3ee';
        });

    nodes.append('text')
        .attr('class', 'node-label')
        .attr('dx', d => (d.size || 10) + 4)
        .attr('dy', 4)
        .text(d => d.id);

    // Tooltips via title
    nodes.append('title').text(d =>
        `${d.id}\nDegree: ${d.degree}\nPackets: ${d.total_packets}\nBytes: ${fmtBytes(d.total_bytes)}\nMAC: ${(d.mac || []).join(', ')}`
    );

    simulation.on('tick', () => {
        links
            .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
        linkLabels
            .attr('x', d => (d.source.x + d.target.x) / 2)
            .attr('y', d => (d.source.y + d.target.y) / 2);
        nodes.attr('transform', d => `translate(${d.x},${d.y})`);
    });
}

// ─── PDF Report ─────────────────────────────────────────────────

function downloadReport() { if (currentAnalysisId) downloadReportById(currentAnalysisId); }
function downloadReportById(id) {
    showToast('Generating PDF...', 'info');
    window.open(`/api/report/${id}`, '_blank');
}

// ─── Model Training ─────────────────────────────────────────────

async function trainModelNow() {
    // Fetch system config for feature/profile counts
    let featureCount = 77, profileCount = 8;
    try {
        const summaryRes = await fetch('/api/summary');
        if (summaryRes.ok) {
            const summaryData = await summaryRes.json();
            featureCount = summaryData.total_features || 77;
            profileCount = summaryData.total_profiles || 8;
        }
    } catch (e) { /* use defaults */ }

    showToast(`Training behavioral model (${featureCount} features, ${profileCount} profiles)...`, 'info');
    try {
        const res = await fetch('/api/train', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ n_samples_per_profile: 200 })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        const data = await res.json();
        if (data.error) { showToast(`Training failed: ${data.error}`, 'error'); return; }

        const acc = data.metrics?.train_accuracy ? `${(data.metrics.train_accuracy * 100).toFixed(1)}%` : '?';
        const cv = data.metrics?.cv_mean_accuracy ? `${(data.metrics.cv_mean_accuracy * 100).toFixed(1)}%` : '?';
        showToast(`✅ Model trained! Accuracy: ${acc}, CV: ${cv}`, 'success');
        await loadDashboard();
    } catch (e) { 
        console.error('Training error:', e);
        showToast(`Error: ${e.message}`, 'error'); 
    }
}

// ─── Behavioral Consistency ─────────────────────────────────────

async function loadBehavioralConsistency() {
    const el = document.getElementById('behavioral-content');
    el.innerHTML = '<div class="status-box info">⏳ Analyzing...</div>';

    try {
        const res = await fetch('/api/behavioral-consistency');
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        const data = await res.json();

        let html = `<p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">${data.message}</p>`;

        if (data.feature_categories && data.feature_categories.length) {
            const gridHTML = data.feature_categories.map(cat => 
                `<div class="feat-cat-card"><div class="feat-cat-icon">${cat.icon}</div><h4>${cat.name}</h4><p>${cat.desc}</p><span class="feat-count">${cat.count} features</span></div>`
            ).join('');
            html += `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:12px;">${gridHTML}</div>`;
        }

        html += `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px;">
            <div class="stat-card"><div class="stat-label">Total Features</div><div class="stat-value" style="font-size:18px">${data.total_features}</div></div>
            <div class="stat-card"><div class="stat-label">IP-Dependent</div><div class="stat-value" style="font-size:18px;color:var(--accent-green)">0</div></div>
            <div class="stat-card"><div class="stat-label">Behavior-Based</div><div class="stat-value" style="font-size:18px">${data.behavior_dependent_features}</div></div>
        </div>`;

        const profiles = data.profiles || {};
        if (Object.keys(profiles).length) {
            html += '<h4 style="margin-bottom:8px;">Cross-Session Matches</h4>';
            for (const [label, info] of Object.entries(profiles)) {
                html += `<div class="prediction-card" style="${info.ip_change_resilient ? 'border-color:var(--accent-green)' : ''}">
                    <div><span class="prediction-label">${label}</span>
                        <span style="font-size:12px;color:var(--text-secondary);margin-left:8px">${info.total_matches} matches across ${info.ip_count} IPs</span></div>
                    <div style="font-size:12px;">
                        ${info.ip_change_resilient ?
                            '<span style="color:var(--accent-green);font-weight:600">✅ RESILIENT</span>' :
                            '<span style="color:var(--text-muted)">Single IP</span>'}
                        · Avg: <strong>${info.avg_confidence}%</strong></div>
                </div>`;
            }
        } else {
            html += '<p class="placeholder-text">Analyze multiple captures to see consistency.</p>';
        }

        el.innerHTML = html;
    } catch (e) { el.innerHTML = `<div class="status-box error">❌ ${e.message}</div>`; }
}

function fmtBytes(b) {
    if (!b) return '0 B';
    const u = ['B','KB','MB','GB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return `${b.toFixed(1)} ${u[i]}`;
}

// NOTE: Use showToast() instead - this old function replaced with new version at top of file

// ─── Init ───────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
    // Load dashboard data
    await loadDashboard();
    
    // Load network interfaces for capture
    await loadInterfaces();
    
    // Set up drag-drop for upload
    const dropZone = document.getElementById('upload-drop');
    if (dropZone) {
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.style.opacity = '0.7';
        });
        dropZone.addEventListener('dragleave', () => {
            dropZone.style.opacity = '1';
        });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.style.opacity = '1';
            if (e.dataTransfer.files[0]) {
                uploadPCAP(e.dataTransfer.files[0]);
            }
        });
    }
    
    showToast('✅ BENFET Dashboard Ready!', 'success');
});
