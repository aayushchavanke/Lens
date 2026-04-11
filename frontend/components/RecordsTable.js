"use client";

import { useState, useEffect, useRef, useCallback } from "react";

const API = "http://127.0.0.1:5000";

// ─── Forensic Insights Side Panel ────────────────────────────────────────────

function ForensicPanel({ record, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const panelRef = useRef(null);

  useEffect(() => {
    const fetchInsights = async () => {
      try {
        const res = await fetch(`${API}/api/forensics/${record.id}`);
        const json = await res.json();
        setData(json);
      } catch {
        setData({ error: "Failed to load forensic data." });
      }
      setLoading(false);
    };
    fetchInsights();
  }, [record.id]);

  // Close on outside click
  useEffect(() => {
    const handler = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        onClose();
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [onClose]);

  // Close on Escape
  useEffect(() => {
    const handler = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onClose]);

  const topFeatures = data?.explanations?.[0]?.top_features || [];
  const insights = data?.explanations?.[0]?.insights || [];
  const predictions = data?.predictions || [];
  const maxWeight = topFeatures.length > 0
    ? Math.max(...topFeatures.map(([, v]) => v))
    : 1;

  return (
    <div style={overlayStyle}>
      <div ref={panelRef} style={panelStyle}>
        {/* Header */}
        <div style={panelHeaderStyle}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem" }}>
              <span style={{ fontSize: "0.6875rem", fontFamily: "var(--font-mono)", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                OBSIDIAN LENS
              </span>
              <span style={{ fontSize: "0.6875rem", color: "var(--text-muted)" }}>·</span>
              <span style={{ fontSize: "0.6875rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                {record.id}
              </span>
            </div>
            <h2 style={{ fontSize: "1rem", fontWeight: 600, margin: 0 }}>Forensic Insights</h2>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem", fontFamily: "var(--font-mono)" }}>
              {record.filename}
            </p>
          </div>
          <button onClick={onClose} style={closeButtonStyle} title="Close">✕</button>
        </div>

        {loading ? (
          <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.8125rem" }}>
            <div className="pulse">Loading forensic data...</div>
          </div>
        ) : data?.error ? (
          <div style={{ padding: "1.5rem", color: "var(--black-badge)", fontSize: "0.875rem" }}>
            {data.error}
          </div>
        ) : (
          <div style={{ padding: "1.25rem", overflowY: "auto", flex: 1 }}>

            {/* ── Summary Row ── */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "0.75rem", marginBottom: "1.5rem" }}>
              <MiniStat label="Total Flows" value={data?.total_flows ?? predictions.length} />
              <MiniStat label="Identities" value={data?.identities_created ?? "—"} />
              <MiniStat
                label="Threat Level"
                value={
                  predictions.filter(p => p.is_malicious).length > predictions.length * 0.5
                    ? "HIGH"
                    : predictions.some(p => p.is_malicious)
                    ? "MEDIUM"
                    : "CLEAR"
                }
                accent
              />
            </div>

            {/* ── Most Influential Parameters ── */}
            {topFeatures.length > 0 && (
              <section style={sectionStyle}>
                <SectionTitle icon="⚡" label="Most Influential Parameters" />
                <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                  {topFeatures.slice(0, 10).map(([name, weight], i) => {
                    const pct = ((weight / maxWeight) * 100).toFixed(0);
                    const barColor =
                      i === 0 ? "var(--accent)" :
                      i <= 2 ? "#a78bfa" :
                      i <= 5 ? "#60a5fa" : "var(--text-muted)";
                    return (
                      <div key={name} style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                        <span style={{ fontSize: "0.6875rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", width: "1.2rem", textAlign: "right", flexShrink: 0 }}>
                          {i + 1}
                        </span>
                        <span style={{ fontSize: "0.75rem", fontFamily: "var(--font-mono)", width: "160px", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={name}>
                          {name}
                        </span>
                        <div style={{ flex: 1, height: "6px", background: "var(--border-color)", borderRadius: "3px", overflow: "hidden" }}>
                          <div style={{ width: `${pct}%`, height: "100%", background: barColor, borderRadius: "3px", transition: "width 0.4s ease" }} />
                        </div>
                        <span style={{ fontSize: "0.6875rem", fontFamily: "var(--font-mono)", color: "var(--text-secondary)", width: "3rem", textAlign: "right", flexShrink: 0 }}>
                          {(weight * 100).toFixed(1)}%
                        </span>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            {/* ── XAI Conclusions ── */}
            {insights.length > 0 && (
              <section style={sectionStyle}>
                <SectionTitle icon="🧠" label="XAI Conclusions" />
                <div style={{ display: "flex", flexDirection: "column", gap: "0.625rem" }}>
                  {insights.map((insight, i) => {
                    const featureMatch = insight.match(/^\[([^\]]+)\]/);
                    const featureName = featureMatch ? featureMatch[1] : null;
                    const body = featureName ? insight.slice(featureMatch[0].length).trim() : insight;
                    const weightMatch = body.match(/^\(([^)]+)\):/);
                    const weightLabel = weightMatch ? weightMatch[1] : null;
                    const text = weightMatch ? body.slice(weightMatch[0].length).trim() : body;

                    return (
                      <div key={i} style={insightCardStyle}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.375rem" }}>
                          {featureName && (
                            <span style={{ fontSize: "0.6875rem", fontFamily: "var(--font-mono)", background: "rgba(96,165,250,0.12)", color: "#60a5fa", padding: "2px 7px", borderRadius: "4px", border: "0.5px solid rgba(96,165,250,0.25)" }}>
                              {featureName}
                            </span>
                          )}
                          {weightLabel && (
                            <span style={{ fontSize: "0.6875rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                              {weightLabel}
                            </span>
                          )}
                        </div>
                        <p style={{ fontSize: "0.75rem", lineHeight: 1.6, color: "var(--text-secondary)", margin: 0 }}>
                          {text}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            {/* ── Suggestions ── */}
            {predictions.length > 0 && (
              <section style={sectionStyle}>
                <SectionTitle icon="💡" label="Analysis Suggestions" />
                <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                  {_buildSuggestions(predictions).map((s, i) => (
                    <div key={i} style={{ display: "flex", gap: "0.625rem", alignItems: "flex-start" }}>
                      <span style={{ fontSize: "0.6875rem", marginTop: "3px", flexShrink: 0 }}>{s.icon}</span>
                      <p style={{ fontSize: "0.75rem", lineHeight: 1.6, color: "var(--text-secondary)", margin: 0 }}>{s.text}</p>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* ── Flow Classifications ── */}
            {predictions.length > 0 && (
              <section style={sectionStyle}>
                <SectionTitle icon="🔗" label={`Flow Classifications (${predictions.length})`} />
                <div style={{ overflowX: "auto" }}>
                  <table className="data-table" style={{ fontSize: "0.6875rem" }}>
                    <thead>
                      <tr>
                        <th>Src → Dst</th>
                        <th>Category</th>
                        <th>Threat</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {predictions.slice(0, 20).map((p, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.625rem" }}>
                            {p.src_ip || "?"} → {p.dst_ip || "?"}
                          </td>
                          <td>
                            <span className={`badge ${p.is_malicious ? "badge-black" : "badge-white"}`}>
                              {p.category}
                            </span>
                          </td>
                          <td style={{ color: p.is_malicious ? "var(--black-badge)" : "var(--text-muted)" }}>
                            {p.threat_type}
                          </td>
                          <td style={{ fontFamily: "var(--font-mono)" }}>
                            {(p.confidence * 100).toFixed(1)}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {predictions.length > 20 && (
                    <p style={{ fontSize: "0.6875rem", color: "var(--text-muted)", marginTop: "0.5rem", textAlign: "center" }}>
                      + {predictions.length - 20} more flows — export PDF for full report
                    </p>
                  )}
                </div>
              </section>
            )}

          </div>
        )}

        {/* Panel Footer */}
        <div style={panelFooterStyle}>
          <button
            className="btn btn-sm"
            onClick={() => window.open(`${API}/api/report/${record.id}`, "_blank")}
            style={{ gap: "0.375rem" }}
          >
            <span style={{ fontSize: "0.75rem" }}>⬇</span> Export PDF Report
          </button>
          <button className="btn btn-sm" style={{ color: "var(--text-muted)" }} onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Helper sub-components ────────────────────────────────────────────────────

function MiniStat({ label, value, accent }) {
  return (
    <div style={{ background: "var(--card-bg)", border: "0.5px solid var(--border-color)", borderRadius: "6px", padding: "0.625rem 0.75rem" }}>
      <div style={{ fontSize: "0.625rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "0.25rem" }}>
        {label}
      </div>
      <div style={{ fontSize: "1.125rem", fontWeight: 600, fontFamily: "var(--font-mono)", color: accent ? "var(--accent)" : "var(--text-primary)" }}>
        {value}
      </div>
    </div>
  );
}

function SectionTitle({ icon, label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "0.375rem", marginBottom: "0.875rem" }}>
      <span style={{ fontSize: "0.75rem" }}>{icon}</span>
      <span style={{ fontSize: "0.6875rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--text-secondary)" }}>
        {label}
      </span>
      <div style={{ flex: 1, height: "0.5px", background: "var(--border-color)", marginLeft: "0.375rem" }} />
    </div>
  );
}

function _buildSuggestions(predictions) {
  const malicious = predictions.filter(p => p.is_malicious);
  const threats = [...new Set(malicious.map(p => p.threat_type).filter(Boolean))];
  const suggestions = [];

  if (malicious.length > 0) {
    suggestions.push({ icon: "🔴", text: `${malicious.length} malicious flow${malicious.length > 1 ? "s" : ""} detected. Immediate review of flagged identities is recommended.` });
    if (threats.length) {
      suggestions.push({ icon: "⚠️", text: `Detected threat types: ${threats.join(", ")}. Cross-reference with MITRE ATT&CK framework for attribution.` });
    }
    if (malicious.some(p => p.threat_type?.toLowerCase().includes("ddos"))) {
      suggestions.push({ icon: "🛡️", text: "DDoS pattern identified. Consider rate-limiting upstream and enabling blackhole routing for persistent source IPs." });
    }
    if (malicious.some(p => p.threat_type?.toLowerCase().includes("botnet") || p.threat_type?.toLowerCase().includes("c2") || p.threat_type?.toLowerCase().includes("beacon"))) {
      suggestions.push({ icon: "🔍", text: "C2 beacon/botnet behavior detected. Isolate affected endpoints and conduct memory forensics for persistence mechanisms." });
    }
    suggestions.push({ icon: "📄", text: "Export a full PDF forensic report for court-admissible documentation and chain-of-custody records." });
  } else {
    suggestions.push({ icon: "✅", text: "No malicious flows detected. Traffic patterns are within expected behavioral baselines." });
    suggestions.push({ icon: "📊", text: "Archive this capture as a baseline reference for future anomaly comparison." });
  }

  const vpnFlows = predictions.filter(p => p.is_vpn);
  if (vpnFlows.length > 0) {
    suggestions.push({ icon: "🔐", text: `${vpnFlows.length} VPN-masked flow${vpnFlows.length > 1 ? "s" : ""} identified via behavioral fingerprint. These flows bypassed IP-based detection.` });
  }

  return suggestions;
}

// ─── Three-dot dropdown ───────────────────────────────────────────────────────

function ActionsMenu({ record, onForensics, onExportPDF, onDelete }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  return (
    <div ref={menuRef} style={{ position: "relative", display: "inline-block" }}>
      <button
        className="btn btn-sm"
        style={{ padding: "3px 7px", fontSize: "1rem", letterSpacing: "0.05em", lineHeight: 1, border: "0.5px solid transparent", background: "transparent" }}
        onClick={() => setOpen(v => !v)}
        title="Actions"
      >
        ⋮
      </button>
      {open && (
        <div style={dropdownStyle}>
          <div style={dropdownGroupLabel}>Analysis</div>
          <button
            style={dropdownItemStyle}
            onClick={() => { setOpen(false); onForensics(record); }}
            onMouseEnter={e => e.currentTarget.style.background = "var(--card-bg)"}
            onMouseLeave={e => e.currentTarget.style.background = "transparent"}
          >
            <span style={{ fontSize: "0.75rem" }}>🔬</span>
            <div>
              <div style={{ fontSize: "0.8125rem" }}>Forensic Insights</div>
              <div style={{ fontSize: "0.6875rem", color: "var(--text-muted)" }}>XAI conclusions &amp; suggestions</div>
            </div>
          </button>

          <div style={dropdownDivider} />
          <div style={dropdownGroupLabel}>Export</div>
          <button
            style={dropdownItemStyle}
            onClick={() => { setOpen(false); onExportPDF(record); }}
            onMouseEnter={e => e.currentTarget.style.background = "var(--card-bg)"}
            onMouseLeave={e => e.currentTarget.style.background = "transparent"}
          >
            <span style={{ fontSize: "0.75rem" }}>📄</span>
            <div>
              <div style={{ fontSize: "0.8125rem" }}>Export PDF</div>
              <div style={{ fontSize: "0.6875rem", color: "var(--text-muted)" }}>Professional forensic report</div>
            </div>
          </button>

          <div style={dropdownDivider} />
          <div style={dropdownGroupLabel}>Manage</div>
          <button
            style={{ ...dropdownItemStyle, color: "var(--black-badge)" }}
            onClick={() => { setOpen(false); onDelete(record); }}
            onMouseEnter={e => e.currentTarget.style.background = "var(--card-bg)"}
            onMouseLeave={e => e.currentTarget.style.background = "transparent"}
          >
            <span style={{ fontSize: "0.75rem" }}>🗑</span>
            <div style={{ fontSize: "0.8125rem" }}>Delete Record</div>
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Delete Confirmation Modal ────────────────────────────────────────────────

function DeleteModal({ record, onConfirm, onCancel }) {
  return (
    <div style={{ ...overlayStyle, zIndex: 200 }}>
      <div style={{ background: "var(--bg-primary)", border: "0.5px solid var(--border-color)", borderRadius: "10px", padding: "1.5rem", width: "min(400px, 94vw)" }}>
        <h3 style={{ fontSize: "0.9375rem", fontWeight: 600, marginBottom: "0.5rem" }}>Delete record?</h3>
        <p style={{ fontSize: "0.8125rem", color: "var(--text-muted)", lineHeight: 1.6, marginBottom: "1.25rem" }}>
          This will permanently remove <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>{record.filename}</span> and all associated analysis data. This action cannot be undone.
        </p>
        <div style={{ display: "flex", gap: "0.625rem", justifyContent: "flex-end" }}>
          <button className="btn btn-sm" onClick={onCancel}>Cancel</button>
          <button className="btn btn-sm btn-danger" onClick={onConfirm}>Delete</button>
        </div>
      </div>
    </div>
  );
}

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ message, visible }) {
  return (
    <div style={{
      position: "fixed", bottom: "1.5rem", left: "50%", transform: `translateX(-50%) translateY(${visible ? "0" : "80px"})`,
      background: "var(--text-primary)", color: "var(--bg-primary)", padding: "0.625rem 1.25rem",
      borderRadius: "8px", fontSize: "0.8125rem", zIndex: 9999,
      transition: "transform 0.3s ease", whiteSpace: "nowrap", pointerEvents: "none",
    }}>
      {message}
    </div>
  );
}

// ─── Main Records Table Component ────────────────────────────────────────────

export default function RecordsTable({ records = [], onRefresh }) {
  const [selected, setSelected] = useState(new Set());
  const [forensicsRecord, setForensicsRecord] = useState(null);
  const [deleteRecord, setDeleteRecord] = useState(null);
  const [toast, setToast] = useState({ message: "", visible: false });
  const toastTimer = useRef(null);

  const showToast = useCallback((message) => {
    clearTimeout(toastTimer.current);
    setToast({ message, visible: true });
    toastTimer.current = setTimeout(() => setToast(t => ({ ...t, visible: false })), 2800);
  }, []);

  const allSelected = records.length > 0 && selected.size === records.length;
  const someSelected = selected.size > 0;

  const toggleAll = (e) => {
    setSelected(e.target.checked ? new Set(records.map(r => r.id)) : new Set());
  };

  const toggleRow = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const handleExportPDF = (record) => {
    showToast("Generating PDF report...");
    window.open(`${API}/api/report/${record.id}`, "_blank");
  };

  const handleDelete = (record) => setDeleteRecord(record);

  const confirmDelete = async () => {
    const id = deleteRecord.id;
    setDeleteRecord(null);
    try {
      await fetch(`${API}/api/analysis/${id}`, { method: "DELETE" });
      setSelected(prev => { const n = new Set(prev); n.delete(id); return n; });
      showToast("Record deleted.");
      if (onRefresh) onRefresh();
    } catch {
      showToast("Failed to delete record.");
    }
  };

  const downloadCumulativeReport = async () => {
    const ids = [...selected].join(",");
    showToast("Building cumulative PDF...");
    window.open(`${API}/api/report/batch?ids=${ids}&format=pdf`, "_blank");
  };

  const downloadZippedPDFs = async () => {
    const ids = [...selected].join(",");
    showToast(`Packaging ${selected.size} PDF reports into ZIP...`);
    window.open(`${API}/api/report/batch?ids=${ids}&format=zip`, "_blank");
  };

  const bulkDelete = async () => {
    if (!window.confirm(`Delete ${selected.size} record(s)? This cannot be undone.`)) return;
    for (const id of selected) {
      await fetch(`${API}/api/analysis/${id}`, { method: "DELETE" }).catch(() => {});
    }
    setSelected(new Set());
    showToast(`${selected.size} records deleted.`);
    if (onRefresh) onRefresh();
  };

  const statusBadge = (status) => {
    const map = {
      analyzed: "badge-white",
      failed:   "badge-black",
      uploaded: "badge-blocked",
    };
    return map[status] || "badge-blocked";
  };

  return (
    <>
      <div className="card" style={{ overflow: "hidden", padding: 0 }}>
        {/* Card header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "1rem 1.25rem 0.875rem", borderBottom: "0.5px solid var(--border-color)" }}>
          <h3 style={{ fontSize: "0.875rem", fontWeight: 600, margin: 0 }}>
            <span className="badge badge-white" style={{ marginRight: "0.5rem" }}>{records.length}</span>
            Recent Captures
          </h3>
          {someSelected && (
            <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", alignSelf: "center" }}>
                {selected.size} selected
              </span>
              <button className="btn btn-sm" onClick={downloadCumulativeReport}>
                ⬇ Cumulative Report
              </button>
              <button
                className="btn btn-sm"
                style={{ color: "var(--accent)", borderColor: "var(--accent)" }}
                onClick={downloadZippedPDFs}
              >
                🗜 Zipped PDFs
              </button>
              <button className="btn btn-sm btn-danger" onClick={bulkDelete}>
                🗑 Delete Selected
              </button>
            </div>
          )}
        </div>

        {records.length === 0 ? (
          <div style={{ padding: "2rem", color: "var(--text-muted)", fontSize: "0.8125rem", textAlign: "center" }}>
            No captures yet. Upload a PCAP or start live capture.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: "2rem" }}>
                    <input type="checkbox" checked={allSelected} onChange={toggleAll} />
                  </th>
                  <th>Filename</th>
                  <th>Source</th>
                  <th>Uploaded</th>
                  <th>Status</th>
                  <th style={{ textAlign: "center" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {records.map((record) => (
                  <tr
                    key={record.id}
                    style={{ background: selected.has(record.id) ? "rgba(96,165,250,0.05)" : undefined }}
                  >
                    <td>
                      <input
                        type="checkbox"
                        checked={selected.has(record.id)}
                        onChange={() => toggleRow(record.id)}
                      />
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8125rem", fontWeight: 600 }}>
                        {record.filename}
                      </span>
                    </td>
                    <td style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      {record.source === "live_capture" ? "🔴 Live Capture" : "📁 Upload"}
                    </td>
                    <td style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      {record.uploaded_at
                        ? new Date(record.uploaded_at).toLocaleString()
                        : "—"}
                    </td>
                    <td>
                      <span className={`badge ${statusBadge(record.status)}`}>
                        {record.status}
                      </span>
                    </td>
                    <td style={{ textAlign: "center" }}>
                      <ActionsMenu
                        record={record}
                        onForensics={setForensicsRecord}
                        onExportPDF={handleExportPDF}
                        onDelete={handleDelete}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Forensic Insights Panel */}
      {forensicsRecord && (
        <ForensicPanel
          record={forensicsRecord}
          onClose={() => setForensicsRecord(null)}
        />
      )}

      {/* Delete Confirmation */}
      {deleteRecord && (
        <DeleteModal
          record={deleteRecord}
          onConfirm={confirmDelete}
          onCancel={() => setDeleteRecord(null)}
        />
      )}

      <Toast message={toast.message} visible={toast.visible} />
    </>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const overlayStyle = {
  position: "fixed", inset: 0,
  background: "rgba(0,0,0,0.55)",
  zIndex: 100,
  display: "flex", alignItems: "center", justifyContent: "center",
};

const panelStyle = {
  background: "var(--bg-primary)",
  border: "0.5px solid var(--border-color)",
  borderRadius: "12px",
  width: "min(700px, 96vw)",
  maxHeight: "90vh",
  display: "flex",
  flexDirection: "column",
  overflow: "hidden",
};

const panelHeaderStyle = {
  display: "flex", justifyContent: "space-between", alignItems: "flex-start",
  padding: "1.25rem 1.5rem 1rem",
  borderBottom: "0.5px solid var(--border-color)",
  flexShrink: 0,
};

const panelFooterStyle = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "0.875rem 1.5rem",
  borderTop: "0.5px solid var(--border-color)",
  flexShrink: 0,
  gap: "0.625rem",
};

const closeButtonStyle = {
  width: "28px", height: "28px",
  display: "flex", alignItems: "center", justifyContent: "center",
  border: "0.5px solid var(--border-color)",
  borderRadius: "6px",
  background: "transparent",
  color: "var(--text-muted)",
  cursor: "pointer",
  fontSize: "0.75rem",
  flexShrink: 0,
};

const sectionStyle = {
  marginBottom: "1.5rem",
};

const insightCardStyle = {
  background: "var(--card-bg)",
  border: "0.5px solid var(--border-color)",
  borderRadius: "6px",
  padding: "0.75rem 0.875rem",
};

const dropdownStyle = {
  position: "absolute", right: 0, top: "calc(100% + 4px)",
  background: "var(--bg-primary)",
  border: "0.5px solid var(--border-color)",
  borderRadius: "10px",
  minWidth: "210px",
  zIndex: 50,
  boxShadow: "0 8px 24px rgba(0,0,0,0.25)",
  overflow: "hidden",
};

const dropdownGroupLabel = {
  padding: "6px 12px 3px",
  fontSize: "0.625rem",
  fontWeight: 600,
  color: "var(--text-muted)",
  textTransform: "uppercase",
  letterSpacing: "0.07em",
};

const dropdownItemStyle = {
  display: "flex", alignItems: "flex-start", gap: "0.625rem",
  padding: "0.5rem 0.75rem",
  cursor: "pointer",
  background: "transparent",
  border: "none",
  width: "100%",
  textAlign: "left",
  color: "var(--text-primary)",
  transition: "background 0.1s",
};

const dropdownDivider = {
  height: "0.5px",
  background: "var(--border-color)",
  margin: "4px 0",
};
