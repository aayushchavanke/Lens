"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import toast, { Toaster } from "react-hot-toast";
import styles from "./page.module.css";
import HealthScore from "../components/HealthScore";
import IdentityTable from "../components/IdentityTable";
import UploadZone from "../components/UploadZone";

const API = "http://127.0.0.1:5000";

export default function Dashboard() {
  const router = useRouter();
  const [health, setHealth] = useState({ health_score: 100, white_count: 0, black_count: 0, blocked_count: 0, active_threats: 0, total_identities: 0 });
  const [whiteUsers, setWhiteUsers] = useState([]);
  const [blackUsers, setBlackUsers] = useState([]);
  const [modelExists, setModelExists] = useState(false);
  const [modelInfo, setModelInfo] = useState(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [captureStats, setCaptureStats] = useState({ packets: 0, elapsed: 0 });
  const [training, setTraining] = useState(false);
  const [lastAnalysisId, setLastAnalysisId] = useState(null);
  const [recentAnalyses, setRecentAnalyses] = useState([]);

  const refreshData = useCallback(async () => {
    try {
      const [summaryRes, identitiesRes] = await Promise.all([
        fetch(`${API}/api/summary`),
        fetch(`${API}/api/identities`),
      ]);
      const summaryData = await summaryRes.json();
      const identitiesData = await identitiesRes.json();

      setHealth(summaryData.health || { health_score: 100 });
      setModelExists(summaryData.model_exists || false);
      setModelInfo(summaryData.model);
      setWhiteUsers(identitiesData.white_users || []);
      setBlackUsers(identitiesData.black_users || []);
      setRecentAnalyses(summaryData.recent_analyses || []);
    } catch (e) {
      console.log("Backend not available yet");
    }
  }, []);

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 5000);
    return () => clearInterval(interval);
  }, [refreshData]);

  // ─── Live Capture ─────────────────────────────────────────

  const startCapture = async () => {
    try {
      setIsCapturing(true);
      toast.success("Live capture started.");
      await fetch(`${API}/api/capture/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ duration: 15, packet_count: 500 }),
      });
      pollCapture();
    } catch (e) {
      console.error(e);
      setIsCapturing(false);
      toast.error("Failed to start live capture.");
    }
  };

  const pollCapture = () => {
    if (window.captureInterval) clearInterval(window.captureInterval);
    window.captureInterval = setInterval(async () => {
      try {
        const res = await fetch(`${API}/api/capture/status`);
        const data = await res.json();
        setCaptureStats({ packets: data.packets_captured || 0, elapsed: Math.round(data.elapsed_seconds || 0) });
        if (!data.is_capturing) {
          clearInterval(window.captureInterval);
          window.captureInterval = null;
          await stopAndAnalyze();
        }
      } catch {
        clearInterval(window.captureInterval);
        window.captureInterval = null;
        setIsCapturing(false);
      }
    }, 1000);
  };

  const stopAndAnalyze = async () => {
    if (window.captureInterval) {
      clearInterval(window.captureInterval);
      window.captureInterval = null;
    }
    
    try {
      const res = await fetch(`${API}/api/capture/stop`, { method: "POST" });
      const data = await res.json();
      setIsCapturing(false);
      
      if (data.analysis_id) {
        toast.success(`Live capture completed: ${data.packets_captured || 0} packets analyzed.`);
        setLastAnalysisId(data.analysis_id);
        await fetch(`${API}/api/analyze/${data.analysis_id}`);
        refreshData();
      }
    } catch {
      setIsCapturing(false);
      toast.error("Failed to stop and analyze the live capture.");
    }
  };

  // ─── Modals & Kebab Menu ────────────────────────────────
  
  const [openMenuId, setOpenMenuId] = useState(null);
  const [analysisModal, setAnalysisModal] = useState({ isOpen: false, data: null, features: [] });
  const [selectedAnalyses, setSelectedAnalyses] = useState([]);

  const toggleSelectAll = (e) => {
    if (e.target.checked) {
      setSelectedAnalyses(recentAnalyses.slice(0, 5).map(a => a.id));
    } else {
      setSelectedAnalyses([]);
    }
  };

  const toggleSelectAnalysis = (id) => {
    if (selectedAnalyses.includes(id)) {
      setSelectedAnalyses(selectedAnalyses.filter(x => x !== id));
    } else {
      setSelectedAnalyses([...selectedAnalyses, id]);
    }
  };

  const deleteSelected = async () => {
    if (confirm(`Are you sure you want to permanently delete ${selectedAnalyses.length} selected analyses?`)) {
      const toastId = toast.loading(`Deleting ${selectedAnalyses.length} records...`);
      try {
        await Promise.all(selectedAnalyses.map(id => fetch(`${API}/api/analysis/${id}`, { method: "DELETE" })));
        toast.success(`Deleted ${selectedAnalyses.length} records.`, { id: toastId });
        setSelectedAnalyses([]);
        refreshData();
      } catch(e) {
        toast.error(`Failed to delete selected records.`, { id: toastId });
      }
    }
  };

  const analyzeGroup = () => {
    if (selectedAnalyses.length > 0) {
      openDeepAnalysis(selectedAnalyses[0]); // Visualizes the first item's footprint
    }
  };

  const generateBatchReport = (format) => {
    if (selectedAnalyses.length === 0) return;
    window.location.href = `${API}/api/report/batch?ids=${selectedAnalyses.join(',')}&format=${format}`;
  };



  const openDeepAnalysis = async (analysisId) => {
    try {
      const res = await fetch(`${API}/api/analysis/${analysisId}`);
      if (res.ok) {
        const data = await res.json();
        let features = [];
        if (data.explanations && data.explanations.length > 0) {
          features = data.explanations[0].top_features || [];
        }
        setAnalysisModal({ isOpen: true, data: data, features: features });
      }
    } catch (e) {
      console.error("Analysis not found", e);
    }
  };

  const deleteRecord = async (analysisId) => {
    if (confirm("Are you sure you want to completely delete this analysis record?")) {
      try {
        await fetch(`${API}/api/analysis/${analysisId}`, { method: "DELETE" });
        toast.success("Analysis record deleted successfully.");
        refreshData();
      } catch (e) {
        toast.error("Failed to delete record.");
      }
    }
  };

  const downloadReport = (analysisId) => {
    window.location.href = `${API}/api/report/${analysisId}`;
  };



  return (
    <div className={styles.dashboard}>
      <Toaster position="bottom-right" toastOptions={{
        style: { background: 'var(--bg-card)', color: 'var(--text)', border: '1px solid var(--border)' }
      }}/>
      {/* ─── Top Bar ──────────────────────────────────────── */}
      <div className={styles.topBar}>
        <div>
          <div className={styles.brand}>THE OBSIDIAN LENS</div>
          <div className={styles.brandSub}>Network Forensic Tool • 49-Param Behavioral Analysis</div>
        </div>
        <div className={styles.actions}>
          <button className="btn btn-accent" style={{background: 'var(--bg-card)', color: 'var(--text-primary)', border: '1px solid var(--border)'}} onClick={refreshData}>
            Sync Dashboard
          </button>
        </div>
      </div>

      {/* ─── Model Status Bar ─────────────────────────────── */}
      <div className={styles.modelBar}>
        <div className={styles.modelStatus}>
          <div className={`${styles.modelDot} ${modelExists ? styles.modelDotActive : styles.modelDotInactive}`} />
          <span style={{ color: modelExists ? "var(--white-badge)" : "var(--text-muted)" }}>
            {modelExists ? "Weighted Random Forest Classifier Active (Learning enabled)" : "Network Service Starting..."}
          </span>
        </div>
        {modelInfo && (
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
            {modelInfo.n_classes || "?"} profiles • {modelInfo.n_samples || "?"} dataset size • {((modelInfo.cv_mean_accuracy || 0) * 100).toFixed(1)}% accuracy
          </span>
        )}
      </div>

      {/* ─── Health + Ingestion ────────────────────────────── */}
      <div className={styles.topRow}>
        <div className={`card ${styles.healthCard}`}>
          <HealthScore
            score={health.health_score}
            whiteCount={health.white_count}
            blackCount={health.black_count}
            blockedCount={health.blocked_count}
            activeThreats={health.active_threats}
            totalIdentities={health.total_identities}
          />
        </div>

        <div className={`card ${styles.ingestionCard}`}>
          <h3>Ingestion</h3>
          <div className={styles.captureRow}>
            {isCapturing ? (
              <button className="btn btn-danger" onClick={stopAndAnalyze}>
                Stop Capture
              </button>
            ) : (
              <button className="btn btn-accent" onClick={startCapture}>
                Live Capture
              </button>
            )}
            {isCapturing && (
              <span className={styles.captureInfo}>
                {captureStats.packets} pkts • {captureStats.elapsed}s
              </span>
            )}
          </div>
          <UploadZone onUploaded={(data) => { setLastAnalysisId(data?.analysis_id); refreshData(); }} />
        </div>
      </div>

      {/* ─── Recent Analyses + PDF Download + Learn ──────────── */}
      {recentAnalyses.length > 0 && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem", minHeight: "40px" }}>
            <h3 style={{ fontSize: "0.875rem", fontWeight: 600 }}>Recent Analyses</h3>
            {selectedAnalyses.length > 0 && (
               <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", padding: "0.4rem", borderRadius: "8px", border: "1px solid var(--accent-dim)" }}>
                   <span style={{fontSize: "0.75rem", fontWeight: 600, color: "var(--accent)", paddingLeft: "0.5rem", paddingRight: "0.5rem"}}>{selectedAnalyses.length} Selected</span>
                   
                   <div style={{width: "1px", height: "16px", background:"var(--border)", margin: "0 0.2rem"}}></div>
                   
                   <button className="btn btn-sm" style={{background:"transparent", border:"1px solid var(--border)", padding:"0.4rem 0.75rem", fontWeight: 500}} onClick={analyzeGroup}>
                     Forensic Analysis 
                   </button>
                   
                   <button className="btn btn-sm" style={{background:"var(--bg-card)", border:"1px solid var(--border)", padding:"0.4rem 0.75rem", fontWeight: 500}} onClick={() => generateBatchReport('pdf')}>
                     Merged PDF
                   </button>
                   
                   <div style={{width: "1px", height: "16px", background:"var(--border)", margin: "0 0.2rem"}}></div>

                   <button className="btn btn-danger btn-sm" style={{padding:"0.4rem 0.75rem", fontWeight: 500}} onClick={deleteSelected}>
                     Delete Group
                   </button>
               </div>
            )}
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: "30px", textAlign: "center" }}>
                  <input type="checkbox" onChange={toggleSelectAll} checked={selectedAnalyses.length > 0 && selectedAnalyses.length === recentAnalyses.slice(0, 5).length} />
                </th>
                <th>ID</th>
                <th>Source</th>
                <th>Filename</th>
                <th>Status</th>
                <th>Time</th>
                <th style={{textAlign: 'right'}}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {recentAnalyses.slice(0, 5).map((a) => (
                <tr key={a.id} style={{ background: selectedAnalyses.includes(a.id) ? "var(--bg-highlight)" : "transparent" }}>
                  <td style={{ textAlign: "center" }}>
                    <input type="checkbox" checked={selectedAnalyses.includes(a.id)} onChange={() => toggleSelectAnalysis(a.id)} />
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{a.id}</td>
                  <td>
                    <span className="badge" style={{
                      background: a.source === "live_capture" ? "var(--accent-dim, rgba(99,102,241,0.15))" : "var(--border)",
                      color: a.source === "live_capture" ? "var(--accent)" : "var(--text-secondary)"
                    }}>
                      {a.source === "live_capture" ? "Live" : "PCAP"}
                    </span>
                  </td>
                  <td style={{ fontSize: "0.75rem" }}>{a.filename}</td>
                  <td>
                    <span className={`badge ${a.status === "analyzed" ? "badge-white" : ""}`}>
                      {a.status}
                    </span>
                  </td>
                  <td style={{ fontSize: "0.7rem" }}>{a.uploaded_at ? new Date(a.uploaded_at).toLocaleString() : "—"}</td>
                  <td style={{textAlign: 'right'}}>
                    {a.status === "analyzed" && (
                      <div className={styles.kebabContainer}>
                        <button className={styles.kebabButton} onClick={() => setOpenMenuId(openMenuId === a.id ? null : a.id)}>
                          ⋮
                        </button>
                        {openMenuId === a.id && (
                          <div className={styles.kebabMenu}>
                            <button className={styles.kebabItem} onClick={() => { setOpenMenuId(null); openDeepAnalysis(a.id); }}>
                              Deep Forensic Analysis
                            </button>
                            <button className={styles.kebabItem} onClick={() => { setOpenMenuId(null); downloadReport(a.id); }}>
                              Export PDF Report
                            </button>
                            <button className={`${styles.kebabItem} ${styles.kebabItemDanger}`} style={{color: "var(--error)"}} onClick={() => { setOpenMenuId(null); deleteRecord(a.id); }}>
                              Delete Record
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ─── Identity Tables ──────────────────────────────── */}
      <div className={styles.tablesSection}>
        <IdentityTable identities={blackUsers} type="black" onAction={refreshData} />
        <IdentityTable identities={whiteUsers} type="white" onAction={refreshData} />
      </div>

      {/* ─── Deep Forensic Analysis Modal ──────────────────── */}
      {analysisModal.isOpen && analysisModal.data && (
        <div className={styles.modalOverlay}>
          <div className={styles.modalContent} style={{ maxWidth: "1000px" }}>
            <button className={styles.modalClose} onClick={() => setAnalysisModal({ isOpen: false, data: null, features: [] })}>&times;</button>
            <h2 style={{ marginBottom: "0.5rem" }}>Deep Forensic Analysis</h2>
            <p style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginBottom: "1.5rem", fontFamily: "var(--font-mono)" }}>
              Analysis Hash: {analysisModal.data.id} • Processed: {new Date(analysisModal.data.uploaded_at).toLocaleString()}
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1.5rem" }}>
              <div style={{ background: "var(--background)", padding: "1rem", borderRadius: "var(--radius)", border: "1px solid var(--border)" }}>
                <h3 style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "0.5rem" }}>Detected Target</h3>
                <div style={{ fontSize: "1.5rem", fontWeight: 700, color: analysisModal.data.predictions?.[0]?.is_malicious ? "var(--error)" : "var(--success)" }}>
                  {analysisModal.data.predictions?.[0]?.prediction?.toUpperCase() || "UNKNOWN CAPTURE"}
                </div>
                <div style={{ fontSize: "0.875rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
                  Confidence Vector: {analysisModal.data.predictions?.[0]?.confidence ? (analysisModal.data.predictions[0].confidence * 100).toFixed(1) : "0.0"}%
                </div>
              </div>

              <div style={{ background: "var(--background)", padding: "1rem", borderRadius: "var(--radius)", border: "1px solid var(--border)" }}>
                <h3 style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "0.5rem" }}>Network Flow Topology</h3>
                <div style={{ fontSize: "0.875rem", fontFamily: "var(--font-mono)", display: "flex", flexDirection: "column", gap: "0.25rem" }}>
                  <span><strong style={{color:"var(--text-primary)"}}>Packets:</strong> {analysisModal.data.metadata?.total_packets || 0}</span>
                  <span><strong style={{color:"var(--text-primary)"}}>Active Flows:</strong> {analysisModal.data.metadata?.total_flows || 0}</span>
                  <span><strong style={{color:"var(--text-primary)"}}>TLS Extracted:</strong> {analysisModal.data.metadata?.tls_flows_detected || 0}</span>
                </div>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
              <div>
                <h3 style={{ fontSize: "0.875rem", fontWeight: 600, marginBottom: "0.75rem" }}>Explainable AI (XAI) Matrix</h3>
                <div style={{ maxHeight: "280px", overflowY: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                  <table className="data-table" style={{ fontSize: "0.75rem", margin: 0, border: "none" }}>
                    <thead style={{ position: "sticky", top: 0, zIndex: 1, background: "var(--bg-card)" }}>
                      <tr>
                        <th>Structural Feature</th>
                        <th>Observed Value</th>
                        <th>Attribution Weight</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analysisModal.features.length > 0 ? (
                        analysisModal.features.map((feat, idx) => {
                          const value = analysisModal.data.features?.[0]?.[feat[0]];
                          return (
                            <tr key={idx}>
                              <td style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>{feat[0]}</td>
                              <td style={{ fontFamily: "var(--font-mono)" }}>{typeof value === 'number' ? (value % 1 === 0 ? value : value.toFixed(2)) : (value || "N/A")}</td>
                              <td>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                  <div style={{ 
                                    width: `${Math.min(100, feat[1] * 200)}%`, 
                                    height: '6px', 
                                    background: 'var(--accent)', 
                                    borderRadius: '3px' 
                                  }} />
                                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>{(feat[1] * 100).toFixed(1)}%</span>
                                </div>
                              </td>
                            </tr>
                          );
                        })
                      ) : (
                        <tr>
                          <td colSpan="3" style={{ textAlign: "center", color: "var(--text-muted)" }}>Running Deep Analysis... No features assigned.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div>
                <h3 style={{ fontSize: "0.875rem", fontWeight: 600, marginBottom: "0.75rem" }}>AI Diagnostic Insights</h3>
                <div style={{ background: "var(--background)", padding: "1rem", borderRadius: "var(--radius)", border: "1px solid var(--border)", height: "280px", overflowY: "auto" }}>
                  {analysisModal.data.explanations?.[0]?.insights?.length > 0 ? (
                    <ul style={{ paddingLeft: "1.25rem", fontSize: "0.8125rem", color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: "1rem", margin: 0 }}>
                      {analysisModal.data.explanations[0].insights.map((insight, idx) => (
                        <li key={idx} style={{ lineHeight: 1.6 }}>
                           <strong style={{color:"var(--text-primary)"}}>{insight.split(':')[0]}:</strong>
                           {insight.split(':').slice(1).join(':')}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", fontStyle: "italic", textAlign: "center", marginTop: "2rem" }}>
                      Waiting for Explainable AI heuristic extraction pipeline to complete...
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
