"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import toast, { Toaster } from "react-hot-toast";
import styles from "./page.module.css";
import HealthScore from "../components/HealthScore";
import IdentityTable from "../components/IdentityTable";
import UploadZone from "../components/UploadZone";
import RecordsTable from "../components/RecordsTable";

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

  // ─── Modals & Kebab Menu handled by RecordsTable ───

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
            {modelInfo.class_labels?.length || "?"} profiles • {modelInfo.n_samples || "?"} dataset size • {((modelInfo.cv_accuracy || 0) * 100).toFixed(1)}% accuracy
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

      {/* ─── Recent Analyses (External RecordsTable) ───────── */}
      <div style={{ marginBottom: "1.25rem" }}>
        <RecordsTable records={recentAnalyses} onRefresh={refreshData} />
      </div>

      {/* ─── Identity Tables ──────────────────────────────── */}
      <div className={styles.tablesSection}>
        <IdentityTable identities={blackUsers} type="black" onAction={refreshData} />
        <IdentityTable identities={whiteUsers} type="white" onAction={refreshData} />
      </div>
    </div>
  );
}
