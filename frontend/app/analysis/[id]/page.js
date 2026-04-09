"use client";

import { useState, useEffect } from "react";
import Link from "next/link";

const API = "http://localhost:5000";

export default function AnalysisPage({ params }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!params?.id) return;

    const runAnalysis = async () => {
      try {
        setLoading(true);
        const analyzeRes = await fetch(`${API}/api/analyze/${params.id}`);
        const analyzeData = await analyzeRes.json();

        if (analyzeData.error) {
          setError(analyzeData.error);
        } else {
          setData(analyzeData);
        }
      } catch (e) {
        setError(e.message);
      }
      setLoading(false);
    };

    runAnalysis();
  }, [params?.id]);

  if (loading) {
    return (
      <div style={containerStyle}>
        <div className="pulse" style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
          Analyzing with 78 parameters...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={containerStyle}>
        <Link href="/" style={backLink}>← Back to Dashboard</Link>
        <div className="card" style={{ marginTop: "1rem", color: "var(--black-badge)" }}>
          Error: {error}
        </div>
      </div>
    );
  }

  return (
    <div style={containerStyle}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <Link href="/" style={backLink}>← Back to Dashboard</Link>
        <h2 style={{ fontSize: "1rem", fontFamily: "var(--font-mono)" }}>
          Analysis {params.id}
        </h2>
      </div>

      {/* Metadata Card */}
      <div className="card" style={{ marginBottom: "1rem" }}>
        <h3 style={{ fontSize: "0.875rem", marginBottom: "0.75rem" }}>Capture Metadata</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1rem" }}>
          <StatBox label="Total Packets" value={data?.metadata?.total_packets || 0} />
          <StatBox label="Total Flows" value={data?.total_flows || 0} />
          <StatBox label="Identities Created" value={data?.identities_created || 0} />
          <StatBox label="Status" value={data?.status || "unknown"} accent />
        </div>
      </div>

      {/* Predictions */}
      {data?.predictions?.length > 0 && (
        <div className="card">
          <h3 style={{ fontSize: "0.875rem", marginBottom: "0.75rem" }}>Flow Classifications</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>Flow</th>
                <th>Category</th>
                <th>Threat Type</th>
                <th>Confidence</th>
                <th>VPN</th>
              </tr>
            </thead>
            <tbody>
              {data.predictions.map((pred, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
                    {pred.src_ip || "?"} → {pred.dst_ip || "?"}
                  </td>
                  <td>
                    <span className={`badge ${pred.is_malicious ? "badge-black" : "badge-white"}`}>
                      {pred.category}
                    </span>
                  </td>
                  <td style={{ color: pred.is_malicious ? "var(--black-badge)" : "var(--text-secondary)" }}>
                    {pred.threat_type}
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)" }}>
                    {(pred.confidence * 100).toFixed(1)}%
                  </td>
                  <td>
                    {pred.is_vpn ? (
                      <span className="badge badge-blocked">VPN</span>
                    ) : (
                      <span style={{ color: "var(--text-muted)" }}>—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StatBox({ label, value, accent }) {
  return (
    <div>
      <div style={{ fontSize: "0.6875rem", color: "var(--text-muted)", marginBottom: 2, textTransform: "uppercase", letterSpacing: "0.04em" }}>
        {label}
      </div>
      <div style={{
        fontSize: "1.25rem", fontWeight: 600,
        fontFamily: "var(--font-mono)",
        color: accent ? "var(--accent)" : "var(--text-primary)"
      }}>
        {value}
      </div>
    </div>
  );
}

const containerStyle = {
  minHeight: "100vh",
  padding: "1.5rem 2rem",
  maxWidth: "1400px",
  margin: "0 auto",
};

const backLink = {
  color: "var(--text-secondary)",
  textDecoration: "none",
  fontSize: "0.8125rem",
};
