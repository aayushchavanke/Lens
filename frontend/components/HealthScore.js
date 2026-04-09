"use client";

export default function HealthScore({ score = 100, whiteCount = 0, blackCount = 0, blockedCount = 0, activeThreats = 0, totalIdentities = 0 }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const getColor = () => {
    if (score >= 80) return "var(--white-badge)";
    if (score >= 50) return "var(--blocked-badge)";
    return "var(--black-badge)";
  };

  const getLabel = () => {
    if (score >= 90) return "Secure";
    if (score >= 70) return "Caution";
    if (score >= 40) return "At Risk";
    return "Critical";
  };

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "2rem", width: "100%" }}>
      {/* Circular gauge */}
      <div style={{ position: "relative", width: 128, height: 128, flexShrink: 0 }}>
        <svg width="128" height="128" viewBox="0 0 128 128">
          <circle cx="64" cy="64" r={radius} fill="none" stroke="var(--border)" strokeWidth="8" />
          <circle
            cx="64" cy="64" r={radius} fill="none"
            stroke={getColor()}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform="rotate(-90 64 64)"
            style={{ transition: "stroke-dashoffset 0.8s ease, stroke 0.4s ease" }}
          />
        </svg>
        <div style={{
          position: "absolute", inset: 0,
          display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center"
        }}>
          <span style={{ fontSize: "1.75rem", fontWeight: 700, color: getColor() }}>{score}</span>
          <span style={{ fontSize: "0.5625rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>{getLabel()}</span>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "0.75rem 1.25rem", flex: 1 }}>
        <Stat label="Total Tracked" value={totalIdentities} color="var(--accent)" />
        <Stat label="White Users" value={whiteCount} color="var(--white-badge)" />
        <Stat label="Black Users" value={blackCount} color="var(--black-badge)" />
        <Stat label="Blocked" value={blockedCount} color="var(--blocked-badge)" />
        <Stat label="Active Threats" value={activeThreats} color={activeThreats > 0 ? "var(--black-badge)" : "var(--white-badge)"} />
        <Stat label="Threat Ratio" value={totalIdentities > 0 ? `${Math.round((blackCount / totalIdentities) * 100)}%` : "0%"} color="var(--text-secondary)" />
      </div>
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div>
      <div style={{ fontSize: "0.625rem", color: "var(--text-muted)", marginBottom: 2, textTransform: "uppercase", letterSpacing: "0.04em" }}>{label}</div>
      <div style={{ fontSize: "1.125rem", fontWeight: 600, color, fontFamily: "var(--font-mono)" }}>{value}</div>
    </div>
  );
}
