"use client";

const API = "http://127.0.0.1:5000";

export default function IdentityTable({ identities = [], type = "white", onAction }) {
  const isBlack = type === "black";
  const title = isBlack ? "Black Entities (Malicious)" : "White Entities (Normal)";
  const emptyMsg = isBlack
    ? "No malicious identities detected."
    : "No normal identities tracked yet.";

  return (
    <div className="card" style={{ overflow: "hidden" }}>
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        marginBottom: "1rem"
      }}>
        <h3 style={{ fontSize: "0.875rem", fontWeight: 600 }}>
          <span className={`badge ${isBlack ? "badge-black" : "badge-white"}`} style={{ marginRight: "0.5rem" }}>
            {identities.length}
          </span>
          {title}
        </h3>
      </div>

      {identities.length === 0 ? (
        <div style={{ color: "var(--text-muted)", fontSize: "0.8125rem", padding: "1rem 0" }}>
          {emptyMsg}
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Identity</th>
                <th>Associated IPs</th>
                {isBlack && <th>Threat Type</th>}
                <th>Confidence</th>
                <th>Flows</th>
                <th>Last Seen</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {identities.map((identity) => (
                <tr key={identity.id}>
                  <td>
                    <div style={{ display: "flex", flexDirection: "column" }}>
                      <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600, fontSize: "0.8125rem" }}>
                        {identity.codename || identity.identity_label}
                      </span>
                      {identity.mac_address && (
                        <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                           MAC: {identity.mac_address}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="ip-list">
                      {(identity.associated_ips || []).slice(0, 3).map((ip, i) => (
                        <span key={i}>
                          {ip}{i < Math.min((identity.associated_ips || []).length, 3) - 1 ? ", " : ""}
                        </span>
                      ))}
                      {(identity.associated_ips || []).length > 3 && (
                        <span style={{ color: "var(--text-muted)" }}> +{identity.associated_ips.length - 3}</span>
                      )}
                    </div>
                  </td>
                  {isBlack && (
                    <td>
                      <span style={{ color: "var(--black-badge)", fontWeight: 500 }}>
                        {identity.threat_type}
                      </span>
                    </td>
                  )}
                  <td>
                    <span style={{ fontFamily: "var(--font-mono)" }}>
                      {(identity.confidence * 100).toFixed(1)}%
                    </span>
                  </td>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
                    {identity.flow_count || 1}
                  </td>
                  <td style={{ fontSize: "0.75rem" }}>
                    {identity.last_seen ? new Date(identity.last_seen).toLocaleString() : "—"}
                  </td>
                  <td>
                    {identity.is_blocked ? (
                      <span className="badge badge-blocked">Blocked</span>
                    ) : isBlack ? (
                      <span className="badge badge-black">Active</span>
                    ) : (
                      <span className="badge badge-white">Clear</span>
                    )}
                  </td>
                  <td>
                    {identity.is_blocked ? (
                      <button
                        className="btn btn-success btn-sm"
                        onClick={() => handleAction(identity.id, "unblock", onAction)}
                      >
                        Unblock
                      </button>
                    ) : (
                      <button
                        className={`btn ${isBlack ? "btn-danger" : "btn-danger"} btn-sm`}
                        onClick={() => handleAction(identity.id, "block", onAction)}
                      >
                        Block
                      </button>
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

async function handleAction(identityId, action, onAction) {
  try {
    await fetch(`${API}/api/identities/${identityId}/${action}`, { method: "POST" });
    if (onAction) onAction();
  } catch (e) {
    console.error(`Failed to ${action} identity:`, e);
  }
}
