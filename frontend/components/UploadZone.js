"use client";

import { useRef, useState } from "react";
const API = "http://127.0.0.1:5000";
export default function UploadZone({ onUploaded }) {
  const inputRef = useRef(null);
  const uploadingRef = useRef(false);
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState("");

  const handleFile = async (file) => {
    if (!file || uploadingRef.current) return;
    uploadingRef.current = true;
    setUploading(true);
    setProgress("Uploading...");

    try {
      const formData = new FormData();
      formData.append("file", file);

      const uploadRes = await fetch(`${API}/api/upload`, {
        method: "POST",
        body: formData,
      });
      const uploadData = await uploadRes.json();

      if (uploadData.error) {
        setProgress(`Error: ${uploadData.error}`);
        setUploading(false);
        uploadingRef.current = false;
        return;
      }

      setProgress("Analyzing 49 parameters...");
      const analyzeRes = await fetch(`${API}/api/analyze/${uploadData.analysis_id}`);
      const analyzeData = await analyzeRes.json();

      if (analyzeData.error) {
        setProgress(`Analysis error: ${analyzeData.error}`);
        setUploading(false);
        uploadingRef.current = false;
        return;
      }

      setProgress(`Done — ${analyzeData.total_flows} flows, ${analyzeData.identities_created} identities`);
      setUploading(false);
      uploadingRef.current = false;

      if (onUploaded) onUploaded(analyzeData);
    } catch (e) {
      setProgress(`Network error: ${e.message}`);
      setUploading(false);
    }
  };

  return (
    <div
      className={`upload-zone ${isDragging ? "dragover" : ""}`}
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setIsDragging(false);
        const file = e.dataTransfer.files[0];
        handleFile(file);
      }}
      onClick={() => inputRef.current?.click()}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng,.cap"
        style={{ display: "none" }}
        onChange={(e) => handleFile(e.target.files[0])}
      />

      {uploading ? (
        <div>
          <div className="pulse" style={{ fontSize: "0.875rem", fontWeight: 500 }}>
            {progress}
          </div>
        </div>
      ) : progress ? (
        <div style={{ fontSize: "0.8125rem" }}>
          <div style={{ color: "var(--white-badge)", marginBottom: "0.25rem" }}>[OK] {progress}</div>
          <div style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>Click to upload another</div>
        </div>
      ) : (
        <div>
          <div style={{ fontSize: "1.5rem", marginBottom: "0.5rem", fontFamily: "var(--font-mono)", fontWeight: 200 }}>[+]</div>
          <div style={{ fontSize: "0.875rem", fontWeight: 500 }}>Drop PCAP file here</div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
            .pcap, .pcapng, .cap — up to 100 MB
          </div>
        </div>
      )}
    </div>
  );
}
