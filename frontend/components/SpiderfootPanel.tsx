"use client";

import React, { useState, useEffect } from "react";
import { api } from "@/lib/api";

export default function SpiderfootPanel({ target }: { target: string }) {
  const [status, setStatus] = useState<"idle" | "running" | "completed" | "error" | "offline">("idle");
  const [scanId, setScanId] = useState<string | null>(null);
  const [results, setResults] = useState<any>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  const BASE = process.env.NEXT_PUBLIC_API_URL || "/_/backend/api/v1";

  const startScan = async () => {
    setStatus("running");
    setErrorMsg("");
    setResults(null);
    setElapsedSeconds(0);
    try {
      const response = await fetch(`${BASE}/spiderfoot/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
        signal: AbortSignal.timeout(90000),
      });

      const data = await response.json();

      if (!response.ok) {
        const detail = data?.detail || "Failed to start scan";
        // Detect SpiderFoot offline specifically
        if (detail.toLowerCase().includes("connection") || detail.toLowerCase().includes("connect error")) {
          setStatus("offline");
        } else {
          setStatus("error");
          setErrorMsg(detail);
        }
        return;
      }

      if (data.scan_id) {
        setScanId(data.scan_id);
      } else {
        setStatus("error");
        setErrorMsg(data.message || "No scan ID returned from SpiderFoot.");
      }
    } catch (err: any) {
      console.error(err);
      setStatus("error");
      setErrorMsg(err.message || "Network error connecting to backend.");
    }
  };

  // Timer to show elapsed time
  useEffect(() => {
    if (status !== "running") return;
    const t = setInterval(() => setElapsedSeconds(s => s + 1), 1000);
    return () => clearInterval(t);
  }, [status]);

  // Polling for results and status
  useEffect(() => {
    if (status !== "running" || !scanId) return;
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${BASE}/spiderfoot/scan/${scanId}/status`);
        const data = await res.json();
        if (data.status === "FINISHED" || data.status === "ABORTED") {
          setStatus("completed");
          fetchResults(scanId);
          clearInterval(interval);
        } else {
          fetchResults(scanId); // show partial results
        }
      } catch (err) {
        console.error(err);
      }
    }, 10000);
    return () => clearInterval(interval);
  }, [status, scanId]);

  const fetchResults = async (id: string) => {
    try {
      const res = await fetch(`${BASE}/spiderfoot/scan/${id}/results`);
      if (res.ok) setResults(await res.json());
    } catch (err) { console.error(err); }
  };

  const fmtTime = (s: number) => `${Math.floor(s / 60)}m ${s % 60}s`;

  return (
    <div className="mt-8">
      <h3 className="font-bold font-label-caps text-[12px] text-on-surface-variant uppercase tracking-wider mb-4 flex items-center gap-2">
        <span className="material-symbols-outlined text-[14px] text-primary">troubleshoot</span>
        Deep OSINT Reconnaissance
        <span className="text-[9px] px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 font-mono">SpiderFoot 200+ modules</span>
      </h3>

      <div className="glass-panel p-6 rounded-xl border border-white/5">

        {/* ── IDLE ── */}
        {status === "idle" && (
          <div className="text-center py-6">
            <span className="material-symbols-outlined text-5xl text-on-surface-variant/30 mb-4 block">travel_explore</span>
            <p className="text-sm text-on-surface-variant mb-2 max-w-lg mx-auto">
              Run a comprehensive deep scan utilizing SpiderFoot's 200+ OSINT modules.<br/>
              Uncover <strong className="text-white">emails, subdomains, dark web mentions, social profiles</strong> and more.
            </p>
            <p className="text-xs text-error/80 mb-5 font-mono">⚠ Deep scans take 5–15 minutes to complete.</p>
            <button onClick={startScan} className="bg-primary text-background font-bold px-8 py-2.5 rounded-lg hover:bg-primary/90 transition-colors text-sm">
              Start Deep Scan
            </button>
          </div>
        )}

        {/* ── SPIDERFOOT OFFLINE ── */}
        {status === "offline" && (
          <div className="text-center py-6">
            <span className="material-symbols-outlined text-5xl text-orange-400 mb-3 block">cloud_off</span>
            <h4 className="font-bold text-orange-300 text-base mb-2">SpiderFoot Engine Offline</h4>
            <p className="text-sm text-on-surface-variant mb-4 max-w-md mx-auto">
              The SpiderFoot local API is not running. Start it in a new terminal with:
            </p>
            <div className="bg-background border border-white/10 rounded-lg px-4 py-3 font-mono text-xs text-primary mb-5 text-left max-w-sm mx-auto">
              cd C:\ThreatMap\spiderfoot<br/>
              ..\backend\venv\Scripts\python.exe sf.py -l 127.0.0.1:5001
            </div>
            <button onClick={() => setStatus("idle")} className="border border-primary/50 text-primary px-5 py-2 rounded-lg hover:bg-primary/10 transition-colors text-sm">
              Try Again
            </button>
          </div>
        )}

        {/* ── GENERIC ERROR ── */}
        {status === "error" && (
          <div className="text-center py-6">
            <span className="material-symbols-outlined text-5xl text-error mb-2 block">error</span>
            <h4 className="font-bold text-error mb-2">Scan Failed</h4>
            <p className="text-sm text-on-surface-variant mb-4 font-mono bg-error/10 border border-error/20 rounded px-4 py-2 max-w-md mx-auto">{errorMsg}</p>
            <button onClick={() => setStatus("idle")} className="border border-error/50 text-error px-5 py-2 rounded-lg hover:bg-error/10 transition-colors text-sm">
              Retry
            </button>
          </div>
        )}

        {/* ── RUNNING / COMPLETED ── */}
        {(status === "running" || status === "completed") && (
          <div className="space-y-5">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center gap-3">
                {status === "running" ? (
                  <span className="material-symbols-outlined text-primary text-2xl animate-spin">refresh</span>
                ) : (
                  <span className="material-symbols-outlined text-green-400 text-2xl">check_circle</span>
                )}
                <div>
                  <h4 className="font-bold text-white text-sm">
                    {status === "running" ? `Scanning... (${fmtTime(elapsedSeconds)})` : "Scan Completed"}
                  </h4>
                  <p className="text-xs text-on-surface-variant font-mono">ID: {scanId}</p>
                </div>
              </div>
              {status === "running" && (
                <button onClick={() => setStatus("idle")} className="text-xs text-on-surface-variant border border-white/10 px-3 py-1 rounded hover:bg-white/5 transition-colors">
                  Cancel
                </button>
              )}
            </div>

            {status === "running" && !results && (
              <p className="text-center text-xs text-on-surface-variant/60 font-mono animate-pulse py-4">
                Fetching intelligence... results will appear below as modules complete.
              </p>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <ResultCard title="Emails Discovered"     data={results?.emails}      icon="mail" />
              <ResultCard title="Subdomains Found"      data={results?.subdomains}  icon="lan" />
              <ResultCard title="Related IPs"           data={results?.related_ips} icon="sensors" />
              <ResultCard title="Dark Web Mentions"     data={results?.darkweb}     icon="public_off" />
              <ResultCard title="Social Media Profiles" data={results?.social}      icon="group" />
              <ResultCard title="Technology Stack"      data={results?.tech_stack}  icon="terminal" />
              <ResultCard title="Breach / Leaks"        data={results?.leaks}       icon="water_drop" />
              <ResultCard title="SSL Certificates"      data={results?.ssl_certs}   icon="lock" />
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

function ResultCard({ title, data, icon }: { title: string; data?: string[]; icon: string }) {
  const items = data ?? [];
  return (
    <div className="bg-surface-container-low border border-white/5 p-4 rounded-lg">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-[18px]">{icon}</span>
          <h5 className="text-sm font-bold text-white">{title}</h5>
        </div>
        <span className={`text-xs font-mono px-2 py-0.5 rounded ${items.length > 0 ? "bg-primary/20 text-primary" : "bg-white/10 text-on-surface-variant"}`}>
          {items.length}
        </span>
      </div>
      <div className="max-h-32 overflow-y-auto hide-scrollbar text-xs text-on-surface-variant font-mono space-y-1">
        {items.length === 0 ? (
          <span className="opacity-40 italic">No results yet...</span>
        ) : (
          items.map((item, i) => (
            <div key={i} className="truncate hover:text-white transition-colors" title={item}>— {item}</div>
          ))
        )}
      </div>
    </div>
  );
}
