"use client";

import React, { useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { ScanResponse } from "@/types";
import RiskBadge from "@/components/RiskBadge";
import RiskGauge from "@/components/RiskGauge";

export default function ComparePage() {
  const [indicatorA, setIndicatorA] = useState("");
  const [indicatorB, setIndicatorB] = useState("");
  const [typeA, setTypeA] = useState<"ip" | "url" | "domain" | "hash">("ip");
  const [typeB, setTypeB] = useState<"ip" | "url" | "domain" | "hash">("ip");
  
  const [scanA, setScanA] = useState<ScanResponse | null>(null);
  const [scanB, setScanB] = useState<ScanResponse | null>(null);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleCompare = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicatorA || !indicatorB) {
      setError("Please enter two indicators to compare.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const [resA, resB] = await Promise.all([
        api.analyzeIndicator(indicatorA, typeA),
        api.analyzeIndicator(indicatorB, typeB)
      ]);
      setScanA(resA);
      setScanB(resB);
    } catch (err: any) {
      console.error("Compare error:", err?.response?.status, err?.response?.data, err?.message);
      const status = err?.response?.status;
      if (status === 422) {
        setError("Invalid indicator format. Please check your inputs and selected types match (e.g. select 'IP' for an IP address).");
      } else if (err?.code === 'ECONNABORTED' || err?.message?.includes('timeout')) {
        setError("Scan timed out — the OSINT lookups took too long. Please try again.");
      } else if (!status) {
        setError("Cannot reach backend. Make sure the server is running on port 8000.");
      } else {
        setError(`Scan failed (HTTP ${status}). Check inputs and try again.`);
      }
    } finally {
      setLoading(false);
    }
  };

  const ComparisonColumn = ({ scan, title }: { scan: ScanResponse | null, title: string }) => {
    if (!scan) {
      return (
        <div className="glass-panel p-md rounded-xl h-full min-h-[400px] flex flex-col items-center justify-center opacity-50 border-dashed border-2 border-white/10">
          <span className="material-symbols-outlined text-[48px] text-on-surface-variant mb-4">compare_arrows</span>
          <p className="font-mono-sm text-xs text-on-surface-variant uppercase tracking-wider">{title}</p>
        </div>
      );
    }

    const vt = scan.raw_data?.virustotal || {};
    const vtTotal = (vt.malicious || 0) + (vt.harmless || 0) + (vt.suspicious || 0) + (vt.undetected || 0);

    return (
      <div className="glass-panel p-lg rounded-xl h-full space-y-6 flex flex-col relative overflow-hidden">
        <div className={`absolute top-0 left-0 w-full h-1 ${
          scan.risk_score >= 90 ? 'bg-error' : 
          scan.risk_score >= 70 ? 'bg-orange-500' : 
          scan.risk_score >= 35 ? 'bg-yellow-500' : 'bg-primary'
        }`} />
        
        <div className="text-center pb-4 border-b border-white/5 space-y-2">
          <span className="text-[10px] font-mono-sm uppercase bg-white/5 border border-white/10 px-2 py-0.5 rounded text-on-surface-variant">
            {scan.type} Indicator
          </span>
          <h3 className="text-xl font-black text-white truncate px-4" title={scan.indicator}>{scan.indicator}</h3>
          <p className="text-[10px] text-on-surface-variant font-mono-sm">ID: {scan.id}</p>
        </div>

        <div className="flex justify-center py-4">
          <RiskGauge score={scan.risk_score} />
        </div>

        <div className="space-y-4 pt-4 border-t border-white/5 flex-1">
          <div className="flex justify-between items-center bg-surface-container-low p-2 rounded border border-white/5">
            <span className="text-[11px] font-mono-sm text-on-surface-variant uppercase">Risk Level</span>
            <RiskBadge level={scan.risk_level} score={scan.risk_score} />
          </div>

          <div className="flex justify-between items-center bg-surface-container-low p-2 rounded border border-white/5">
            <span className="text-[11px] font-mono-sm text-on-surface-variant uppercase">VirusTotal</span>
            <span className={`text-xs font-bold ${vt.malicious > 0 ? 'text-error' : 'text-emerald-400'}`}>
              {vt.malicious || 0} / {vtTotal || 0} Malicious
            </span>
          </div>

          {scan.type === 'ip' && scan.raw_data?.abuseipdb && (
            <div className="flex justify-between items-center bg-surface-container-low p-2 rounded border border-white/5">
              <span className="text-[11px] font-mono-sm text-on-surface-variant uppercase">AbuseIPDB</span>
              <span className={`text-xs font-bold ${scan.raw_data.abuseipdb.abuseConfidenceScore > 0 ? 'text-error' : 'text-white'}`}>
                {scan.raw_data.abuseipdb.abuseConfidenceScore || 0}% Confidence
              </span>
            </div>
          )}

          <div className="mt-4">
            <span className="text-[11px] font-mono-sm text-on-surface-variant uppercase block mb-2">AI Summary</span>
            <p className="text-xs leading-relaxed text-on-surface line-clamp-4">{scan.summary}</p>
          </div>
        </div>

        <div className="pt-4 border-t border-white/5 mt-auto">
          <Link href={`/results/${scan.id}`} className="block text-center w-full py-2 bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 rounded font-bold text-xs uppercase tracking-wider transition-all">
            View Full Report
          </Link>
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12 pt-8 px-4 md:px-8">
      <div className="text-center mb-8">
        <span className="material-symbols-outlined text-[32px] text-primary mb-2">compare_arrows</span>
        <h1 className="text-3xl font-black text-white tracking-tight">Indicator Comparison</h1>
        <p className="text-on-surface-variant text-sm mt-2 max-w-2xl mx-auto">
          Compare the telemetry and risk allocation of two threat vectors side-by-side to determine relationship or severity variance.
        </p>
      </div>

      <div className="glass-panel p-md rounded-xl max-w-4xl mx-auto">
        <form onSubmit={handleCompare} className="flex flex-col md:flex-row gap-4 items-center">
          <div className="flex-1 w-full space-y-2">
            <label className="text-[10px] font-mono-sm uppercase text-primary font-bold">Target A</label>
            <div className="flex gap-2">
              <select 
                value={typeA} 
                onChange={(e: any) => setTypeA(e.target.value)}
                className="bg-surface-container-lowest border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-primary/50"
              >
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">Hash</option>
              </select>
              <input 
                type="text" 
                value={indicatorA}
                onChange={(e) => setIndicatorA(e.target.value)}
                placeholder="Indicator A..."
                className="flex-1 bg-surface-container-lowest border border-white/10 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-primary/50"
              />
            </div>
          </div>

          <div className="hidden md:flex mt-6 w-8 justify-center shrink-0">
            <span className="material-symbols-outlined text-on-surface-variant/40">sync_alt</span>
          </div>

          <div className="flex-1 w-full space-y-2">
            <label className="text-[10px] font-mono-sm uppercase text-tertiary font-bold text-[#df7412]">Target B</label>
            <div className="flex gap-2">
              <select 
                value={typeB} 
                onChange={(e: any) => setTypeB(e.target.value)}
                className="bg-surface-container-lowest border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-[#df7412]/50"
              >
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">Hash</option>
              </select>
              <input 
                type="text" 
                value={indicatorB}
                onChange={(e) => setIndicatorB(e.target.value)}
                placeholder="Indicator B..."
                className="flex-1 bg-surface-container-lowest border border-white/10 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-[#df7412]/50"
              />
            </div>
          </div>

          <button 
            type="submit" 
            disabled={loading}
            className="w-full md:w-auto mt-6 bg-primary text-on-primary py-2.5 px-6 rounded-lg font-bold text-xs uppercase tracking-widest flex items-center justify-center gap-2 hover:opacity-90 shrink-0 disabled:opacity-60"
          >
            {loading ? (
              <>
                <span className="animate-spin w-4 h-4 border-2 border-white/20 border-t-white rounded-full" />
                <span>SCANNING...</span>
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-[16px]">compare</span>
                <span>COMPARE</span>
              </>
            )}
          </button>
        </form>
        {error && <p className="text-error text-xs mt-3 text-center">{error}</p>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4">
        <ComparisonColumn scan={scanA} title="Waiting for Target A..." />
        <ComparisonColumn scan={scanB} title="Waiting for Target B..." />
      </div>
    </div>
  );
}
