"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import RiskBadge from "@/components/RiskBadge";

export default function BulkResultsPage() {
  const [results, setResults] = useState<any>(null);

  useEffect(() => {
    const data = sessionStorage.getItem("bulkScanResults");
    if (data) {
      setResults(JSON.parse(data));
    }
  }, []);

  if (!results) {
    return (
      <div className="max-w-4xl mx-auto py-16 text-center px-4 md:px-8">
        <span className="animate-spin inline-block w-8 h-8 border-4 border-primary border-t-transparent rounded-full mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Processing Bulk Telemetry</h2>
        <p className="text-on-surface-variant text-sm">Validating indicators across threat intelligence engines...</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12 px-4 md:px-8 mt-6">
      <div className="glass-panel p-md rounded-xl flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="material-symbols-outlined text-primary text-[24px]">library_add</span>
            <h2 className="text-2xl font-black text-white tracking-tight">Bulk Scan Results</h2>
          </div>
          <p className="text-xs text-on-surface-variant font-body-sm">
            Analyzed {results.total} indicators. Results are sorted by risk score.
          </p>
        </div>
        <Link href="/" className="bg-surface-container-low text-white border border-white/10 hover:bg-white/5 py-2 px-4 rounded-lg font-bold text-xs font-label-caps transition-all">
          NEW SCAN
        </Link>
      </div>

      <div className="glass-panel rounded-xl overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-surface-container-lowest border-b border-white/10 text-[10px] font-label-caps text-on-surface-variant uppercase tracking-wider">
              <th className="p-4 font-bold">Indicator</th>
              <th className="p-4 font-bold text-center">Type</th>
              <th className="p-4 font-bold text-center">Risk Score</th>
              <th className="p-4 font-bold text-center">Malicious Engines</th>
              <th className="p-4 font-bold text-center">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-sm font-mono-sm">
            {results.results.map((r: any, idx: number) => (
              <tr key={idx} className="hover:bg-white/5 transition-colors group">
                <td className="p-4 text-white font-bold">{r.indicator}</td>
                <td className="p-4 text-center text-on-surface-variant">
                  <span className="bg-white/5 border border-white/10 px-2 py-0.5 rounded text-[10px] uppercase">
                    {r.type}
                  </span>
                </td>
                <td className="p-4 text-center">
                  <div className="flex flex-col items-center gap-1">
                    <RiskBadge level={r.risk_level} />
                    <span className="text-[10px] text-on-surface-variant">{r.risk_score}/100</span>
                  </div>
                </td>
                <td className="p-4 text-center">
                  <span className={`${r.malicious_engines > 0 ? "text-error font-bold" : "text-emerald-400"}`}>
                    {r.malicious_engines}
                  </span>
                  <span className="text-on-surface-variant"> / {r.total_engines}</span>
                </td>
                <td className="p-4 text-center">
                  <button 
                    className="text-primary hover:text-primary/80 transition-colors text-[10px] uppercase tracking-wider border border-primary/20 px-2 py-1 rounded bg-primary/10 opacity-0 group-hover:opacity-100"
                    onClick={() => navigator.clipboard.writeText(r.indicator)}
                  >
                    COPY
                  </button>
                </td>
              </tr>
            ))}
            {results.results.length === 0 && (
              <tr>
                <td colSpan={5} className="p-8 text-center text-on-surface-variant">
                  No valid results returned.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
