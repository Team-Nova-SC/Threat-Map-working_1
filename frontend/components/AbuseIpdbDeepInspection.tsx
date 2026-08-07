"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface AbuseIpdbDeepInspectionProps {
  abuseData: any;
}

const CATEGORY_MAP: Record<number, string> = {
  3: "Fraud Orders",
  4: "DDoS Attack",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  14: "Port Scan",
  15: "Hacking",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted"
};

export default function AbuseIpdbDeepInspection({ abuseData }: AbuseIpdbDeepInspectionProps) {
  const [activeTab, setActiveTab] = useState<string>("network");
  
  if (!abuseData || abuseData.status !== "success") return null;

  const tabs = [
    { id: "network", label: "Network & Identity" },
    { id: "reports", label: "Report History" }
  ];

  const reports = abuseData.reports || [];

  return (
    <div className="glass-panel rounded-xl flex flex-col border border-white/5 mt-6 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-md border-b border-white/10 bg-white/[0.02]">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[#ff3953]/20 rounded-lg border border-[#ff3953]/30">
            <span className="material-symbols-outlined text-[#ff899a] text-[20px]">security</span>
          </div>
          <div>
            <h3 className="text-sm font-bold text-white tracking-wider font-label-caps uppercase flex items-center gap-2">
              AbuseIPDB Deep Inspection
              <span className="px-1.5 py-0.5 rounded bg-primary/20 text-primary text-[9px] border border-primary/30">PRO</span>
            </h3>
            <span className="text-[10px] text-on-surface-variant font-mono-sm">Extended telemetry and report history</span>
          </div>
        </div>
        <div className="text-right">
          <span className="block text-[10px] font-mono-sm text-on-surface-variant uppercase">Confidence</span>
          <span className={`text-xl font-bold ${abuseData.abuseConfidenceScore > 50 ? 'text-error' : 'text-emerald-400'}`}>
            {abuseData.abuseConfidenceScore}%
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex px-4 border-b border-white/5 overflow-x-auto no-scrollbar">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 text-xs font-bold tracking-wider font-label-caps uppercase transition-colors relative whitespace-nowrap ${
              activeTab === tab.id ? "text-[#ff3953]" : "text-on-surface-variant hover:text-white"
            }`}
          >
            {tab.label}
            {activeTab === tab.id && (
              <motion.div layoutId="abuse-tab" className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#ff3953]" />
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="p-md">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
          >
            {/* NETWORK TAB */}
            {activeTab === "network" && (
              <div className="space-y-6">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <DataBox label="Total Reports" value={String(abuseData.totalReports)} />
                  <DataBox label="Distinct Users" value={String(abuseData.numDistinctUsers)} />
                  <DataBox label="Whitelisted" value={abuseData.isWhitelisted ? "Yes" : "No"} />
                  <DataBox label="Usage Type" value={abuseData.usageType || "Unknown"} />
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <DataBox label="ISP" value={abuseData.isp || "N/A"} />
                  <DataBox label="Domain" value={abuseData.domain || "N/A"} />
                  <DataBox label="Country" value={`${abuseData.countryName || ''} (${abuseData.countryCode || ''})`} />
                </div>

                {abuseData.hostnames && abuseData.hostnames.length > 0 && (
                  <div>
                    <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2 block">Hostnames</span>
                    <div className="flex flex-wrap gap-2">
                      {abuseData.hostnames.map((hn: string, i: number) => (
                        <span key={i} className="px-2 py-1 bg-surface-container-high rounded text-xs text-white border border-white/10 font-mono-sm">
                          {hn}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* REPORTS TAB */}
            {activeTab === "reports" && (
              <div>
                {reports.length === 0 ? (
                  <div className="p-6 text-center text-on-surface-variant text-sm font-mono-sm">
                    No recent reports found for this IP.
                  </div>
                ) : (
                  <div className="max-h-[400px] overflow-y-auto custom-scrollbar pr-2 space-y-3">
                    {reports.map((report: any, idx: number) => (
                      <div key={idx} className="bg-surface-container-low p-4 rounded-lg border border-white/5 relative">
                        <div className="flex justify-between items-start mb-2">
                          <span className="text-[10px] font-mono text-on-surface-variant/80">
                            {new Date(report.reportedAt).toLocaleString()}
                          </span>
                          <span className="text-[10px] font-bold text-white bg-black/40 px-2 py-0.5 rounded border border-white/10">
                            Reporter ID: {report.reporterId} ({report.reporterCountryCode})
                          </span>
                        </div>
                        <p className="text-sm text-white/90 mb-3 line-clamp-3 leading-relaxed">
                          "{report.comment}"
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {report.categories.map((cat: number) => (
                            <span key={cat} className="text-[9px] font-mono-sm px-1.5 py-0.5 bg-error/20 text-[#ffb4ab] border border-error/30 rounded">
                              {CATEGORY_MAP[cat] || `Category ${cat}`}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}

function DataBox({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-surface-container-low p-3 rounded-lg border border-white/5 flex flex-col justify-center">
      <span className="text-[9px] text-on-surface-variant font-mono-sm uppercase mb-1">{label}</span>
      <span className="text-sm font-bold text-white truncate" title={value}>{value}</span>
      {sub && <span className="text-[10px] text-on-surface-variant mt-1 truncate" title={sub}>{sub}</span>}
    </div>
  );
}
