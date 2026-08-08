"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface Pulse {
  id?: string;
  name: string;
  description?: string;
  author?: string;
  created?: string;
  modified?: string;
  tlp?: string;
  tags?: string[];
  malware_families?: string[];
  attack_ids?: string[];
  targeted_countries?: string[];
  industries?: string[];
  references?: string[];
}

interface PassiveDnsEntry {
  hostname: string;
  record_type?: string;
  first?: string;
  last?: string;
  asn?: string;
}

interface MalwareSample {
  hash: string;
  name?: string;
  date?: string;
}

interface UrlEntry {
  url: string;
  httpcode?: string | number;
  date?: string;
}

interface GeoInfo {
  country_name?: string;
  country_code?: string;
  city?: string;
  asn?: string;
  latitude?: number;
  longitude?: number;
}

interface ReputationInfo {
  threat_score?: number;
  activities?: any[];
}

interface AlienVaultData {
  status?: string;
  pulse_count?: number;
  pulses?: Pulse[];
  tags?: string[];
  malware_families?: string[];
  attack_ids?: string[];
  target_countries?: string[];
  target_industries?: string[];
  references?: string[];
  geo?: GeoInfo;
  reputation?: ReputationInfo;
  passive_dns?: PassiveDnsEntry[];
  malware_samples?: MalwareSample[];
  url_list?: UrlEntry[];
  raw?: any;
}

const TLP_COLORS: Record<string, string> = {
  white: "bg-white/10 text-white border-white/20",
  green: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  amber: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  red: "bg-rose-500/20 text-rose-400 border-rose-500/30",
};

export default function AlienVaultDeepInspection({ data }: { data: AlienVaultData }) {
  const [activeTab, setActiveTab] = useState<"pulses" | "pdns" | "malware" | "urls" | "geo">("pulses");

  if (!data || data.status === "unavailable" || data.status === "error") {
    return (
      <div className="glass-panel p-6 rounded-xl border border-white/5 mt-8">
        <div className="flex items-center gap-3 text-on-surface-variant">
          <span className="material-symbols-outlined text-[24px]">hub</span>
          <div>
            <h3 className="font-bold text-white text-md font-headline-sm">AlienVault OTX Intelligence</h3>
            <p className="text-xs opacity-70">No threat exchange records found or provider offline for this indicator.</p>
          </div>
        </div>
      </div>
    );
  }

  const pulseCount = data.pulse_count || (data.pulses ? data.pulses.length : 0);
  const pulses = data.pulses || [];
  const tags = data.tags || [];
  const malwareFamilies = data.malware_families || [];
  const attackIds = data.attack_ids || [];
  const passiveDns = data.passive_dns || [];
  const malwareSamples = data.malware_samples || [];
  const urlList = data.url_list || [];
  const geo = data.geo || {};
  const reputation = data.reputation || {};

  return (
    <div className="glass-panel p-6 rounded-xl border border-white/10 mt-8 relative overflow-hidden">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-5 border-b border-white/10 gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-teal-500/10 border border-teal-500/30 flex items-center justify-center text-teal-400">
            <span className="material-symbols-outlined text-[22px]">hub</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-white text-lg font-headline-sm">AlienVault OTX Deep Inspection</h3>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                pulseCount > 0 ? "bg-rose-500/20 text-rose-400 border-rose-500/30" : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
              }`}>
                {pulseCount} {pulseCount === 1 ? "PULSE MATCH" : "PULSES MATCHED"}
              </span>
            </div>
            <p className="text-xs text-on-surface-variant font-body-sm">
              Global Open Threat Exchange crowd-sourced threat intelligence & attack attribution.
            </p>
          </div>
        </div>

        {/* Reputation Badge */}
        {reputation.threat_score !== undefined && reputation.threat_score !== null && (
          <div className="flex items-center gap-3 bg-white/5 border border-white/10 px-3 py-1.5 rounded-lg">
            <span className="text-xs text-on-surface-variant">Threat Score:</span>
            <span className={`font-mono text-sm font-bold ${
              reputation.threat_score > 50 ? "text-rose-400" : reputation.threat_score > 20 ? "text-amber-400" : "text-emerald-400"
            }`}>
              {reputation.threat_score} / 100
            </span>
          </div>
        )}
      </div>

      {/* Threat Attributes Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 my-6">
        {/* MITRE ATT&CK */}
        <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg">
          <div className="flex items-center gap-2 mb-2 text-xs font-bold text-teal-400 uppercase tracking-wider">
            <span className="material-symbols-outlined text-[16px]">grid_view</span>
            MITRE ATT&CK Techniques
          </div>
          {attackIds.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {attackIds.slice(0, 5).map((att) => (
                <span key={att} className="text-[10px] font-mono bg-teal-500/10 border border-teal-500/20 text-teal-300 px-2 py-0.5 rounded">
                  {att}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-[11px] text-on-surface-variant/60 italic">None mapped</span>
          )}
        </div>

        {/* Malware Families */}
        <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg">
          <div className="flex items-center gap-2 mb-2 text-xs font-bold text-rose-400 uppercase tracking-wider">
            <span className="material-symbols-outlined text-[16px]">bug_report</span>
            Malware Families
          </div>
          {malwareFamilies.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {malwareFamilies.slice(0, 5).map((mf) => (
                <span key={mf} className="text-[10px] font-mono bg-rose-500/10 border border-rose-500/20 text-rose-300 px-2 py-0.5 rounded">
                  {mf}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-[11px] text-on-surface-variant/60 italic">None identified</span>
          )}
        </div>

        {/* Targeted Industries */}
        <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg">
          <div className="flex items-center gap-2 mb-2 text-xs font-bold text-purple-400 uppercase tracking-wider">
            <span className="material-symbols-outlined text-[16px]">domain</span>
            Targeted Sectors
          </div>
          {data.target_industries && data.target_industries.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {data.target_industries.slice(0, 4).map((ind) => (
                <span key={ind} className="text-[10px] font-mono bg-purple-500/10 border border-purple-500/20 text-purple-300 px-2 py-0.5 rounded">
                  {ind}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-[11px] text-on-surface-variant/60 italic">Broad / Unspecified</span>
          )}
        </div>

        {/* Top Threat Tags */}
        <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg">
          <div className="flex items-center gap-2 mb-2 text-xs font-bold text-sky-400 uppercase tracking-wider">
            <span className="material-symbols-outlined text-[16px]">label</span>
            Top Tags
          </div>
          {tags.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {tags.slice(0, 5).map((t) => (
                <span key={t} className="text-[10px] font-mono bg-sky-500/10 border border-sky-500/20 text-sky-300 px-2 py-0.5 rounded">
                  #{t}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-[11px] text-on-surface-variant/60 italic">No tags</span>
          )}
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-white/10 pb-3 mb-5">
        <button
          onClick={() => setActiveTab("pulses")}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
            activeTab === "pulses"
              ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
              : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
          }`}
        >
          <span className="material-symbols-outlined text-[15px]">description</span>
          Threat Pulses ({pulses.length})
        </button>

        {passiveDns.length > 0 && (
          <button
            onClick={() => setActiveTab("pdns")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
              activeTab === "pdns"
                ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
                : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">dns</span>
            Passive DNS ({passiveDns.length})
          </button>
        )}

        {malwareSamples.length > 0 && (
          <button
            onClick={() => setActiveTab("malware")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
              activeTab === "malware"
                ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
                : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">coronavirus</span>
            Malware Samples ({malwareSamples.length})
          </button>
        )}

        {urlList.length > 0 && (
          <button
            onClick={() => setActiveTab("urls")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
              activeTab === "urls"
                ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
                : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">link</span>
            Hosted URLs ({urlList.length})
          </button>
        )}

        <button
          onClick={() => setActiveTab("geo")}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
            activeTab === "geo"
              ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
              : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
          }`}
        >
          <span className="material-symbols-outlined text-[15px]">public</span>
          Geo & Network Context
        </button>
      </div>

      {/* Tab Contents */}
      <AnimatePresence mode="wait">
        {activeTab === "pulses" && (
          <motion.div
            key="pulses"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="space-y-3.5"
          >
            {pulses.length === 0 ? (
              <p className="text-xs text-on-surface-variant/70 italic p-4 text-center">No community pulses linked to this indicator.</p>
            ) : (
              pulses.map((pulse, idx) => {
                const tlpColor = TLP_COLORS[pulse.tlp?.toLowerCase() || "white"] || TLP_COLORS.white;
                return (
                  <div key={pulse.id || idx} className="bg-surface-container-low/60 border border-white/5 p-4 rounded-xl hover:border-teal-500/30 transition-all">
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${tlpColor}`}>
                          TLP:{pulse.tlp || "WHITE"}
                        </span>
                        <h4 className="font-bold text-white text-sm">{pulse.name}</h4>
                      </div>
                      <div className="text-[11px] text-on-surface-variant font-mono">
                        Author: <span className="text-teal-300 font-semibold">{pulse.author || "AlienVault Analyst"}</span>
                        {pulse.created && <span className="ml-2 opacity-60">• {new Date(pulse.created).toLocaleDateString()}</span>}
                      </div>
                    </div>

                    {pulse.description && (
                      <p className="text-xs text-on-surface-variant/90 leading-relaxed mb-3 line-clamp-3">
                        {pulse.description}
                      </p>
                    )}

                    {/* Metadata Pill Row */}
                    <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                      {pulse.malware_families && pulse.malware_families.length > 0 && (
                        <div className="flex items-center gap-1 text-rose-300 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                          <span className="material-symbols-outlined text-[12px]">bug_report</span>
                          {pulse.malware_families.join(", ")}
                        </div>
                      )}
                      {pulse.attack_ids && pulse.attack_ids.length > 0 && (
                        <div className="flex items-center gap-1 text-teal-300 bg-teal-500/10 px-2 py-0.5 rounded border border-teal-500/20">
                          <span className="material-symbols-outlined text-[12px]">security</span>
                          {pulse.attack_ids.join(", ")}
                        </div>
                      )}
                      {pulse.tags && pulse.tags.map((t) => (
                        <span key={t} className="bg-white/5 text-on-surface-variant px-2 py-0.5 rounded border border-white/10">
                          #{t}
                        </span>
                      ))}
                    </div>

                    {pulse.references && pulse.references.length > 0 && (
                      <div className="mt-3 pt-2 border-t border-white/5 flex flex-wrap gap-2 text-[11px]">
                        <span className="text-on-surface-variant opacity-70">References:</span>
                        {pulse.references.map((ref, rIdx) => (
                          <a
                            key={rIdx}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-teal-400 hover:underline truncate max-w-[250px] inline-flex items-center gap-0.5"
                          >
                            {ref.replace(/^https?:\/\//, "")}
                            <span className="material-symbols-outlined text-[12px]">open_in_new</span>
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </motion.div>
        )}

        {activeTab === "pdns" && (
          <motion.div
            key="pdns"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="overflow-x-auto"
          >
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-on-surface-variant uppercase tracking-wider text-[10px]">
                  <th className="py-2.5 px-3">Resolved Hostname / IP</th>
                  <th className="py-2.5 px-3">Record Type</th>
                  <th className="py-2.5 px-3">First Seen</th>
                  <th className="py-2.5 px-3">Last Seen</th>
                  <th className="py-2.5 px-3">ASN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-white">
                {passiveDns.map((pd, idx) => (
                  <tr key={idx} className="hover:bg-white/5">
                    <td className="py-2.5 px-3 text-teal-300 font-bold">{pd.hostname}</td>
                    <td className="py-2.5 px-3"><span className="bg-white/10 px-1.5 py-0.5 rounded text-[10px]">{pd.record_type || "A"}</span></td>
                    <td className="py-2.5 px-3 text-on-surface-variant">{pd.first ? new Date(pd.first).toLocaleDateString() : "N/A"}</td>
                    <td className="py-2.5 px-3 text-on-surface-variant">{pd.last ? new Date(pd.last).toLocaleDateString() : "N/A"}</td>
                    <td className="py-2.5 px-3 text-on-surface-variant">{pd.asn || "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </motion.div>
        )}

        {activeTab === "malware" && (
          <motion.div
            key="malware"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="overflow-x-auto"
          >
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-on-surface-variant uppercase tracking-wider text-[10px]">
                  <th className="py-2.5 px-3">File Hash (SHA256/MD5)</th>
                  <th className="py-2.5 px-3">Sample Name / Detection</th>
                  <th className="py-2.5 px-3">Observed Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-white">
                {malwareSamples.map((mw, idx) => (
                  <tr key={idx} className="hover:bg-white/5">
                    <td className="py-2.5 px-3 text-rose-300 font-bold truncate max-w-[220px]">{mw.hash}</td>
                    <td className="py-2.5 px-3 text-white">{mw.name || "Suspicious Binary"}</td>
                    <td className="py-2.5 px-3 text-on-surface-variant">{mw.date ? new Date(mw.date).toLocaleDateString() : "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </motion.div>
        )}

        {activeTab === "urls" && (
          <motion.div
            key="urls"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="overflow-x-auto"
          >
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-on-surface-variant uppercase tracking-wider text-[10px]">
                  <th className="py-2.5 px-3">Hosted URL Path</th>
                  <th className="py-2.5 px-3">HTTP Code</th>
                  <th className="py-2.5 px-3">Discovered Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-white">
                {urlList.map((u, idx) => (
                  <tr key={idx} className="hover:bg-white/5">
                    <td className="py-2.5 px-3 text-sky-300 truncate max-w-[320px]">{u.url}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                        String(u.httpcode).startsWith("2") ? "bg-emerald-500/20 text-emerald-400" : "bg-rose-500/20 text-rose-400"
                      }`}>
                        {u.httpcode || "N/A"}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-on-surface-variant">{u.date ? new Date(u.date).toLocaleDateString() : "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </motion.div>
        )}

        {activeTab === "geo" && (
          <motion.div
            key="geo"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="grid grid-cols-1 md:grid-cols-3 gap-4"
          >
            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Country & City</span>
              <p className="text-white font-bold text-sm">{geo.city || "Unknown City"}, {geo.country_name || "Unknown Country"}</p>
              {geo.country_code && <span className="text-xs text-teal-400 font-mono mt-1 block">Code: {geo.country_code}</span>}
            </div>

            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Autonomous System (ASN)</span>
              <p className="text-white font-bold text-sm">{geo.asn || "N/A"}</p>
            </div>

            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Coordinates (Lat / Lon)</span>
              <p className="text-white font-bold text-sm">
                {geo.latitude !== undefined && geo.longitude !== undefined ? `${geo.latitude}, ${geo.longitude}` : "N/A"}
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
