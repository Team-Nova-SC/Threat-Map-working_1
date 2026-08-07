"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface VirusTotalDeepInspectionProps {
  vtData: any;
  type: "ip" | "domain" | "url" | "hash";
}

export default function VirusTotalDeepInspection({ vtData, type }: VirusTotalDeepInspectionProps) {
  const [activeTab, setActiveTab] = useState<string>("network");
  
  if (!vtData || !vtData.attributes) return null;
  
  const attrs = vtData.attributes;
  const rels = vtData.relationships || {};

  const tabs = [];
  if (type === "ip" || type === "domain") tabs.push({ id: "network", label: "Network & Reg" });
  if (type === "hash") tabs.push({ id: "technical", label: "Technical Data" });
  if (type === "url") tabs.push({ id: "http", label: "HTTP Context" });
  
  // Generic tabs for all
  if (attrs.last_analysis_results || attrs.tags) tabs.push({ id: "context", label: "Threat Context" });
  if (Object.keys(rels).length > 0) tabs.push({ id: "relations", label: "VT Relations" });

  if (tabs.length === 0) return null;
  // If current active tab is not valid for this type, default to first
  if (!tabs.find(t => t.id === activeTab)) {
    setActiveTab(tabs[0].id);
  }

  return (
    <div className="glass-panel rounded-xl flex flex-col border border-white/5 mt-6 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-md border-b border-white/10 bg-white/[0.02]">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[#394eff]/20 rounded-lg border border-[#394eff]/30">
            <span className="material-symbols-outlined text-[#8997ff] text-[20px]">policy</span>
          </div>
          <div>
            <h3 className="text-sm font-bold text-white tracking-wider font-label-caps uppercase flex items-center gap-2">
              VirusTotal Deep Inspection
              <span className="px-1.5 py-0.5 rounded bg-primary/20 text-primary text-[9px] border border-primary/30">PRO</span>
            </h3>
            <span className="text-[10px] text-on-surface-variant font-mono-sm">Extended attributes and relational telemetry</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex px-4 border-b border-white/5 overflow-x-auto no-scrollbar">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 text-xs font-bold tracking-wider font-label-caps uppercase transition-colors relative whitespace-nowrap ${
              activeTab === tab.id ? "text-primary" : "text-on-surface-variant hover:text-white"
            }`}
          >
            {tab.label}
            {activeTab === tab.id && (
              <motion.div layoutId="vt-tab" className="absolute bottom-0 left-0 right-0 h-[2px] bg-primary" />
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
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {attrs.asn && (
                  <DataBox label="ASN" value={`AS${attrs.asn}`} sub={attrs.as_owner} />
                )}
                {attrs.network && <DataBox label="Network (CIDR)" value={attrs.network} />}
                {attrs.country && <DataBox label="Country" value={attrs.country} />}
                {attrs.continent && <DataBox label="Continent" value={attrs.continent} />}
                {attrs.regional_internet_registry && <DataBox label="RIR" value={attrs.regional_internet_registry} />}
                {attrs.whois_date && <DataBox label="WHOIS Date" value={new Date(attrs.whois_date * 1000).toLocaleDateString()} />}
              </div>
            )}

            {/* TECHNICAL / HTTP TAB */}
            {(activeTab === "technical" || activeTab === "http") && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {attrs.type_description && <DataBox label="File Type" value={attrs.type_description} />}
                  {attrs.size && <DataBox label="File Size" value={`${(attrs.size / 1024).toFixed(2)} KB`} />}
                  {attrs.last_http_response_code && <DataBox label="HTTP Response Code" value={String(attrs.last_http_response_code)} />}
                  {attrs.last_http_response_content_length && <DataBox label="Content Length" value={`${attrs.last_http_response_content_length} bytes`} />}
                </div>
                {attrs.last_http_response_headers && (
                  <div className="mt-4">
                    <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2 block">Response Headers</span>
                    <pre className="text-[10px] text-white/70 bg-black/40 p-3 rounded-lg border border-white/5 overflow-x-auto whitespace-pre-wrap font-mono">
                      {JSON.stringify(attrs.last_http_response_headers, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* CONTEXT TAB */}
            {activeTab === "context" && (
              <div className="space-y-6">
                {attrs.tags && attrs.tags.length > 0 && (
                  <div>
                    <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2 block">Crowdsourced Tags</span>
                    <div className="flex flex-wrap gap-2">
                      {attrs.tags.map((tag: string) => (
                        <span key={tag} className="px-2 py-1 bg-surface-container-high rounded text-xs text-white border border-white/10 font-mono-sm">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                
                {attrs.categories && Object.keys(attrs.categories).length > 0 && (
                  <div>
                    <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2 block">Categories</span>
                    <div className="flex flex-wrap gap-2">
                      {Object.values(attrs.categories).map((cat: any, i: number) => (
                        <span key={i} className="px-2 py-1 bg-primary/10 text-primary rounded text-[11px] font-bold border border-primary/20">
                          {cat}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* RELATIONS TAB */}
            {activeTab === "relations" && (
              <div>
                <p className="text-xs text-on-surface-variant mb-4 font-mono-sm">
                  Relational data fetched from VT directly. This is synced into the graph explorer below.
                </p>
                {Object.keys(rels).map((key) => (
                  <div key={key} className="mb-4">
                    <h4 className="text-[10px] font-bold text-white uppercase tracking-wider mb-2">{key.replace("_", " ")}</h4>
                    <div className="flex flex-wrap gap-2 max-h-[200px] overflow-y-auto pr-2 custom-scrollbar">
                      {rels[key].map((item: any, idx: number) => {
                        let label = item.id;
                        if (item.attributes && item.attributes.ip_address) label = item.attributes.ip_address;
                        else if (item.attributes && item.attributes.host_name) label = item.attributes.host_name;
                        
                        return (
                          <span key={idx} className="px-2 py-1 bg-black/40 text-white rounded text-[11px] border border-white/5 font-mono">
                            {label}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                ))}
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
