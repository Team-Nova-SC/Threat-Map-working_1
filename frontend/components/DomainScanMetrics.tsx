"use client";

import React from "react";
import { motion } from "framer-motion";

interface DomainScanMetricsProps {
  data: any;
}

export default function DomainScanMetrics({ data }: DomainScanMetricsProps) {
  if (!data || data.status !== "success") return null;

  const bots = data.bot_access_matrix || {};
  const meta = data.metadata_validation || {};
  const perf = data.performance_metrics || {};
  const render = data.live_browser_rendering || {};

  return (
    <div className="glass-panel rounded-xl p-md flex flex-col h-full border border-white/5">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
          <span className="material-symbols-outlined text-primary text-[20px]">smart_toy</span>
        </div>
        <h3 className="text-sm font-bold text-white tracking-wider font-label-caps uppercase">
          DomainScan Diagnostics
        </h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Left Col: AI Score & Performance */}
        <div className="space-y-6">
          <div className="bg-surface-container-low rounded-lg p-4 border border-white/5 flex items-center justify-between">
            <div>
              <p className="text-[10px] text-on-surface-variant font-mono-sm mb-1 uppercase">AI-Readiness Score</p>
              <div className="flex items-end gap-2">
                <span className={`text-4xl font-black font-mono-md leading-none ${data.ai_readiness?.score >= 80 ? 'text-emerald-400' : data.ai_readiness?.score >= 50 ? 'text-yellow-400' : 'text-error'}`}>
                  {data.ai_readiness?.score}
                </span>
                <span className="text-sm text-on-surface-variant font-bold mb-1">/ 100</span>
              </div>
            </div>
            <div className={`w-14 h-14 rounded-full flex items-center justify-center border-4 text-2xl font-black ${
                data.ai_readiness?.grade === 'A' || data.ai_readiness?.grade === 'B' ? 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10' :
                data.ai_readiness?.grade === 'C' || data.ai_readiness?.grade === 'D' ? 'border-yellow-500/30 text-yellow-400 bg-yellow-500/10' :
                'border-error/30 text-error bg-error/10'
            }`}>
              {data.ai_readiness?.grade}
            </div>
          </div>

          <div className="space-y-2">
            <p className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2">Performance & Network</p>
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-surface-container-low p-3 rounded-lg border border-white/5 flex flex-col gap-1">
                <span className="text-[10px] text-on-surface-variant font-mono-sm">Latency</span>
                <span className="text-sm font-bold text-white font-mono-sm">{perf.latency_ms} ms</span>
              </div>
              <div className="bg-surface-container-low p-3 rounded-lg border border-white/5 flex flex-col gap-1">
                <span className="text-[10px] text-on-surface-variant font-mono-sm">Server Delay</span>
                <span className="text-sm font-bold text-white font-mono-sm">{perf.server_delay_ms} ms</span>
              </div>
              <div className="bg-surface-container-low p-3 rounded-lg border border-white/5 flex flex-col gap-1">
                <span className="text-[10px] text-on-surface-variant font-mono-sm">HTTP Status</span>
                <span className={`text-sm font-bold font-mono-sm ${perf.http_handshake_code === 200 ? 'text-emerald-400' : 'text-yellow-400'}`}>
                  {perf.http_handshake_code}
                </span>
              </div>
              <div className="bg-surface-container-low p-3 rounded-lg border border-white/5 flex flex-col gap-1">
                <span className="text-[10px] text-on-surface-variant font-mono-sm">Network Path Health</span>
                <span className={`text-xs font-bold ${data.network_path_health?.includes("Warning") ? 'text-error' : 'text-emerald-400'}`}>
                  {data.network_path_health}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Col: Bots & Meta */}
        <div className="space-y-6">
          <div className="space-y-2">
            <p className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2">Bot Access Matrix</p>
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(bots).map(([bot, allowed]) => (
                <div key={bot} className="bg-surface-container-low px-3 py-2 rounded border border-white/5 flex items-center justify-between">
                  <span className="text-[11px] text-white font-medium truncate pr-2">{bot}</span>
                  {allowed ? (
                    <span className="material-symbols-outlined text-[14px] text-emerald-400 shrink-0">check_circle</span>
                  ) : (
                    <span className="material-symbols-outlined text-[14px] text-error shrink-0">block</span>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <p className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2">Metadata Validation</p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(meta).map(([key, value]) => {
                if (key === "schema_org_types") return null;
                return (
                  <div key={key} className={`px-2 py-1 rounded text-[10px] font-bold font-mono-sm border ${
                    value ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-error/10 text-error border-error/20'
                  }`}>
                    {key.replace("has_", "").toUpperCase()}
                  </div>
                );
              })}
              {meta.schema_org_types && meta.schema_org_types.map((schema: string) => (
                <div key={schema} className="px-2 py-1 rounded text-[10px] font-bold font-mono-sm border bg-primary/10 text-primary border-primary/20">
                  SCHEMA: {schema.toUpperCase()}
                </div>
              ))}
            </div>
          </div>
          
          <div className="space-y-2">
            <p className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2">Live Browser Render</p>
            <div className="bg-surface-container-low p-3 rounded-lg border border-white/5 flex items-center justify-between">
               <div className="flex items-center gap-2">
                 <span className="material-symbols-outlined text-[16px] text-secondary">web</span>
                 <span className="text-xs text-white font-mono-sm">DOM Elements: {render.dom_elements_count || 0}</span>
               </div>
               <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${render.snapshot_status === 'captured' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-error/10 text-error'}`}>
                 {render.snapshot_status}
               </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
