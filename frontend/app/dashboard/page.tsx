"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { DashboardStats } from "@/types";
import RiskBadge from "@/components/RiskBadge";
import dynamic from "next/dynamic";
import { CheckCircle, TrendingUp, TrendingDown, ArrowRight, Activity } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, Cell } from "recharts";
import ThreatRadar from "@/components/ThreatRadar";
import AnimatedCounter from "@/components/AnimatedCounter";
import { motion } from "framer-motion";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

// Dynamically load the Leaflet Global Threat Map to bypass SSR issues
const GlobalMap = dynamic(() => import("@/components/GlobalMap"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full min-h-[350px] bg-surface-container-low animate-pulse flex items-center justify-center rounded-xl border border-white/5">
      <span className="text-xs text-on-surface-variant font-mono-sm">LOADING THREAT STREAM...</span>
    </div>
  ),
});

export default function Dashboard() {
  const queryClient = useQueryClient();

  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery({
    queryKey: ['dashboardStats'],
    queryFn: () => api.getDashboardStats(),
    staleTime: 30000, // 30s cache
  });

  const { data: activity, isLoading: activityLoading } = useQuery({
    queryKey: ['scanActivity'],
    queryFn: () => api.getScanActivity(),
    staleTime: 60000,
  });

  const { data: topIocs, isLoading: topIocsLoading } = useQuery({
    queryKey: ['topIocs'],
    queryFn: () => api.getTopIocs(),
    staleTime: 60000,
  });

  const { data: apiHealth, isLoading: apiHealthLoading } = useQuery({
    queryKey: ['apiHealth'],
    queryFn: () => api.getApiHealth(),
    staleTime: 60000,
  });

  const loading = statsLoading || activityLoading || topIocsLoading || apiHealthLoading;
  const error = statsError ? "Failed to fetch telemetry metrics from backend." : "";

  const dismissMutation = useMutation({
    mutationFn: (alertId: number) => api.dismissAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboardStats'] });
    },
  });

  const handleDismissAlert = (alertId: number) => {
    dismissMutation.mutate(alertId);
  };

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto space-y-6 py-8 animate-pulse px-4 md:px-8">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-28 bg-white/5 rounded-xl border border-white/5" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 h-[400px] bg-white/5 rounded-xl border border-white/5" />
          <div className="h-[400px] bg-white/5 rounded-xl border border-white/5" />
        </div>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="max-w-xl mx-auto py-16 text-center">
        <span className="material-symbols-outlined text-[64px] text-error mb-4 font-light">report_problem</span>
        <h2 className="text-xl font-bold text-white mb-2">Telemetry Offline</h2>
        <p className="text-on-surface-variant text-sm mb-6">{error || "Could not retrieve statistics."}</p>
        <button onClick={() => queryClient.invalidateQueries({ queryKey: ['dashboardStats'] })} className="bg-primary text-on-primary py-2 px-6 rounded-lg text-sm font-bold">
          Retry Connection
        </button>
      </div>
    );
  }

  const mapPoints = stats.recent_scans
    .filter((s) => s.raw_data && s.raw_data.ipinfo && s.raw_data.ipinfo.lat && s.raw_data.ipinfo.lon)
    .map((s) => ({
      lat:        s.raw_data!.ipinfo.lat,
      lon:        s.raw_data!.ipinfo.lon,
      label:      `${s.indicator} (${s.raw_data!.ipinfo.city || "Unknown"})`,
      level:      s.risk_level,
      indicator:  s.indicator,
      risk_score: s.risk_score,
      country:    s.raw_data!.ipinfo.country || s.raw_data!.ipinfo.region || "Unknown",
      scanned_at: s.created_at,
    }));

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12 px-4 md:px-8 mt-6">
      <div className="flex justify-between items-center mb-2">
        <h1 className="text-2xl font-black text-white font-headline-lg">Command Center</h1>
        <button 
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ['dashboardStats'] });
            queryClient.invalidateQueries({ queryKey: ['scanActivity'] });
            queryClient.invalidateQueries({ queryKey: ['topIocs'] });
            queryClient.invalidateQueries({ queryKey: ['apiHealth'] });
          }}
          disabled={loading}
          className="bg-surface-container-low border border-white/10 hover:bg-white/5 text-white py-1.5 px-4 rounded-lg text-[11px] font-bold font-mono-sm flex items-center gap-2 transition-all disabled:opacity-50 hover:border-primary/50 hover:text-primary"
        >
          <span className={`material-symbols-outlined text-[16px] ${loading ? 'animate-spin text-primary' : ''}`}>refresh</span>
          REFRESH
        </button>
      </div>

      {/* Live Threat Ticker (Top IOCs) */}
      {topIocs && topIocs.top_iocs && topIocs.top_iocs.length > 0 && (
        <div className="bg-surface-container-low border border-white/10 rounded-lg overflow-hidden flex items-center">
          <div className="bg-primary text-on-primary font-bold px-4 py-2 flex items-center gap-2 font-label-caps text-[10px] whitespace-nowrap shrink-0">
            <span className="material-symbols-outlined text-[14px]">local_fire_department</span>
            LIVE THREATS
          </div>
          <div className="flex-1 overflow-x-auto whitespace-nowrap hide-scrollbar flex items-center px-4 gap-8 text-xs font-mono-sm py-2">
            {topIocs.top_iocs.map((ioc: any, idx: number) => {
              const isDangerous = ioc.max_risk > 60;
              return (
                <div key={idx} className="flex items-center gap-2 shrink-0">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${isDangerous ? 'bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.8)]' : 'bg-emerald-500'}`} />
                  <span className="text-on-surface-variant text-[10px]">{ioc.type.toUpperCase()}:</span>
                  <span className={`${isDangerous ? 'text-red-400' : 'text-emerald-400'} font-bold`}>{ioc.indicator}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold ${
                    isDangerous
                      ? 'bg-red-500/10 text-red-400 border-red-500/20'
                      : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                  }`}>
                    {isDangerous ? '⚠ dangerous' : '✓ safe'}
                  </span>
                  <span className="text-on-surface-variant/50 text-[10px]">({ioc.scan_count} scans)</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Bento KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }} className="glass-panel p-md rounded-xl flex items-center justify-between hover:border-white/10 transition-all duration-300">
          <div className="space-y-1.5">
            <p className="text-[11px] font-mono-sm uppercase text-on-surface-variant">Total Global Scans</p>
            <AnimatedCounter value={stats.total_scans_24h} className="text-3xl font-black text-white block" />
          </div>
          <div className="p-3 rounded-lg bg-primary/10 border border-primary/20 text-primary">
            <span className="material-symbols-outlined text-[24px]">biotech</span>
          </div>
        </motion.div>

        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.2 }} className="glass-panel p-md rounded-xl flex items-center justify-between hover:border-white/10 transition-all duration-300">
          <div className="space-y-1.5">
            <p className="text-[11px] font-mono-sm uppercase text-on-surface-variant">Critical Threat Assets</p>
            <AnimatedCounter value={stats.critical_threats} className="text-3xl font-black text-error block" />
          </div>
          <div className="p-3 rounded-lg bg-error-container/20 border border-error-container/30 text-error">
            <span className="material-symbols-outlined text-[24px]">gpp_maybe</span>
          </div>
        </motion.div>

        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.3 }} className="glass-panel p-md rounded-xl flex items-center justify-between hover:border-white/10 transition-all duration-300">
          <div className="space-y-1.5">
            <p className="text-[11px] font-mono-sm uppercase text-on-surface-variant">High Risk Watchlist</p>
            <AnimatedCounter value={stats.high_risk_assets} className="text-3xl font-black text-tertiary-container block" />
          </div>
          <div className="p-3 rounded-lg bg-tertiary-container/10 border border-tertiary-container/25 text-tertiary-container">
            <span className="material-symbols-outlined text-[24px]">warning</span>
          </div>
        </motion.div>

        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.4 }} className="glass-panel p-md rounded-xl flex items-center justify-between hover:border-white/10 transition-all duration-300">
          <div className="space-y-1.5">
            <p className="text-[11px] font-mono-sm uppercase text-on-surface-variant">Monitored IOCs</p>
            <AnimatedCounter value={stats.monitored_iocs || 0} className="text-3xl font-black text-primary-container block" />
          </div>
          <div className="p-3 rounded-lg bg-primary-container/10 border border-primary-container/20 text-primary-container">
            <span className="material-symbols-outlined text-[24px]">visibility</span>
          </div>
        </motion.div>
      </div>

      {/* Map & 14-Day Activity Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Span: Threat Map */}
        <div className="lg:col-span-2 glass-panel p-lg rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-white/5 pb-2 mb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-[20px]">public</span>
                <h3 className="font-bold text-white text-md font-headline-sm">Global Threat Propagation Map</h3>
              </div>
              <p className="text-[11px] text-on-surface-variant mt-1 ml-7">
                Each pin = one IP address you have scanned.&nbsp;
                <span className="text-red-400 font-semibold">Red</span> = dangerous,&nbsp;
                <span className="text-yellow-400 font-semibold">Yellow</span> = suspicious,&nbsp;
                <span className="text-emerald-400 font-semibold">Green</span> = safe.
              </p>
            </div>
            <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase">Live Telemetry</span>
          </div>
          <div className="h-[350px] relative">
            <GlobalMap points={mapPoints} />
          </div>
        </div>

        {/* Right Span: 14-Day Activity Chart */}
        <div className="glass-panel p-lg rounded-xl flex flex-col h-[435px]">
          <div className="flex items-center justify-between border-b border-white/5 pb-2 mb-3">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-[20px]">bar_chart</span>
              <div>
                <h3 className="font-bold text-white text-md font-headline-sm">14-Day Scan Activity</h3>
                <p className="text-[10px] text-on-surface-variant">🔵 safe days &nbsp;|&nbsp; 🔴 days with high-risk scans</p>
              </div>
            </div>
          </div>
          
          <div className="flex-1 w-full min-h-0">
            {activity && activity.activity ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={activity.activity} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                  <XAxis
                    dataKey="date"
                    stroke="#ffffff40"
                    fontSize={9}
                    tickMargin={8}
                    axisLine={false}
                    tickLine={false}
                    label={{ value: "Date", position: "insideBottom", offset: -12, fill: "#ffffff40", fontSize: 10 }}
                  />
                  <YAxis
                    stroke="#ffffff40"
                    fontSize={9}
                    axisLine={false}
                    tickLine={false}
                    allowDecimals={false}
                    label={{ value: "Scans", angle: -90, position: "insideLeft", offset: 15, fill: "#ffffff40", fontSize: 10 }}
                  />
                  <RechartsTooltip
                    cursor={{ fill: "#ffffff08" }}
                    contentStyle={{ backgroundColor: "#0f172a", borderColor: "#ffffff20", borderRadius: "8px", fontSize: "12px" }}
                    formatter={(value) => {
                      const num = Number(value) || 0;
                      return [`${num} scan${num !== 1 ? "s" : ""}`, "Total"];
                    }}
                    labelFormatter={(label) => `📅 ${label}`}
                  />
                  <Bar dataKey="scans" radius={[4, 4, 0, 0]} barSize={18}>
                    {activity.activity.map((entry: any, index: number) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={entry.has_high_risk ? "#ef4444" : "#71a1ff"}
                        fillOpacity={0.85}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="w-full h-full flex items-center justify-center text-on-surface-variant font-mono-sm text-xs">
                No activity data available
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Split Row: API Health, Risk Allocation, Incident Alert Center */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 1 Span: API Health Status */}
        <div className="glass-panel p-lg rounded-xl flex flex-col justify-between">
          <div className="flex items-center gap-2 border-b border-white/5 pb-2 mb-4">
            <Activity size={20} className="text-primary" />
            <h3 className="font-bold text-white text-md font-headline-sm">OSINT Engine Health</h3>
          </div>
          
          <div className="space-y-4">
            {apiHealth && apiHealth.apis ? (
              apiHealth.apis.map((apiItem: any) => (
                <div key={apiItem.name} className="flex items-center justify-between">
                  <span className="text-sm font-bold text-white">{apiItem.name}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-on-surface-variant font-mono-sm">{apiItem.code || 'N/A'}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono-sm uppercase border ${
                      apiItem.status === 'online' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 
                      apiItem.status === 'degraded' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' : 
                      'bg-error/10 text-error border-error/20'
                    }`}>
                      {apiItem.status}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-xs text-on-surface-variant text-center py-4">Checking APIs...</div>
            )}
          </div>
        </div>

        {/* Center 1 Span: Threat Radar */}
        <div className="glass-panel p-lg rounded-xl flex flex-col">
          <div className="flex items-center gap-2 border-b border-white/5 pb-2 mb-4">
            <span className="material-symbols-outlined text-primary text-[20px]">radar</span>
            <div>
              <h3 className="font-bold text-white text-md font-headline-sm">Threat Radar</h3>
              <p className="text-[10px] text-on-surface-variant">Risk distribution across all scanned indicators</p>
            </div>
          </div>
          <div className="flex-1 flex items-center justify-center">
            <ThreatRadar
              distribution={stats.threat_distribution}
              totalScans={stats.total_scans_24h}
            />
          </div>
        </div>

        {/* Right 1 Span: Incident Alert Center */}
        <div className="glass-panel p-lg rounded-xl flex flex-col justify-between max-h-[300px]">
          <div className="flex items-center justify-between border-b border-white/5 pb-2 mb-4 shrink-0">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-[20px]">notifications_active</span>
              <h3 className="font-bold text-white text-md font-headline-sm">Alert Center</h3>
            </div>
            <span className="text-[10px] bg-error-container/20 text-error px-2 py-0.5 border border-error-container/30 rounded font-mono-sm uppercase">
              {stats.alerts.length} Incidents
            </span>
          </div>

          <div className="space-y-3 overflow-y-auto pr-1 hide-scrollbar">
            {stats.alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-on-surface-variant/40 space-y-2">
                <CheckCircle size={36} className="text-primary/40 animate-pulse" />
                <p className="text-[10px] font-mono-sm text-center">ALL WATCHLIST REPUTATIONS STABLE</p>
              </div>
            ) : (
              stats.alerts.map((alert) => (
                <div
                  key={alert.id}
                  className="p-3 bg-surface-container-low border border-white/5 rounded-lg flex flex-col gap-2 hover:border-white/10 transition-all"
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-xs font-bold text-white font-headline-sm leading-tight">{alert.title}</span>
                    <button
                      onClick={() => handleDismissAlert(alert.id)}
                      className="p-1 hover:bg-white/5 rounded text-on-surface-variant hover:text-white transition-all text-[10px] font-mono-sm"
                    >
                      DISMISS
                    </button>
                  </div>
                  <p className="text-xs text-on-surface-variant line-clamp-2">{alert.message}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Recent Scans Feed Table */}
      <div className="glass-panel p-lg rounded-xl">
        <div className="flex items-center justify-between border-b border-white/5 pb-2 mb-4">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-[20px]">history</span>
            <h3 className="font-bold text-white text-md font-headline-sm">Global Threat Activity Feed</h3>
          </div>
          <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase">Recent scan registries</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-white/5 text-on-surface-variant font-mono-sm font-semibold">
                <th className="py-2.5">INDICATOR TARGET</th>
                <th className="py-2.5">TYPE</th>
                <th className="py-2.5">DATE / TIME</th>
                <th className="py-2.5">SEVERITY</th>
                <th className="py-2.5 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-on-surface font-body-sm font-semibold">
              {stats.recent_scans.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-on-surface-variant/40 font-mono-sm">
                    NO HISTORIC IOC SCANS LOGGED
                  </td>
                </tr>
              ) : (
                stats.recent_scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-white/5 transition-all">
                    <td className="py-3 font-mono-md select-all pr-4 truncate max-w-[200px] sm:max-w-xs text-white">
                      {scan.indicator}
                    </td>
                    <td className="py-3">
                      <span className="font-mono-sm uppercase text-[10px] px-1.5 py-0.5 bg-white/5 border border-white/10 rounded">
                        {scan.type}
                      </span>
                    </td>
                    <td className="py-3 text-on-surface-variant">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-3">
                      <RiskBadge level={scan.risk_level} score={scan.risk_score} />
                    </td>
                    <td className="py-3 text-right">
                      <Link
                        href={`/results/${scan.id}`}
                        className="inline-flex items-center gap-1 text-primary hover:underline font-mono-sm"
                      >
                        REPORT
                        <ArrowRight size={12} />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
