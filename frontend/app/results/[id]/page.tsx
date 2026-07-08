"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { ScanResponse } from "@/types";
import RiskGauge from "@/components/RiskGauge";
import RiskBadge from "@/components/RiskBadge";
import DetectionCard from "@/components/DetectionCard";
import LoadingSkeleton from "@/components/LoadingSkeleton";
import AdvancedOsintPanels from "@/components/AdvancedOsintPanels";
import WebVulnReport from "@/components/WebVulnReport";
import SpiderfootPanel from "@/components/SpiderfootPanel";
import CommunityNotes from "@/components/CommunityNotes";
import DomainScanMetrics from "@/components/DomainScanMetrics";
import WhoisJsonData from "@/components/WhoisJsonData";
import dynamic from "next/dynamic";
import { Download, Plus, Check, Share2, Target, FileCode2, AlertTriangle, X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { LineChart, Line, ResponsiveContainer, Tooltip, YAxis } from "recharts";
import { useToast } from "@/context/ToastContext";
import { useSession, signIn } from "next-auth/react";

// Dynamically load the Leaflet map to avoid Next.js server-side compilation issues
const GeoMap = dynamic(() => import("@/components/GeoMap"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full min-h-[300px] bg-surface-container-low animate-pulse flex items-center justify-center rounded-xl border border-white/5">
      <span className="text-xs text-on-surface-variant font-mono-sm">LOADING MAP COMPONENT...</span>
    </div>
  ),
});

const RelationshipGraph = dynamic(() => import("@/components/RelationshipGraph"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-64 bg-surface-container-low animate-pulse flex items-center justify-center rounded-xl border border-white/5">
      <span className="text-xs text-on-surface-variant font-mono-sm">LOADING GRAPH...</span>
    </div>
  ),
});

export default function ResultsPage({ params }: { params: { id: string } }) {
  const { id } = params;
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [isAddedToWatch, setIsAddedToWatch] = useState(false);
  const [watchNotes, setWatchNotes] = useState("");
  const [showWatchModal, setShowWatchModal] = useState(false);
  const [showMitreHelp, setShowMitreHelp] = useState(false);
  const [showSidebar, setShowSidebar] = useState(false);
  const [webVulnData, setWebVulnData] = useState<any>(null);
  const [showCampaignModal, setShowCampaignModal] = useState(false);
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [addingToCampaign, setAddingToCampaign] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "graph" | "notes">("overview");
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const { addToast } = useToast();
  const { data: session } = useSession();
  const [isSavingDrive, setIsSavingDrive] = useState(false);

  useEffect(() => {
    async function fetchReport() {
      try {
        setLoading(true);
        const data = await api.getScanReport(id);
        setScan(data);
        
        // Fetch history for Trend Graph safely
        if (typeof (api as any).searchHistory === 'function') {
          (api as any).searchHistory({ query: data.indicator }).then((res: any) => setScanHistory(res.results?.reverse() || [])).catch(console.error);
        }

        // Check if item is already in watchlist
        const watchlist = await api.getWatchlist();
        const found = watchlist.some((w: any) => w.indicator === data.indicator);
        setIsAddedToWatch(found);
      } catch (err: any) {
        console.error(err);
        setError(err.response?.data?.detail || "Failed to load threat report. Please verify the URL or try scanning again.");
      } finally {
        setLoading(false);
      }
    }
    fetchReport();
    
    // Pre-fetch campaigns for the modal
    api.getCampaigns().then(setCampaigns).catch(console.error);
  }, [id]);

  // Separately fetch web vuln data after scan loads
  useEffect(() => {
    if (!scan) return;
    const type = scan.type;
    if (type !== "domain" && type !== "url") return;
    let domain = scan.indicator;
    if (type === "url") {
      try { domain = new URL(scan.indicator).hostname; } catch {}
    }
    api.getWebVulns(domain)
      .then(data => setWebVulnData(data))
      .catch(() => setWebVulnData(null));
  }, [scan]);

  // Cyber Background Threat Reactivity
  useEffect(() => {
    if (scan && scan.risk_score >= 90) {
      document.body.classList.add("threat-active");
    } else {
      document.body.classList.remove("threat-active");
    }
    return () => {
      document.body.classList.remove("threat-active");
    };
  }, [scan]);

  const handleAddToWatchlist = async () => {
    if (!scan) return;
    try {
      await api.addToWatchlist(scan.indicator, scan.type, watchNotes);
      setIsAddedToWatch(true);
      setShowWatchModal(false);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveToDrive = async () => {
    if (!scan) return;
    if (!session) {
      signIn("google");
      return;
    }
    
    setIsSavingDrive(true);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/export/drive`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scan_id: scan.id,
          access_token: (session as any).accessToken
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to upload to Google Drive");
      
      addToast("Saved to Google Drive successfully!", "success");
      // Open link in a new tab if available
      if (data.webViewLink) {
        window.open(data.webViewLink, "_blank");
      }
    } catch (err: any) {
      console.error(err);
      addToast(err.message || "Failed to save to Drive", "error");
    } finally {
      setIsSavingDrive(false);
    }
  };

  if (loading) return <LoadingSkeleton />;

  if (error || !scan) {
    return (
      <div className="max-w-xl mx-auto py-16 text-center px-4 md:px-8">
        <span className="material-symbols-outlined text-[64px] text-error mb-4">gpp_maybe</span>
        <h2 className="text-xl font-bold text-white mb-2">Analysis Report Error</h2>
        <p className="text-on-surface-variant text-sm mb-6">{error || "Indicator scan not found."}</p>
        <Link href="/" className="bg-primary text-on-primary py-2 px-6 rounded-lg text-sm font-bold">
          Return to Scanner
        </Link>
      </div>
    );
  }

  const raw = scan.raw_data || {};
  const vt = raw.virustotal || {};
  const abuse = raw.abuseipdb || {};
  const gn = raw.greynoise || {};
  const otx = raw.alienvault_otx || {};
  const urlscan = raw.urlscan || {};
  // dns var left out until domain records mapping expanded
  const whois = raw.whois_records || {};
  const ssl = raw.ssl_metadata || {};
  const ai = raw.ai_insights || {};

  // Determine if location coordinates are available
  const ipinfo = raw.ipinfo || {};
  const hasCoordinates = !!(ipinfo.lat && ipinfo.lon);

  // MITRE ATT&CK Grid Data — ONLY activate tactics confirmed by AI, never by score thresholds
  const aiMitre = Array.isArray(ai.mitre_tactics) ? ai.mitre_tactics : [];
  const mitreTactics = [
    { id: "TA0001", name: "Initial Access",       active: aiMitre.includes("TA0001"), technique: "T1190 (Exploit Public-Facing Application)", desc: "How the attacker first got into the system." },
    { id: "TA0002", name: "Execution",            active: aiMitre.includes("TA0002"), technique: "T1059 (Command and Scripting Interpreter)", desc: "Running malicious code on the system." },
    { id: "TA0003", name: "Persistence",          active: aiMitre.includes("TA0003"), technique: "T1547 (Boot or Logon Autostart Execution)", desc: "Maintaining access across system restarts." },
    { id: "TA0004", name: "Privilege Escalation", active: aiMitre.includes("TA0004"), technique: "T1068 (Exploitation for Privilege Escalation)", desc: "Gaining higher-level permissions (e.g. Admin)." },
    { id: "TA0005", name: "Defense Evasion",      active: aiMitre.includes("TA0005"), technique: "T1027 (Obfuscated Files or Information)", desc: "Hiding from security controls and antivirus." },
    { id: "TA0006", name: "Credential Access",    active: aiMitre.includes("TA0006"), technique: "T1110 (Brute Force)", desc: "Stealing passwords or login tokens." },
    { id: "TA0007", name: "Discovery",            active: aiMitre.includes("TA0007"), technique: "T1046 (Network Service Discovery)", desc: "Exploring the system to see what exists." },
    { id: "TA0008", name: "Lateral Movement",     active: aiMitre.includes("TA0008"), technique: "T1210 (Exploitation of Remote Services)", desc: "Moving to other computers in the network." },
    { id: "TA0009", name: "Collection",           active: aiMitre.includes("TA0009"), technique: "T1114 (Email Collection)", desc: "Gathering sensitive data to steal." },
    { id: "TA0011", name: "Command and Control",  active: aiMitre.includes("TA0011"), technique: "T1071 (Application Layer Protocol)", desc: "Communicating with the attacker's server." },
    { id: "TA0010", name: "Exfiltration",         active: aiMitre.includes("TA0010"), technique: "T1048 (Exfiltration Over Alternative Protocol)", desc: "Stealing data and sending it out." },
    { id: "TA0040", name: "Impact",               active: aiMitre.includes("TA0040"), technique: "T1486 (Data Encrypted for Impact)", desc: "Destroying or encrypting data (e.g. Ransomware)." },
  ];
  
  const hasMitreTactics = mitreTactics.some(t => t.active);


  // ── Plain-English risk summary ───────────────────────────────────────────
  function getPlainEnglishSummary(score: number) {
    if (score < 30) {
      return {
        emoji: "✅",
        color: "border-emerald-500/30 bg-emerald-500/10",
        titleColor: "text-emerald-400",
        title: "SAFE",
        text: "No threats detected by any security feed. This target appears clean.",
      };
    } else if (score < 60) {
      return {
        emoji: "⚠️",
        color: "border-yellow-500/30 bg-yellow-500/10",
        titleColor: "text-yellow-400",
        title: "CAUTION",
        text: "Some suspicious signals found. Review the details below carefully.",
      };
    } else if (score < 80) {
      return {
        emoji: "🔶",
        color: "border-orange-500/30 bg-orange-500/10",
        titleColor: "text-orange-400",
        title: "HIGH RISK",
        text: "Multiple security feeds flagged this target. Avoid interaction.",
      };
    } else {
      return {
        emoji: "🚨",
        color: "border-red-500/30 bg-red-500/10",
        titleColor: "text-red-400",
        title: "CRITICAL",
        text: "Confirmed malicious by multiple security companies.",
      };
    }
  }

  // ── Risk breakdown weights ───────────────────────────────────────────────
  const vtScore    = Math.min(100, (vt.malicious || 0) * 5);
  const abuseScore = abuse.abuseConfidenceScore || 0;
  const gnScore    = gn.classification === "malicious" ? 80 : gn.noise ? 30 : 0;
  const plainEnglish = getPlainEnglishSummary(scan.risk_score);

  // count active feeds
  const activeFeedCount = [vt, abuse, gn, otx, urlscan].filter(f => Object.keys(f).length > 0).length || 5;

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12 px-4 md:px-8 mt-6">

      {/* ── Plain English Summary Card ─────────────────────────── */}
      <motion.div 
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ type: "spring" as const, stiffness: 300, damping: 20 }}
        className={`rounded-xl border p-4 flex items-start gap-4 ${plainEnglish.color}`}
      >
        <span className="text-3xl leading-none mt-0.5">{plainEnglish.emoji}</span>
        <div>
          <h3 className={`font-bold text-base mb-1 ${plainEnglish.titleColor}`}>{plainEnglish.title}</h3>
          <p className="text-sm text-on-surface/90 leading-relaxed">{plainEnglish.text}</p>
        </div>
      </motion.div>

      {/* ── LINKED TO THREAT ACTOR Alert ──────────────────────────── */}
      {scan.linked_actors && scan.linked_actors.length > 0 && (
        <div className="rounded-xl border border-[#ffb4ab]/30 bg-[#93000a]/10 p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-[#93000a]/30 border border-[#ffb4ab]/20">
              <span className="material-symbols-outlined text-[#ffb4ab] text-[20px]">groups</span>
            </div>
            <div>
              <h3 className="font-black text-[#ffb4ab] text-sm tracking-wider uppercase">⚠ Linked to Known Threat Actor</h3>
              <p className="text-[10px] text-[#ffb4ab]/70 mt-0.5">This IOC matches infrastructure associated with tracked APT groups</p>
            </div>
          </div>
          <div className="space-y-3">
            {scan.linked_actors.map((actor) => (
              <div key={actor.name} className="bg-[#93000a]/20 rounded-lg p-4 border border-[#ffb4ab]/10 flex flex-col sm:flex-row sm:items-start gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-bold text-white text-sm">{actor.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${actor.threat_level === "CRITICAL" ? "bg-[#93000a]/20 text-[#ffb4ab] border-[#ffb4ab]/25" : "bg-[#df7412]/20 text-[#ffb786] border-[#ffb786]/20"}`}>
                      {actor.threat_level}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#ffb4ab]/70 mb-1">{actor.country || "Unknown Origin"}</p>
                  <p className="text-[11px] text-on-surface-variant/80 line-clamp-2">{actor.description?.substring(0, 180)}...</p>
                </div>
                <Link href="/threat-actors" className="shrink-0 text-[10px] font-bold text-[#ffb4ab] hover:text-white border border-[#ffb4ab]/20 hover:border-[#ffb4ab]/50 px-3 py-1.5 rounded-lg transition-all whitespace-nowrap">
                  VIEW PROFILE →
                </Link>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Header Banner */}
      <div className="glass-panel p-md rounded-xl flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2 sm:gap-3">
            <span className="material-symbols-outlined text-primary text-[24px]">
              {scan.type === "ip"
                ? "sensors"
                : scan.type === "url"
                ? "link"
                : scan.type === "domain"
                ? "language"
                : "tag"}
            </span>
            <span className="text-[10px] font-mono-sm uppercase bg-white/5 border border-white/10 px-2 py-0.5 rounded text-on-surface-variant">
              {scan.type} Indicator
            </span>
            <RiskBadge level={scan.risk_level} />
            {scan.raw_data?.risk_confidence && (
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono-sm font-bold border ${
                    scan.raw_data.risk_confidence.level === "HIGH" ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" :
                    scan.raw_data.risk_confidence.level === "MEDIUM" ? "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" :
                    "text-error bg-error/10 border-error/20"
                }`}>
                    CONFIDENCE: {scan.raw_data.risk_confidence.score}%
                </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2 sm:gap-4">
            <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight break-all font-mono-md select-all">
              {scan.indicator}
            </h2>
            <button 
              onClick={() => {
                navigator.clipboard.writeText(scan.indicator);
                addToast("IOC Copied to clipboard!", "success");
              }}
              className="p-2 rounded-lg bg-white/5 border border-white/10 hover:bg-primary/20 hover:text-primary transition-all duration-200 shadow-sm hover:shadow-[0_0_15px_rgba(20,184,166,0.3)] active:scale-95"
              title="Copy IOC"
            >
              <span className="material-symbols-outlined text-[18px]">content_copy</span>
            </button>
          </div>
          <p className="text-xs text-on-surface-variant/80 font-body-sm">
            Analyzed on {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => {
              navigator.clipboard.writeText(window.location.href);
              alert("Report URL copied to clipboard!");
            }}
            className="py-2 px-4 rounded-lg bg-surface-container-low text-white border border-white/10 hover:bg-white/5 font-bold text-xs font-label-caps tracking-wider transition-all duration-150 flex items-center gap-2"
            title="Copy Report Link"
          >
            <span className="material-symbols-outlined text-[14px]">share</span>
            SHARE
          </button>

          <button
            onClick={() => (isAddedToWatch ? null : setShowWatchModal(true))}
            className={`py-2 px-4 rounded-lg font-bold text-xs font-label-caps tracking-wider transition-all duration-150 flex items-center gap-2 ${
              isAddedToWatch
                ? "bg-primary-container/20 text-primary border border-primary/20 cursor-default"
                : "bg-surface-container-low text-white border border-white/10 hover:bg-white/5"
            }`}
          >
            {isAddedToWatch ? <Check size={14} /> : <Plus size={14} />}
            {isAddedToWatch ? "WATCHING" : "WATCH INDICATOR"}
          </button>

          <button
            onClick={() => setShowCampaignModal(true)}
            className="py-2 px-4 rounded-lg bg-surface-container-low text-white border border-white/10 hover:bg-white/5 font-bold text-xs font-label-caps tracking-wider transition-all duration-150 flex items-center gap-2"
          >
            <Target size={14} />
            ADD TO CAMPAIGN
          </button>

          {/* Export Downloads */}
          <div className="flex bg-surface-container-low rounded-lg p-1 border border-white/5">
            <a
              href={api.getExportUrl(scan.id, "pdf")}
              download
              className="p-2 hover:bg-white/5 rounded text-on-surface-variant hover:text-white transition-all flex items-center gap-1.5 text-xs font-semibold"
              title="Export PDF Report"
            >
              <Download size={14} />
              <span className="hidden sm:inline">PDF</span>
            </a>
            <a
              href={api.getExportUrl(scan.id, "csv")}
              download
              className="p-2 hover:bg-white/5 rounded text-on-surface-variant hover:text-white transition-all flex items-center gap-1.5 text-xs font-semibold"
              title="Export CSV Telemetry"
            >
              <Download size={14} />
              <span className="hidden sm:inline">CSV</span>
            </a>
            <a
              href={api.getExportUrl(scan.id, "json")}
              download
              className="p-2 hover:bg-white/5 rounded text-on-surface-variant hover:text-white transition-all flex items-center gap-1.5 text-xs font-semibold"
              title="Export JSON Metadata"
            >
              <Download size={14} />
              <span className="hidden sm:inline">JSON</span>
            </a>
            <button
              onClick={async () => {
                try {
                  const stixData = await api.exportStix(scan.id);
                  const blob = new Blob([JSON.stringify(stixData, null, 2)], { type: "application/json" });
                  const url = window.URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `threatmap_stix_${scan.indicator}.json`;
                  a.click();
                  window.URL.revokeObjectURL(url);
                } catch (e) {
                  console.error("STIX export failed:", e);
                  alert("Failed to export STIX bundle.");
                }
              }}
              className="p-2 hover:bg-white/5 rounded text-primary hover:text-primary transition-all flex items-center gap-1.5 text-xs font-bold border-l border-white/5 ml-1 pl-3"
              title="Export STIX 2.1 Bundle"
            >
              <FileCode2 size={14} />
              <span className="hidden sm:inline">STIX</span>
            </button>
            <button
              onClick={handleSaveToDrive}
              disabled={isSavingDrive}
              className={`p-2 hover:bg-white/5 rounded transition-all flex items-center gap-1.5 text-xs font-bold border-l border-white/5 ml-1 pl-3 ${
                isSavingDrive ? "opacity-50 cursor-not-allowed text-on-surface-variant" : "text-[#4285F4] hover:text-[#4285F4]"
              }`}
              title={session ? "Save report to Google Drive" : "Sign in to save to Google Drive"}
            >
              {isSavingDrive ? (
                <span className="w-3 h-3 border-2 border-[#4285F4] border-t-transparent rounded-full animate-spin" />
              ) : (
                <span className="material-symbols-outlined text-[14px]">add_to_drive</span>
              )}
              <span className="hidden sm:inline">{session ? "DRIVE" : "DRIVE (LOGIN)"}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Analytics Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Cell 1: Risk Gauge + Breakdown */}
        <div className="md:col-span-1 glass-panel p-lg rounded-xl flex flex-col items-center justify-center gap-6 min-h-[300px]">
          <RiskGauge score={scan.risk_score} feedCount={activeFeedCount} />

          {/* Risk Score Breakdown Bar */}
          <div className="w-full space-y-2.5 border-t border-white/5 pt-4">
            <p className="text-[10px] font-mono-sm uppercase text-on-surface-variant tracking-wider mb-2">Score Breakdown</p>

            {[
              { label: "VirusTotal",   desc: "90+ AV engines",  weight: 40, score: vtScore,    color: "bg-primary" },
              { label: "AbuseIPDB",    desc: "Community abuse", weight: 35, score: abuseScore,  color: "bg-orange-500" },
              { label: "GreyNoise",    desc: "Noise scanning",  weight: 25, score: gnScore,     color: "bg-yellow-500" },
            ].filter(engine => scan.type === "ip" || engine.label === "VirusTotal").map((engine) => (
              <div key={engine.label}>
                <div className="flex justify-between text-[10px] font-mono-sm mb-1">
                  <span className="text-on-surface-variant">{engine.label} <span className="opacity-50">({engine.desc})</span></span>
                  <span className="text-white font-bold">{engine.score}<span className="text-on-surface-variant">/100</span></span>
                </div>
                <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-1000 ${engine.color}`}
                    style={{ width: `${engine.score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
          
          {scanHistory.length > 1 && (
            <div className="w-full space-y-2.5 border-t border-white/5 pt-4">
              <p className="text-[10px] font-mono-sm uppercase text-on-surface-variant tracking-wider mb-2">IOC Risk Trend</p>
              <div className="h-[80px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={scanHistory}>
                    <YAxis domain={[0, 100]} hide />
                    <Tooltip contentStyle={{backgroundColor: '#0f172a', border: '1px solid #1e293b', fontSize: '10px'}} labelStyle={{display: 'none'}} />
                    <Line type="monotone" dataKey="risk_score" stroke="#f43f5e" strokeWidth={2} dot={{r: 2, fill: '#f43f5e'}} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>

        {/* Cell 2: Gemini AI Brief */}
        <div className="md:col-span-2 glass-panel p-lg rounded-xl flex flex-col justify-between min-h-[300px]">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-white/5 pb-2">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-[20px]">psychology</span>
                <h3 className="font-bold text-white text-md font-headline-sm">Gemini Analyst Brief</h3>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono-sm font-bold bg-primary/10 text-primary border border-primary/20">
                AI Confidence: {ai.confidence || "HIGH"}
              </span>
            </div>
            <div>
              <p className="text-[11px] font-mono-sm uppercase text-primary font-bold mb-1">
                Category: {ai.threat_category || "Botnet C2"}
              </p>
              <p className="text-sm text-on-surface leading-relaxed">{scan.summary}</p>
            </div>
            {ai.playbook && ai.playbook.length > 0 ? (
              <div className="mt-4 border-t border-white/5 pt-4">
                <p className="text-[11px] font-mono-sm uppercase text-error font-bold mb-3 flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px]">local_police</span>
                  Incident Remediation Playbook
                </p>
                <div className="space-y-2">
                  {ai.playbook.map((step: string, idx: number) => (
                    <div key={idx} className="flex items-start gap-2 text-xs bg-error/10 border border-error/20 p-2 rounded-lg">
                      <div className="w-5 h-5 rounded-full bg-error/20 flex items-center justify-center shrink-0 mt-0.5">
                        <span className="text-error font-bold text-[10px]">{idx + 1}</span>
                      </div>
                      <span className="text-error/90 leading-relaxed mt-0.5">{step.replace(/^\d+\.\s*/, '')}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : ai.recommendations ? (
              <div className="mt-4 border-t border-white/5 pt-4">
                <p className="text-[11px] font-mono-sm uppercase text-error font-bold mb-1">
                  Mitigation Plan
                </p>
                <p className="text-xs text-on-surface-variant leading-relaxed">
                  {ai.recommendations}
                </p>
              </div>
            ) : null}
          </div>
          <div className="text-[10px] text-on-surface-variant/60 font-mono-sm mt-4 text-right">
            Generated via Gemini 1.5 Flash - Structured Mode
          </div>
        </div>
      </div>

      {/* Geolocation Section */}
      {scan.type === "ip" && hasCoordinates && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 glass-panel p-lg rounded-xl space-y-4 flex flex-col justify-center">
            <div className="flex items-center gap-2 border-b border-white/5 pb-2">
              <span className="material-symbols-outlined text-primary text-[20px]">my_location</span>
              <h3 className="font-bold text-white text-md font-headline-sm">IP Geolocation</h3>
            </div>
            <div className="space-y-3 font-mono-sm text-xs">
              <div className="flex justify-between">
                <span className="text-on-surface-variant">Location:</span>
                <span className="text-white font-bold">{ipinfo.city}, {ipinfo.region}, {ipinfo.country}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-on-surface-variant">Coordinates:</span>
                <span className="text-white font-bold">{ipinfo.loc}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-on-surface-variant">ISP:</span>
                <span className="text-white font-bold text-right truncate max-w-[150px]">{ipinfo.org}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-on-surface-variant">Timezone:</span>
                <span className="text-white font-bold">{ipinfo.timezone}</span>
              </div>
            </div>
          </div>
          <div className="lg:col-span-2 h-[300px]">
            <GeoMap lat={ipinfo.lat} lon={ipinfo.lon} label={`${scan.indicator} - ${ipinfo.city}`} />
          </div>
        </div>
      )}

      {/* OSINT Vendor Telemetry Grid */}
      <div>
        <h3 className="font-bold font-label-caps text-label-caps text-[12px] text-on-surface-variant uppercase tracking-wider mb-4">
          Detailed Vendor Intelligence
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* VirusTotal */}
          <DetectionCard
            title="VirusTotal"
            subtitle="Checked by 90+ antivirus engines worldwide"
            status={`${vt.malicious || 0} / ${(vt.malicious || 0) + (vt.harmless || 0)} flags`}
            isMalicious={vt.malicious > 0}
            iconName="security"
          >
            <div className="text-[11px] font-mono-sm space-y-1 text-on-surface-variant">
              <div className="flex justify-between">
                <span>Malicious engines:</span>
                <span className="text-white font-bold">{vt.malicious || 0}</span>
              </div>
              <div className="flex justify-between">
                <span>Undetected:</span>
                <span className="text-white">{vt.harmless || 0}</span>
              </div>
            </div>
          </DetectionCard>

          {/* AbuseIPDB (only IP) */}
          {scan.type === "ip" && (
            <DetectionCard
              title="AbuseIPDB"
              subtitle="Community-sourced abuse reports"
              status={`${abuse.abuseConfidenceScore || 0}% abuse`}
              isMalicious={abuse.abuseConfidenceScore > 0}
              iconName="gpp_bad"
            >
              <div className="text-[11px] font-mono-sm space-y-1 text-on-surface-variant">
                <div className="flex justify-between">
                  <span>Total Reports:</span>
                  <span className="text-white font-bold">{abuse.totalReports || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>Last Reported:</span>
                  <span className="text-white">{abuse.lastReportedAt ? new Date(abuse.lastReportedAt).toLocaleDateString() : "Never"}</span>
                </div>
              </div>
            </DetectionCard>
          )}

          {/* GreyNoise (only IP) */}
          {scan.type === "ip" && (
            <DetectionCard
              title="GreyNoise"
              subtitle="Internet background noise check"
              status={gn.classification || "unknown"}
              isMalicious={gn.classification === "malicious"}
              iconName="hearing"
            >
              <div className="text-[11px] font-mono-sm space-y-1 text-on-surface-variant">
                <div className="flex justify-between">
                  <span>Known Scanner:</span>
                  <span className="text-white font-bold">{gn.noise ? "YES" : "NO"}</span>
                </div>
                <div className="flex justify-between">
                  <span>Scanner Name:</span>
                  <span className="text-white">{gn.name || "N/A"}</span>
                </div>
              </div>
            </DetectionCard>
          )}

          {/* AlienVault OTX */}
          <DetectionCard
            title="AlienVault OTX"
            subtitle="Global threat intelligence feeds"
            status={`${otx.pulse_count || 0} pulses`}
            isMalicious={otx.pulse_count > 0}
            iconName="hub"
          >
            {otx.tags && otx.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {otx.tags.slice(0, 4).map((tag: string) => (
                  <span
                    key={tag}
                    className="text-[9px] font-mono-sm bg-white/5 border border-white/10 px-1.5 py-0.5 rounded text-on-surface-variant"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </DetectionCard>

          {/* Phishing Kit Matches */}
          {raw.phishing_kit_matches && raw.phishing_kit_matches.length > 0 && (
            <DetectionCard
              title="Phishing Fingerprint"
              subtitle="DOM/Header analysis match"
              status={`${raw.phishing_kit_matches.length} kit(s) found`}
              isMalicious={true}
              iconName="phishing"
            >
              <div className="flex flex-col gap-1 mt-1">
                {raw.phishing_kit_matches.map((kit: string) => (
                  <span key={kit} className="text-[9px] font-mono-sm bg-error/20 border border-error/30 text-error px-1.5 py-0.5 rounded truncate">
                    {kit}
                  </span>
                ))}
              </div>
            </DetectionCard>
          )}

          {/* URLScan (only domains & urls) */}
          {(scan.type === "url" || scan.type === "domain") && (
            <DetectionCard
              title="URLScan Sandbox"
              subtitle="Visual screenshot & link safety check"
              status={urlscan.overall_status || (urlscan.screenshot_url ? "success" : "pending")}
              isMalicious={false}
              iconName="pageview"
            >
              <div className="relative mt-2 h-24 rounded border border-white/5 overflow-hidden group cursor-zoom-in bg-surface-container-low flex items-center justify-center">
                {urlscan.screenshot_url ? (
                  <img
                    src={urlscan.screenshot_url}
                    alt="URLScan Screenshot"
                    className="w-full h-full object-cover opacity-80 group-hover:opacity-100 transition-opacity"
                    onError={(e) => {
                      // Hide broken image, show fallback div
                      e.currentTarget.style.display = "none";
                      const parent = e.currentTarget.parentElement;
                      if (parent) {
                        const fallback = parent.querySelector('.fallback-ui');
                        if (fallback) fallback.classList.remove('hidden');
                        const overlay = parent.querySelector('.overlay-ui');
                        if (overlay) overlay.classList.add('hidden');
                      }
                    }}
                  />
                ) : null}
                
                <div className={`fallback-ui flex flex-col items-center justify-center text-on-surface-variant/40 ${urlscan.screenshot_url ? 'hidden absolute inset-0' : 'w-full h-full'}`}>
                  <span className="material-symbols-outlined text-[24px] mb-1 opacity-50">image_not_supported</span>
                  <span className="text-[9px] font-mono-sm">Scan Pending or Unavailable</span>
                </div>

                {urlscan.screenshot_url && (
                  <div className="overlay-ui absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-all flex items-center justify-center">
                    <span className="text-[10px] text-white font-mono-sm">View sandbox report</span>
                  </div>
                )}
              </div>
            </DetectionCard>
          )}

          {/* OSINT / Local Data */}
          {scan.type === "domain" && (
            <DetectionCard
              title="OSINT WHOIS & DNS"
              subtitle="Domain registration & certificate data"
              status="records" isMalicious={false} iconName="lan"
            >
              <div className="text-[10px] font-mono-sm space-y-1 text-on-surface-variant">
                <div className="flex justify-between">
                  <span>Registrar:</span>
                  <span className="text-white truncate max-w-[100px]">{whois.registrar}</span>
                </div>
                <div className="flex justify-between">
                  <span>Expiry Date:</span>
                  <span className="text-white">{whois.expiration_date}</span>
                </div>
                <div className="flex justify-between">
                  <span>SSL Issuer:</span>
                  <span className="text-white truncate max-w-[100px]">{ssl.issuer}</span>
                </div>
                {raw.historical_whois_changes && raw.historical_whois_changes.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-white/10">
                        <span className="text-[9px] text-error font-bold block mb-1">⚠️ WHOIS CHANGES DETECTED:</span>
                        {raw.historical_whois_changes.map((c: string, idx: number) => (
                            <p key={idx} className="text-white leading-tight mb-1">{c}</p>
                        ))}
                    </div>
                )}
              </div>
            </DetectionCard>
          )}
        </div>
      </div>

      {/* Advanced Live OSINT Telemetry */}
      <AdvancedOsintPanels scan={scan} />

      {/* DomainScan Analytics */}
      {scan.raw_data?.domainscan && (
        <div className="mt-8">
          <DomainScanMetrics data={scan.raw_data.domainscan} />
        </div>
      )}

      {/* WhoisJSON Deep Inspection */}
      {scan.raw_data?.whoisjson && (
        <WhoisJsonData data={scan.raw_data.whoisjson} />
      )}

      {/* SpiderFoot Deep OSINT Section */}
      <SpiderfootPanel target={scan.indicator} />

      {/* ── Web Security Audit ───────────────────────────── */}
      {webVulnData && (scan.type === "domain" || scan.type === "url") && (
        <div className="mt-8">
          <h3 className="font-bold font-label-caps text-[12px] text-on-surface-variant uppercase tracking-wider mb-4 flex items-center gap-2">
            <span className="material-symbols-outlined text-[14px] text-primary">security_update_warning</span>
            Web Security Audit
            {webVulnData.status === "success" && (
              <span className={`text-[9px] px-1.5 py-0.5 rounded border font-mono ${
                webVulnData.vulnerabilities?.length > 0
                  ? "bg-error/20 text-error border-error/30"
                  : "bg-green-500/20 text-green-400 border-green-500/30"
              }`}>
                {webVulnData.vulnerabilities?.length > 0
                  ? `${webVulnData.vulnerabilities.length} ISSUES FOUND`
                  : "ALL CLEAR"}
              </span>
            )}
          </h3>
          <WebVulnReport data={webVulnData} />
        </div>
      )}

      {/* MITRE ATT&CK Matrix Grid Mapping */}
      <div className="glass-panel p-lg rounded-xl relative">
        <div className="flex items-center justify-between border-b border-white/5 pb-2 mb-4">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-[20px]">grid_view</span>
            <div>
              <h3 className="font-bold text-white text-md font-headline-sm">MITRE ATT&CK Tactics</h3>
              <p className="text-[11px] text-on-surface-variant font-body-sm">
                Adversary tactics mapped against telemetry indicators.
              </p>
            </div>
          </div>
          <button 
            onClick={() => setShowMitreHelp(true)}
            className="text-xs text-primary hover:bg-primary/10 border border-primary/20 px-2 py-1 rounded transition-colors flex items-center gap-1"
          >
            <span className="material-symbols-outlined text-[14px]">help</span>
            What is this?
          </button>
        </div>

        {!hasMitreTactics ? (
          <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 p-6 rounded-xl flex flex-col items-center justify-center space-y-2 text-center shadow-[0_0_15px_rgba(16,185,129,0.1)]">
            <motion.svg 
              initial={{ pathLength: 0 }} 
              animate={{ pathLength: 1 }} 
              transition={{ duration: 1.5, ease: "easeInOut" }}
              viewBox="0 0 24 24" 
              fill="none" 
              stroke="currentColor" 
              strokeWidth="2" 
              strokeLinecap="round" 
              strokeLinejoin="round" 
              className="w-10 h-10 text-emerald-400 mb-1"
            >
              <polyline points="20 6 9 17 4 12" />
            </motion.svg>
            <h4 className="font-bold font-headline-sm text-lg">ALL CLEAR</h4>
            <p className="text-xs max-w-sm opacity-80">No known hacker tactics or techniques were detected from this indicator during our scan.</p>
          </div>
        ) : (
          <motion.div 
            initial="hidden"
            animate="show"
            variants={{
              hidden: { opacity: 0 },
              show: { opacity: 1, transition: { staggerChildren: 0.1 } }
            }}
            className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3"
          >
            {mitreTactics.map((t) => (
              <motion.div
                key={t.id}
                variants={{
                  hidden: { scale: 0.8, opacity: 0 },
                  show: { scale: 1, opacity: 1, transition: { type: "spring" as const, stiffness: 200 } }
                }}
                whileHover={t.active ? { scale: 1.05, boxShadow: "0 0 25px rgba(239,68,68,0.6)" } : {}}
                title={t.desc}
                className={`p-3 rounded-lg border flex flex-col justify-between min-h-[90px] transition-colors duration-300 cursor-help ${
                  t.active
                    ? "bg-[#93000a]/20 text-[#ffb4ab] border-[#ffb4ab]/40 shadow-[0_0_15px_rgba(239,68,68,0.4)]"
                    : "bg-surface-container-low text-on-surface-variant/40 border-white/5 opacity-50"
                }`}
              >
                <div className="space-y-1">
                  <span className="text-[9px] font-mono-sm block uppercase tracking-wider">{t.id}</span>
                  <span className="text-xs font-bold font-headline-sm block tracking-tight leading-tight">{t.name}</span>
                </div>
                {t.active && (
                  <span className="text-[8px] font-mono-sm block text-on-surface-variant/80 truncate mt-2 border-t border-[#ffb4ab]/20 pt-1">
                    {t.technique}
                  </span>
                )}
              </motion.div>
            ))}
          </motion.div>
        )}
      </div>

      {/* ── Relationship Graph Tab ─────────────────────────────────── */}
      <div className="glass-panel rounded-xl overflow-hidden">
        <div className="flex border-b border-white/5">
          {(["overview", "graph", "notes"] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-3 text-xs font-bold font-mono-sm uppercase tracking-wider transition-all ${
                activeTab === tab
                  ? "text-primary border-b-2 border-primary bg-primary/5"
                  : "text-on-surface-variant hover:text-white"
              }`}
            >
              {tab === "graph" ? "Relationship Graph" : tab === "notes" ? "Community Notes" : "Correlated IOCs"}
            </button>
          ))}
        </div>
        <div className="p-5">
          {activeTab === "overview" && (
            <div>
              {(() => {
                const corr = (scan as any)?.correlation;
                const subnetMatches = corr?.subnet_matches || [];
                const asnMatches = corr?.asn_matches || [];
                const domainMatches = corr?.domain_matches || [];
                const allMatches = [...subnetMatches, ...asnMatches, ...domainMatches];
                if (allMatches.length === 0) {
                  return (
                    <div className="flex flex-col items-center justify-center py-10 text-center">
                      <span className="material-symbols-outlined text-[40px] text-on-surface-variant/20 mb-3">hub</span>
                      <p className="text-sm text-on-surface-variant">No correlated IOCs found in the database.</p>
                      <p className="text-xs text-on-surface-variant/50 mt-1">Scan more related infrastructure to build correlations.</p>
                    </div>
                  );
                }
                return (
                  <div className="space-y-4">
                    {subnetMatches.length > 0 && (
                      <div>
                        <p className="text-[10px] font-mono-sm uppercase text-on-surface-variant tracking-wider mb-2">Same /24 Subnet ({subnetMatches.length})</p>
                        <div className="space-y-2">
                          {subnetMatches.map((m: any) => (
                            <Link key={m.scan_id} href={`/results/${m.scan_id}`} className="flex items-center gap-3 p-3 rounded-lg bg-surface-container-low border border-white/5 hover:border-primary/30 transition-all">
                              <span className="material-symbols-outlined text-primary text-[16px]">sensors</span>
                              <span className="text-sm text-white font-mono-sm flex-1">{m.indicator}</span>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                m.risk_level === "CRITICAL" ? "text-[#ffb4ab] bg-[#93000a]/20 border-[#ffb4ab]/25" :
                                m.risk_level === "HIGH" ? "text-orange-400 bg-orange-500/10 border-orange-500/20" :
                                "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                              }`}>{m.risk_level}</span>
                            </Link>
                          ))}
                        </div>
                      </div>
                    )}
                    {asnMatches.length > 0 && (
                      <div>
                        <p className="text-[10px] font-mono-sm uppercase text-on-surface-variant tracking-wider mb-2">Same ASN ({asnMatches.length})</p>
                        <div className="space-y-2">
                          {asnMatches.map((m: any) => (
                            <Link key={m.scan_id} href={`/results/${m.scan_id}`} className="flex items-center gap-3 p-3 rounded-lg bg-surface-container-low border border-white/5 hover:border-primary/30 transition-all">
                              <span className="material-symbols-outlined text-sky-400 text-[16px]">account_tree</span>
                              <span className="text-sm text-white font-mono-sm flex-1">{m.indicator}</span>
                              <span className="text-[10px] text-on-surface-variant">{m.org}</span>
                            </Link>
                          ))}
                        </div>
                      </div>
                    )}
                    {domainMatches.length > 0 && (
                      <div>
                        <p className="text-[10px] font-mono-sm uppercase text-on-surface-variant tracking-wider mb-2">Same Domain Family ({domainMatches.length})</p>
                        <div className="space-y-2">
                          {domainMatches.map((m: any) => (
                            <Link key={m.scan_id} href={`/results/${m.scan_id}`} className="flex items-center gap-3 p-3 rounded-lg bg-surface-container-low border border-white/5 hover:border-primary/30 transition-all">
                              <span className="material-symbols-outlined text-emerald-400 text-[16px]">language</span>
                              <span className="text-sm text-white font-mono-sm flex-1">{m.indicator}</span>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                m.risk_level === "CRITICAL" ? "text-[#ffb4ab] bg-[#93000a]/20 border-[#ffb4ab]/25" : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                              }`}>{m.risk_level}</span>
                            </Link>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          )}
          {activeTab === "graph" && (
            <RelationshipGraph
              nodes={[
                { id: scan!.id, label: scan!.indicator, type: "ioc", risk: scan!.risk_score },
                ...((scan as any)?.correlation?.asn_matches || []).map((m: any) => ({ id: m.scan_id + "_asn", label: m.org || "ASN", type: "asn" as const })),
                ...((scan as any)?.correlation?.subnet_matches || []).slice(0, 8).map((m: any) => ({ id: m.scan_id, label: m.indicator, type: "ioc" as const, risk: m.risk_score })),
                ...(scan!.linked_actors || []).map(a => ({ id: a.name, label: a.name, type: "actor" as const })),
              ]}
              edges={[
                ...((scan as any)?.correlation?.asn_matches || []).map((m: any) => ({ from: scan!.id, to: m.scan_id + "_asn", label: "same ASN" })),
                ...((scan as any)?.correlation?.subnet_matches || []).slice(0, 8).map((m: any) => ({ from: scan!.id, to: m.scan_id, label: "/24" })),
                ...(scan!.linked_actors || []).map(a => ({ from: a.name, to: scan!.id, label: "attributed" })),
              ]}
            />
          )}
          {activeTab === "notes" && scan && (
            <CommunityNotes indicator={scan.indicator} />
          )}
        </div>
      </div>

      {/* MITRE Info Modal */}
      {showMitreHelp && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass-panel p-lg rounded-xl max-w-sm w-full space-y-4">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-[24px]">info</span>
              <h3 className="text-lg font-bold text-white">What is MITRE ATT&CK?</h3>
            </div>
            <p className="text-sm text-on-surface-variant leading-relaxed">
              MITRE ATT&CK is a global knowledge base of hacker tactics and techniques based on real-world observations.
              <br/><br/>
              When we see a specific tactic highlighted in red, it means we detected behavior that matches how cybercriminals operate (e.g., trying to steal passwords or encrypt data).
            </p>
            <div className="flex justify-end pt-2 border-t border-white/5">
              <button
                onClick={() => setShowMitreHelp(false)}
                className="py-2 px-6 rounded-lg bg-primary text-on-primary text-xs font-bold hover:opacity-90 transition-opacity"
              >
                GOT IT
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add to Campaign Modal */}
      <AnimatePresence>
        {showCampaignModal && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          >
            <motion.div
              initial={{ scale: 0.9 }} animate={{ scale: 1 }} exit={{ scale: 0.9 }}
              className="glass-panel p-lg rounded-xl max-w-md w-full space-y-4"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Target size={18} className="text-primary" /> Add to Campaign
                </h3>
                <button onClick={() => setShowCampaignModal(false)} className="text-on-surface-variant hover:text-white"><X size={18} /></button>
              </div>
              <p className="text-xs text-on-surface-variant">Select a campaign to add <strong className="text-white">{scan?.indicator}</strong> to:</p>
              {campaigns.length === 0 ? (
                <div className="py-6 text-center">
                  <p className="text-sm text-on-surface-variant">No campaigns found.</p>
                  <Link href="/campaigns" className="text-xs text-primary mt-2 block">Create one on the Campaigns page →</Link>
                </div>
              ) : (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {campaigns.map((c: any) => (
                    <button
                      key={c.id}
                      disabled={addingToCampaign === c.id}
                      onClick={async () => {
                        if (!scan) return;
                        setAddingToCampaign(c.id);
                        try {
                          await api.addIOCToCampaign(c.id, scan.id);
                          setShowCampaignModal(false);
                        } catch (e: any) {
                          if (e?.response?.status === 409) alert("Already in this campaign.");
                        } finally { setAddingToCampaign(null); }
                      }}
                      className="w-full text-left p-3 rounded-lg bg-surface-container-low border border-white/5 hover:border-primary/30 transition-all flex items-center justify-between"
                    >
                      <div>
                        <p className="text-sm font-bold text-white">{c.name}</p>
                        <p className="text-[10px] text-on-surface-variant">{c.ioc_count} IOCs</p>
                      </div>
                      {addingToCampaign === c.id && <span className="text-[10px] text-primary">Adding...</span>}
                    </button>
                  ))}
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Add To Watchlist Modal */}
      {showWatchModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass-panel p-lg rounded-xl max-w-md w-full space-y-4">
            <h3 className="text-lg font-bold text-white">Watch Threat Indicator</h3>
            <p className="text-xs text-on-surface-variant">
              System will track <strong>{scan.indicator}</strong> and trigger real-time alerts if its threat reputation shifts.
            </p>
            <div className="space-y-1.5">
              <label className="text-[10px] font-mono-sm uppercase text-on-surface-variant">Watcher Notes</label>
              <textarea
                value={watchNotes}
                onChange={(e) => setWatchNotes(e.target.value)}
                placeholder="e.g. Host suspected to run command server relay..."
                className="w-full bg-surface-container-lowest border border-white/10 rounded-lg p-3 text-xs text-on-surface focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary/50 h-24"
              />
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowWatchModal(false)}
                className="py-2 px-4 rounded-lg bg-transparent text-white border border-white/10 text-xs font-bold"
              >
                CANCEL
              </button>
              <button
                onClick={handleAddToWatchlist}
                className="py-2 px-4 rounded-lg bg-primary text-on-primary text-xs font-bold"
              >
                ADD TO WATCH
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Floating Help Button ────────────────────────────────────────── */}
      <button
        onClick={() => setShowSidebar(true)}
        className="fixed bottom-6 right-6 z-40 w-12 h-12 rounded-full bg-primary text-on-primary shadow-lg hover:scale-110 active:scale-95 transition-all duration-200 flex items-center justify-center text-lg font-black"
        title="Open Glossary"
      >
        ?
      </button>

      {/* ── Threat Explainer Sidebar ─────────────────────────────────────── */}
      {showSidebar && (
        <div className="fixed inset-0 z-50 flex justify-end">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/50 backdrop-blur-sm"
            onClick={() => setShowSidebar(false)}
          />
          {/* Panel */}
          <div className="relative w-full max-w-sm bg-surface border-l border-white/10 shadow-2xl flex flex-col h-full overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between p-5 border-b border-white/5 shrink-0 bg-surface-container-low">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-primary text-[22px]">menu_book</span>
                <div>
                  <h3 className="font-bold text-white text-sm">Security Glossary</h3>
                  <p className="text-[10px] text-on-surface-variant">Plain-English explanations</p>
                </div>
              </div>
              <button
                onClick={() => setShowSidebar(false)}
                className="p-1.5 rounded-lg hover:bg-white/10 text-on-surface-variant hover:text-white transition-colors"
              >
                <span className="material-symbols-outlined text-[18px]">close</span>
              </button>
            </div>

            {/* Glossary entries */}
            <div className="flex-1 overflow-y-auto p-5 space-y-1 hide-scrollbar">
              {[
                {
                  term: "IP Address",
                  icon: "router",
                  def: "A unique number assigned to every device connected to the internet, like a home address for your computer. Example: 192.168.1.1",
                },
                {
                  term: "Domain",
                  icon: "language",
                  def: "The human-readable name of a website, like \"google.com\". It maps to an IP address behind the scenes.",
                },
                {
                  term: "Risk Score",
                  icon: "speed",
                  def: "A number from 0–100 showing how dangerous something is. 0 = completely safe, 100 = confirmed threat. We calculate it by combining multiple security feeds.",
                },
                {
                  term: "VirusTotal",
                  icon: "security",
                  def: "A free Google-owned service that scans files and websites with 90+ antivirus engines simultaneously. If many engines flag it, it's very likely dangerous.",
                },
                {
                  term: "AbuseIPDB",
                  icon: "gpp_bad",
                  def: "A community-driven database where internet users and companies report IP addresses that have sent spam, tried to hack systems, or behaved maliciously.",
                },
                {
                  term: "GreyNoise",
                  icon: "hearing",
                  def: "A service that watches the entire internet for scanners and bots. If an IP is in GreyNoise, it means it has been observed scanning the internet — possibly looking for targets.",
                },
                {
                  term: "MITRE ATT&CK",
                  icon: "grid_view",
                  def: "A free encyclopedia of hacker tactics and techniques built from real cyberattack data. When a tactic lights up red, it means we detected behaviour matching that attack pattern.",
                },
                {
                  term: "IOC (Indicator of Compromise)",
                  icon: "crisis_alert",
                  def: "Any piece of evidence — like an IP address, URL, or file — that suggests a computer system may have been breached or is being attacked.",
                },
                {
                  term: "ASN (Autonomous System)",
                  icon: "account_tree",
                  def: "The company that owns and operates a block of IP addresses and their internet connection. Think of it as the landlord of a group of IP addresses.",
                },
                {
                  term: "WHOIS",
                  icon: "person_search",
                  def: "A public record showing who registered a domain name, when it was registered, and when it expires — like a property registry for websites.",
                },
                {
                  term: "SSL Certificate",
                  icon: "verified_user",
                  def: "A digital certificate that proves a website is who it claims to be. Websites with HTTPS have one. If a site's SSL is suspicious, it may be fake or expired.",
                },
              ].map((entry) => (
                <div
                  key={entry.term}
                  className="p-4 rounded-xl bg-surface-container-low border border-white/5 hover:border-white/10 transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="material-symbols-outlined text-primary text-[16px]">{entry.icon}</span>
                    <h4 className="font-bold text-white text-sm">{entry.term}</h4>
                  </div>
                  <p className="text-[12px] text-on-surface-variant leading-relaxed">{entry.def}</p>
                </div>
              ))}
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-white/5 shrink-0 bg-surface-container-lowest">
              <p className="text-[10px] text-on-surface-variant/60 text-center font-mono-sm">
                ThreatMap Security Glossary · v1.0
              </p>
            </div>
          </div>
        </div>
      )}

    </div>

  );
}
