"use client";

import React, { useState } from "react";

interface Vulnerability {
  type: string;
  severity: "High" | "Medium" | "Low";
  description: string;
  fix_code: string;
  fix_lang: string;
  fix_hint: string;
}

interface WebVulnReportProps {
  data: {
    domain: string;
    vulnerabilities: Vulnerability[];
    security_score: number;
    total_checks: number;
    checks_passed: number;
    status: string;
  };
}

const SEVERITY_CONFIG = {
  High:   { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",   dot: "bg-red-400",    ring: "ring-red-500/20" },
  Medium: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", dot: "bg-orange-400", ring: "ring-orange-500/20" },
  Low:    { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", dot: "bg-yellow-400", ring: "ring-yellow-500/20" },
};

function ScoreArc({ score }: { score: number }) {
  const r = 52;
  const cx = 64, cy = 64;
  const circumference = 2 * Math.PI * r;
  const filled = (score / 100) * circumference;
  const color = score >= 70 ? "#4ade80" : score >= 40 ? "#fb923c" : "#f87171";

  return (
    <svg width="128" height="128" className="drop-shadow-lg">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
      <circle
        cx={cx} cy={cy} r={r} fill="none"
        stroke={color} strokeWidth="10"
        strokeDasharray={`${filled} ${circumference}`}
        strokeLinecap="round"
        transform="rotate(-90 64 64)"
        style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dasharray 1s ease" }}
      />
      <text x={cx} y={cy - 6} textAnchor="middle" fill="white" fontSize="22" fontWeight="bold" fontFamily="JetBrains Mono, monospace">
        {score}
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="9" fontFamily="JetBrains Mono, monospace">
        /100
      </text>
    </svg>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button
      onClick={copy}
      className="flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded bg-white/5 hover:bg-white/10 border border-white/10 text-on-surface-variant hover:text-white transition-all"
    >
      <span className="material-symbols-outlined text-[12px]">{copied ? "check" : "content_copy"}</span>
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

function VulnCard({ vuln, idx }: { vuln: Vulnerability; idx: number }) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEVERITY_CONFIG[vuln.severity] || SEVERITY_CONFIG.Low;

  return (
    <div
      className={`rounded-xl border ${sev.border} ${sev.bg} overflow-hidden transition-all duration-300`}
      style={{ animationDelay: `${idx * 80}ms` }}
    >
      {/* Header Row */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-3 text-left hover:bg-white/5 transition-all"
      >
        <div className={`w-2 h-2 rounded-full shrink-0 ${sev.dot} shadow-[0_0_6px] ${sev.ring}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-bold font-mono uppercase tracking-wider ${sev.color}`}>
              [{vuln.severity}]
            </span>
            <span className="text-white text-xs font-semibold truncate">{vuln.type}</span>
          </div>
          <p className="text-[10px] text-on-surface-variant mt-0.5 line-clamp-1">{vuln.description}</p>
        </div>
        <span className={`material-symbols-outlined text-[16px] text-on-surface-variant shrink-0 transition-transform ${expanded ? "rotate-180" : ""}`}>
          expand_more
        </span>
      </button>

      {/* Expanded Detail */}
      {expanded && (
        <div className="px-3 pb-3 border-t border-white/5 space-y-3 pt-3">
          {/* Full Description */}
          <p className="text-[11px] text-on-surface-variant leading-relaxed">{vuln.description}</p>

          {/* Fix Code Block */}
          <div className="rounded-lg overflow-hidden border border-white/10">
            <div className="flex items-center justify-between px-3 py-1.5 bg-surface-container border-b border-white/10">
              <div className="flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[12px] text-primary">code</span>
                <span className="text-[9px] text-primary font-mono uppercase tracking-widest">Fix: {vuln.fix_lang}</span>
              </div>
              <CopyButton text={vuln.fix_code} />
            </div>
            <pre className="p-3 text-[10px] font-mono text-green-300 bg-[#0a0f1e] overflow-x-auto leading-relaxed whitespace-pre-wrap break-words">
              {vuln.fix_code}
            </pre>
          </div>

          {/* Hint */}
          {vuln.fix_hint && (
            <div className="flex gap-2 p-2 bg-primary/5 border border-primary/20 rounded-lg">
              <span className="material-symbols-outlined text-[14px] text-primary shrink-0 mt-0.5">lightbulb</span>
              <p className="text-[10px] text-on-surface-variant leading-relaxed">{vuln.fix_hint}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function WebVulnReport({ data }: WebVulnReportProps) {
  if (!data || data.status === "error") {
    return (
      <div className="glass-panel rounded-xl p-4 border border-white/5 text-center text-on-surface-variant text-xs font-mono-sm">
        <span className="material-symbols-outlined text-[20px] block mb-1 opacity-40">wifi_off</span>
        Web vulnerability scan unavailable for this target.
      </div>
    );
  }

  const highCount = data.vulnerabilities?.filter(v => v.severity === "High").length || 0;
  const medCount  = data.vulnerabilities?.filter(v => v.severity === "Medium").length || 0;
  const lowCount  = data.vulnerabilities?.filter(v => v.severity === "Low").length || 0;

  return (
    <div className="glass-panel rounded-xl p-5 border border-white/5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-primary">security_update_warning</span>
            Web Security Audit
          </h3>
          <p className="text-[10px] text-on-surface-variant font-mono mt-0.5">
            Active header scan · {data.domain}
          </p>
        </div>
        <div className="text-right">
          <div className="text-[9px] text-on-surface-variant font-mono uppercase tracking-wider mb-1">Security Score</div>
          <ScoreArc score={data.security_score ?? 0} />
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-3 gap-2 text-center">
        {[
          { label: "High", count: highCount, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
          { label: "Medium", count: medCount, color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20" },
          { label: "Low", count: lowCount, color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20" },
        ].map(s => (
          <div key={s.label} className={`rounded-lg border p-2 ${s.bg}`}>
            <div className={`text-xl font-black font-mono ${s.color}`}>{s.count}</div>
            <div className="text-[9px] text-on-surface-variant font-mono uppercase tracking-wider">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Checks Passed */}
      <div>
        <div className="flex justify-between text-[10px] font-mono-sm mb-1.5">
          <span className="text-on-surface-variant">Checks Passed</span>
          <span className="text-white font-bold">{data.checks_passed} / {data.total_checks}</span>
        </div>
        <div className="w-full h-2 bg-white/5 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full bg-gradient-to-r from-primary to-green-400 transition-all duration-1000"
            style={{ width: `${(data.checks_passed / data.total_checks) * 100}%` }}
          />
        </div>
      </div>

      {/* Vuln List */}
      {(data.vulnerabilities?.length || 0) > 0 ? (
        <div className="space-y-2">
          <p className="text-[10px] font-mono uppercase text-on-surface-variant tracking-wider flex items-center gap-1.5">
            <span className="material-symbols-outlined text-[12px] text-error">bug_report</span>
            Findings &amp; Remediations ({data.vulnerabilities?.length || 0})
          </p>
          {data.vulnerabilities?.map((v, i) => (
            <VulnCard key={i} vuln={v} idx={i} />
          ))}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-4 text-success gap-2">
          <span className="material-symbols-outlined text-[32px]">verified_user</span>
          <span className="text-sm font-bold">No Vulnerabilities Detected</span>
          <span className="text-[10px] text-on-surface-variant font-mono">All {data.total_checks} security checks passed.</span>
        </div>
      )}
    </div>
  );
}
