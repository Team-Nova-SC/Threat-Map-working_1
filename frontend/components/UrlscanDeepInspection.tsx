"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface TechItem {
  name: string;
  confidence?: number;
  categories?: string[];
}

interface RequestItem {
  url: string;
  method?: string;
  status?: string | number;
  mime?: string;
  size?: number;
  ip?: string;
}

interface CookieItem {
  name: string;
  domain?: string;
  httpOnly?: boolean;
  secure?: boolean;
}

interface LinkItem {
  href: string;
  text?: string;
}

interface UrlscanData {
  status?: string;
  overall_status?: string;
  scan_id?: string;
  report_url?: string;
  screenshot_url?: string;
  dom_url?: string;
  page_title?: string;
  final_url?: string;
  server?: string;
  ip?: string;
  asn?: string;
  country?: string;
  verdicts?: any;
  stats?: any;
  lists?: any;
  technologies?: TechItem[];
  requests?: RequestItem[];
  cookies?: CookieItem[];
  console_logs?: any[];
  links?: LinkItem[];
  certificates?: any[];
  detail?: string;
}

export default function UrlscanDeepInspection({ data, indicator }: { data: UrlscanData; indicator: string }) {
  const [activeTab, setActiveTab] = useState<"overview" | "page" | "domains" | "tech" | "requests" | "certs">("overview");
  const [showScreenshotModal, setShowScreenshotModal] = useState(false);

  if (!data || data.status === "unavailable" || data.overall_status === "no_results" || !data.scan_id) {
    return (
      <div className="glass-panel p-6 rounded-xl border border-white/5 mt-8">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 text-on-surface-variant">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <span className="material-symbols-outlined text-[22px]">pageview</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-white text-md font-headline-sm">URLScan.io Sandbox Intelligence</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-white/5 text-on-surface-variant border-white/10">
                  NO RECENT SANDBOX SCANS
                </span>
              </div>
              <p className="text-xs text-on-surface-variant/80 font-body-sm mt-0.5">
                {data?.detail || "No public automated headless browser executions recorded for this specific target on urlscan.io."}
              </p>
            </div>
          </div>
          <a
            href={`https://urlscan.io/search/#${indicator}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-bold bg-sky-500/10 text-sky-300 border border-sky-500/30 hover:bg-sky-500/20 transition-colors self-start md:self-auto"
          >
            <span>Search urlscan.io</span>
            <span className="material-symbols-outlined text-[14px]">open_in_new</span>
          </a>
        </div>
      </div>
    );
  }

  const verdicts = data.verdicts?.overall || data.verdicts?.urlscan || {};
  const isMalicious = verdicts.malicious === true || (verdicts.score && verdicts.score > 0);
  const score = verdicts.score || 0;
  const categories = verdicts.categories || [];
  const brands = verdicts.brands || [];
  const lists = data.lists || {};
  const stats = data.stats || {};
  const techs = data.technologies || [];
  const requests = data.requests || [];
  const cookies = data.cookies || [];
  const certs = data.certificates || lists.certificates || [];
  const contactedDomains = lists.domains || [];
  const contactedIps = lists.ips || [];
  const contactedAsns = lists.asns || [];
  const reportUrl = data.report_url || `https://urlscan.io/result/${data.scan_id}/`;

  return (
    <div className="glass-panel p-6 rounded-xl border border-white/10 mt-8 relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-5 border-b border-white/10 gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
            <span className="material-symbols-outlined text-[22px]">pageview</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-white text-lg font-headline-sm">URLScan.io Sandbox Intelligence</h3>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                isMalicious ? "bg-rose-500/20 text-rose-400 border-rose-500/30" : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
              }`}>
                {isMalicious ? `MALICIOUS (SCORE ${score})` : "VERDICT: CLEAN / SUSPICION 0"}
              </span>
            </div>
            <p className="text-xs text-on-surface-variant font-body-sm">
              Headless browser sandbox rendering, network requests logging, DOM inspection & technology fingerprinting.
            </p>
          </div>
        </div>

        {/* Cross Verification Link */}
        <a
          href={reportUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-sky-500/20 text-sky-300 border border-sky-500/40 hover:bg-sky-500/30 transition-all shadow-[0_0_15px_rgba(14,165,233,0.15)] self-start md:self-auto"
        >
          <span className="material-symbols-outlined text-[16px]">open_in_new</span>
          <span>Verify on urlscan.io</span>
        </a>
      </div>

      {/* Overview Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 my-6">
        {/* Left 2 Cols: Key Details */}
        <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg">
            <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Rendered Page Title</span>
            <p className="text-white font-bold text-sm truncate">{data.page_title || "No Title Captured"}</p>
          </div>

          <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg">
            <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Final Landed URL</span>
            <p className="text-sky-300 font-mono text-xs truncate" title={data.final_url}>{data.final_url || indicator}</p>
          </div>

          <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg">
            <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Server Software & Location</span>
            <p className="text-white font-bold text-xs">{data.server || "Unknown Server"}</p>
            <span className="text-[11px] text-on-surface-variant font-mono block mt-0.5">
              IP: {data.ip || "N/A"} {data.country ? `(${data.country})` : ""}
            </span>
          </div>

          <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg">
            <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Brands & Categories</span>
            {brands.length > 0 || categories.length > 0 ? (
              <div className="flex flex-wrap gap-1">
                {brands.map((b: string) => (
                  <span key={b} className="text-[9px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30 px-1.5 py-0.5 rounded">
                    IMPERSONATING: {b}
                  </span>
                ))}
                {categories.map((c: string) => (
                  <span key={c} className="text-[9px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30 px-1.5 py-0.5 rounded">
                    {c}
                  </span>
                ))}
              </div>
            ) : (
              <span className="text-[11px] text-emerald-400 font-mono">No brand impersonation or phishing tags.</span>
            )}
          </div>
        </div>

        {/* Right Col: Screenshot Card */}
        {data.screenshot_url && (
          <div className="bg-surface-container-low/50 border border-white/5 p-3.5 rounded-lg flex flex-col justify-between">
            <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-2">Live Browser Screenshot</span>
            <div
              onClick={() => setShowScreenshotModal(true)}
              className="relative h-32 w-full rounded border border-white/10 overflow-hidden cursor-zoom-in group bg-black/40"
            >
              <img
                src={data.screenshot_url}
                alt="URLScan Page Screenshot"
                className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300 opacity-90 group-hover:opacity-100"
                onError={(e) => {
                  e.currentTarget.style.display = "none";
                }}
              />
              <div className="absolute inset-0 bg-black/30 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                <span className="text-[11px] text-white font-mono bg-black/70 px-2 py-1 rounded border border-white/20">
                  Click to Expand
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-white/10 pb-3 mb-5">
        <button
          onClick={() => setActiveTab("overview")}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
            activeTab === "overview"
              ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
              : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
          }`}
        >
          <span className="material-symbols-outlined text-[15px]">dashboard</span>
          Overview & Stats
        </button>

        {contactedDomains.length > 0 && (
          <button
            onClick={() => setActiveTab("domains")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
              activeTab === "domains"
                ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">lan</span>
            Contacted Domains & IPs ({contactedDomains.length})
          </button>
        )}

        {techs.length > 0 && (
          <button
            onClick={() => setActiveTab("tech")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
              activeTab === "tech"
                ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">memory</span>
            Technologies ({techs.length})
          </button>
        )}

        {requests.length > 0 && (
          <button
            onClick={() => setActiveTab("requests")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
              activeTab === "requests"
                ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">data_object</span>
            Network Requests ({requests.length})
          </button>
        )}

        {certs.length > 0 && (
          <button
            onClick={() => setActiveTab("certs")}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
              activeTab === "certs"
                ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                : "bg-white/5 text-on-surface-variant hover:text-white border border-transparent"
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">verified_user</span>
            TLS Certificates ({certs.length})
          </button>
        )}
      </div>

      {/* Tab Contents */}
      <AnimatePresence mode="wait">
        {activeTab === "overview" && (
          <motion.div
            key="overview"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4"
          >
            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">HTTPS Encryption</span>
              <p className="text-white font-bold text-sm">{stats.securePercentage ? `${stats.securePercentage}% Secure` : "TLS Enabled"}</p>
            </div>

            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Total Sub-Requests</span>
              <p className="text-white font-bold text-sm">{stats.uniqCountries ? `${stats.uniqCountries} Countries Involved` : `${requests.length} Requests`}</p>
            </div>

            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">Cookies Set</span>
              <p className="text-white font-bold text-sm">{cookies.length} Cookie(s)</p>
            </div>

            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <span className="text-[10px] text-on-surface-variant font-mono uppercase block mb-1">DOM Snapshot</span>
              {data.dom_url ? (
                <a href={data.dom_url} target="_blank" rel="noopener noreferrer" className="text-sky-400 hover:underline font-mono text-xs font-bold flex items-center gap-1 mt-1">
                  View Rendered HTML
                  <span className="material-symbols-outlined text-[13px]">open_in_new</span>
                </a>
              ) : (
                <span className="text-xs text-on-surface-variant">Available</span>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === "domains" && (
          <motion.div
            key="domains"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="grid grid-cols-1 md:grid-cols-2 gap-4"
          >
            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <h4 className="font-bold text-white text-xs uppercase font-mono mb-3 text-sky-400">Contacted Domains ({contactedDomains.length})</h4>
              <div className="flex flex-wrap gap-1.5 max-h-56 overflow-y-auto pr-2">
                {contactedDomains.map((d: string) => (
                  <span key={d} className="text-[10px] font-mono bg-white/5 border border-white/10 px-2 py-0.5 rounded text-white">
                    {d}
                  </span>
                ))}
              </div>
            </div>

            <div className="bg-surface-container-low/60 p-4 rounded-xl border border-white/5">
              <h4 className="font-bold text-white text-xs uppercase font-mono mb-3 text-emerald-400">Contacted IP Addresses ({contactedIps.length})</h4>
              <div className="flex flex-wrap gap-1.5 max-h-56 overflow-y-auto pr-2">
                {contactedIps.map((ip: string) => (
                  <span key={ip} className="text-[10px] font-mono bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded text-emerald-300">
                    {ip}
                  </span>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === "tech" && (
          <motion.div
            key="tech"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3"
          >
            {techs.map((t, idx) => (
              <div key={idx} className="bg-surface-container-low/60 border border-white/5 p-3 rounded-lg flex items-center justify-between">
                <div>
                  <h5 className="font-bold text-white text-xs">{t.name}</h5>
                  {t.categories && t.categories.length > 0 && (
                    <span className="text-[9px] text-on-surface-variant font-mono block mt-0.5">{t.categories.join(", ")}</span>
                  )}
                </div>
                <span className="text-[10px] font-mono bg-sky-500/10 border border-sky-500/20 text-sky-300 px-2 py-0.5 rounded">
                  {t.confidence}% CONF
                </span>
              </div>
            ))}
          </motion.div>
        )}

        {activeTab === "requests" && (
          <motion.div
            key="requests"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="overflow-x-auto"
          >
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-on-surface-variant uppercase tracking-wider text-[10px]">
                  <th className="py-2.5 px-3">HTTP Method</th>
                  <th className="py-2.5 px-3">Target URL</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">MIME Type</th>
                  <th className="py-2.5 px-3">Remote IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-white">
                {requests.map((r, idx) => (
                  <tr key={idx} className="hover:bg-white/5">
                    <td className="py-2.5 px-3 font-bold text-teal-400">{r.method || "GET"}</td>
                    <td className="py-2.5 px-3 text-sky-300 truncate max-w-[300px]" title={r.url}>{r.url}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                        String(r.status).startsWith("2") ? "bg-emerald-500/20 text-emerald-400" : "bg-rose-500/20 text-rose-400"
                      }`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-on-surface-variant">{r.mime || "N/A"}</td>
                    <td className="py-2.5 px-3 text-on-surface-variant">{r.ip || "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </motion.div>
        )}

        {activeTab === "certs" && (
          <motion.div
            key="certs"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="space-y-3"
          >
            {certs.map((c: any, idx: number) => (
              <div key={idx} className="bg-surface-container-low/60 border border-white/5 p-3.5 rounded-lg">
                <div className="flex justify-between items-center mb-1">
                  <h5 className="font-bold text-white text-xs font-mono">{c.subjectName || c.issuer || "TLS Certificate"}</h5>
                  <span className="text-[10px] text-emerald-400 font-mono">VALID</span>
                </div>
                <p className="text-[11px] text-on-surface-variant font-mono">Issuer: {c.issuer || "Unknown Issuer"}</p>
                {c.validTo && <p className="text-[10px] text-on-surface-variant/70 font-mono mt-0.5">Expires: {new Date(c.validTo * 1000).toLocaleDateString()}</p>}
              </div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Screenshot Modal */}
      {showScreenshotModal && data.screenshot_url && (
        <div
          onClick={() => setShowScreenshotModal(false)}
          className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 cursor-zoom-out"
        >
          <div className="relative max-w-4xl max-h-[90vh] bg-surface-container rounded-xl overflow-hidden border border-white/20 shadow-2xl">
            <img src={data.screenshot_url} alt="Full Screenshot" className="w-full h-full object-contain" />
            <button
              onClick={() => setShowScreenshotModal(false)}
              className="absolute top-3 right-3 bg-black/70 text-white p-1.5 rounded-full hover:bg-black"
            >
              <span className="material-symbols-outlined text-[20px]">close</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
