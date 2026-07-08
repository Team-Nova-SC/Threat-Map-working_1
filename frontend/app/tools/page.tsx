"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { api } from "@/lib/api";

const TOOLS = [
  { id: 'email', name: 'Email Header Analyzer', icon: 'mail', desc: 'Extract and analyze email headers for spoofing' },
  { id: 'typo', name: 'Typosquatting Detector', icon: 'spellcheck', desc: 'Find active variations of a domain' },
  { id: 'decode', name: 'Base64/Hex Decoder', icon: 'code_blocks', desc: 'Decode malicious payloads' },
  { id: 'dns', name: 'Full DNS Enumerator', icon: 'dns', desc: 'Dump all DNS records for a domain' },
  { id: 'shodan', name: 'Shodan InternetDB', icon: 'radar', desc: 'Free open ports & vulns check for an IP' },
  { id: 'mac', name: 'MAC Vendor Lookup', icon: 'router', desc: 'Identify hardware vendor from MAC address' },
  { id: 'network', name: 'Network Range Scanner', icon: 'hub', desc: 'Analyze CIDR blocks and sample host reputation' },
  { id: 'http', name: 'HTTP Security Headers', icon: 'http', desc: 'Check HSTS, CSP, X-Frame-Options' }
];

export default function ToolsPage() {
  const [activeTool, setActiveTool] = useState(TOOLS[0].id);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Decoder specific
  const [decodeType, setDecodeType] = useState("auto");

  const activeToolDef = TOOLS.find(t => t.id === activeTool);

  const handleToolChange = (id: string) => {
    setActiveTool(id);
    setInput("");
    setResult(null);
    setError(null);
  };

  const handleRun = async () => {
    if (!input.trim()) return;
    setIsLoading(true);
    setResult(null);
    setError(null);

    try {
      let res;
      switch (activeTool) {
        case 'email':
          res = await api.toolsEmailHeaders(input);
          break;
        case 'typo':
          res = await api.toolsTyposquatting(input);
          break;
        case 'decode':
          res = await api.toolsDecode(input, decodeType);
          break;
        case 'dns':
          res = await api.toolsDns(input);
          break;
        case 'shodan':
          res = await api.toolsShodan(input);
          break;
        case 'mac':
          res = await api.toolsMac(input);
          break;
        case 'network':
          res = await api.toolsNetworkRange(input);
          break;
        case 'http':
          res = await api.toolsHttpHeaders(input);
          break;
      }
      setResult(res);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || "An error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const renderResult = () => {
    if (isLoading) {
      return (
        <div className="flex flex-col items-center justify-center py-12 text-on-surface-variant space-y-4">
          <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="animate-pulse">Running tool...</p>
        </div>
      );
    }

    if (error) {
      return (
        <div className="bg-error-container/20 border border-error/50 p-4 rounded-xl text-error text-sm">
          <strong>Error:</strong> {error}
        </div>
      );
    }

    if (!result) return null;

    if (activeTool === 'decode') {
      return (
        <div className="space-y-4">
          <div className="flex gap-4 mb-2 text-xs">
            <span className="bg-primary/20 text-primary px-2 py-1 rounded">Detected Type: {result.type}</span>
          </div>
          <div className="bg-[#111827] border border-white/5 p-4 rounded-xl">
            <pre className="whitespace-pre-wrap break-all text-sm text-emerald-400 font-mono">{result.decoded}</pre>
          </div>
        </div>
      );
    }

    // Default JSON renderer for tools where custom UI isn't strictly necessary yet
    // I will build out nicer views for them gradually if requested, but for now a formatted JSON or structured view is best.
    if (activeTool === 'typo') {
      return (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-surface-container-low p-4 rounded-xl border border-white/5">
              <div className="text-xs text-on-surface-variant uppercase tracking-wider mb-1">Variations Checked</div>
              <div className="text-2xl font-bold text-white">{result.variations_checked}</div>
            </div>
            <div className="bg-error-container/10 p-4 rounded-xl border border-error/20">
              <div className="text-xs text-error uppercase tracking-wider mb-1">Active Typosquats</div>
              <div className="text-2xl font-bold text-error">{result.active_typosquats?.length || 0}</div>
            </div>
          </div>

          {result.active_typosquats?.length > 0 && (
            <div className="bg-[#111827] border border-white/5 rounded-xl overflow-hidden">
              <div className="px-4 py-3 bg-error/10 border-b border-error/20 text-error font-bold text-sm flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px]">warning</span>
                Active Resolving Domains
              </div>
              <ul className="divide-y divide-white/5">
                {result.active_typosquats.map((t: any, i: number) => (
                  <li key={i} className="p-4 flex justify-between items-center hover:bg-white/[0.02]">
                    <span className="text-white font-mono">{t.domain}</span>
                    <div className="flex gap-2">
                      {t.ips.map((ip: string) => (
                        <span key={ip} className="bg-white/5 text-xs text-on-surface-variant px-2 py-1 rounded border border-white/10">{ip}</span>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      );
    }

    if (activeTool === 'http') {
        return (
            <div className="space-y-6">
                <div className="flex items-center gap-4">
                    <div className={`w-16 h-16 rounded-full flex items-center justify-center text-2xl font-black ${
                        result.score >= 80 ? 'bg-emerald-500/20 text-emerald-400' : 
                        result.score >= 50 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-red-500/20 text-red-400'
                    }`}>
                        {result.score}
                    </div>
                    <div>
                        <h3 className="text-lg font-bold text-white">Security Score</h3>
                        <p className="text-sm text-on-surface-variant">Based on presence of standard security headers.</p>
                    </div>
                </div>

                {result.missing_headers?.length > 0 && (
                    <div className="bg-error-container/10 border border-error/20 p-4 rounded-xl">
                        <h4 className="text-error font-bold text-sm mb-2">Missing Headers (-20 pts each)</h4>
                        <div className="flex flex-wrap gap-2">
                            {result.missing_headers.map((h: string) => (
                                <span key={h} className="bg-error/20 text-error text-xs px-2 py-1 rounded font-mono">{h}</span>
                            ))}
                        </div>
                    </div>
                )}

                <div className="bg-[#111827] border border-white/5 rounded-xl overflow-hidden">
                    <table className="w-full text-left text-sm">
                        <tbody className="divide-y divide-white/5">
                            {Object.entries(result.security_headers).map(([k, v]) => (
                                <tr key={k}>
                                    <td className="p-3 font-mono text-on-surface-variant w-1/3">{k}</td>
                                    <td className={`p-3 font-mono ${v ? 'text-emerald-400' : 'text-on-surface-variant/30'}`}>
                                        {v ? (v as string) : 'Not Present'}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        )
    }

    // Generic fallback for others (Email, DNS, Shodan, Mac, Network Range)
    return (
      <div className="bg-[#111827] border border-white/5 p-4 rounded-xl overflow-auto max-h-[600px] custom-scrollbar">
        <pre className="text-xs text-emerald-400 font-mono">
          {JSON.stringify(result, null, 2)}
        </pre>
      </div>
    );
  };

  const getPlaceholder = () => {
      switch (activeTool) {
          case 'email': return "Paste raw email headers here...";
          case 'typo': return "example.com";
          case 'decode': return "Paste base64 or hex string...";
          case 'dns': return "example.com";
          case 'shodan': return "8.8.8.8";
          case 'mac': return "00:1A:2B:3C:4D:5E";
          case 'network': return "192.168.1.0/24";
          case 'http': return "https://example.com";
          default: return "Enter input...";
      }
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-in fade-in duration-500 pb-12 px-4 md:px-8 mt-6">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black text-white font-headline-lg tracking-wider">
            STANDALONE <span className="text-primary font-light">TOOLS</span>
          </h1>
          <p className="text-on-surface-variant text-sm mt-1">
            Quick-access utilities for threat intelligence and forensic analysis.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar Navigation */}
        <div className="lg:col-span-1 space-y-2">
          {TOOLS.map(tool => (
            <button
              key={tool.id}
              onClick={() => handleToolChange(tool.id)}
              className={`w-full text-left px-4 py-3 rounded-xl border flex items-center gap-3 transition-all ${
                activeTool === tool.id
                  ? 'bg-primary/10 border-primary/30 text-primary'
                  : 'bg-surface-container border-white/5 text-on-surface-variant hover:bg-white/5 hover:text-white'
              }`}
            >
              <span className="material-symbols-outlined text-[20px]">{tool.icon}</span>
              <div className="flex flex-col">
                <span className="font-bold text-sm">{tool.name}</span>
              </div>
            </button>
          ))}
        </div>

        {/* Main Content Area */}
        <div className="lg:col-span-3">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTool}
              initial={{ opacity: 0, x: 10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2 }}
              className="bg-surface glass-panel border border-white/5 rounded-2xl p-6 min-h-[500px] flex flex-col"
            >
              <div className="flex items-center gap-3 mb-2">
                <span className="material-symbols-outlined text-primary text-[28px]">{activeToolDef?.icon}</span>
                <h2 className="text-2xl font-bold text-white">{activeToolDef?.name}</h2>
              </div>
              <p className="text-on-surface-variant text-sm mb-6 pb-6 border-b border-white/5">
                {activeToolDef?.desc}
              </p>

              <div className="space-y-6 flex-1">
                {activeTool === 'email' || activeTool === 'decode' ? (
                  <textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={getPlaceholder()}
                    className="w-full bg-[#111827] border border-white/10 rounded-xl p-4 text-sm text-white font-mono focus:ring-1 focus:ring-primary focus:border-primary resize-y min-h-[150px]"
                  />
                ) : (
                  <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={getPlaceholder()}
                    className="w-full bg-[#111827] border border-white/10 rounded-xl px-4 py-3 text-sm text-white font-mono focus:ring-1 focus:ring-primary focus:border-primary"
                    onKeyDown={(e) => e.key === 'Enter' && handleRun()}
                  />
                )}

                {activeTool === 'decode' && (
                  <div className="flex gap-4">
                    <label className="flex items-center gap-2 text-sm text-on-surface-variant cursor-pointer">
                      <input type="radio" name="dtype" value="auto" checked={decodeType==='auto'} onChange={e => setDecodeType(e.target.value)} className="text-primary focus:ring-primary bg-black border-white/20"/>
                      Auto-Detect
                    </label>
                    <label className="flex items-center gap-2 text-sm text-on-surface-variant cursor-pointer">
                      <input type="radio" name="dtype" value="base64" checked={decodeType==='base64'} onChange={e => setDecodeType(e.target.value)} className="text-primary focus:ring-primary bg-black border-white/20"/>
                      Base64
                    </label>
                    <label className="flex items-center gap-2 text-sm text-on-surface-variant cursor-pointer">
                      <input type="radio" name="dtype" value="hex" checked={decodeType==='hex'} onChange={e => setDecodeType(e.target.value)} className="text-primary focus:ring-primary bg-black border-white/20"/>
                      Hex
                    </label>
                  </div>
                )}

                <button
                  onClick={handleRun}
                  disabled={isLoading || !input.trim()}
                  className="bg-primary text-black font-bold px-6 py-2.5 rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {isLoading ? (
                    <>
                      <span className="material-symbols-outlined animate-spin text-[20px]">refresh</span>
                      Processing...
                    </>
                  ) : (
                    <>
                      <span className="material-symbols-outlined text-[20px]">play_arrow</span>
                      Run Tool
                    </>
                  )}
                </button>

                <div className="pt-4 border-t border-white/5">
                  {renderResult()}
                </div>
              </div>
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
