"use client";

import React, { useState } from "react";
import { api } from "@/lib/api";

type Dork = {
  name: string;
  category: string;
  query: string;
  url: string;
  description: string;
  expected_findings: string;
};

type Explanation = {
  how_it_works: string;
  why_results_might_be_empty: string[];
  defensive_hardening: string[];
};

export default function GoogleDorkingPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("domain");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [dorks, setDorks] = useState<Dork[]>([]);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [hasSearched, setHasSearched] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState("ALL");
  const [copiedQuery, setCopiedQuery] = useState<string | null>(null);

  const runDorking = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setIsLoading(true);
    setError("");
    setDorks([]);
    setExplanation(null);
    setHasSearched(true);
    setSelectedCategory("ALL");

    try {
      const result = await api.toolsGoogleDorks(target.trim(), mode);
      setDorks(result.dorks || []);
      setExplanation(result.explanation || null);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || "Failed to generate Google dorks.");
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedQuery(text);
    setTimeout(() => setCopiedQuery(null), 2000);
  };

  const categories = ["ALL", ...Array.from(new Set(dorks.map((d) => d.category)))];

  const filteredDorks = selectedCategory === "ALL"
    ? dorks
    : dorks.filter((d) => d.category === selectedCategory);

  return (
    <div className="max-w-6xl mx-auto py-10 px-4 md:px-8 space-y-8 animate-in fade-in duration-500">
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center justify-center p-3 rounded-full bg-primary/10 text-primary mb-2 border border-primary/20">
          <span className="material-symbols-outlined text-4xl">manage_search</span>
        </div>
        <h1 className="text-3xl md:text-4xl font-black text-white tracking-wider uppercase font-headline-lg">
          Advanced Google <span className="text-primary font-light">Dork Engine</span>
        </h1>
        <p className="text-on-surface-variant max-w-2xl mx-auto text-sm leading-relaxed">
          Construct structured search engine audit queries to inspect publicly indexed assets, configuration files, and domain exposure footprint.
        </p>
      </div>

      {/* Target Search Panel */}
      <div className="glass-panel p-6 rounded-2xl border border-white/10 shadow-xl">
        <form onSubmit={runDorking} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-[200px_1fr_auto] gap-4">
            <div>
              <label className="block text-[11px] font-bold text-on-surface-variant uppercase tracking-wider mb-1.5 font-mono">
                Scan Target Mode
              </label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                disabled={isLoading}
                className="w-full bg-background/80 border border-white/15 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-primary/60 transition-all font-mono"
              >
                <option value="domain">🌐 Target Domain</option>
                <option value="company">🏢 Company / Brand</option>
                <option value="email">✉️ Email Address</option>
                <option value="keyword">🔑 Technology Keyword</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-bold text-on-surface-variant uppercase tracking-wider mb-1.5 font-mono">
                Target Input Value
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={
                  mode === "domain"
                    ? "example.com"
                    : mode === "email"
                    ? "security@company.com"
                    : mode === "company"
                    ? "Acme Corporation"
                    : "AWS S3 Bucket"
                }
                className="w-full bg-background/80 border border-white/15 rounded-xl px-4 py-3 text-sm text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-all font-mono"
                required
                disabled={isLoading}
              />
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                disabled={isLoading || !target.trim()}
                className="w-full md:w-auto bg-primary text-background font-bold text-sm px-8 py-3 rounded-xl hover:bg-primary/90 active:scale-[0.98] transition-all disabled:opacity-50 font-mono uppercase tracking-wider shadow-lg shadow-primary/20"
              >
                {isLoading ? "Generating Dorks..." : "Launch Dork Audit"}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs text-on-surface-variant/80 pt-2 border-t border-white/5 font-mono">
            <span className="material-symbols-outlined text-sm text-primary">security</span>
            <span>All search queries run client-side against public search engine indexes. Practice authorized defensive auditing only.</span>
          </div>
        </form>
      </div>

      {error && (
        <div className="bg-error-container/20 border border-error/40 p-4 rounded-xl text-error text-sm font-mono flex items-center gap-3">
          <span className="material-symbols-outlined">error</span>
          <div><strong>Generation Error:</strong> {error}</div>
        </div>
      )}

      {/* Dork Results Section */}
      {!isLoading && dorks.length > 0 && (
        <div className="space-y-6">
          {/* Category Filter Tabs */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
            <span className="text-xs font-mono text-on-surface-variant uppercase tracking-wider shrink-0 mr-2">Filter:</span>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all shrink-0 ${
                  selectedCategory === cat
                    ? "bg-primary text-background font-bold shadow-md shadow-primary/20"
                    : "bg-surface-container-low border border-white/10 text-on-surface-variant hover:text-white hover:bg-white/5"
                }`}
              >
                {cat} {cat === "ALL" ? `(${dorks.length})` : `(${dorks.filter(d => d.category === cat).length})`}
              </button>
            ))}
          </div>

          {/* Dork Cards Bento Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {filteredDorks.map((dork) => (
              <div
                key={dork.name}
                className="glass-panel p-5 rounded-2xl border border-white/10 flex flex-col justify-between hover:border-primary/40 transition-all duration-300 space-y-4"
              >
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="inline-block text-[10px] font-mono uppercase bg-primary/10 text-primary border border-primary/25 px-2 py-0.5 rounded-md mb-1.5">
                        {dork.category}
                      </span>
                      <h3 className="font-bold text-white text-base font-headline-sm">{dork.name}</h3>
                    </div>

                    <a
                      href={dork.url}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 bg-primary text-background font-bold text-xs rounded-lg hover:bg-primary/90 transition-all flex items-center gap-1 shrink-0 font-mono shadow-sm"
                    >
                      <span>Run Search</span>
                      <span className="material-symbols-outlined text-sm">open_in_new</span>
                    </a>
                  </div>

                  <p className="text-xs text-on-surface-variant leading-relaxed">
                    {dork.description}
                  </p>
                </div>

                <div className="space-y-2 bg-background/60 p-3 rounded-xl border border-white/5 font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-on-surface-variant uppercase tracking-wider">Generated Search Query</span>
                    <button
                      onClick={() => copyToClipboard(dork.query)}
                      className="text-[10px] text-primary hover:underline flex items-center gap-1"
                    >
                      <span className="material-symbols-outlined text-xs">content_copy</span>
                      <span>{copiedQuery === dork.query ? "Copied!" : "Copy"}</span>
                    </button>
                  </div>
                  <code className="block text-xs text-primary/90 break-all select-all font-mono leading-relaxed">
                    {dork.query}
                  </code>
                </div>

                <div className="text-[11px] text-on-surface-variant/90 flex items-start gap-2 pt-1 border-t border-white/5">
                  <span className="material-symbols-outlined text-sm text-yellow-400 shrink-0">insights</span>
                  <span><strong>Expected Findings:</strong> {dork.expected_findings}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Educational & Troubleshooting Guide */}
      {explanation && (
        <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-6">
          <div className="flex items-center gap-3 border-b border-white/10 pb-4">
            <span className="material-symbols-outlined text-primary text-2xl">school</span>
            <div>
              <h2 className="text-lg font-bold text-white font-headline-sm">Google Dorking Technical Mechanics & Exposure Guide</h2>
              <p className="text-xs text-on-surface-variant">Understanding crawler behavior, expected findings, and empty search troubleshooting.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
            {/* Column 1: Mechanics */}
            <div className="space-y-2 bg-white/[0.02] p-4 rounded-xl border border-white/5">
              <h3 className="text-primary font-bold uppercase text-xs flex items-center gap-2">
                <span className="material-symbols-outlined text-sm">settings_suggest</span>
                How Dorking Works
              </h3>
              <p className="text-on-surface-variant leading-relaxed text-[11px]">
                {explanation.how_it_works}
              </p>
            </div>

            {/* Column 2: Troubleshooting empty results */}
            <div className="space-y-2 bg-white/[0.02] p-4 rounded-xl border border-white/5">
              <h3 className="text-emerald-400 font-bold uppercase text-xs flex items-center gap-2">
                <span className="material-symbols-outlined text-sm">check_circle</span>
                Why 0 Results Appear
              </h3>
              <ul className="space-y-1.5 text-on-surface-variant text-[11px]">
                {explanation.why_results_might_be_empty.map((reason, idx) => (
                  <li key={idx} className="leading-snug">• {reason}</li>
                ))}
              </ul>
            </div>

            {/* Column 3: Defensive Hardening */}
            <div className="space-y-2 bg-white/[0.02] p-4 rounded-xl border border-white/5">
              <h3 className="text-yellow-400 font-bold uppercase text-xs flex items-center gap-2">
                <span className="material-symbols-outlined text-sm">shield</span>
                Defensive Hardening
              </h3>
              <ul className="space-y-1.5 text-on-surface-variant text-[11px]">
                {explanation.defensive_hardening.map((hard, idx) => (
                  <li key={idx} className="leading-snug">✓ {hard}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
