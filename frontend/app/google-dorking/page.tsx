"use client";

import React, { useState } from "react";
import { api } from "@/lib/api";

type Dork = {
  name: string;
  query: string;
  url: string;
};

export default function GoogleDorkingPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("domain");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [dorks, setDorks] = useState<Dork[]>([]);
  const [hasSearched, setHasSearched] = useState(false);

  const runDorking = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setIsLoading(true);
    setError("");
    setDorks([]);
    setHasSearched(true);

    try {
      const result = await api.toolsGoogleDorks(target.trim(), mode);
      setDorks(result.dorks || []);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || "Failed to generate Google dorks.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-12 px-4 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="text-center space-y-4 mb-10">
        <span className="material-symbols-outlined text-[64px] text-primary">manage_search</span>
        <h1 className="text-4xl font-black text-white tracking-widest font-headline-lg">
          GOOGLE <span className="text-primary font-light">DORKING</span>
        </h1>
        <p className="text-on-surface-variant max-w-2xl mx-auto">
          Generate advanced Google search queries for authorized OSINT research on domains, companies, emails, and keywords.
        </p>
      </div>

      <div className="glass-panel p-6 rounded-xl border border-white/5 mb-8">
        <form onSubmit={runDorking} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-[180px_1fr_auto] gap-4">
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              disabled={isLoading}
              className="bg-background border border-white/10 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary/50 transition-colors"
            >
              <option value="domain">Domain</option>
              <option value="company">Company</option>
              <option value="email">Email</option>
              <option value="keyword">Keyword</option>
            </select>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={mode === "domain" ? "example.com" : mode === "email" ? "analyst@example.com" : "Acme Corp"}
              className="bg-background border border-white/10 rounded-lg px-4 py-3 text-white placeholder-white/30 focus:outline-none focus:border-primary/50 transition-colors font-mono"
              required
              disabled={isLoading}
            />
            <button
              type="submit"
              disabled={isLoading || !target.trim()}
              className="bg-primary text-background font-bold px-8 py-3 rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              {isLoading ? "Generating..." : "Generate Dorks"}
            </button>
          </div>
          <p className="text-xs text-on-surface-variant">
            Use these queries only for systems, brands, and assets you are authorized to investigate.
          </p>
        </form>
      </div>

      {error && (
        <div className="bg-error-container/20 border border-error/50 p-4 rounded-xl text-error text-sm mb-6">
          <strong>Error:</strong> {error}
        </div>
      )}

      {isLoading && (
        <div className="text-center py-12 text-on-surface-variant text-sm">
          Generating dork queries...
        </div>
      )}

      {!isLoading && hasSearched && !error && dorks.length === 0 && (
        <div className="text-center py-12 text-on-surface-variant text-sm">
          No dork queries were generated for this target.
        </div>
      )}

      {!isLoading && dorks.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {dorks.map((dork) => (
            <div key={dork.name} className="bg-surface border border-white/5 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <h3 className="font-bold text-white">{dork.name}</h3>
                <a
                  href={dork.url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs bg-primary text-background font-bold px-3 py-1.5 rounded-lg hover:bg-primary/90"
                >
                  Open
                </a>
              </div>
              <code className="block text-xs text-primary bg-background/70 border border-white/10 rounded-lg p-3 break-all">
                {dork.query}
              </code>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
