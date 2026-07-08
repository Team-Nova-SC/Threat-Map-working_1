"use client";

import React, { useState } from "react";
import SpiderfootPanel from "@/components/SpiderfootPanel";

export default function DeepScanPage() {
  const [target, setTarget] = useState("");
  const [submittedTarget, setSubmittedTarget] = useState("");

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (target.trim()) {
      setSubmittedTarget(target.trim());
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-12 px-4 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="text-center space-y-4 mb-12">
        <span className="material-symbols-outlined text-[64px] text-primary">troubleshoot</span>
        <h1 className="text-4xl font-black text-white tracking-widest font-headline-lg">
          DEEP <span className="text-primary font-light">OSINT</span>
        </h1>
        <p className="text-on-surface-variant max-w-lg mx-auto">
          Execute a comprehensive 200+ module reconnaissance scan against any IP or Domain. Uncover dark web mentions, subdomains, emails, and full technology stacks.
        </p>
      </div>

      <div className="glass-panel p-6 rounded-xl border border-white/5 mb-8">
        <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-4">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter Domain or IP (e.g. github.com)"
            className="flex-1 bg-background border border-white/10 rounded-lg px-4 py-3 text-white placeholder-white/30 focus:outline-none focus:border-primary/50 transition-colors font-mono"
            required
          />
          <button
            type="submit"
            className="bg-primary text-background font-bold px-8 py-3 rounded-lg hover:bg-primary/90 transition-colors whitespace-nowrap"
          >
            Run Deep Scan
          </button>
        </form>
      </div>

      {submittedTarget && (
        <SpiderfootPanel target={submittedTarget} key={submittedTarget} />
      )}
    </div>
  );
}
