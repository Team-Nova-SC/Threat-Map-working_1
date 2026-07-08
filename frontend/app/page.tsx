"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { motion, useReducedMotion } from "framer-motion";
import ScanInput from "@/components/ScanInput";
import ScanSequence from "@/components/ScanSequence";
import { api } from "@/lib/api";

export default function Home() {
  const router = useRouter();
  const prefersReducedMotion = useReducedMotion();
  const [isLoading, setIsLoading] = useState(false);
  const [scanError, setScanError] = useState("");

  const titleWords = "AI-Powered Threat Intelligence".split(" ");
  
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.1, delayChildren: 0.2 },
    },
  };
  
  const wordVariants = {
    hidden: { opacity: 0, y: 30, filter: "blur(4px)" },
    visible: { opacity: 1, y: 0, filter: "blur(0px)", transition: { type: "spring" as const, damping: 12, stiffness: 100 } },
  };
  
  const cardContainerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.08, delayChildren: 0.5 },
    },
  };
  
  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0, transition: { type: "spring" as const, stiffness: 100 } },
  };

  const handleScan = async (indicator: string, type: "ip" | "url" | "domain" | "hash" | "bulk" | "cve") => {
    setIsLoading(true);
    setScanError("");
    try {
      if (type === "bulk") {
        const indicators = indicator.split(/[\n,]+/).map(i => i.trim()).filter(i => i.length > 0);
        // We'll navigate to a new bulk results page (which we can build next or pass state)
        // For now, let's just trigger the bulk scan and log it, or redirect to a /results/bulk page
        const result = await api.bulkScan(indicators);
        // We need a way to display bulk results. For now we can route to /bulk-results
        // We'll encode the result in sessionStorage to pass it easily without a DB record
        sessionStorage.setItem("bulkScanResults", JSON.stringify(result));
        router.push(`/results/bulk`);
      } else if (type === "cve") {
        // Redirect to a specific CVE results view
        router.push(`/results/cve/${indicator}`);
      } else {
        // Run API call + 6s minimum UX delay in parallel.
        // If API responds in 2s, we wait the remaining 4s (professional feel).
        // If API takes 10s, we just wait for it (delay already passed).
        const minDelay = new Promise<void>(r => setTimeout(r, 6000));
        const [result] = await Promise.all([
          api.analyzeIndicator(indicator, type),
          minDelay,
        ]);

        if (result && result.id) {
          router.push(`/results/${result.id}`);
        } else {
          setScanError("Invalid response from server. Please try again.");
        }
      }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      console.error(err);
      const detail = err.response?.data?.detail || "An unexpected error occurred during scan.";
      setScanError(detail);
    } finally {
      setIsLoading(false);
    }
  };

  const platforms = [
    {
      name: "VirusTotal",
      description: "Aggregates malicious reputation across 90+ security engines.",
      icon: "security",
      status: "Active",
    },
    {
      name: "AbuseIPDB",
      description: "IP blacklist engine reporting spam, brute-force, and malware C2s.",
      icon: "sensors",
      status: "Active",
    },
    {
      name: "GreyNoise",
      description: "Classifies internet background scanners and internet noise.",
      icon: "hearing",
      status: "Active",
    },
    {
      name: "AlienVault OTX",
      description: "Extracts open indicator pulse counts and threat campaign tags.",
      icon: "hub",
      status: "Active",
    },
    {
      name: "URLScan.io",
      description: "Analyses URL behaviors and renders sandbox snapshots.",
      icon: "pageview",
      status: "Active",
    },
    {
      name: "Local OSINT Engine",
      description: "Resolves direct WHOIS parameters, DNS records, and SSL handshakes.",
      icon: "lan",
      status: "Active",
    },
  ];

  return (
    <div className="max-w-6xl mx-auto py-8 md:py-12 px-4 md:px-8 flex flex-col justify-center min-h-[calc(100vh-8rem)]">
      {/* Title/Branding Header */}
      <div className="text-center mb-8 md:mb-12">
        <div className="inline-flex items-center justify-center p-2 rounded-xl bg-primary/10 border border-primary/20 mb-4 md:mb-6">
          <span className="material-symbols-outlined text-primary text-[24px] md:text-[32px] animate-pulse">
            radar
          </span>
        </div>
        <motion.h1 
          className="text-3xl sm:text-4xl md:text-5xl font-black text-white tracking-tight mb-4 font-headline-lg flex justify-center flex-wrap gap-x-2 md:gap-x-3"
          variants={containerVariants}
          initial={prefersReducedMotion ? "visible" : "hidden"}
          animate="visible"
        >
          {titleWords.map((word, i) => (
            <motion.span key={i} variants={wordVariants} className="inline-block">
              {word}
            </motion.span>
          ))}
        </motion.h1>
        <p className="text-sm md:text-base text-on-surface-variant max-w-2xl mx-auto font-body-lg leading-relaxed px-2 md:px-0">
          Aggregates IP geolocation, malicious binary signals, domain DNS mapping, and URL scan screenshots
          into a single, consolidated threat score supported by automated Google Gemini mitigation reports.
        </p>
      </div>

      {/* Unified Search Control */}
      <div className="mb-16">
        <ScanInput onScan={handleScan} isLoading={isLoading} />
        {scanError && (
          <div className="mt-4 p-4 rounded-xl bg-error-container/20 border border-error-container/30 text-error text-sm font-mono-sm text-center">
            {scanError}
          </div>
        )}

        <ScanSequence isVisible={isLoading} />
      </div>

      {/* Integration Feeds Matrix */}
      <div className="mt-8 md:mt-0">
        <h3 className="text-center font-bold font-label-caps text-label-caps text-[11px] md:text-[12px] text-on-surface-variant uppercase tracking-widest mb-6">
          Aggregated OSINT Partners & Feeds
        </h3>
        <motion.div 
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6"
          variants={cardContainerVariants}
          initial={prefersReducedMotion ? "visible" : "hidden"}
          animate="visible"
        >
          {platforms.map((p) => (
            <motion.div
              key={p.name}
              variants={cardVariants}
              whileHover={{ y: -5, boxShadow: "0 10px 30px -10px rgba(255,255,255,0.1)" }}
              className="glass-panel p-md rounded-xl border border-white/5 transition-colors duration-300 flex items-start gap-4 cursor-default"
            >
              <div className="p-2.5 rounded-lg bg-surface-container-low border border-white/5 flex items-center justify-center">
                <span className="material-symbols-outlined text-primary text-[22px]">
                  {p.icon}
                </span>
              </div>
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-white text-sm">{p.name}</h4>
                  <span className="text-[9px] bg-primary/10 text-primary px-1.5 py-0.5 rounded font-mono-sm uppercase border border-primary/15">
                    {p.status}
                  </span>
                </div>
                <p className="text-xs text-on-surface-variant leading-relaxed">
                  {p.description}
                </p>
              </div>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </div>
  );
}
