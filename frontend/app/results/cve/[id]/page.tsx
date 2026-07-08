"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";

export default function CveResultsPage({ params }: { params: { id: string } }) {
  const { id } = params;
  const [cve, setCve] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function fetchCve() {
      try {
        setLoading(true);
        const data = await api.getCves(id);
        if (data.status === "success") {
          setCve(data);
        } else {
          setError(`CVE not found or error occurred: ${data.detail || data.status}`);
        }
      } catch (err: any) {
        setError("Failed to reach CVE service.");
      } finally {
        setLoading(false);
      }
    }
    fetchCve();
  }, [id]);

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto py-16 text-center px-4 md:px-8">
        <span className="animate-spin inline-block w-8 h-8 border-4 border-primary border-t-transparent rounded-full mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Querying NVD Database</h2>
        <p className="text-on-surface-variant text-sm">Retrieving vulnerability details for {id}...</p>
      </div>
    );
  }

  if (error || !cve) {
    return (
      <div className="max-w-xl mx-auto py-16 text-center px-4 md:px-8">
        <span className="material-symbols-outlined text-[64px] text-error mb-4">bug_report</span>
        <h2 className="text-xl font-bold text-white mb-2">Vulnerability Not Found</h2>
        <p className="text-on-surface-variant text-sm mb-6">{error || "The requested CVE ID does not exist in the NVD database."}</p>
        <Link href="/" className="bg-primary text-on-primary py-2 px-6 rounded-lg text-sm font-bold">
          Return to Scanner
        </Link>
      </div>
    );
  }

  const getCvssColor = (score: number) => {
    if (!score) return "bg-surface-container-low text-on-surface";
    if (score >= 9.0) return "bg-error/20 text-error border-error/30";
    if (score >= 7.0) return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    if (score >= 4.0) return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12 px-4 md:px-8 mt-6">
      <div className="glass-panel p-md rounded-xl flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span className="material-symbols-outlined text-error text-[32px]">bug_report</span>
          <div>
            <h2 className="text-2xl font-black text-white tracking-tight">{cve.cve_id}</h2>
            <p className="text-xs text-on-surface-variant font-body-sm">
              Published: {new Date(cve.published_date).toLocaleDateString()} | Last Modified: {new Date(cve.last_modified).toLocaleDateString()}
            </p>
          </div>
        </div>
        <Link href="/" className="bg-surface-container-low text-white border border-white/10 hover:bg-white/5 py-2 px-4 rounded-lg font-bold text-xs font-label-caps transition-all">
          NEW SCAN
        </Link>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 glass-panel p-lg rounded-xl space-y-4">
          <h3 className="font-bold text-white text-md font-headline-sm border-b border-white/5 pb-2">Vulnerability Description</h3>
          <p className="text-sm text-on-surface leading-relaxed">{cve.description}</p>
          
          <h3 className="font-bold text-white text-md font-headline-sm border-b border-white/5 pb-2 mt-6">Known Affected Configurations</h3>
          {cve.affected_products && cve.affected_products.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {cve.affected_products.map((prod: string, i: number) => (
                <span key={i} className="text-xs font-mono-sm bg-white/5 border border-white/10 px-2 py-1 rounded text-on-surface-variant">
                  {prod}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-on-surface-variant italic">No specific CPEs detailed or available.</p>
          )}
        </div>

        <div className="md:col-span-1 space-y-6">
          <div className="glass-panel p-lg rounded-xl">
            <h3 className="font-bold text-white text-md font-headline-sm border-b border-white/5 pb-2 mb-4">CVSS Severity</h3>
            <div className="flex flex-col items-center text-center">
              <div className={`w-24 h-24 rounded-full flex items-center justify-center border-4 border-surface-container-lowest shadow-lg ${getCvssColor(cve.cvss_score)} mb-3`}>
                <span className="text-3xl font-black">{cve.cvss_score || "N/A"}</span>
              </div>
              <span className="text-sm font-bold uppercase tracking-wider">{cve.cvss_severity || "UNSCORED"}</span>
              <span className="text-[10px] font-mono-sm text-on-surface-variant mt-2 break-all">{cve.cvss_vector || ""}</span>
            </div>
          </div>
          
          <div className="glass-panel p-lg rounded-xl">
            <h3 className="font-bold text-white text-md font-headline-sm border-b border-white/5 pb-2 mb-4">References</h3>
            <ul className="space-y-2">
              {cve.references && cve.references.length > 0 ? (
                cve.references.map((ref: string, i: number) => (
                  <li key={i} className="truncate">
                    <a href={ref} target="_blank" rel="noopener noreferrer" className="text-xs font-mono-sm text-primary hover:underline" title={ref}>
                      {ref}
                    </a>
                  </li>
                ))
              ) : (
                <li className="text-xs text-on-surface-variant">No external references found.</li>
              )}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
