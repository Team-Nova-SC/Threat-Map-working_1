"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface WhoisJsonDataProps {
  data: any;
}

export default function WhoisJsonData({ data }: WhoisJsonDataProps) {
  const [expandedSection, setExpandedSection] = useState<string | null>("dns");

  if (!data || data.status !== "success") return null;

  const dns = data.dns_records || {};
  const contacts = data.contacts || {};
  const subs = data.active_subdomains || [];
  const reg = data.registrar_metadata || {};
  const dates = data.registry_dates || {};
  const epp = data.epp_status || [];

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  return (
    <div className="glass-panel rounded-xl p-md flex flex-col border border-white/5 mt-6">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-secondary-container rounded-lg border border-white/10">
          <span className="material-symbols-outlined text-on-secondary-container text-[20px]">account_tree</span>
        </div>
        <h3 className="text-sm font-bold text-white tracking-wider font-label-caps uppercase">
          WhoisJSON Deep Inspection
        </h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div className="bg-surface-container-low p-4 rounded-xl border border-white/5 flex flex-col">
          <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-1">Registrar Metadata</span>
          <span className="text-sm font-bold text-white truncate" title={reg.name}>{reg.name || "Unknown"}</span>
          <a href={reg.url} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline mt-1 truncate">
            {reg.url}
          </a>
        </div>
        <div className="bg-surface-container-low p-4 rounded-xl border border-white/5 flex flex-col">
          <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-1">Availability</span>
          <span className="text-sm font-bold text-white capitalize">{data.availability}</span>
          <span className="text-xs text-on-surface-variant mt-1">Rev WHOIS: {data.reverse_whois_count} domains</span>
        </div>
        <div className="bg-surface-container-low p-4 rounded-xl border border-white/5 flex flex-col">
          <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-1">SSL/TLS State</span>
          <span className={`text-sm font-bold truncate ${data.ssl_tls_state?.status === 'valid' ? 'text-emerald-400' : 'text-error'}`}>
            {data.ssl_tls_state?.status?.toUpperCase()}
          </span>
          <span className="text-xs text-on-surface-variant mt-1 truncate" title={data.ssl_tls_state?.issuer}>
            {data.ssl_tls_state?.issuer}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <div className="bg-surface-container-low p-4 rounded-xl border border-white/5">
          <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2 block">Lifecycle Dates</span>
          <div className="grid grid-cols-3 gap-2">
             <div className="flex flex-col">
               <span className="text-[9px] text-on-surface-variant uppercase">Created</span>
               <span className="text-xs text-white truncate">{dates.creation_date ? dates.creation_date.split('T')[0] : 'N/A'}</span>
             </div>
             <div className="flex flex-col">
               <span className="text-[9px] text-on-surface-variant uppercase">Updated</span>
               <span className="text-xs text-white truncate">{dates.updated_date ? dates.updated_date.split('T')[0] : 'N/A'}</span>
             </div>
             <div className="flex flex-col">
               <span className="text-[9px] text-error uppercase font-bold">Expires</span>
               <span className="text-xs text-white truncate">{dates.expiration_date ? dates.expiration_date.split('T')[0] : 'N/A'}</span>
             </div>
          </div>
        </div>
        <div className="bg-surface-container-low p-4 rounded-xl border border-white/5">
          <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase mb-2 block">EPP Status Codes</span>
          <div className="flex flex-wrap gap-2">
            {epp.map((status: string, idx: number) => (
               <span key={idx} className="text-[9px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-mono-sm">
                 {status}
               </span>
            ))}
            {epp.length === 0 && <span className="text-xs text-on-surface-variant">No EPP status codes found.</span>}
          </div>
        </div>
      </div>

      {/* Accordion Sections */}
      <div className="space-y-3">
        {/* DNS Records */}
        <div className="bg-surface-container-lowest rounded-xl border border-white/5 overflow-hidden">
          <button 
            onClick={() => toggleSection('dns')}
            className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors"
          >
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-primary">dns</span>
              <span className="text-xs font-bold text-white tracking-wider uppercase font-label-caps">Full DNS Arrays</span>
            </div>
            <span className={`material-symbols-outlined text-[20px] transition-transform duration-200 ${expandedSection === 'dns' ? 'rotate-180' : ''}`}>
              expand_more
            </span>
          </button>
          
          <AnimatePresence>
            {expandedSection === 'dns' && (
              <motion.div 
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden border-t border-white/5"
              >
                <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {Object.entries(dns).map(([type, records]) => {
                    if (!Array.isArray(records) || records.length === 0) return null;
                    return (
                      <div key={type} className="space-y-1">
                        <span className="text-[10px] text-on-surface-variant font-mono-sm font-bold bg-white/5 px-2 py-0.5 rounded inline-block">
                          {type}
                        </span>
                        {records.map((r: string, idx: number) => (
                          <div key={idx} className="text-xs text-white bg-surface-container-low p-2 rounded border border-white/5 font-mono break-all">
                            {r}
                          </div>
                        ))}
                      </div>
                    );
                  })}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Subdomains Map */}
        <div className="bg-surface-container-lowest rounded-xl border border-white/5 overflow-hidden">
          <button 
            onClick={() => toggleSection('subs')}
            className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors"
          >
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-emerald-400">lan</span>
              <span className="text-xs font-bold text-white tracking-wider uppercase font-label-caps">Active Subdomain Map</span>
              <span className="bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full text-[10px] font-bold ml-2">
                {subs.length}
              </span>
            </div>
            <span className={`material-symbols-outlined text-[20px] transition-transform duration-200 ${expandedSection === 'subs' ? 'rotate-180' : ''}`}>
              expand_more
            </span>
          </button>
          
          <AnimatePresence>
            {expandedSection === 'subs' && (
              <motion.div 
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden border-t border-white/5"
              >
                <div className="p-4 flex flex-wrap gap-2">
                  {subs.map((sub: string, idx: number) => (
                    <div key={idx} className="text-xs text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/20 font-mono flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                      {sub}
                    </div>
                  ))}
                  {subs.length === 0 && <span className="text-xs text-on-surface-variant">No active subdomains mapped.</span>}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Contacts */}
        <div className="bg-surface-container-lowest rounded-xl border border-white/5 overflow-hidden">
          <button 
            onClick={() => toggleSection('contacts')}
            className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors"
          >
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#ffb4ab]">contact_mail</span>
              <span className="text-xs font-bold text-white tracking-wider uppercase font-label-caps">Registrant & Admin Contacts</span>
            </div>
            <span className={`material-symbols-outlined text-[20px] transition-transform duration-200 ${expandedSection === 'contacts' ? 'rotate-180' : ''}`}>
              expand_more
            </span>
          </button>
          
          <AnimatePresence>
            {expandedSection === 'contacts' && (
              <motion.div 
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden border-t border-white/5"
              >
                <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
                  {Object.entries(contacts).map(([type, info]: [string, any]) => (
                    <div key={type} className="bg-surface-container-low p-3 rounded-lg border border-white/5">
                      <span className="text-[10px] text-on-surface-variant font-mono-sm uppercase block mb-2">{type} Contact</span>
                      <div className="space-y-1">
                        <p className="text-xs text-white truncate"><span className="text-on-surface-variant mr-1">Name:</span> {info.name || "N/A"}</p>
                        <p className="text-xs text-white truncate"><span className="text-on-surface-variant mr-1">Org:</span> {info.organization || "N/A"}</p>
                        <p className="text-xs text-white truncate"><span className="text-on-surface-variant mr-1">Email:</span> {info.email || "N/A"}</p>
                        {info.country && <p className="text-xs text-white truncate"><span className="text-on-surface-variant mr-1">Country:</span> {info.country}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
