import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";

interface ScanInputProps {
  onScan: (indicator: string, type: ScanType) => void;
  isLoading?: boolean;
}

export type ScanType = "ip" | "url" | "domain" | "hash" | "bulk" | "cve";

export const ScanInput: React.FC<ScanInputProps> = ({ onScan, isLoading = false }) => {
  const [activeTab, setActiveTab] = useState<ScanType>("ip");
  const [inputValue, setInputValue] = useState("");
  const [error, setError] = useState("");
  const [timer, setTimer] = useState(0);
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  const [isFocused, setIsFocused] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("threatmap_recent_searches");
    if (saved) {
      try { setRecentSearches(JSON.parse(saved)); } catch (e) {}
    }
  }, []);

  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.key === "/" || (e.key === "k" && (e.ctrlKey || e.metaKey))) && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") {
        e.preventDefault();
        document.getElementById("global-search-input")?.focus();
      }
      if (e.key === "Escape") {
        document.getElementById("global-search-input")?.blur();
        setIsFocused(false);
      }
    };
    window.addEventListener("keydown", handleGlobalKeyDown);
    return () => window.removeEventListener("keydown", handleGlobalKeyDown);
  }, []);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isLoading) {
      setTimer(0);
      interval = setInterval(() => {
        setTimer(prev => prev + 1);
      }, 1000);
    } else {
      setTimer(0);
    }
    return () => clearInterval(interval);
  }, [isLoading]);

  useEffect(() => {
    // Auto-detect IOC type
    const val = inputValue.trim();
    if (!val) return;
    
    // Skip auto-detect if already bulk and contains multiple
    if (activeTab === "bulk" && (val.includes(",") || val.includes("\n"))) return;

    if (val.includes(",") || val.includes("\n")) { setActiveTab("bulk"); return; }
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(val)) { setActiveTab("ip"); return; }
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(val)) { setActiveTab("hash"); return; }
    if (/^CVE-\d{4}-\d{4,}$/i.test(val)) { setActiveTab("cve"); return; }
    if (/^https?:\/\//i.test(val)) { setActiveTab("url"); return; }
    if (/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/.test(val) && !val.includes("/")) { setActiveTab("domain"); return; }
  }, [inputValue]);

  const tabConfig: Record<ScanType, any> = {
    ip: {
      label: "IP Address",
      placeholder: "Enter IPv4 address (e.g., 192.0.2.1)...",
      icon: <span className="material-symbols-outlined text-[18px]">sensors</span>,
      validate: (val: string) => {
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        return ipRegex.test(val.trim()) ? "" : "Invalid IPv4 address format.";
      },
    },
    domain: {
      label: "Domain",
      placeholder: "Enter domain (e.g., malicious-dns.io)...",
      icon: <span className="material-symbols-outlined text-[18px]">language</span>,
      validate: (val: string) => {
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
        return domainRegex.test(val.trim()) ? "" : "Invalid domain format.";
      },
    },
    url: {
      label: "URL",
      placeholder: "Enter full URL (e.g., https://phishing-update.net/login)...",
      icon: <span className="material-symbols-outlined text-[18px]">link</span>,
      validate: (val: string) => {
        try {
          // Check if valid URL structure
          const parsed = new URL(val.trim());
          if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
             return "Invalid URL protocol. Must be http:// or https://.";
          }
          return "";
        } catch {
          return "Invalid URL format. Must include protocol (e.g. http:// or https://).";
        }
      },
    },
    hash: {
      label: "File Hash",
      placeholder: "Enter file signature (MD5, SHA-1, SHA-256)...",
      icon: <span className="material-symbols-outlined text-[18px]">tag</span>,
      validate: (val: string) => {
        const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
        return hashRegex.test(val.trim()) ? "" : "Invalid hash. Must be MD5, SHA-1 or SHA-256.";
      },
    },
    bulk: {
      label: "Bulk Scan",
      placeholder: "Enter up to 20 indicators separated by commas or newlines...",
      icon: <span className="material-symbols-outlined text-[18px]">library_add</span>,
      validate: (val: string) => {
        const count = val.split(/[\n,]+/).filter(i => i.trim().length > 0).length;
        if (count === 0) return "Please enter at least one indicator.";
        if (count > 20) return `Maximum 20 indicators allowed. You provided ${count}.`;
        return "";
      },
    },
    cve: {
      label: "CVE Lookup",
      placeholder: "Enter CVE ID (e.g., CVE-2021-44228)...",
      icon: <span className="material-symbols-outlined text-[18px]">bug_report</span>,
      validate: (val: string) => {
        const cveRegex = /^CVE-\d{4}-\d{4,}$/i;
        return cveRegex.test(val.trim()) ? "" : "Invalid format. Expected format: CVE-YYYY-NNNNN";
      },
    },
  };

  const handleTabChange = (tab: ScanType) => {
    setActiveTab(tab);
    setError("");
    setInputValue("");
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) {
      setError("Please input a threat indicator.");
      return;
    }

    const validationError = tabConfig[activeTab].validate(inputValue);
    if (validationError) {
      setError(validationError);
      return;
    }

    // Save to recent
    const val = inputValue.trim();
    if (val && activeTab !== "bulk") {
      setRecentSearches(prev => {
        const updated = [val, ...prev.filter(i => i !== val)].slice(0, 5);
        localStorage.setItem("threatmap_recent_searches", JSON.stringify(updated));
        return updated;
      });
    }

    setError("");
    setIsFocused(false);
    onScan(val, activeTab);
  };

  return (
    <div className={`w-full max-w-4xl mx-auto glass-panel p-md rounded-xl transition-all duration-300 ${!isLoading ? 'scan-pulse-idle' : 'border-primary/50 shadow-[0_0_20px_rgba(20,184,166,0.3)]'}`}>
      {/* Tabs */}
      <div className="flex flex-nowrap sm:flex-wrap bg-surface-container-low rounded-lg p-1 border border-white/5 mb-4 max-w-3xl mx-auto gap-1 justify-start sm:justify-center overflow-x-auto hide-scrollbar snap-x">
        {(Object.keys(tabConfig) as ScanType[]).map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => handleTabChange(tab)}
            className={`flex-1 py-2 px-3 rounded-md flex items-center justify-center gap-2 font-label-caps text-label-caps text-[12px] transition-all duration-150 min-w-[110px] snap-center whitespace-nowrap flex-shrink-0 ${
              activeTab === tab
                ? "bg-primary/20 text-primary border border-primary/20 shadow-lg"
                : "text-on-surface-variant hover:text-on-surface hover:bg-white/5 border border-transparent"
            }`}
          >
            {tabConfig[tab].icon}
            {tabConfig[tab].label}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative">
          <span className="material-symbols-outlined absolute left-4 top-4 text-on-surface-variant/60 text-[20px]">
            {activeTab === "bulk" ? "format_list_bulleted" : "search"}
          </span>
          
          {activeTab === "bulk" ? (
            <textarea
              id="global-search-input"
              value={inputValue}
              onChange={(e) => {
                setInputValue(e.target.value);
                if (error) setError("");
              }}
              onFocus={() => setIsFocused(true)}
              onBlur={() => setTimeout(() => setIsFocused(false), 200)}
              disabled={isLoading}
              rows={4}
              className="w-full bg-surface-container-lowest border border-white/10 rounded-lg pl-10 sm:pl-12 pr-14 sm:pr-32 py-3.5 text-sm text-on-surface focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary/50 transition-all font-body-sm text-body-sm resize-y"
              placeholder={tabConfig[activeTab].placeholder}
            />
          ) : (
            <input
              id="global-search-input"
              type="text"
              value={inputValue}
              onChange={(e) => {
                setInputValue(e.target.value);
                if (error) setError("");
              }}
              onFocus={() => setIsFocused(true)}
              onBlur={() => setTimeout(() => setIsFocused(false), 200)}
              disabled={isLoading}
              className="w-full bg-surface-container-lowest border border-white/10 rounded-lg pl-10 sm:pl-12 pr-14 sm:pr-32 py-3.5 text-sm text-on-surface focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary/50 transition-all font-body-sm text-body-sm"
              placeholder={tabConfig[activeTab].placeholder}
            />
          )}

          {isFocused && recentSearches.length > 0 && activeTab !== "bulk" && !inputValue && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-surface-container-high border border-white/10 rounded-lg shadow-xl z-50 overflow-hidden">
              <div className="px-4 py-2 border-b border-white/5 text-[10px] font-mono-sm text-on-surface-variant uppercase flex justify-between items-center">
                <span>Recent Searches</span>
                <span className="text-[10px] bg-white/5 px-1.5 py-0.5 rounded text-white/40">Esc to close</span>
              </div>
              {recentSearches.map((search, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setInputValue(search);
                    setIsFocused(false);
                  }}
                  className="w-full text-left px-4 py-3 text-sm text-white hover:bg-white/5 transition-colors flex items-center gap-3 border-b border-white/5 last:border-0"
                >
                  <span className="material-symbols-outlined text-[16px] text-on-surface-variant">history</span>
                  <span className="font-mono-sm">{search}</span>
                </button>
              ))}
            </div>
          )}

          <motion.button
            whileHover={{ scale: 1.02, boxShadow: "0 0 15px rgba(20, 184, 166, 0.5)" }}
            whileTap={{ scale: 0.98 }}
            type="submit"
            disabled={isLoading}
            className={`absolute right-1 sm:right-2 top-1 sm:top-2 bg-primary text-on-primary font-bold py-2 sm:px-6 px-3 rounded-lg text-label-caps font-label-caps text-[12px] flex items-center justify-center gap-2 ${
              activeTab === "bulk" ? "" : "top-1/2 -translate-y-1/2"
            } ${isLoading ? "opacity-80" : ""}`}
            title={isLoading ? `ANALYZING (${timer}S)` : "SCAN NOW"}
          >
            {isLoading ? (
              <span className="animate-spin inline-block w-4 h-4 border-2 border-on-primary border-t-transparent rounded-full" />
            ) : (
              <span className="material-symbols-outlined text-[16px]">biotech</span>
            )}
            <span className="hidden sm:inline">
              {isLoading ? `ANALYZING (${timer}S)` : "SCAN NOW"}
            </span>
          </motion.button>
        </div>
        {error && <p className="text-error text-xs mt-2 px-2 font-mono-sm">{error}</p>}
      </form>
    </div>
  );
};
export default ScanInput;
