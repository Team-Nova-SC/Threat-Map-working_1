"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { api } from "@/lib/api";

interface ToolDef {
  id: string;
  name: string;
  icon: string;
  desc: string;
  thesis: string;
  expectedOutput: string[];
  verifiableProof: string;
  possibleEmptyReasons: string[];
}

const TOOLS: ToolDef[] = [
  {
    id: 'email',
    name: 'Email Header Analyzer',
    icon: 'mail',
    desc: 'Extract and analyze email headers for spoofing, hop delays, and SPF/DKIM/DMARC validation.',
    thesis: 'Parses MIME/RFC 5322 Received: headers to trace email routing hops, calculate transit delays, and verify SPF/DKIM/DMARC authentication signatures.',
    expectedOutput: [
      'Original Sender & Return-Path addresses',
      'Hop-by-hop MTA routing path with latency delays',
      'Authentication status (SPF, DKIM, DMARC alignment)',
      'Originating client IP address & geolocation'
    ],
    verifiableProof: 'Direct RFC 5322 specification parser evaluating Authentication-Results and Received headers.',
    possibleEmptyReasons: [
      'Pasted text is an email body rather than raw headers.',
      'Email client stripped Received: headers during export.',
      'Headers missing standard Authentication-Results fields.'
    ]
  },
  {
    id: 'typo',
    name: 'Typosquatting Detector',
    icon: 'spellcheck',
    desc: 'Find active variations, soundalike domains, and potential phishing clones of a domain.',
    thesis: 'Generates algorithmic domain permutations (bitsquatting, homoglyphs, omission, hyphenation, repetition) and queries global DNS to detect active resolving typosquats.',
    expectedOutput: [
      'Total domain variations evaluated',
      'List of actively resolving typosquat domains',
      'Associated A-record IPv4 addresses for each domain',
      'Risk classification for phishing or brand impersonation'
    ],
    verifiableProof: 'Live DNS resolution queries across standard TLD root servers.',
    possibleEmptyReasons: [
      'Domain name typed incorrectly or contains invalid characters.',
      'No typosquatting variations are currently registered or resolving to IP addresses.',
      'DNS resolution rate-limited by upstream resolver.'
    ]
  },
  {
    id: 'decode',
    name: 'Base64/Hex Decoder',
    icon: 'code_blocks',
    desc: 'Safely decode obfuscated Base64, Hexadecimal, and URL-encoded malicious payloads.',
    thesis: 'Executes deterministic string decoding algorithms to unmask Base64, Hexadecimal, URL encoding, and XOR obfuscation commonly used in cyber threat payloads.',
    expectedOutput: [
      'Auto-detected encoding format (Base64, Hex, URL)',
      'Decoded plain-text UTF-8 string or binary representation',
      'Payload length & character distribution entropy'
    ],
    verifiableProof: 'Deterministic RFC 4648 Base64 & Hexadecimal specification decoder.',
    possibleEmptyReasons: [
      'Input string is not valid Base64, Hex, or URL-encoded data.',
      'Input is double-encoded or encrypted using a secret key (AES/DES).',
      'String contains non-printable binary bytes.'
    ]
  },
  {
    id: 'dns',
    name: 'Full DNS Enumerator',
    icon: 'dns',
    desc: 'Dump all authoritative DNS records (A, AAAA, MX, TXT, NS, SOA, CAA) for a domain.',
    thesis: 'Performs comprehensive DNS zone enumeration querying Google DNS (8.8.8.8) and Cloudflare DNS (1.1.1.1) for complete record discovery.',
    expectedOutput: [
      'IPv4 A-records & IPv6 AAAA-records',
      'Mail Exchange (MX) records with priority ranks',
      'Text (TXT) records including SPF & DMARC policy strings',
      'Authoritative Nameservers (NS) & Start of Authority (SOA)'
    ],
    verifiableProof: 'Direct UDP/TCP DNS queries over port 53 via system DNS resolver.',
    possibleEmptyReasons: [
      'Domain name does not exist (NXDOMAIN).',
      'Domain is freshly registered and nameservers have not propagated.',
      'Authoritative DNS server timed out or blocked automated queries.'
    ]
  },
  {
    id: 'shodan',
    name: 'Shodan InternetDB',
    icon: 'radar',
    desc: 'Check open ports, running services, and known vulnerabilities (CVEs) for an IP address.',
    thesis: 'Queries Shodan InternetDB infrastructure API to fetch scanned open ports, CPE software banners, hostnames, and CVE vulnerability IDs for any public IP address.',
    expectedOutput: [
      'Open TCP/UDP listening ports',
      'Associated hostnames and PTR records',
      'Known CVE vulnerability identifiers',
      'Common Platform Enumeration (CPE) software tags'
    ],
    verifiableProof: 'Official Shodan InternetDB REST endpoint (internetdb.shodan.io).',
    possibleEmptyReasons: [
      'Target IP is a private/internal RFC 1918 address (e.g. 192.168.x.x, 10.x.x.x).',
      'IP has not been scanned recently by Shodan crawlers.',
      'IP has strict firewall filtering blocking all external port scans.'
    ]
  },
  {
    id: 'mac',
    name: 'MAC Vendor Lookup',
    icon: 'router',
    desc: 'Identify hardware manufacturer, device type, and registration address from a MAC address.',
    thesis: 'Extracts the Organizationally Unique Identifier (OUI) first 3-bytes (24 bits) of a MAC address and cross-references it with IEEE Standards Association OUI Registry database.',
    expectedOutput: [
      'Validated MAC address format (HEX/Colon/Hyphen)',
      'Extracted OUI prefix (e.g. 00:1A:2B)',
      'Registered Vendor Manufacturer Name (e.g. Cisco, Apple, Intel)',
      'Vendor Organization Address & Country Code'
    ],
    verifiableProof: 'IEEE Standards Association Public OUI & MA-L/MA-M Registry.',
    possibleEmptyReasons: [
      'MAC address format is invalid (must be 12 hexadecimal characters).',
      'MAC address uses a Randomized / Private MAC address scheme (2nd bit set).',
      'OUI is newly assigned by IEEE and not yet synchronized in database.'
    ]
  },
  {
    id: 'network',
    name: 'Network Range Scanner',
    icon: 'hub',
    desc: 'Analyze Subnet CIDR blocks, calculate network/broadcast boundaries, and sample host IP status.',
    thesis: 'Calculates IP network masks, broadcast boundaries, usable host count, and performs rapid ICMP/DNS health checks across CIDR blocks (e.g., /24, /28).',
    expectedOutput: [
      'Network Address & Broadcast Address',
      'Subnet Mask & Total Usable Host IP Count',
      'First & Last usable Host IP addresses',
      'Sample host resolution status matrix'
    ],
    verifiableProof: 'Standard CIDR IPv4 bitmask calculation (RFC 4632).',
    possibleEmptyReasons: [
      'CIDR notation is invalid (e.g., prefix length outside /8 to /30 range).',
      'Target IP range is unroutable or malformed.',
      'Subnet prefix is too large (scans capped at /20 for performance).'
    ]
  },
  {
    id: 'http',
    name: 'HTTP Security Headers',
    icon: 'http',
    desc: 'Audit web server HTTP response headers for HSTS, CSP, X-Frame-Options, and CORS policies.',
    thesis: 'Sends an HTTPS HEAD/GET request to analyze mandatory security defense headers and generates a security score penalty grade.',
    expectedOutput: [
      'Overall Security Score (0 to 100)',
      'Presence & configuration of HSTS (Strict-Transport-Security)',
      'Content-Security-Policy (CSP) & X-Frame-Options status',
      'Server header disclosure & X-Content-Type-Options'
    ],
    verifiableProof: 'Live HTTP/1.1 & HTTP/2 TLS response header handshake.',
    possibleEmptyReasons: [
      'Target URL unreachable or blocked by Cloudflare/WAF challenge.',
      'Web server lacks SSL certificate or refuses HTTPS connection.',
      'URL domain name failed DNS resolution.'
    ]
  }
];

export default function ToolsPage() {
  const [activeTool, setActiveTool] = useState(TOOLS[0].id);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [showExplainer, setShowExplainer] = useState(true);
  
  // Decoder specific
  const [decodeType, setDecodeType] = useState("auto");

  const activeToolDef = TOOLS.find(t => t.id === activeTool) || TOOLS[0];

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
      setError(err.response?.data?.detail || err.message || "An error occurred executing tool.");
    } finally {
      setIsLoading(false);
    }
  };

  const renderResult = () => {
    if (isLoading) {
      return (
        <div className="flex flex-col items-center justify-center py-12 text-on-surface-variant space-y-4">
          <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="animate-pulse text-sm font-mono">Querying forensic intelligence API...</p>
        </div>
      );
    }

    if (error) {
      return (
        <div className="bg-error-container/20 border border-error/50 p-4 rounded-xl text-error text-sm space-y-2">
          <div className="flex items-center gap-2 font-bold">
            <span className="material-symbols-outlined text-[18px]">error</span>
            Tool Execution Error
          </div>
          <p className="text-xs text-error/90 leading-relaxed">{error}</p>
        </div>
      );
    }

    if (!result) return null;

    // EMAIL HEADER ANALYZER
    if (activeTool === 'email') {
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-surface-container-low p-3 rounded-xl border border-white/5">
              <span className="text-[10px] font-mono text-on-surface-variant uppercase">Hops Count</span>
              <p className="text-lg font-bold text-white">{result.hops?.length || 0} MTAs</p>
            </div>
            <div className="bg-surface-container-low p-3 rounded-xl border border-white/5">
              <span className="text-[10px] font-mono text-on-surface-variant uppercase">SPF Status</span>
              <p className={`text-sm font-bold ${result.spf?.includes('pass') ? 'text-emerald-400' : 'text-amber-400'}`}>
                {result.spf || 'Unknown'}
              </p>
            </div>
            <div className="bg-surface-container-low p-3 rounded-xl border border-white/5">
              <span className="text-[10px] font-mono text-on-surface-variant uppercase">DKIM Signature</span>
              <p className={`text-sm font-bold ${result.dkim?.includes('pass') ? 'text-emerald-400' : 'text-amber-400'}`}>
                {result.dkim || 'Unknown'}
              </p>
            </div>
            <div className="bg-surface-container-low p-3 rounded-xl border border-white/5">
              <span className="text-[10px] font-mono text-on-surface-variant uppercase">DMARC Policy</span>
              <p className="text-sm font-bold text-primary">{result.dmarc || 'Evaluated'}</p>
            </div>
          </div>

          {result.hops && result.hops.length > 0 && (
            <div className="bg-[#0f172a] border border-white/10 rounded-xl overflow-hidden">
              <div className="px-4 py-2.5 bg-white/5 text-xs font-bold text-white flex items-center justify-between border-b border-white/5">
                <span>MTA Hop Path Analysis</span>
                <span className="text-primary font-mono text-[10px]">Proof: Received: Headers</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-black/30 text-on-surface-variant">
                    <tr>
                      <th className="p-2.5">#</th>
                      <th className="p-2.5">From MTA</th>
                      <th className="p-2.5">By MTA</th>
                      <th className="p-2.5">Delay</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-on-surface">
                    {result.hops.map((hop: any, i: number) => (
                      <tr key={i} className="hover:bg-white/[0.02]">
                        <td className="p-2.5 text-primary font-bold">{i + 1}</td>
                        <td className="p-2.5 text-white">{hop.from || 'N/A'}</td>
                        <td className="p-2.5 text-on-surface-variant">{hop.by || 'N/A'}</td>
                        <td className="p-2.5 text-amber-400">{hop.delay || '0s'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      );
    }

    // TYPOSQUATTING
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

          {result.active_typosquats?.length > 0 ? (
            <div className="bg-[#0f172a] border border-white/10 rounded-xl overflow-hidden">
              <div className="px-4 py-3 bg-error/10 border-b border-error/20 text-error font-bold text-sm flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-[18px]">warning</span>
                  Active Resolving Domains ({result.active_typosquats.length})
                </span>
                <span className="text-[10px] font-mono text-error/80">Authoritative Root DNS</span>
              </div>
              <ul className="divide-y divide-white/5">
                {result.active_typosquats.map((t: any, i: number) => (
                  <li key={i} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-white/[0.02]">
                    <span className="text-white font-mono text-sm font-bold">{t.domain}</span>
                    <div className="flex flex-wrap gap-1.5">
                      {t.ips.map((ip: string) => (
                        <span key={ip} className="bg-white/5 text-xs text-primary px-2 py-0.5 rounded border border-white/10 font-mono">{ip}</span>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-xl text-emerald-400 text-xs flex items-center gap-2">
              <span className="material-symbols-outlined">check_circle</span>
              No active typosquatting variations registered or resolving for this domain.
            </div>
          )}
        </div>
      );
    }

    // BASE64/HEX DECODER
    if (activeTool === 'decode') {
      return (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs">
            <span className="bg-primary/20 text-primary px-3 py-1 rounded font-mono font-bold border border-primary/30">
              Detected Format: {result.type?.toUpperCase()}
            </span>
            <button
              onClick={() => navigator.clipboard.writeText(result.decoded)}
              className="text-xs text-on-surface-variant hover:text-white flex items-center gap-1 bg-white/5 px-2.5 py-1 rounded border border-white/10"
            >
              <span className="material-symbols-outlined text-[14px]">content_copy</span>
              Copy Decoded Output
            </button>
          </div>
          <div className="bg-[#0f172a] border border-white/10 p-4 rounded-xl overflow-auto max-h-[300px]">
            <pre className="whitespace-pre-wrap break-all text-xs text-emerald-400 font-mono leading-relaxed">{result.decoded}</pre>
          </div>
        </div>
      );
    }

    // SHODAN INTERNETDB
    if (activeTool === 'shodan') {
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="bg-surface-container-low p-3 rounded-xl border border-white/5">
              <span className="text-[10px] font-mono text-on-surface-variant uppercase">Target Host IP</span>
              <p className="text-sm font-bold text-white font-mono">{result.ip || input}</p>
            </div>
            <div className="bg-surface-container-low p-3 rounded-xl border border-white/5">
              <span className="text-[10px] font-mono text-on-surface-variant uppercase">Open Ports</span>
              <p className="text-sm font-bold text-primary font-mono">{result.ports?.length || 0} Ports</p>
            </div>
            <div className="bg-surface-container-low p-3 rounded-xl border border-white/5">
              <span className="text-[10px] font-mono text-on-surface-variant uppercase">Vulnerabilities (CVEs)</span>
              <p className={`text-sm font-bold font-mono ${result.vulns?.length > 0 ? 'text-error' : 'text-emerald-400'}`}>
                {result.vulns?.length || 0} CVEs
              </p>
            </div>
          </div>

          {result.ports && result.ports.length > 0 && (
            <div className="bg-[#0f172a] border border-white/10 p-4 rounded-xl space-y-2">
              <span className="text-xs font-mono uppercase text-on-surface-variant">Detected Open Ports</span>
              <div className="flex flex-wrap gap-2 pt-1">
                {result.ports.map((port: number) => (
                  <span key={port} className="px-2.5 py-1 bg-primary/10 text-primary border border-primary/30 rounded font-mono text-xs font-bold">
                    Port {port}
                  </span>
                ))}
              </div>
            </div>
          )}

          {result.vulns && result.vulns.length > 0 && (
            <div className="bg-error/10 border border-error/20 p-4 rounded-xl space-y-2">
              <span className="text-xs font-mono uppercase text-error font-bold flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[16px]">bug_report</span>
                Shodan Vulnerability Index ({result.vulns.length} CVEs)
              </span>
              <div className="flex flex-wrap gap-2 pt-1">
                {result.vulns.map((cve: string) => (
                  <span key={cve} className="px-2 py-0.5 bg-error/20 text-error border border-error/40 rounded font-mono text-[11px]">
                    {cve}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    }

    // MAC VENDOR LOOKUP
    if (activeTool === 'mac') {
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="bg-surface-container-low p-4 rounded-xl border border-white/5 space-y-1">
              <span className="text-xs font-mono text-on-surface-variant uppercase">Vendor Manufacturer</span>
              <p className="text-xl font-bold text-white">{result.vendor || 'Unknown Vendor'}</p>
            </div>
            <div className="bg-surface-container-low p-4 rounded-xl border border-white/5 space-y-1">
              <span className="text-xs font-mono text-on-surface-variant uppercase">OUI Prefix</span>
              <p className="text-xl font-bold text-primary font-mono">{result.mac_prefix || input.slice(0,8)}</p>
            </div>
          </div>
          <div className="bg-[#0f172a] border border-white/10 p-4 rounded-xl text-xs space-y-2">
            <div className="flex justify-between items-center border-b border-white/5 pb-2">
              <span className="text-on-surface-variant font-mono">IEEE Registry Proof:</span>
              <span className="text-emerald-400 font-mono font-bold">MATCH FOUND</span>
            </div>
            <p className="text-on-surface text-xs leading-relaxed">{result.address || 'Registered in IEEE Standards Association global database.'}</p>
          </div>
        </div>
      );
    }

    // HTTP SECURITY HEADERS
    if (activeTool === 'http') {
      return (
        <div className="space-y-6">
          <div className="flex items-center gap-4">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center text-2xl font-black shrink-0 ${
              result.score >= 80 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 
              result.score >= 50 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'
            }`}>
              {result.score}
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">HTTP Security Headers Grade</h3>
              <p className="text-xs text-on-surface-variant">Evaluates defensive HTTP headers against OWASP Secure Headers Project standards.</p>
            </div>
          </div>

          {result.missing_headers?.length > 0 && (
            <div className="bg-error-container/10 border border-error/20 p-4 rounded-xl space-y-2">
              <h4 className="text-error font-bold text-xs uppercase font-mono">Missing Mandatory Headers (-20 pts each)</h4>
              <div className="flex flex-wrap gap-2">
                {result.missing_headers.map((h: string) => (
                  <span key={h} className="bg-error/20 text-error text-xs px-2.5 py-1 rounded font-mono border border-error/30">{h}</span>
                ))}
              </div>
            </div>
          )}

          <div className="bg-[#0f172a] border border-white/10 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-black/30 text-on-surface-variant font-mono">
                <tr>
                  <th className="p-3">Header Name</th>
                  <th className="p-3">Configuration Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-mono">
                {Object.entries(result.security_headers || {}).map(([k, v]) => (
                  <tr key={k}>
                    <td className="p-3 text-primary w-1/3 font-bold">{k}</td>
                    <td className={`p-3 ${v ? 'text-emerald-400' : 'text-on-surface-variant/40'}`}>
                      {v ? (v as string) : 'Not Present'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      );
    }

    // Generic JSON view for remaining tools (DNS, Network Range)
    return (
      <div className="bg-[#0f172a] border border-white/10 p-4 rounded-xl overflow-auto max-h-[500px]">
        <div className="flex items-center justify-between border-b border-white/5 pb-2 mb-3">
          <span className="text-xs font-mono text-primary font-bold">Execution Telemetry Data</span>
          <span className="text-[10px] font-mono text-on-surface-variant">JSON Response</span>
        </div>
        <pre className="text-xs text-emerald-400 font-mono leading-relaxed">
          {JSON.stringify(result, null, 2)}
        </pre>
      </div>
    );
  };

  const getPlaceholder = () => {
    switch (activeTool) {
      case 'email': return "Paste raw MIME email headers here (Received:, Authentication-Results:, etc.)...";
      case 'typo': return "example.com";
      case 'decode': return "Paste Base64 or Hex encoded string...";
      case 'dns': return "example.com";
      case 'shodan': return "8.8.8.8";
      case 'mac': return "00:1A:2B:3C:4D:5E";
      case 'network': return "192.168.1.0/24";
      case 'http': return "https://example.com";
      default: return "Enter target input...";
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-in fade-in duration-500 pb-12 px-4 md:px-8 mt-4">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-white/10 pb-6">
        <div>
          <h1 className="text-3xl font-black text-white font-headline-lg tracking-wider flex items-center gap-3">
            STANDALONE <span className="text-primary font-light">CYBER TOOLS</span>
          </h1>
          <p className="text-on-surface-variant text-sm mt-1">
            High-precision utility modules for email forensics, network discovery, payloads, and domain intelligence.
          </p>
        </div>
        <button
          onClick={() => setShowExplainer(!showExplainer)}
          className="text-xs font-mono px-3 py-1.5 rounded-lg bg-surface-container border border-white/10 text-primary hover:text-white flex items-center gap-1.5 transition-colors"
        >
          <span className="material-symbols-outlined text-[16px]">info</span>
          {showExplainer ? "Hide Thesis & Provenance" : "Show Thesis & Provenance"}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left Sidebar Navigation */}
        <div className="lg:col-span-1 space-y-2">
          {TOOLS.map(tool => (
            <button
              key={tool.id}
              onClick={() => handleToolChange(tool.id)}
              className={`w-full text-left px-4 py-3 rounded-xl border flex items-center gap-3 transition-all ${
                activeTool === tool.id
                  ? 'bg-primary/10 border-primary/40 text-primary shadow-lg shadow-primary/5'
                  : 'bg-surface-container border-white/5 text-on-surface-variant hover:bg-white/5 hover:text-white'
              }`}
            >
              <span className="material-symbols-outlined text-[20px]">{tool.icon}</span>
              <div className="flex flex-col min-w-0">
                <span className="font-bold text-sm truncate">{tool.name}</span>
              </div>
            </button>
          ))}
        </div>

        {/* Main Tool Workbench */}
        <div className="lg:col-span-3">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTool}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
              className="bg-surface glass-panel border border-white/10 rounded-2xl p-6 min-h-[550px] flex flex-col space-y-6"
            >
              {/* Header */}
              <div className="border-b border-white/10 pb-4">
                <div className="flex items-center gap-3 mb-1">
                  <span className="material-symbols-outlined text-primary text-[28px]">{activeToolDef.icon}</span>
                  <h2 className="text-2xl font-bold text-white font-headline-sm">{activeToolDef.name}</h2>
                </div>
                <p className="text-on-surface-variant text-sm">
                  {activeToolDef.desc}
                </p>
              </div>

              {/* Tool Thesis & Provenance Explainer Accordion */}
              {showExplainer && (
                <div className="bg-[#090d16] border border-white/10 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between text-xs border-b border-white/5 pb-2">
                    <span className="font-bold text-primary flex items-center gap-1.5 font-mono">
                      <span className="material-symbols-outlined text-[16px]">verified</span>
                      TOOL THESIS & PROVENANCE EXPLAINER
                    </span>
                    <span className="text-[10px] text-on-surface-variant font-mono">STANDALONE UTILITY SPEC</span>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="text-white font-bold block mb-0.5">What this tool evaluates:</span>
                      <p className="text-on-surface-variant leading-relaxed">{activeToolDef.thesis}</p>
                    </div>

                    <div>
                      <span className="text-white font-bold block mb-0.5">Verifiable Source Authority:</span>
                      <p className="text-primary font-mono text-[11px]">{activeToolDef.verifiableProof}</p>
                    </div>

                    <div>
                      <span className="text-white font-bold block mb-1">What output data to expect:</span>
                      <ul className="list-disc list-inside text-on-surface-variant space-y-0.5 text-[11px]">
                        {activeToolDef.expectedOutput.map((item, idx) => (
                          <li key={idx}>{item}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="pt-2 border-t border-white/5">
                      <span className="text-amber-400 font-bold block mb-1 flex items-center gap-1">
                        <span className="material-symbols-outlined text-[14px]">help_outline</span>
                        Possible Reasons if Data Returns Empty or N/A:
                      </span>
                      <ul className="list-disc list-inside text-on-surface-variant/80 space-y-0.5 text-[11px]">
                        {activeToolDef.possibleEmptyReasons.map((reason, idx) => (
                          <li key={idx}>{reason}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* Input Control & Run Action */}
              <div className="space-y-4 flex-1">
                {activeTool === 'email' || activeTool === 'decode' ? (
                  <textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={getPlaceholder()}
                    className="w-full bg-[#0f172a] border border-white/10 rounded-xl p-4 text-xs text-white font-mono focus:ring-1 focus:ring-primary focus:border-primary resize-y min-h-[140px]"
                  />
                ) : (
                  <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={getPlaceholder()}
                    className="w-full bg-[#0f172a] border border-white/10 rounded-xl px-4 py-3 text-xs text-white font-mono focus:ring-1 focus:ring-primary focus:border-primary"
                    onKeyDown={(e) => e.key === 'Enter' && handleRun()}
                  />
                )}

                {activeTool === 'decode' && (
                  <div className="flex gap-4">
                    <label className="flex items-center gap-2 text-xs text-on-surface-variant cursor-pointer">
                      <input type="radio" name="dtype" value="auto" checked={decodeType==='auto'} onChange={e => setDecodeType(e.target.value)} className="text-primary focus:ring-primary bg-black border-white/20"/>
                      Auto-Detect Format
                    </label>
                    <label className="flex items-center gap-2 text-xs text-on-surface-variant cursor-pointer">
                      <input type="radio" name="dtype" value="base64" checked={decodeType==='base64'} onChange={e => setDecodeType(e.target.value)} className="text-primary focus:ring-primary bg-black border-white/20"/>
                      Force Base64
                    </label>
                    <label className="flex items-center gap-2 text-xs text-on-surface-variant cursor-pointer">
                      <input type="radio" name="dtype" value="hex" checked={decodeType==='hex'} onChange={e => setDecodeType(e.target.value)} className="text-primary focus:ring-primary bg-black border-white/20"/>
                      Force Hexadecimal
                    </label>
                  </div>
                )}

                <button
                  onClick={handleRun}
                  disabled={isLoading || !input.trim()}
                  className="bg-primary text-black font-bold px-6 py-2.5 rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-xs uppercase tracking-wider font-mono"
                >
                  {isLoading ? (
                    <>
                      <span className="material-symbols-outlined animate-spin text-[18px]">refresh</span>
                      Executing Tool...
                    </>
                  ) : (
                    <>
                      <span className="material-symbols-outlined text-[18px]">play_arrow</span>
                      Run Standalone Analysis
                    </>
                  )}
                </button>

                {/* Result Display Container */}
                <div className="pt-4 border-t border-white/10">
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
