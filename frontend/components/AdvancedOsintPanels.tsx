"use client";

import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ScanResponse } from "@/types";
import DetectionCard from "@/components/DetectionCard";

export default function AdvancedOsintPanels({ scan }: { scan: ScanResponse }) {
  const [data, setData] = useState<any>({
    whois: null,
    ssl: null,
    ports: null,
    reverseDns: null,
    asn: null,
    subdomains: null,
    dns: null,
    shodan: null,
    darkweb: null,
    webvulns: null,
    techStack: null,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchOsint() {
      setLoading(true);
      const indicator = scan.indicator;
      const type = scan.type;
      
      const newData = { ...data };

      try {
        // Run lookups in parallel based on indicator type
        const promises = [];

        if (type === "ip") {
          promises.push(api.getReverseDns(indicator).then(r => newData.reverseDns = r));
          promises.push(api.getPorts(indicator).then(r => newData.ports = r));
          promises.push(api.getAsnDetails(indicator).then(r => newData.asn = r));
          promises.push(api.getSsl(indicator).then(r => newData.ssl = r));
          promises.push(api.getShodan(indicator).then(r => newData.shodan = r));
        } else if (type === "domain" || type === "url") {
          let domain = indicator;
          if (type === "url") {
            try {
              domain = new URL(indicator).hostname;
            } catch (e) {
              // fallback
            }
          }
          
          promises.push(api.getWhois(domain).then(r => newData.whois = r));
          promises.push(api.getSsl(domain).then(r => newData.ssl = r));
          promises.push(api.getSubdomains(domain).then(r => newData.subdomains = r));
          promises.push(api.getDnsRecords(domain).then(r => newData.dns = r));
          promises.push(api.getDarkWeb(domain).then(r => newData.darkweb = r));
          promises.push(api.getWebVulns(domain).then(r => newData.webvulns = r));
          promises.push(api.getTechStack(domain).then(r => newData.techStack = r));
        }

        await Promise.allSettled(promises);
        setData(newData);
      } catch (e) {
        console.error("OSINT fetch error", e);
      } finally {
        setLoading(false);
      }
    }

    fetchOsint();
  }, [scan.indicator, scan.type]);


  if (loading) {
    return (
      <div className="mt-8">
        <h3 className="font-bold font-label-caps text-label-caps text-[12px] text-on-surface-variant uppercase tracking-wider mb-4 flex items-center gap-2">
          Advanced Telemetry <span className="animate-pulse bg-primary/20 text-primary text-[9px] px-1.5 py-0.5 rounded border border-primary/30">GATHERING...</span>
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 opacity-50">
          <div className="glass-panel h-[120px] rounded-xl animate-pulse"></div>
          <div className="glass-panel h-[120px] rounded-xl animate-pulse"></div>
          <div className="glass-panel h-[120px] rounded-xl animate-pulse"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="mt-8">
      <h3 className="font-bold font-label-caps text-label-caps text-[12px] text-on-surface-variant uppercase tracking-wider mb-4">
        Advanced Active Telemetry
      </h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">

        {/* Shodan Panel */}
        {data.shodan && (
          <DetectionCard
            title="Attack Surface (Shodan)"
            subtitle="Known vulnerabilities & exposed services on this IP"
            status={data.shodan?.vulns?.length > 0 ? "VULNERABLE" : "Clean"}
            isMalicious={data.shodan?.vulns?.length > 0}
            iconName="radar"
          >
            <div className="text-[10px] font-mono-sm space-y-1 text-on-surface-variant mt-2">
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <div className={`h-2 w-2 rounded-full ${data.shodan?.vulns?.length ? 'bg-error animate-ping' : 'bg-success'}`}></div>
                  <span>CVEs Found: {data.shodan?.vulns?.length || 0}</span>
                </div>
                {data.shodan?.vulns?.length > 0 && (
                  <div className="flex gap-1 flex-wrap">
                    {data.shodan?.vulns.map((v: string) => (
                      <span key={v} className="bg-error/20 text-error px-1 py-0.5 rounded text-[8px]">{v}</span>
                    ))}
                  </div>
                )}
                <div className="mt-1 border-t border-white/10 pt-1">
                  <span className="text-white/50 text-[9px]">Server OS:</span> {data.shodan?.os || "Unknown"}
                </div>
              </div>
            </div>
          </DetectionCard>
        )}

        {/* Dark Web Mentions Panel */}
        {data.darkweb && (
          <DetectionCard
            title="Dark Web Exposure"
            subtitle="Mentions in hacker forums and leaked DBs"
            status={data.darkweb?.mentions > 0 ? "Exposed" : "Clear"}
            isMalicious={data.darkweb?.mentions > 0}
            iconName="public_off"
          >
            <div className="mt-3">
              <div className="flex justify-between text-[10px] font-mono-sm text-on-surface-variant mb-1">
                <span>Threat Level</span>
                <span className={data.darkweb?.mentions > 0 ? "text-error" : "text-success"}>
                  {data.darkweb?.mentions} Mentions
                </span>
              </div>
              <div className="w-full bg-surface-variant rounded-full h-1.5 overflow-hidden">
                <div 
                  className={`h-full ${data.darkweb?.mentions > 5 ? 'bg-error' : data.darkweb?.mentions > 0 ? 'bg-warning' : 'bg-success'}`}
                  style={{ width: `${Math.min(100, ((data.darkweb?.mentions || 0) / 15) * 100)}%` }}
                ></div>
              </div>
              {data.darkweb?.forums?.length > 0 && (
                <div className="flex gap-1 mt-2 flex-wrap">
                  {data.darkweb?.forums.map((f: string) => (
                    <span key={f} className="text-[9px] bg-surface-variant text-on-surface px-1.5 py-0.5 rounded">
                      {f}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </DetectionCard>
        )}

        {/* DNS Records Panel */}
        {data.dns && (
          <DetectionCard
            title="DNS Enumeration"
            subtitle="Core routing records for this domain"
            status={data.dns?.status === "success" ? "Resolved" : "Failed"}
            isMalicious={false}
            iconName="dns"
          >
            <div className="text-[10px] font-mono-sm space-y-1.5 text-on-surface-variant mt-2 max-h-[80px] overflow-y-auto custom-scrollbar">
              {['A', 'MX', 'TXT'].map(type => (
                data.dns?.records?.[type]?.length > 0 && (
                  <div key={type} className="flex gap-2 border-b border-white/5 pb-1">
                    <span className="text-primary font-bold w-6">{type}</span>
                    <span className="text-white truncate flex-1" title={data.dns?.records?.[type]?.[0]}>
                      {data.dns?.records?.[type]?.[0]}
                      {data.dns?.records?.[type]?.length > 1 && ` (+${data.dns.records[type].length - 1})`}
                    </span>
                  </div>
                )
              ))}
              {!data.dns?.records?.A?.length && !data.dns?.records?.MX?.length && (
                <div className="text-white/40 italic">No standard records found.</div>
              )}
            </div>
          </DetectionCard>
        )}

        {/* Tech Stack Panel */}
        {data.techStack && (
          <DetectionCard
            title="Tech Stack Fingerprint"
            subtitle="Detected backend technologies and frameworks"
            status={data.techStack?.status === "success" ? "Analyzed" : "Failed"}
            isMalicious={false}
            iconName="memory"
          >
            <div className="text-[10px] font-mono-sm space-y-1.5 text-on-surface-variant mt-2 max-h-[80px] overflow-y-auto custom-scrollbar">
              {data.techStack?.stack?.server && (
                <div className="flex gap-2">
                  <span className="text-primary font-bold min-w-[70px]">SERVER:</span>
                  <span className="text-white truncate">{data.techStack.stack.server}</span>
                </div>
              )}
              {data.techStack?.stack?.frameworks?.length > 0 && (
                <div className="flex gap-2">
                  <span className="text-primary font-bold min-w-[70px]">FRAMEWORK:</span>
                  <span className="text-white truncate">{data.techStack.stack.frameworks.join(', ')}</span>
                </div>
              )}
              {data.techStack?.stack?.cms && (
                <div className="flex gap-2">
                  <span className="text-primary font-bold min-w-[70px]">CMS:</span>
                  <span className="text-white truncate">{data.techStack.stack.cms}</span>
                </div>
              )}
              {data.techStack?.stack?.cdn && (
                <div className="flex gap-2">
                  <span className="text-primary font-bold min-w-[70px]">CDN/WAF:</span>
                  <span className="text-white truncate">{data.techStack.stack.cdn}</span>
                </div>
              )}
              {(!data.techStack?.stack?.server && !data.techStack?.stack?.frameworks?.length && !data.techStack?.stack?.cms && !data.techStack?.stack?.cdn) && (
                <div className="text-white/40 italic">No distinctive stack signatures detected.</div>
              )}
            </div>
          </DetectionCard>
        )}

        {/* WHOIS Panel */}
        {data.whois && (
          <DetectionCard
            title="Live WHOIS Data"
            subtitle="Who registered this domain and when"
            status={data.whois.lookup_status === "success" ? "Registered" : "Failed"}
            isMalicious={false}
            iconName="contact_page"
          >
            <div className="text-[10px] font-mono-sm space-y-1 text-on-surface-variant mt-2">
              <div className="flex justify-between">
                <span>Registrar:</span>
                <span className="text-white truncate max-w-[120px]" title={data.whois?.registrar}>{data.whois?.registrar || "N/A"}</span>
              </div>
              <div className="flex justify-between">
                <span>Created:</span>
                <span className="text-white">{data.whois?.creation_date ? String(data.whois.creation_date).split(" ")[0] : "N/A"}</span>
              </div>
              <div className="flex justify-between">
                <span>Expires:</span>
                <span className="text-white">{data.whois?.expiration_date ? String(data.whois.expiration_date).split(" ")[0] : "N/A"}</span>
              </div>
            </div>
          </DetectionCard>
        )}

        {/* SSL Panel */}
        {data.ssl && (
          <DetectionCard
            title="SSL Certificate"
            subtitle="Proves this site is who it says it is"
            status={data.ssl?.is_expired ? "EXPIRED" : data.ssl?.status === "success" ? "Valid" : "None"}
            isMalicious={data.ssl?.is_expired}
            iconName="lock"
          >
            {data.ssl?.status === "success" ? (
              <div className="text-[10px] font-mono-sm space-y-1 text-on-surface-variant mt-2">
                <div className="flex justify-between">
                  <span>Issuer Org:</span>
                  <span className="text-white truncate max-w-[120px]">{data.ssl?.issuer_org}</span>
                </div>
                <div className="flex justify-between">
                  <span>Days Left:</span>
                  <span className={(data.ssl?.days_remaining || 0) < 30 ? "text-error font-bold" : "text-white"}>
                    {data.ssl?.days_remaining}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Subject CN:</span>
                  <span className="text-white truncate max-w-[120px]">{data.ssl?.subject_cn}</span>
                </div>
              </div>
            ) : (
              <div className="text-xs text-on-surface-variant mt-2">No valid SSL cert detected.</div>
            )}
          </DetectionCard>
        )}

        {/* Open Ports Panel */}
        {data.ports && (
          <DetectionCard
            title="Exposed Ports"
            subtitle="Open doors into this server — more = higher risk"
            status={`${data.ports?.total_open || 0} open`}
            isMalicious={(data.ports?.total_open || 0) > 3}
            iconName="router"
          >
            {data.ports?.open_ports && data.ports?.open_ports.length > 0 ? (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {data.ports.open_ports.slice(0, 6).map((p: any) => (
                  <span key={p.port} className="text-[9px] font-mono-sm bg-error/10 border border-error/20 text-error px-1.5 py-0.5 rounded flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-error inline-block"></span>
                    {p.port}/{p.service}
                  </span>
                ))}
                {data.ports.open_ports.length > 6 && (
                  <span className="text-[9px] font-mono-sm bg-white/5 border border-white/10 text-white px-1.5 py-0.5 rounded">
                    +{data.ports.open_ports.length - 6} more
                  </span>
                )}
              </div>
            ) : (
              <div className="text-xs text-on-surface-variant mt-2 font-mono-sm">No common ports exposed.</div>
            )}
          </DetectionCard>
        )}

        {/* Reverse DNS Panel */}
        {data.reverseDns && (
          <DetectionCard
            title="Reverse DNS"
            subtitle="What name is attached to this IP address"
            status={data.reverseDns.hostname ? "Resolved" : "No PTR"}
            isMalicious={false}
            iconName="dns"
          >
            <div className="text-[10px] font-mono-sm space-y-1 text-on-surface-variant mt-2">
              <div className="flex justify-between">
                <span>Hostname:</span>
                <span className="text-white truncate max-w-[130px]" title={data.reverseDns.hostname}>
                  {data.reverseDns.hostname || "None"}
                </span>
              </div>
              <div className="flex justify-between mt-2">
                <span>Aliases:</span>
                <span className="text-white">{data.reverseDns.aliases?.length || 0}</span>
              </div>
            </div>
          </DetectionCard>
        )}

        {/* ASN Panel */}
        {data.asn && (
          <DetectionCard
            title="ASN Network"
            subtitle="The company that owns this IP & its internet connection"
            status={data.asn.asn || "Unknown"}
            isMalicious={false}
            iconName="lan"
          >
            <div className="text-[10px] font-mono-sm space-y-1 text-on-surface-variant mt-2">
              <div className="flex justify-between">
                <span>Org Name:</span>
                <span className="text-white truncate max-w-[130px]" title={data.asn.org_name}>{data.asn.org_name || "N/A"}</span>
              </div>
              <div className="flex justify-between">
                <span>Network:</span>
                <span className="text-white">{data.asn.network || "N/A"}</span>
              </div>
              <div className="flex justify-between">
                <span>Country:</span>
                <span className="text-white">{data.asn.country || "N/A"}</span>
              </div>
            </div>
          </DetectionCard>
        )}

        {/* Subdomains Panel */}
        {data.subdomains && (
          <DetectionCard
            title="Subdomain Enum"
            subtitle="Other addresses attached to this domain"
            status={`${data.subdomains.total_found || 0} found`}
            isMalicious={false}
            iconName="account_tree"
          >
            {data.subdomains.subdomains && data.subdomains.subdomains.length > 0 ? (
              <div className="flex flex-col gap-1 mt-2">
                {data.subdomains.subdomains.slice(0, 3).map((sub: string) => (
                  <span key={sub} className="text-[9px] font-mono-sm text-on-surface-variant truncate border-b border-white/5 pb-0.5">
                    {sub}.{scan.indicator}
                  </span>
                ))}
                {data.subdomains.total_found > 3 && (
                  <span className="text-[9px] font-mono-sm text-primary mt-1">
                    +{data.subdomains.total_found - 3} additional subdomains
                  </span>
                )}
              </div>
            ) : (
              <div className="text-xs text-on-surface-variant mt-2 font-mono-sm">No subdomains discovered in crt.sh</div>
            )}
          </DetectionCard>
        )}

      </div>
    </div>
  );
}
