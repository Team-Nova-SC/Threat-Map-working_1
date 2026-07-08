"use client";
import React, { useEffect, useRef } from "react";

interface GlobalMapPoint {
  lat: number;
  lon: number;
  label: string;
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  indicator?: string;
  risk_score?: number;
  country?: string;
  scanned_at?: string;
}

interface GlobalMapProps {
  points: GlobalMapPoint[];
}

const LEVEL_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
};

const LEVEL_GLOW: Record<string, string> = {
  CRITICAL: "#fca5a5",
  HIGH:     "#fdba74",
  MEDIUM:   "#fde047",
  LOW:      "#86efac",
};

const LEVEL_LABEL: Record<string, string> = {
  CRITICAL: "🔴 CRITICAL — Very Dangerous",
  HIGH:     "🟠 HIGH — Dangerous",
  MEDIUM:   "🟡 MEDIUM — Suspicious",
  LOW:      "🟢 LOW — Safe",
};

export const GlobalMap: React.FC<GlobalMapProps> = ({ points }) => {
  const mapRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mapInstanceRef = useRef<any>(null);

  const fallbackPoints: GlobalMapPoint[] = [
    { lat: 39.0438, lon: -77.4874, label: "Botnet C2 — Ashburn, US",         level: "CRITICAL", indicator: "192.168.0.1",  risk_score: 95, country: "United States", scanned_at: new Date().toISOString() },
    { lat: 55.7558, lon: 37.6173,  label: "Ransomware Core — Moscow, RU",    level: "CRITICAL", indicator: "45.33.32.156", risk_score: 91, country: "Russia",         scanned_at: new Date().toISOString() },
    { lat: 31.2304, lon: 121.4737, label: "APT Brute-Force — Shanghai, CN",  level: "HIGH",     indicator: "103.21.244.0", risk_score: 76, country: "China",          scanned_at: new Date().toISOString() },
    { lat: 52.3676, lon: 4.9041,   label: "Spam Relay — Amsterdam, NL",      level: "MEDIUM",   indicator: "185.220.101.x",risk_score: 48, country: "Netherlands",    scanned_at: new Date().toISOString() },
    { lat: -33.8688,lon: 151.2093, label: "Phishing Redirect — Sydney, AU",  level: "HIGH",     indicator: "1.1.1.1",      risk_score: 72, country: "Australia",      scanned_at: new Date().toISOString() },
    { lat: 1.3521,  lon: 103.8198, label: "DDoS Amplifier — Singapore",      level: "MEDIUM",   indicator: "8.8.8.8",      risk_score: 41, country: "Singapore",      scanned_at: new Date().toISOString() },
    { lat: 48.8566, lon: 2.3522,   label: "Credential Stealer — Paris, FR",  level: "HIGH",     indicator: "91.108.4.1",   risk_score: 79, country: "France",         scanned_at: new Date().toISOString() },
    { lat: 19.4326, lon: -99.1332, label: "Cryptominer — Mexico City, MX",   level: "LOW",      indicator: "200.23.45.1",  risk_score: 12, country: "Mexico",         scanned_at: new Date().toISOString() },
  ];

  const activePoints = points.length > 0 ? points : fallbackPoints;
  const dangerCount  = activePoints.filter(p => p.level === "HIGH" || p.level === "CRITICAL").length;

  useEffect(() => {
    if (typeof window === "undefined" || !mapRef.current) return;

    if (!document.getElementById("leaflet-css")) {
      const link = document.createElement("link");
      link.id   = "leaflet-css";
      link.rel  = "stylesheet";
      link.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
      document.head.appendChild(link);
    }

    import("leaflet").then((L) => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }

      const map = L.map(mapRef.current!, {
        zoomControl:       true,
        scrollWheelZoom:   false,
        attributionControl: false,
        minZoom: 2,
        maxZoom: 12,
      }).setView([25.0, 10.0], 2);

      mapInstanceRef.current = map;

      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        { attribution: "&copy; CARTO &copy; OpenStreetMap", maxZoom: 20 }
      ).addTo(map);

      activePoints.forEach((pt) => {
        const color = LEVEL_COLORS[pt.level] || "#64748b";
        const glow  = LEVEL_GLOW[pt.level]   || "#94a3b8";
        const label = LEVEL_LABEL[pt.level]   || pt.level;

        const scanDate = pt.scanned_at
          ? new Date(pt.scanned_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
          : "Unknown";

        const popupHtml = `
          <div style="font-family:monospace;font-size:11px;color:#e2e8f0;min-width:200px;line-height:1.8;">
            <div style="font-weight:bold;color:${color};font-size:12px;margin-bottom:6px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:4px;">${label}</div>
            ${pt.indicator ? `<div><span style="color:#94a3b8;">IP / Domain: </span><b>${pt.indicator}</b></div>` : ""}
            ${pt.risk_score !== undefined ? `<div><span style="color:#94a3b8;">Risk Score: </span><b style="color:${color};">${pt.risk_score}/100</b></div>` : ""}
            ${pt.country ? `<div><span style="color:#94a3b8;">Country: </span><b>${pt.country}</b></div>` : ""}
            <div><span style="color:#94a3b8;">Location: </span>${pt.label}</div>
            <div><span style="color:#94a3b8;">Scanned: </span>${scanDate}</div>
          </div>`;

        // Inner filled marker
        L.circleMarker([pt.lat, pt.lon], {
          radius: 7, fillColor: color, color: glow,
          weight: 2, opacity: 1, fillOpacity: 0.9,
        })
          .addTo(map)
          .bindPopup(popupHtml, { className: "globalmap-popup" });

        // Outer pulse ring
        L.circleMarker([pt.lat, pt.lon], {
          radius: 16, fillColor: "transparent",
          color: color, weight: 1, opacity: 0.3, fillOpacity: 0,
        }).addTo(map);
      });

      setTimeout(() => {
        if (mapInstanceRef.current) {
          mapInstanceRef.current.invalidateSize();
        }
      }, 100);
    });

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(activePoints)]);

  return (
    <div className="w-full h-full rounded-xl overflow-hidden border border-white/10 relative" style={{ minHeight: 350 }}>
      <style>{`
        .leaflet-container { background: #0a0d14 !important; }
        .globalmap-popup .leaflet-popup-content-wrapper {
          background: #1e2130;
          border: 1px solid rgba(255,255,255,0.15);
          border-radius: 10px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.7);
          color: #e2e8f0;
          padding: 2px;
        }
        .globalmap-popup .leaflet-popup-content { margin: 10px 14px; }
        .globalmap-popup .leaflet-popup-tip { background: #1e2130; }
        .leaflet-control-attribution { display: none; }
        .leaflet-control-zoom a {
          background: #1e2130 !important; color: #94a3b8 !important;
          border-color: rgba(255,255,255,0.1) !important;
        }
        .leaflet-control-zoom a:hover {
          background: #2d3452 !important; color: #e2e8f0 !important;
        }
      `}</style>

      <div ref={mapRef} style={{ width: "100%", height: "100%", minHeight: 350 }} />

      {/* Pin Count Legend — bottom right overlay */}
      <div className="absolute bottom-3 right-3 z-[1000] bg-black/70 backdrop-blur-sm border border-white/10 rounded-lg px-3 py-2 text-[10px] font-mono-sm space-y-1.5 pointer-events-none">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block shadow-[0_0_6px_rgba(239,68,68,0.8)]" />
          <span className="text-on-surface-variant">Critical / High</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-yellow-400 inline-block" />
          <span className="text-on-surface-variant">Medium</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
          <span className="text-on-surface-variant">Low / Safe</span>
        </div>
        <div className="border-t border-white/10 pt-1.5 text-white font-bold">
          {activePoints.length} locations &nbsp;|&nbsp;
          <span className={dangerCount > 0 ? "text-red-400" : "text-emerald-400"}>
            {dangerCount} threat{dangerCount !== 1 ? "s" : ""}
          </span>
        </div>
      </div>
    </div>
  );
};

export default GlobalMap;
