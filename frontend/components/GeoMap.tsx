"use client";
import React, { useEffect, useRef } from "react";

interface GeoMapProps {
  lat: number;
  lon: number;
  label: string;
  city?: string;
  country?: string;
  org?: string;
}

export const GeoMap: React.FC<GeoMapProps> = ({ lat, lon, label, city, country, org }) => {
  const mapRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mapInstanceRef = useRef<any>(null);

  useEffect(() => {
    if (typeof window === "undefined" || !mapRef.current) return;

    // Inject Leaflet CSS once
    if (!document.getElementById("leaflet-css")) {
      const link = document.createElement("link");
      link.id = "leaflet-css";
      link.rel = "stylesheet";
      link.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
      document.head.appendChild(link);
    }

    import("leaflet").then((L) => {
      // Tear down any stale instance before re-initializing
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }

      const map = L.map(mapRef.current!, {
        zoomControl: true,
        scrollWheelZoom: false,
        attributionControl: true,
      }).setView([lat, lon], 8);

      mapInstanceRef.current = map;

      // Stadia Alidade Smooth Dark tiles
      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          attribution:
            '&copy; <a href="https://carto.com/">CARTO</a>, &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
          maxZoom: 20,
        }
      ).addTo(map);

      // Build rich popup content
      const popupContent = `
        <div style="font-family: monospace; font-size: 12px; min-width: 180px; color: #e2e8f0;">
          <div style="font-size: 13px; font-weight: bold; color: #a5b4fc; margin-bottom: 6px;">📍 ${label}</div>
          ${city ? `<div><span style="color:#94a3b8;">City:</span> ${city}${country ? `, ${country}` : ""}</div>` : ""}
          ${org ? `<div style="margin-top:4px;"><span style="color:#94a3b8;">ISP/Org:</span> ${org}</div>` : ""}
          <div style="margin-top:4px;"><span style="color:#94a3b8;">Coords:</span> ${lat.toFixed(4)}, ${lon.toFixed(4)}</div>
        </div>
      `;

      // Glowing red circle marker
      const glowMarker = L.circleMarker([lat, lon], {
        radius: 10,
        fillColor: "#ef4444",
        color: "#fca5a5",
        weight: 2,
        opacity: 1,
        fillOpacity: 0.85,
      })
        .addTo(map)
        .bindPopup(popupContent, { maxWidth: 260, className: "threatmap-popup" })
        .openPopup();

      // Outer pulse ring
      L.circleMarker([lat, lon], {
        radius: 20,
        fillColor: "transparent",
        color: "#ef4444",
        weight: 1,
        opacity: 0.4,
        fillOpacity: 0,
      }).addTo(map);

      // Fix popup close clearing map
      glowMarker.on("popupclose", () => {
        glowMarker.openPopup();
      });

      // Ensure full resize on mount
      setTimeout(() => map.invalidateSize(), 100);
    });

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lat, lon, label]);

  return (
    <div className="w-full h-full rounded-xl overflow-hidden border border-white/10 relative" style={{ minHeight: 300 }}>
      <style>{`
        .leaflet-container { background: #0f1117 !important; }
        .threatmap-popup .leaflet-popup-content-wrapper {
          background: #1e2130;
          border: 1px solid rgba(165,180,252,0.2);
          border-radius: 8px;
          box-shadow: 0 4px 20px rgba(0,0,0,0.5);
          color: #e2e8f0;
        }
        .threatmap-popup .leaflet-popup-tip { background: #1e2130; }
        .leaflet-control-attribution { display: none; }
      `}</style>
      <div ref={mapRef} style={{ width: "100%", height: "100%", minHeight: 300 }} />
    </div>
  );
};

export default GeoMap;
