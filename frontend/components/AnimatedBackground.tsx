"use client";

import React, { useEffect, useState } from "react";

export default function AnimatedBackground() {
  const [mounted, setMounted] = useState(false);
  const [nodes, setNodes] = useState<any[]>([]);

  useEffect(() => {
    setMounted(true);
    // Generate nodes on client to avoid hydration mismatch
    const generatedNodes = Array.from({ length: 25 }).map((_, i) => ({
      id: i,
      left: Math.random() * 100,
      delay: Math.random() * 15,
      duration: 10 + Math.random() * 20,
      size: Math.random() > 0.8 ? "w-1.5 h-1.5" : "w-1 h-1",
      color:
        Math.random() > 0.8
          ? "bg-error shadow-error"
          : Math.random() > 0.6
          ? "bg-orange-400 shadow-orange-400"
          : "bg-primary shadow-primary",
    }));
    setNodes(generatedNodes);
  }, []);

  return (
    <div className="fixed inset-0 z-0 overflow-hidden pointer-events-none bg-transparent">
      <style>{`
        @keyframes radar-spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes float-up {
          0% { transform: translateY(100vh) scale(0); opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { transform: translateY(-10vh) scale(1.5); opacity: 0; }
        }
        @keyframes pulse-slow {
          0%, 100% { opacity: 0.2; }
          50% { opacity: 0.6; }
        }
        .bg-grid {
          background-size: 40px 40px;
          background-image: 
            linear-gradient(to right, rgba(173, 198, 255, 0.05) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(173, 198, 255, 0.05) 1px, transparent 1px);
        }
        .radar-sweep {
          background: conic-gradient(from 0deg at 50% 50%, transparent 0deg, rgba(173, 198, 255, 0.05) 60deg, rgba(173, 198, 255, 0.3) 90deg, transparent 90deg);
          animation: radar-spin 12s linear infinite;
          transform-origin: center;
        }
        .radial-mask {
          background: radial-gradient(circle at center, transparent 10%, #020617 80%);
        }
      `}</style>

      {/* Base Grid */}
      <div className="absolute inset-0 bg-grid opacity-30"></div>

      {/* Radar Sweep Effect (Optimized) */}
      <div className="absolute top-[0%] left-[0%] w-[100%] h-[100%] radar-sweep opacity-50"></div>

      {/* Soft Vignette Mask to fade out edges */}
      <div className="absolute inset-0 radial-mask opacity-90"></div>

      {/* Static glowing hot spots (Optimized blurs) */}
      <div className="absolute top-[20%] left-[30%] w-64 h-64 bg-primary/10 rounded-full blur-[40px]" style={{animation: "pulse-slow 6s ease-in-out infinite"}}></div>
      <div className="absolute top-[70%] left-[80%] w-96 h-96 bg-error/10 rounded-full blur-[50px]" style={{animation: "pulse-slow 8s ease-in-out infinite 2s"}}></div>
      <div className="absolute bottom-[20%] left-[10%] w-72 h-72 bg-orange-500/10 rounded-full blur-[40px]" style={{animation: "pulse-slow 7s ease-in-out infinite 1s"}}></div>

      {/* Floating data nodes (Rendered only on client) */}
      {mounted &&
        nodes.map((node) => (
          <div
            key={node.id}
            className={`absolute rounded-full ${node.size} ${node.color} shadow-[0_0_8px]`}
            style={{
              left: `${node.left}%`,
              bottom: "-20px",
              animation: `float-up ${node.duration}s linear ${node.delay}s infinite`,
            }}
          />
        ))}
    </div>
  );
}
