"use client";

import React, { useEffect, useRef, useState } from "react";

export default function CyberBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isGlitching, setIsGlitching] = useState(false);
  const [glitchIntensity, setGlitchIntensity] = useState<"mild" | "severe">("mild");
  const glitchRef = useRef({ active: false, intensity: "mild", shatterProgress: 0 });

  useEffect(() => {
    let glitchTimeout: NodeJS.Timeout;
    const triggerGlitch = () => {
      setIsGlitching(true);
      const isSevere = Math.random() > 0.6;
      setGlitchIntensity(isSevere ? "severe" : "mild");
      
      glitchRef.current.active = true;
      glitchRef.current.intensity = isSevere ? "severe" : "mild";
      glitchRef.current.shatterProgress = 1.0; // Start shatter

      const duration = isSevere ? 800 : 300;
      setTimeout(() => {
        setIsGlitching(false);
        glitchRef.current.active = false;
      }, duration);
      
      glitchTimeout = setTimeout(triggerGlitch, Math.random() * 15000 + 10000);
    };
    glitchTimeout = setTimeout(triggerGlitch, 5000);
    return () => clearTimeout(glitchTimeout);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) return;

    let animationFrameId: number;
    let lastTime = 0;
    const FPS = 30;
    const interval = 1000 / FPS;

    let width = window.innerWidth;
    let height = window.innerHeight;

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width;
      canvas.height = height;
    };
    window.addEventListener("resize", resize);
    resize();

    // Setup Matrix Rain
    const chars = "0123456789ABCDEF▓░▒■□◆◇∑∆Ωλπ".split("");
    const fontSize = 14;
    const columns = Math.floor(width / 20); // 20px width
    const drops: number[] = Array(columns).fill(1);
    const speeds: number[] = Array(columns).fill(0).map(() => Math.random() * 0.5 + 0.5);

    // Setup Floating Nodes
    const numNodes = 15;
    const nodes = Array.from({ length: numNodes }).map(() => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 1.5,
      vy: (Math.random() - 0.5) * 1.5,
      radius: Math.random() * 5 + 3,
      isThreat: Math.random() > 0.7,
      pulsePhase: Math.random() * Math.PI * 2
    }));

    // Setup Scan Line
    let scanY = 0;

    // Setup Random Dialogues
    const bgTexts = ["ANALYZING PAYLOAD", "MONITORING NETWORK", "AWAITING TELEMETRY", "DECRYPTING STREAM", "INTERCEPTING SOCKET"];
    const threatTexts = ["THREAT DETECTED", "SYSTEM COMPROMISED", "UNAUTHORIZED ACCESS", "BREACH CRITICAL", "CONTAINMENT FAILED"];
    
    interface Dialogue {
      text: string;
      x: number;
      y: number;
      vertical: boolean;
      scrollSpeedX: number;
      scrollSpeedY: number;
      life: number;
      maxLife: number;
      chars: { char: string; vx: number; vy: number }[];
    }
    
    let dialogues: Dialogue[] = [];

    const spawnDialogue = (isThreatActive: boolean) => {
      const textList = isThreatActive ? threatTexts : bgTexts;
      const text = textList[Math.floor(Math.random() * textList.length)];
      
      const zone = Math.floor(Math.random() * 3); // 0: top, 1: left, 2: right
      
      let x, y, isVertical, scrollSpeedX, scrollSpeedY;
      
      if (zone === 0) {
        // Top zone (Horizontal scrolling left)
        isVertical = false;
        x = width; 
        y = 80;
        scrollSpeedX = -1.5 - Math.random() * 1.5;
        scrollSpeedY = 0;
      } else if (zone === 1) {
        // Left zone (Vertical scrolling down)
        isVertical = true;
        x = 320;
        y = -text.length * 60;
        scrollSpeedX = 0;
        scrollSpeedY = 1 + Math.random();
      } else {
        // Right zone (Vertical scrolling down)
        isVertical = true;
        x = width - 100;
        y = -text.length * 60;
        scrollSpeedX = 0;
        scrollSpeedY = 1 + Math.random();
      }

      dialogues.push({
        text,
        x,
        y,
        vertical: isVertical,
        scrollSpeedX,
        scrollSpeedY,
        life: 0,
        maxLife: 800, // Enough time to cross screen
        chars: text.split("").map((c) => ({
          char: c,
          vx: (Math.random() - 0.5) * 30,
          vy: (Math.random() - 0.5) * 30
        }))
      });
    };

    // Setup Target Scopes
    interface TargetScope {
      x: number;
      y: number;
      radius: number;
      life: number;
      maxLife: number;
      isError: boolean;
      label: string;
      rotation: number;
      rotSpeed: number;
    }
    let scopes: TargetScope[] = [];

    const spawnScope = (isThreatActive: boolean) => {
      // High chance of error if threat is active, small random chance otherwise
      const isError = isThreatActive ? Math.random() > 0.2 : Math.random() > 0.85;
      const radius = 30 + Math.random() * 60;
      
      // Avoid sidebar (left 260px)
      const x = 320 + radius + Math.random() * (width - 340 - radius * 2);
      const y = radius + 50 + Math.random() * (height - 100 - radius * 2);

      const ips = ["192.168.1.45", "10.0.0.2", "172.16.0.1", "8.8.8.8", "104.21.5.12", "198.51.100.1"];
      const errors = ["ERR: ANOMALY", "SIG: MALWARE", "WARN: BREACH", "PORT 443 CLOSED", "SIG: DATA EXFIL"];
      const normals = ["TRG: ", "SCAN: ", "NODE: ", "PING: "];
      
      let label = isError 
        ? errors[Math.floor(Math.random() * errors.length)]
        : normals[Math.floor(Math.random() * normals.length)] + ips[Math.floor(Math.random() * ips.length)];

      scopes.push({
        x, y, radius,
        life: 0,
        maxLife: 150 + Math.random() * 200,
        isError,
        label,
        rotation: Math.random() * Math.PI,
        rotSpeed: (Math.random() - 0.5) * 0.03
      });
    };

    const draw = (currentTime: number) => {
      animationFrameId = requestAnimationFrame(draw);

      if (document.visibilityState !== "visible") return;

      const deltaTime = currentTime - lastTime;
      if (deltaTime < interval) return;
      lastTime = currentTime - (deltaTime % interval);

      const isThreatActive = document.body.classList.contains("threat-active");
      const baseColor = isThreatActive ? "#FF4444" : "#00D4AA";
      const dimColor = isThreatActive ? "#881111" : "#005544";

      // Semi-transparent black to create trailing effect
      ctx.fillStyle = "rgba(10, 10, 10, 0.2)";
      ctx.fillRect(0, 0, width, height);

      // 4. Hex/Grid Texture (subtle dots overlay)
      ctx.fillStyle = isThreatActive ? "rgba(255, 68, 68, 0.03)" : "rgba(0, 212, 170, 0.03)";
      for (let x = 0; x < width; x += 30) {
        for (let y = 0; y < height; y += 30) {
          ctx.fillRect(x, y, 1, 1);
        }
      }

      // 1. Matrix Rain
      ctx.font = `${fontSize}px monospace`;
      ctx.textAlign = "center";
      
      for (let i = 0; i < drops.length; i++) {
        // Only draw randomly to sparse out the rain a bit
        if (Math.random() > 0.5) {
          const text = chars[Math.floor(Math.random() * chars.length)];
          const x = i * 20 + 10;
          const y = drops[i] * fontSize;

          // Head of the drop
          ctx.fillStyle = "#FFFFFF";
          ctx.fillText(text, x, y);

          // Body of the drop
          ctx.fillStyle = baseColor;
          ctx.fillText(text, x, y - fontSize);
          
          // Tail
          ctx.fillStyle = dimColor;
          ctx.fillText(text, x, y - fontSize * 2);
        }

        // Reset drop or move it down
        if (drops[i] * fontSize > height && Math.random() > 0.95) {
          drops[i] = 0;
          speeds[i] = Math.random() * 0.5 + 0.5;
        }
        
        drops[i] += speeds[i] * (isThreatActive ? 1.5 : 1);
      }

      // 2. Floating Nodes & Connections
      const maxDistance = 150;
      
      // Update & Draw Lines
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDistance) {
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            const lineOpacity = (1 - dist / maxDistance) * 0.15;
            ctx.strokeStyle = `rgba(${isThreatActive ? '255, 68, 68' : '0, 212, 170'}, ${lineOpacity})`;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }

      // Update & Draw Nodes
      nodes.forEach(node => {
        // Move
        const speedMultiplier = isThreatActive ? 2 : 1;
        node.x += node.vx * speedMultiplier;
        node.y += node.vy * speedMultiplier;

        // Bounce
        if (node.x <= 0 || node.x >= width) node.vx *= -1;
        if (node.y <= 0 || node.y >= height) node.vy *= -1;

        // Pulse
        node.pulsePhase += 0.05 * speedMultiplier;
        const currentRadius = node.radius + Math.sin(node.pulsePhase) * 2;

        ctx.beginPath();
        ctx.arc(node.x, node.y, Math.max(1, currentRadius), 0, Math.PI * 2);
        const nodeColor = node.isThreat ? "#FF4444" : "#00D4AA";
        ctx.fillStyle = nodeColor;
        ctx.globalAlpha = 0.3;
        ctx.fill();
        
        // Glow
        ctx.shadowBlur = 15;
        ctx.shadowColor = nodeColor;
        ctx.fill();
        ctx.shadowBlur = 0; // reset
        ctx.globalAlpha = 1.0;
      });

      // 3. Cinematic Random Dialogues
      if (Math.random() > 0.98 && dialogues.length < 4) {
        spawnDialogue(isThreatActive);
      }
      
      // Handle Shatter Logic
      if (!glitchRef.current.active && glitchRef.current.shatterProgress > 0) {
        // Recover from shatter slowly
        glitchRef.current.shatterProgress = Math.max(0, glitchRef.current.shatterProgress - 0.015);
      }

      for (let i = dialogues.length - 1; i >= 0; i--) {
        const d = dialogues[i];
        d.life++;
        
        // Update scroll position
        if (!glitchRef.current.active) {
          d.x += d.scrollSpeedX;
          d.y += d.scrollSpeedY;
        }

        // Remove if out of bounds or dead
        if (d.life > d.maxLife || d.x < -1000 || d.y > height + 1000) {
          dialogues.splice(i, 1);
          continue;
        }

        // Fade in and out
        let textOpacity = 1.0;
        if (d.life < 30) textOpacity = d.life / 30;
        if (d.maxLife - d.life < 30) textOpacity = (d.maxLife - d.life) / 30;

        ctx.save();
        ctx.font = `800 60px "JetBrains Mono", monospace`;
        ctx.textAlign = "left";
        ctx.textBaseline = "top";
        ctx.fillStyle = isThreatActive ? `rgba(255, 68, 68, ${textOpacity})` : `rgba(0, 212, 170, ${textOpacity * 0.8})`;

        const shatterMult = glitchRef.current.shatterProgress;
        
        for (let j = 0; j < d.text.length; j++) {
          const char = d.text[j];
          const charData = d.chars[j];
          
          let charX = d.x;
          let charY = d.y;

          if (d.vertical) {
            charY += j * 55;
          } else {
            charX += j * 36;
          }

          // Apply shatter displacement
          if (shatterMult > 0) {
            charX += charData.vx * shatterMult * 15;
            charY += charData.vy * shatterMult * 15;
            
            // Random jitter during active glitch
            if (glitchRef.current.active) {
               charX += (Math.random() - 0.5) * 15;
               charY += (Math.random() - 0.5) * 15;
            }
          }

          ctx.fillText(char, charX, charY);
        }
        ctx.restore();
      }

      // 4. Dynamic Targeting Scopes (Crosshairs)
      if (Math.random() > 0.95 && scopes.length < 5) {
        spawnScope(isThreatActive);
      }

      for (let i = scopes.length - 1; i >= 0; i--) {
        const s = scopes[i];
        
        if (!glitchRef.current.active) {
          s.life++;
        }
        
        if (s.life > s.maxLife) {
          scopes.splice(i, 1);
          continue;
        }
        
        let opacity = 1.0;
        if (s.life < 20) opacity = s.life / 20;
        if (s.maxLife - s.life < 20) opacity = (s.maxLife - s.life) / 20;
        
        // During severe glitch, randomly flicker scopes
        if (glitchRef.current.active && Math.random() > 0.5) {
          opacity *= 0.3;
        }

        const color = s.isError ? `rgba(255, 68, 68, ${opacity * 0.9})` : `rgba(0, 212, 170, ${opacity * 0.7})`;
        
        ctx.save();
        ctx.translate(s.x, s.y);
        
        if (!glitchRef.current.active) {
          s.rotation += s.rotSpeed;
        }
        
        // Draw crosshair (Plus in the center)
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.moveTo(-15, 0); ctx.lineTo(15, 0);
        ctx.moveTo(0, -15); ctx.lineTo(0, 15);
        ctx.stroke();

        // Draw outer dashed ring
        ctx.rotate(s.rotation);
        ctx.beginPath();
        ctx.arc(0, 0, s.radius, 0, Math.PI * 2);
        ctx.setLineDash([15, 10, 2, 10]);
        ctx.stroke();
        
        // Draw secondary inner ring
        ctx.rotate(-s.rotation * 1.5);
        ctx.beginPath();
        ctx.arc(0, 0, s.radius * 0.7, 0, Math.PI * 2);
        ctx.setLineDash([50, 40]);
        ctx.stroke();
        ctx.restore();

        // Draw label text next to scope
        ctx.save();
        ctx.font = `600 16px "JetBrains Mono", monospace`;
        ctx.fillStyle = color;
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        // Apply slight shatter offset to label during glitch
        let labelX = s.x + s.radius + 15;
        let labelY = s.y + s.radius - 15;
        if (glitchRef.current.shatterProgress > 0) {
          labelX += (Math.random() - 0.5) * 10 * glitchRef.current.shatterProgress;
          labelY += (Math.random() - 0.5) * 10 * glitchRef.current.shatterProgress;
        }
        ctx.fillText(s.label, labelX, labelY);
        
        // Draw tracking line from scope to label
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 1;
        ctx.moveTo(s.x + Math.cos(Math.PI/4) * s.radius, s.y + Math.sin(Math.PI/4) * s.radius);
        ctx.lineTo(labelX - 5, labelY);
        ctx.stroke();
        ctx.restore();
      }

      // 5. Scanning Line
      scanY += (height / (30 * 8)) * (isThreatActive ? 2 : 1); // 8 seconds to sweep
      if (scanY > height) scanY = 0;

      const grad = ctx.createLinearGradient(0, scanY - 50, 0, scanY);
      grad.addColorStop(0, "transparent");
      grad.addColorStop(1, isThreatActive ? "rgba(255, 68, 68, 0.1)" : "rgba(0, 212, 170, 0.05)");
      
      ctx.fillStyle = grad;
      ctx.fillRect(0, scanY - 50, width, 50);
      
      ctx.fillStyle = isThreatActive ? "rgba(255, 68, 68, 0.2)" : "rgba(0, 212, 170, 0.2)";
      ctx.fillRect(0, scanY, width, 2);
    };

    animationFrameId = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <>
      <style>{`
        @keyframes cyber-glitch {
          0% { transform: translateX(0); }
          20% { transform: translateX(-4px); filter: hue-rotate(90deg) contrast(150%); }
          40% { transform: translateX(4px); filter: hue-rotate(-90deg) contrast(150%); }
          60% { transform: translateX(-2px); }
          80% { transform: translateX(2px); }
          100% { transform: translateX(0); }
        }
        @keyframes cyber-glitch-severe {
          0% { transform: translateX(0); filter: grayscale(100%) contrast(200%) invert(0%); }
          10% { transform: translateX(-15px) translateY(5px); filter: grayscale(100%) contrast(300%) invert(100%) hue-rotate(90deg); }
          20% { transform: translateX(15px) translateY(-5px) skewX(20deg); filter: grayscale(100%) contrast(200%) invert(0%); }
          30% { transform: translateX(-10px) skewX(-10deg); filter: grayscale(100%) invert(100%); }
          40% { transform: translateX(10px) skewX(-20deg); filter: grayscale(100%) contrast(300%) invert(100%); }
          50% { transform: translateX(0); filter: grayscale(100%) contrast(200%) invert(0%); }
          100% { transform: translateX(0); filter: grayscale(0%) contrast(100%) invert(0%); }
        }
        .animate-glitch-mild {
          animation: cyber-glitch 0.2s cubic-bezier(.25, .46, .45, .94) both;
        }
        .animate-glitch-severe {
          animation: cyber-glitch-severe 0.6s cubic-bezier(.25, .46, .45, .94) both;
        }
      `}</style>
      
      {/* Vignette Overlay */}
      <div 
        className="fixed inset-0 pointer-events-none z-0"
        style={{
          background: "radial-gradient(circle at center, transparent 30%, rgba(5, 5, 5, 0.85) 100%)"
        }}
      />
      
      {/* Background Canvas */}
      <canvas
        ref={canvasRef}
        className={`fixed inset-0 pointer-events-none z-0 opacity-[0.15] mix-blend-screen transition-opacity duration-300 ${
          isGlitching ? (glitchIntensity === "severe" ? "animate-glitch-severe opacity-[0.4]" : "animate-glitch-mild opacity-[0.3]") : ""
        }`}
      />
    </>
  );
}
