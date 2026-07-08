"use client";

import React, { useEffect, useState, useRef } from "react";
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';

interface Node {
  id: string;
  label: string;
  type: "ioc" | "asn" | "country" | "actor" | "subnet";
  risk?: number;
}

interface Edge {
  from: string;
  to: string;
  label?: string;
}

interface RelationshipGraphProps {
  nodes: Node[];
  edges: Edge[];
}

const TYPE_COLORS: Record<string, string> = {
  ioc: "#6366f1",    // indigo-500
  asn: "#0ea5e9",    // sky-500
  country: "#10b981",// emerald-500
  actor: "#ef4444",  // red-500
  subnet: "#f59e0b", // amber-500
};

export const RelationshipGraph: React.FC<RelationshipGraphProps> = ({ nodes, edges }) => {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted || typeof window === 'undefined') {
    return (
      <div className="flex items-center justify-center h-[400px] border border-white/5 bg-white/[0.02] rounded-xl text-xs text-on-surface-variant font-mono-sm">
        LOADING GRAPH...
      </div>
    );
  }

  if (nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-on-surface-variant/40 text-sm gap-2">
        <span className="material-symbols-outlined text-[40px] opacity-30">hub</span>
        <p>No relationship data available for this IOC.</p>
      </div>
    );
  }

  try {
    const elements: cytoscape.ElementDefinition[] = [
      ...nodes.map(n => ({
        data: { id: n.id, label: n.label, type: n.type, color: TYPE_COLORS[n.type] || TYPE_COLORS.ioc }
      })),
      ...edges.map(e => ({
        data: { source: e.from, target: e.to, label: e.label || '' }
      }))
    ];

    const stylesheet: cytoscape.StylesheetCSS[] = [
      {
        selector: 'node',
        css: {
          'background-color': 'data(color)',
          'label': 'data(label)',
          'color': '#ffffff',
          'text-valign': 'bottom',
          'text-margin-y': 5,
          'font-size': '10px',
          'font-family': 'monospace',
          'width': 24,
          'height': 24
        }
      },
      {
        selector: 'edge',
        css: {
          'width': 2,
          'line-color': '#ffffff',
          'target-arrow-color': '#ffffff',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'opacity': 0.3,
          'label': 'data(label)',
          'font-size': '8px',
          'color': '#ffffff',
          'text-background-opacity': 1,
          'text-background-color': '#111111',
          'text-background-padding': '2px',
          'text-background-shape': 'roundrectangle'
        }
      }
    ];

    return (
      <div className="space-y-4">
        {/* Legend */}
        <div className="flex flex-wrap gap-3">
          {Object.entries(TYPE_COLORS).map(([type, color]) => (
            <div key={type} className="flex items-center gap-1.5 text-[10px] text-on-surface-variant font-mono">
              <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }} />
              {type.toUpperCase()}
            </div>
          ))}
        </div>

        <div className="h-[400px] w-full border border-white/10 rounded-xl bg-black/20 relative overflow-hidden">
          <CytoscapeComponent 
            elements={elements} 
            style={{ width: '100%', height: '100%' }} 
            stylesheet={stylesheet}
            layout={{ name: 'concentric', minNodeSpacing: 50 }}
          />
        </div>
      </div>
    );
  } catch (err) {
    console.error("Cytoscape render error:", err);
    return (
      <div className="flex items-center justify-center h-[400px] border border-red-500/20 bg-red-500/5 rounded-xl text-xs text-red-400 font-mono-sm">
        Error rendering network graph. Check console.
      </div>
    );
  }
};

export default RelationshipGraph;
