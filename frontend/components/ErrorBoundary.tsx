"use client";

import React, { Component, ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  name?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error(`ErrorBoundary caught an error in [${this.props.name || "Widget"}]:`, error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="w-full h-full min-h-[150px] p-6 bg-surface-container-low/80 border border-red-500/20 rounded-xl flex flex-col items-center justify-center text-center space-y-3">
          <span className="material-symbols-outlined text-red-400 text-3xl">warning</span>
          <div>
            <h4 className="text-xs font-bold text-white font-mono-sm uppercase">
              {this.props.name || "Telemetry Widget"} Rendering Error
            </h4>
            <p className="text-[11px] text-on-surface-variant mt-1">
              Component isolated safely to prevent application interruption.
            </p>
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            className="px-3 py-1 bg-white/5 hover:bg-white/10 border border-white/10 text-white rounded text-[10px] font-mono-sm font-bold transition-all"
          >
            RETRY WIDGET
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
