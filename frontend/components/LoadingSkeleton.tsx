import React from "react";

export const LoadingSkeleton: React.FC = () => {
  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 py-8 animate-pulse">
      {/* Risk Gauge and top summary row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-1 glass-panel p-lg rounded-xl flex flex-col items-center justify-center min-h-[300px]">
          <div className="w-32 h-32 rounded-full bg-white/5 mb-4" />
          <div className="h-4 w-24 bg-white/5 rounded" />
        </div>
        <div className="md:col-span-2 glass-panel p-lg rounded-xl flex flex-col justify-between min-h-[300px]">
          <div className="space-y-4">
            <div className="h-6 w-1/3 bg-white/5 rounded" />
            <div className="h-4 w-full bg-white/5 rounded" />
            <div className="h-4 w-5/6 bg-white/5 rounded" />
            <div className="h-4 w-4/6 bg-white/5 rounded" />
          </div>
          <div className="h-10 w-36 bg-white/5 rounded mt-6" />
        </div>
      </div>

      {/* Grid of details */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="glass-panel p-md rounded-xl h-40 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-white/5" />
                <div className="space-y-2">
                  <div className="h-4 w-24 bg-white/5 rounded" />
                  <div className="h-3 w-16 bg-white/5 rounded" />
                </div>
              </div>
            </div>
            <div className="h-4 w-full bg-white/5 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
};

export default LoadingSkeleton;
