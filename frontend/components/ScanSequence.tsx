import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle, Loader2 } from "lucide-react";

interface ScanSequenceProps {
  isVisible: boolean;
  onComplete?: () => void;
}

const STEPS = [
  "Initializing security engines...",
  "Querying VirusTotal reputation...",
  "Checking AbuseIPDB records...",
  "Running WHOIS & DNS lookups...",
  "Fetching geographic coordinates...",
  "Generating AI analysis brief...",
  "Finalizing threat report..."
];

export const ScanSequence: React.FC<ScanSequenceProps> = ({ isVisible, onComplete }) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [loadingMessage, setLoadingMessage] = useState("Analyzing Target...");

  useEffect(() => {
    if (!isVisible) {
      setCurrentStepIndex(0);
      setLoadingMessage("Analyzing Target...");
      return;
    }

    const timer15 = setTimeout(() => {
      setLoadingMessage("Still working... some APIs are slow today");
    }, 15000);

    const timer30 = setTimeout(() => {
      setLoadingMessage("Almost done... finalizing threat report");
    }, 30000);

    // Simulate progress through the steps while the actual API call is happening
    const timer = setInterval(() => {
      setCurrentStepIndex((prev) => {
        if (prev < STEPS.length - 1) {
          return prev + 1;
        }
        return prev;
      });
    }, 800);

    return () => {
      clearInterval(timer);
      clearTimeout(timer15);
      clearTimeout(timer30);
    };
  }, [isVisible]);

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-background/80 backdrop-blur-md"
        >
          {/* Particles */}
          <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
            {Array.from({ length: 20 }).map((_, i) => (
              <motion.div
                key={i}
                className="absolute w-1.5 h-1.5 bg-primary/40 rounded-full blur-[1px]"
                initial={{
                  x: Math.random() * (typeof window !== 'undefined' ? window.innerWidth : 1000),
                  y: (typeof window !== 'undefined' ? window.innerHeight : 1000) + 10,
                  opacity: Math.random() * 0.5 + 0.3
                }}
                animate={{
                  y: -10,
                  x: `+=${Math.random() * 100 - 50}`
                }}
                transition={{
                  duration: Math.random() * 3 + 2,
                  repeat: Infinity,
                  ease: "linear",
                  delay: Math.random() * 2
                }}
              />
            ))}
          </div>

          <motion.div
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            transition={{ type: "spring" as const, damping: 25, stiffness: 300 }}
            className="bg-surface-container border border-white/10 p-8 rounded-2xl w-full max-w-md shadow-2xl relative z-10 overflow-hidden"
          >
            {/* Glowing orb behind content */}
            <div className="absolute -top-24 -right-24 w-48 h-48 bg-primary/20 rounded-full blur-3xl pointer-events-none" />
            
            <div className="flex items-center gap-3 mb-6 relative z-10">
              <Loader2 className="w-6 h-6 text-primary animate-spin" />
              <h2 className="text-xl font-bold text-white font-headline-sm">{loadingMessage}</h2>
            </div>

            <div className="space-y-4">
              {STEPS.map((step, index) => {
                const isActive = index === currentStepIndex;
                const isCompleted = index < currentStepIndex;
                const isUpcoming = index > currentStepIndex;

                if (isUpcoming && index > currentStepIndex + 1) return null; // Only show one upcoming step

                return (
                  <motion.div
                    key={step}
                    initial={{ x: -20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    className={`flex items-center gap-3 relative z-10 ${
                      isActive ? "text-primary" : isCompleted ? "text-emerald-400" : "text-white/30"
                    }`}
                  >
                    {isCompleted ? (
                      <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring" as const }}>
                        <CheckCircle className="w-4 h-4 shrink-0" />
                      </motion.div>
                    ) : isActive ? (
                      <Loader2 className="w-4 h-4 shrink-0 animate-spin" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border-2 border-white/10 shrink-0" />
                    )}
                    <span className="text-sm font-mono-sm">{step}</span>
                  </motion.div>
                );
              })}
            </div>
            
            <div className="mt-8 h-1 w-full bg-white/5 rounded-full overflow-hidden relative z-10">
              <motion.div 
                className="h-full bg-primary relative"
                initial={{ width: "0%" }}
                animate={{ width: `${(currentStepIndex / (STEPS.length - 1)) * 100}%` }}
                transition={{ ease: [0.16, 1, 0.3, 1], duration: 1.5 }}
              >
                <div className="absolute top-0 right-0 bottom-0 w-10 bg-white/30 blur-[2px]" />
              </motion.div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default ScanSequence;
