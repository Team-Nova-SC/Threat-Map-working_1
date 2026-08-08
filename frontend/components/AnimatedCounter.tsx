import React, { useEffect } from "react";
import { motion, useSpring, useTransform } from "framer-motion";

interface AnimatedCounterProps {
  value: number;
  className?: string;
}

export const AnimatedCounter: React.FC<AnimatedCounterProps> = ({ value, className }) => {
  const safeValue = typeof value === "number" && !isNaN(value) ? value : 0;
  const spring = useSpring(0, { bounce: 0, duration: 1500 });
  const display = useTransform(spring, (current) => Math.round(current).toLocaleString());

  useEffect(() => {
    spring.set(safeValue);
  }, [spring, safeValue]);

  return <motion.span className={className}>{display}</motion.span>;
};

export default AnimatedCounter;
