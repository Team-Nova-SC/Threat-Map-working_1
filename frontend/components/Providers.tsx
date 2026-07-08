"use client";

import React, { useState, useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { usePathname, useSearchParams } from "next/navigation";
import NProgress from "nprogress";
import "nprogress/nprogress.css";
import { ToastProvider } from "@/context/ToastContext";
import { SessionProvider } from "next-auth/react";

// Customize NProgress configuration
NProgress.configure({ showSpinner: false, speed: 400, minimum: 0.1 });

function NavigationProgress() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    // Stop NProgress when the route finishes loading
    NProgress.done();
    return () => {
      // Start NProgress when the route starts changing
      NProgress.start();
    };
  }, [pathname, searchParams]);

  return null;
}

export default function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 10 * 1000, // 10 seconds default stale time
            refetchOnWindowFocus: false,
          },
        },
      })
  );

  return (
    <SessionProvider>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <React.Suspense fallback={null}>
            <NavigationProgress />
          </React.Suspense>
          {children}
        </ToastProvider>
      </QueryClientProvider>
    </SessionProvider>
  );
}
