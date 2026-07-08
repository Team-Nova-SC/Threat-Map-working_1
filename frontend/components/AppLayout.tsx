"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { useSession, signIn, signOut } from "next-auth/react";
import AnimatedBackground from "./AnimatedBackground";

interface AppLayoutProps {
  children: React.ReactNode;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
  const pathname = usePathname();
  const [alerts, setAlerts] = React.useState<any[]>([]);
  const [showNotifications, setShowNotifications] = React.useState(false);
  const [showProfileMenu, setShowProfileMenu] = React.useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);
  const [isDarkMode, setIsDarkMode] = React.useState(true);
  const { data: session } = useSession();

  React.useEffect(() => {
    const isLight = localStorage.getItem("threatmap_theme") === "light";
    if (isLight) {
      setIsDarkMode(false);
      document.documentElement.classList.add("light-theme");
    }
  }, []);

  const toggleTheme = () => {
    setIsDarkMode(!isDarkMode);
    if (isDarkMode) {
      document.documentElement.classList.add("light-theme");
      localStorage.setItem("threatmap_theme", "light");
    } else {
      document.documentElement.classList.remove("light-theme");
      localStorage.setItem("threatmap_theme", "dark");
    }
  };

  React.useEffect(() => {
    // We import api dynamically or use the global api if it was imported. 
    // Wait, let's import it at the top of the file!
    import("@/lib/api").then(({ api }) => {
      api.getDashboardStats().then((stats) => {
        setAlerts(stats.alerts);
      }).catch(err => console.error(err));
    });
  }, [pathname]);

  const navigation = [
    {
      name: "IOC Scanner",
      href: "/",
      icon: <span className="material-symbols-outlined text-[20px]">biotech</span>,
    },
    {
      name: "Deep OSINT",
      href: "/deep-scan",
      icon: <span className="material-symbols-outlined text-[20px]">troubleshoot</span>,
    },
    {
      name: "Dashboard",
      href: "/dashboard",
      icon: <span className="material-symbols-outlined text-[20px]">analytics</span>,
    },
    {
      name: "Standalone Tools",
      href: "/tools",
      icon: <span className="material-symbols-outlined text-[20px]">build</span>,
    },
    {
      name: "Watchlist & Alerts",
      href: "/watchlist",
      icon: <span className="material-symbols-outlined text-[20px]">visibility</span>,
    },
    {
      name: "Threat Actors",
      href: "/threat-actors",
      icon: <span className="material-symbols-outlined text-[20px]">groups</span>,
    },
    {
      name: "Campaigns",
      href: "/campaigns",
      icon: <span className="material-symbols-outlined text-[20px]">target</span>,
    },
    {
      name: "Compare IOCs",
      href: "/compare",
      icon: <span className="material-symbols-outlined text-[20px]">compare_arrows</span>,
    },
    {
      name: "Bulk Analytics",
      href: "/results/bulk",
      icon: <span className="material-symbols-outlined text-[20px]">table_chart</span>,
    },
    {
      name: "About",
      href: "/about",
      icon: <span className="material-symbols-outlined text-[20px]">info</span>,
    },
    {
      name: "AI Assistant",
      href: "/chat",
      icon: <span className="material-symbols-outlined text-[20px]">smart_toy</span>,
    },
  ];

  return (
    <div className="flex min-h-screen bg-transparent text-on-background font-body-md text-body-md overflow-x-hidden relative">
      <AnimatedBackground />

      {/* Mobile Sidebar Overlay */}
      {isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 md:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar Navigation */}
      <aside 
        className={`fixed inset-y-0 left-0 z-40 w-64 transform transition-transform duration-300 ease-in-out md:relative md:translate-x-0 ${
          isMobileMenuOpen ? "translate-x-0 shadow-2xl" : "-translate-x-full"
        } shrink-0 bg-surface border-r border-white/5 flex flex-col justify-between p-md`}
      >
        <div>
          {/* Brand/Logo */}
          <div className="flex items-center justify-between gap-2 mb-8 px-2">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-[28px] animate-pulse">
                shield_lock
              </span>
              <span className="text-lg font-black tracking-widest text-white font-headline-lg">
                THREAT<span className="text-primary font-light">MAP</span>
              </span>
            </div>
            <button 
              className="md:hidden text-on-surface-variant hover:text-white"
              onClick={() => setIsMobileMenuOpen(false)}
            >
              <span className="material-symbols-outlined text-[20px]">close</span>
            </button>
          </div>

          {/* Navigation links */}
          <nav className="space-y-1.5">
            {navigation.map((item) => {
              const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  prefetch={true}
                  onClick={() => setIsMobileMenuOpen(false)}
                  className={`relative flex items-center px-4 py-3 rounded-lg text-sm font-semibold tracking-wide transition-colors duration-150 ${
                    isActive
                      ? "text-primary"
                      : "text-on-surface-variant hover:text-on-surface hover:bg-white/5"
                  }`}
                >
                  {isActive && (
                    <motion.div
                      layoutId="activeNav"
                      className="absolute inset-0 bg-primary/10 border-l-2 border-primary rounded-lg"
                      initial={false}
                      transition={{ type: "spring" as const, stiffness: 350, damping: 30 }}
                    />
                  )}
                  <motion.div 
                    className="flex items-center gap-3.5 relative z-10 w-full"
                    whileHover={{ x: isActive ? 0 : 4 }}
                    transition={{ type: "spring" as const, stiffness: 400, damping: 25 }}
                  >
                    {item.icon}
                    {item.name}
                  </motion.div>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Footer/System Status */}
        <div className="mt-auto pt-md border-t border-white/5 space-y-2 relative">
          <button
            onClick={toggleTheme}
            className="absolute -top-12 right-2 p-2 rounded-lg text-on-surface-variant hover:text-white hover:bg-white/5 transition-colors border border-white/5"
            title="Toggle Theme"
          >
            <span className="material-symbols-outlined text-[16px]">
              {isDarkMode ? "light_mode" : "dark_mode"}
            </span>
          </button>
          
          <div className="flex items-center gap-2.5 px-2 text-[10px] font-mono-sm tracking-wide text-on-surface-variant">
            <div className="w-2 h-2 rounded-full bg-[#adc6ff] animate-ping" />
            <span>DB ENGINE: CONNECTED</span>
          </div>
          <div className="flex items-center gap-2.5 px-2 text-[10px] font-mono-sm tracking-wide text-on-surface-variant">
            <div className="w-2 h-2 rounded-full bg-[#adc6ff]" />
            <span>API AGENT: ONLINE</span>
          </div>
          <div className="text-[9px] text-on-surface-variant/40 text-center font-mono-sm pt-2">
            v{process.env.NEXT_PUBLIC_VERSION || "1.0.0"} - ThreatMap
          </div>
        </div>
      </aside>

      {/* Main Container */}
      <div className="flex-1 flex flex-col min-w-0 md:ml-0">
        {/* Header Breadcrumbs */}
        <header className="h-16 border-b border-white/5 flex items-center justify-between px-4 lg:px-lg shrink-0">
          <div className="flex items-center gap-2 text-xs font-semibold tracking-wider font-label-caps uppercase text-on-surface-variant">
            <button 
              className="md:hidden mr-3 p-2 text-white hover:text-primary flex items-center justify-center bg-white/5 hover:bg-white/10 rounded-lg transition-colors drop-shadow-md"
              onClick={() => setIsMobileMenuOpen(true)}
            >
              <span className="material-symbols-outlined text-[24px]">menu</span>
            </button>
            <Link href="/" className="hover:text-primary hidden sm:inline">ThreatMap</Link>
            <span className="text-[10px] text-white/20 hidden sm:inline">/</span>
            <span className="text-white">
              {pathname === "/"
                ? "IOC Scanner"
                : pathname === "/dashboard"
                ? "Dashboard Telemetry"
                : pathname === "/watchlist"
                ? "Watchlist & Alerts"
                : pathname === "/about"
                ? "About ThreatMap"
                : pathname.startsWith("/results")
                ? "Threat Analysis Report"
                : "Navigation"}
            </span>
          </div>

          {/* Top Info Bar & Notifications */}
          <div className="flex items-center gap-4 relative">
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 bg-surface-container-low border border-white/5 rounded text-[10px] font-mono-sm text-on-secondary-container">
              <span className="material-symbols-outlined text-[12px] text-primary">dns</span>
              <span>API SERVER: /_/backend</span>
            </div>

            {/* Notification Bell */}
            <div className="relative">
              <button 
                onClick={() => setShowNotifications(!showNotifications)}
                className="relative p-2 text-on-surface-variant hover:text-white hover:bg-white/5 rounded-full transition-all"
              >
                <span className="material-symbols-outlined text-[20px]">notifications</span>
                {alerts.length > 0 && (
                  <span className="absolute top-1 right-1 w-2 h-2 bg-error rounded-full animate-pulse border border-background"></span>
                )}
              </button>

              {/* Dropdown Menu */}
              {showNotifications && (
                <div className="absolute right-0 mt-2 w-80 bg-surface border border-white/10 rounded-xl shadow-2xl z-50 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-surface-container-low">
                    <span className="text-sm font-bold text-white font-headline-sm">Notifications</span>
                    <span className="text-[10px] bg-error-container/20 text-error px-2 py-0.5 rounded font-mono-sm">
                      {alerts.length} New
                    </span>
                  </div>
                  <div className="max-h-64 overflow-y-auto hide-scrollbar divide-y divide-white/5">
                    {alerts.length === 0 ? (
                      <div className="p-4 text-center text-xs text-on-surface-variant font-mono-sm">
                        No active alerts
                      </div>
                    ) : (
                      alerts.map((alert) => (
                        <div key={alert.id} className="p-4 hover:bg-white/5 transition-all">
                          <div className="flex items-start justify-between gap-2 mb-1">
                            <span className="text-xs font-bold text-white">{alert.title}</span>
                            <span className="text-[9px] text-on-surface-variant font-mono-sm">
                              {new Date(alert.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                            </span>
                          </div>
                          <p className="text-[11px] text-on-surface-variant line-clamp-2">{alert.message}</p>
                        </div>
                      ))
                    )}
                  </div>
                  <div className="p-2 border-t border-white/5 bg-surface-container-lowest text-center">
                    <Link href="/dashboard" prefetch={true} onClick={() => setShowNotifications(false)} className="text-[10px] text-primary hover:underline font-mono-sm uppercase tracking-wider">
                      View Alert Center
                    </Link>
                  </div>
                </div>
              )}
            </div>

            {/* Profile Dropdown */}
            <div className="relative">
              <button
                onClick={() => setShowProfileMenu(!showProfileMenu)}
                className="flex items-center justify-center w-8 h-8 rounded-full bg-surface-container-low border border-white/10 overflow-hidden hover:border-primary/50 transition-colors"
              >
                {session?.user?.image ? (
                  <img src={session.user.image} alt="Profile" className="w-full h-full object-cover" />
                ) : (
                  <span className="material-symbols-outlined text-[18px] text-on-surface-variant">person</span>
                )}
              </button>

              <AnimatePresence>
                {showProfileMenu && (
                  <motion.div
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 10, scale: 0.95 }}
                    transition={{ duration: 0.15 }}
                    className="absolute right-0 mt-2 w-56 bg-surface border border-white/10 rounded-xl shadow-2xl z-50 overflow-hidden"
                  >
                    {session ? (
                      <>
                        <div className="px-4 py-3 border-b border-white/5 bg-surface-container-low">
                          <p className="text-sm font-semibold text-white truncate">{session.user?.name}</p>
                          <p className="text-xs text-on-surface-variant truncate">{session.user?.email}</p>
                        </div>
                        <div className="p-1">
                          <button
                            onClick={() => { setShowProfileMenu(false); signOut(); }}
                            className="w-full text-left px-3 py-2 text-sm text-error hover:bg-white/5 rounded-lg transition-colors flex items-center gap-2"
                          >
                            <span className="material-symbols-outlined text-[16px]">logout</span>
                            Sign Out
                          </button>
                        </div>
                      </>
                    ) : (
                      <div className="p-1">
                        <button
                          onClick={() => { setShowProfileMenu(false); signIn("google"); }}
                          className="w-full text-left px-3 py-2 text-sm text-white hover:bg-white/5 rounded-lg transition-colors flex items-center gap-2"
                        >
                          <span className="material-symbols-outlined text-[16px]">login</span>
                          Sign in with Google
                        </button>
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </header>

        {/* Content Portal */}
        <main className="flex-1 overflow-y-auto p-lg relative bg-transparent z-10">
          <AnimatePresence mode="wait">
            <motion.div
              key={pathname}
              initial={{ opacity: 0, y: 10, filter: "blur(4px)" }}
              animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              exit={{ opacity: 0, y: -10, filter: "blur(4px)" }}
              transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
              className="h-full"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
};
export default AppLayout;
