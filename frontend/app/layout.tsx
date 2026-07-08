import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import AppLayout from "@/components/AppLayout";
import Providers from "@/components/Providers";
import ConnectionBanner from "@/components/ConnectionBanner";
import CyberBackground from "@/components/CyberBackground";
import { ChatProvider } from "@/context/ChatContext";
import ChatWidget from "@/components/ChatWidget";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  display: "swap",
});

export const metadata: Metadata = {
  title: "ThreatMap - AI Threat Intelligence & OSINT Aggregation Platform",
  description:
    "Aggregates data from VirusTotal, AbuseIPDB, IPinfo, AlienVault, GreyNoise, and Google Gemini AI to analyze IPs, URLs, domains, and file hashes.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable}`}>
      <head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"
        />
      </head>
      <body className="antialiased font-sans">
        <Providers>
          <ChatProvider>
            <CyberBackground />
            <ConnectionBanner />
            <div className="relative z-10">
              <AppLayout>{children}</AppLayout>
            </div>
            <ChatWidget />
          </ChatProvider>
        </Providers>
      </body>
    </html>
  );
}
