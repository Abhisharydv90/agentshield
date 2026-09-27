import type { Metadata, Viewport } from "next";
import { Geist, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  display: "swap",
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://agentshield.app"),
  title: {
    default: "AgentShield · Autonomous Agent Firewall",
    template: "%s · AgentShield",
  },
  description:
    "Zero-trust proxy for AI agents. Blocks prompt injections, redacts PII, and enforces policy on every tool call.",
  applicationName: "AgentShield",
  keywords: [
    "AI security",
    "agent firewall",
    "LLM security",
    "prompt injection",
    "PII redaction",
    "AI gateway",
    "zero-trust",
  ],
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://agentshield.app",
    siteName: "AgentShield",
    title: "AgentShield · Autonomous Agent Firewall",
    description:
      "Zero-trust proxy for AI agents. Blocks prompt injections, redacts PII, and enforces policy on every tool call.",
  },
  twitter: {
    card: "summary_large_image",
    title: "AgentShield · Autonomous Agent Firewall",
    description:
      "Zero-trust proxy for AI agents. Blocks prompt injections, redacts PII.",
  },
  icons: {
    icon: [{ url: "/icon.svg", type: "image/svg+xml" }],
  },
  robots: {
    index: true,
    follow: true,
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#000000",
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${geistSans.variable} ${jetbrainsMono.variable} dark`} suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://cdn.jsdelivr.net" crossOrigin="" />
        <link rel="dns-prefetch" href="https://cdn.jsdelivr.net" />
        <meta name="color-scheme" content="dark" />
        <style
          dangerouslySetInnerHTML={{
            __html: `html,body{background:#000;color:#e2e8f0;}*{-webkit-tap-highlight-color:transparent;}`,
          }}
        />
      </head>
      <body className="bg-black text-slate-200 font-sans">
        {children}
      </body>
    </html>
  );
}