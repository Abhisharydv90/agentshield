import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "AgentShield · Autonomous Agent Firewall",
    short_name: "AgentShield",
    description:
      "Zero-trust proxy for AI agents. Blocks prompt injections, redacts PII, and enforces policy on every tool call.",
    start_url: "/",
    scope: "/",
    display: "standalone",
    orientation: "landscape",
    background_color: "#000000",
    theme_color: "#000000",
    categories: ["security", "developer", "productivity"],
    lang: "en",
    dir: "ltr",
    icons: [
      {
        src: "/icon.svg",
        sizes: "any",
        type: "image/svg+xml",
        purpose: "any",
      },
      {
        src: "/favicon.ico",
        sizes: "any",
        type: "image/x-icon",
      },
    ],
  };
}