import type { NextConfig } from "next";

/* ============================================================
   Security headers — applied to every route
   ============================================================ */

const securityHeaders = [
  { key: "X-DNS-Prefetch-Control", value: "on" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
];

/* ============================================================
   Next.js configuration
   ============================================================ */

const nextConfig: NextConfig = {
  /* --- Core --- */
  reactStrictMode: true,
  poweredByHeader: false,
  compress: true,
  productionBrowserSourceMaps: false,
  output: "standalone",

  /* --- Build strictness --- */
  typescript: {
    ignoreBuildErrors: false,
  },

  /* --- Turbopack (Next.js 16 default) — empty config = use defaults --- */
  turbopack: {},

  /* --- Image optimization --- */
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "cdn.jsdelivr.net" },
      { protocol: "https", hostname: "raw.githubusercontent.com" },
    ],
    formats: ["image/avif", "image/webp"],
    minimumCacheTTL: 60 * 60 * 24 * 30,
  },

    /* --- Bundle optimization --- */
  experimental: {
    optimizePackageImports: [
      "lucide-react",
      "recharts",
      "date-fns",
    ],
  },

  /* --- Security headers on every response --- */
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
      {
        /* Never cache API responses */
        source: "/api/:path*",
        headers: [{ key: "Cache-Control", value: "no-store, max-age=0" }],
      },
    ];
  },

  /* --- API proxy: forward /api/* and /v1/* to the FastAPI backend --- */
    async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "https://agentshield-production-0091.up.railway.app/api/:path*",
      },
      {
        source: "/v1/:path*",
        destination: "https://agentshield-production-0091.up.railway.app/v1/:path*",
      },
    ];
  },
};

export default nextConfig;