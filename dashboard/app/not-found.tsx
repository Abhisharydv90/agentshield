import Link from "next/link";
import { ArrowRight } from "lucide-react";

export default function NotFound() {
  return (
    <main className="min-h-screen bg-black text-slate-200 flex items-center justify-center px-8 relative overflow-hidden">
      <div
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[80vw] h-[60vh] rounded-full pointer-events-none"
        style={{
          background:
            "radial-gradient(circle, rgba(125,211,252,0.10) 0%, transparent 60%)",
          filter: "blur(80px)",
        }}
      />

      <div className="relative max-w-[620px] text-center">
        <div className="text-[11px] font-mono tracking-[0.22em] uppercase text-[#7dd3fc] mb-8">
          404 · Not Found
        </div>
        <h1
          className="text-[80px] md:text-[120px] leading-[0.9] tracking-[-0.045em] text-white mb-8"
          style={{ fontFamily: "Georgia, serif" }}
        >
          Lost in the
          <br />
          <em className="italic text-[#7dd3fc]">void.</em>
        </h1>
        <p className="text-[16px] text-slate-400 mb-12 leading-[1.6] max-w-[480px] mx-auto">
          The page you're looking for doesn't exist. Or it did, and we
          secured it into oblivion. Either way — head back.
        </p>
        <Link
          href="/"
          className="inline-flex items-center gap-2 bg-white text-black px-7 py-3.5 text-[14px] font-medium rounded-lg hover:bg-slate-200 transition-colors"
        >
          Back to home
          <ArrowRight className="w-4 h-4" />
        </Link>
      </div>
    </main>
  );
}