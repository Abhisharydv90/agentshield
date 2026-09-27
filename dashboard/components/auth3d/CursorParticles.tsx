"use client";

import { useEffect, useRef } from "react";

/**
 * DOM-based particle trail. Cheaper than WebGL for cursor follow.
 * Caps at 30 live particles. Pauses on tab hidden.
 */
export function CursorParticles() {
  const containerRef = useRef<HTMLDivElement>(null);
  const lastSpawnRef = useRef(0);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const spawn = (x: number, y: number) => {
      const p = document.createElement("div");
      const size = 3 + Math.random() * 4;
      p.style.cssText = `
        position: fixed;
        left: ${x}px;
        top: ${y}px;
        width: ${size}px;
        height: ${size}px;
        border-radius: 9999px;
        background: rgba(52, 211, 153, ${0.5 + Math.random() * 0.5});
        box-shadow: 0 0 8px rgba(52, 211, 153, 0.6);
        pointer-events: none;
        transform: translate(-50%, -50%);
        transition: opacity 700ms ease-out, transform 700ms ease-out;
        z-index: 5;
      `;
      container.appendChild(p);

      // Animate out
      requestAnimationFrame(() => {
        p.style.opacity = "0";
        p.style.transform = `translate(-50%, -50%) translate(${(Math.random() - 0.5) * 30}px, ${(Math.random() - 0.5) * 30}px) scale(0.3)`;
      });

      setTimeout(() => p.remove(), 800);

      // Cap
      while (container.childElementCount > 30) {
        container.firstChild?.remove();
      }
    };

    const onMove = (e: MouseEvent) => {
      const now = performance.now();
      if (now - lastSpawnRef.current < 20) return;
      lastSpawnRef.current = now;
      spawn(e.clientX, e.clientY);
    };

    window.addEventListener("mousemove", onMove);
    return () => {
      window.removeEventListener("mousemove", onMove);
      container.innerHTML = "";
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 pointer-events-none z-[5]"
      aria-hidden
    />
  );
}