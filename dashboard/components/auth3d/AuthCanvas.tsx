"use client";

import { Canvas, useFrame, useLoader, useThree } from "@react-three/fiber";
import { useRef, useMemo, Suspense, useEffect } from "react";
import * as THREE from "three";
import { useAuthTransition } from "./context";
import { Background3D } from "./Background3D";

const EARTH_DAY =
  "https://cdn.jsdelivr.net/gh/mrdoob/three.js@r160/examples/textures/planets/earth_atmos_2048.jpg";
const EARTH_CLOUDS =
  "https://cdn.jsdelivr.net/gh/mrdoob/three.js@r160/examples/textures/planets/earth_clouds_1024.png";

function EarthWarp() {
  const earthRef = useRef<THREE.Mesh>(null!);
  const cloudsRef = useRef<THREE.Mesh>(null!);
  const { camera } = useThree();
  const { phase } = useAuthTransition();

  const [dayMap, cloudMap] = useLoader(THREE.TextureLoader, [
    EARTH_DAY,
    EARTH_CLOUDS,
  ]);

  useMemo(() => {
    dayMap.colorSpace = THREE.SRGBColorSpace;
    cloudMap.colorSpace = THREE.SRGBColorSpace;
  }, [dayMap, cloudMap]);

  const startTime = useRef<number | null>(null);

  useEffect(() => {
    if (phase === "warp") startTime.current = performance.now();
  }, [phase]);

  useFrame((_, d) => {
    if (earthRef.current) earthRef.current.rotation.y += d * 0.6;
    if (cloudsRef.current) cloudsRef.current.rotation.y += d * 0.75;

    if (phase === "warp" && startTime.current !== null) {
      const elapsed = (performance.now() - startTime.current) / 1000;
      // Faster: 1.4s total (was 2.0s)
      const t = Math.min(elapsed / 1.4, 1);
      const e = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
      camera.position.z = 12 - e * 9.2;
      camera.position.x = Math.sin(elapsed * 2) * 0.15;
      camera.position.y = Math.cos(elapsed * 1.7) * 0.1;
      (camera as THREE.PerspectiveCamera).fov = 50 + e * 15;
      camera.updateProjectionMatrix();

      if (t >= 1) {
        // Do NOT reset phase here — the auth layout unmounts on navigation.
        // Resetting causes the login page to flash back into view.
        if (typeof window !== "undefined" && window.location.pathname !== "/") {
          window.location.href = "/";
        }
      }
    }
  });

  if (phase !== "warp") return null;

  return (
    <group>
      <mesh ref={earthRef}>
        <sphereGeometry args={[3, 96, 96]} />
        <meshPhongMaterial
          map={dayMap}
          emissive="#ffb35c"
          emissiveIntensity={0.3}
          specular="#6bb6ff"
          shininess={35}
        />
      </mesh>
      <mesh ref={cloudsRef} scale={1.01}>
        <sphereGeometry args={[3, 64, 64]} />
        <meshPhongMaterial
          map={cloudMap}
          transparent
          opacity={0.45}
          depthWrite={false}
        />
      </mesh>
      <mesh scale={1.05}>
        <sphereGeometry args={[3, 48, 48]} />
        <meshBasicMaterial
          color="#34d399"
          transparent
          opacity={0.15}
          side={THREE.BackSide}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
    </group>
  );
}

export function AuthCanvas() {
  const { phase } = useAuthTransition();

  return (
    <>
      <div className="absolute inset-0 pointer-events-none z-0">
        <Canvas
          camera={{ position: [0, 0, 12], fov: 50 }}
          dpr={[1, 1.5]}
          gl={{
            antialias: true,
            alpha: false,
            powerPreference: "high-performance",
          }}
        >
          <Background3D />
          <Suspense fallback={null}>
            <EarthWarp />
          </Suspense>
        </Canvas>
      </div>

      {/* Blackout overlay — hides the login card during warp.
          Fades to full opacity exactly when Earth would finish zooming. */}
      {phase === "warp" && (
        <div
          className="fixed inset-0 z-[75] pointer-events-none bg-black"
          style={{ animation: "blackoutFade 1.4s ease-in forwards", opacity: 0 }}
        />
      )}
    </>
  );
}