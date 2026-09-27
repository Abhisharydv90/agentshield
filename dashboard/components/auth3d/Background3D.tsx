"use client";

import { useFrame, useThree } from "@react-three/fiber";
import { useRef, useEffect } from "react";
import * as THREE from "three";
import { ArcReactor } from "./ArcReactor";
import { RadialScan, CornerHUDs } from "./RadialScan";

/* Distant starfield — small and cheap */
function Starfield({ count = 400 }: { count?: number }) {
  const ref = useRef<THREE.Points>(null!);
  const positions = useMemoPositions(count);

  useFrame((_, d) => {
    if (ref.current) ref.current.rotation.y += d * 0.004;
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={0.04}
        color="#a5f3fc"
        transparent
        opacity={0.5}
        sizeAttenuation
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  );
}

function useMemoPositions(count: number) {
  const ref = useRef<Float32Array | null>(null);
  if (!ref.current) {
    let seed = 12345;
    const rand = () => {
      seed = (seed * 9301 + 49297) % 233280;
      return seed / 233280;
    };
    const arr = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const r = 25 + rand() * 25;
      const theta = rand() * Math.PI * 2;
      const phi = Math.acos(2 * rand() - 1);
      arr[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      arr[i * 3 + 1] = r * Math.cos(phi);
      arr[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta);
    }
    ref.current = arr;
  }
  return ref.current;
}

/* Slow drift of the whole camera */
function CameraParallax() {
  const { camera } = useThree();
  const mouse = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      mouse.current.x = (e.clientX / window.innerWidth - 0.5) * 2;
      mouse.current.y = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener("mousemove", onMove);
    return () => window.removeEventListener("mousemove", onMove);
  }, []);

  useFrame((_, d) => {
    const tx = mouse.current.x * 0.6;
    const ty = -mouse.current.y * 0.35;
    camera.position.x += (tx - camera.position.x) * d * 1.2;
    camera.position.y += (ty - camera.position.y) * d * 1.2;
    camera.lookAt(0, 0, -5);
  });

  return null;
}

export function Background3D() {
  return (
    <>
      <color attach="background" args={["#020810"]} />
      <fog attach="fog" args={["#020810", 15, 40]} />
      <ambientLight intensity={0.4} />

      <Starfield count={400} />
      <ArcReactor />
      <RadialScan />
      <CornerHUDs />
      <CameraParallax />
    </>
  );
}