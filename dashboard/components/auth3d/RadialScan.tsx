"use client";

import { useFrame } from "@react-three/fiber";
import { useRef } from "react";
import * as THREE from "three";

/* The sweeping beam — a cone of light that rotates around the reactor */
export function RadialScan() {
  const ref = useRef<THREE.Mesh>(null!);

  useFrame((state) => {
    if (ref.current) {
      ref.current.rotation.z = state.clock.elapsedTime * 0.6;
    }
  });

  return (
    <mesh ref={ref} position={[0, 0, -7.5]}>
      <circleGeometry args={[6.5, 64, 0, Math.PI / 5]} />
      <meshBasicMaterial
        color="#22d3ee"
        transparent
        opacity={0.08}
        side={THREE.DoubleSide}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </mesh>
  );
}

/* Floating HUD arcs in corners */
export function CornerHUDs() {
  return (
    <>
      <group position={[-8, 5, -6]}>
        <ArcCorner rotation={0} />
      </group>
      <group position={[8, 5, -6]}>
        <ArcCorner rotation={Math.PI / 2} />
      </group>
      <group position={[-8, -5, -6]}>
        <ArcCorner rotation={-Math.PI / 2} />
      </group>
      <group position={[8, -5, -6]}>
        <ArcCorner rotation={Math.PI} />
      </group>
    </>
  );
}

function ArcCorner({ rotation }: { rotation: number }) {
  const ref = useRef<THREE.Group>(null!);

  useFrame((state) => {
    if (ref.current) {
      const t = state.clock.elapsedTime;
      ref.current.rotation.z = rotation + Math.sin(t * 0.3) * 0.1;
    }
  });

  return (
    <group ref={ref}>
      {/* Arc segments */}
      <mesh>
        <ringGeometry args={[1.2, 1.22, 32, 1, 0, Math.PI / 3]} />
        <meshBasicMaterial color="#22d3ee" transparent opacity={0.6} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh>
        <ringGeometry args={[0.9, 0.92, 32, 1, Math.PI / 6, Math.PI / 3]} />
        <meshBasicMaterial color="#f59e0b" transparent opacity={0.5} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh>
        <ringGeometry args={[0.5, 0.52, 32, 1, Math.PI / 4, Math.PI / 4]} />
        <meshBasicMaterial color="#67e8f9" transparent opacity={0.7} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      {/* Tick marks */}
      {Array.from({ length: 8 }).map((_, i) => {
        const angle = (i / 8) * (Math.PI / 2);
        const x = Math.cos(angle) * 1.5;
        const y = Math.sin(angle) * 1.5;
        return (
          <mesh key={i} position={[x, y, 0]} rotation={[0, 0, angle + Math.PI / 2]}>
            <planeGeometry args={[0.02, i % 4 === 0 ? 0.3 : 0.15]} />
            <meshBasicMaterial color="#67e8f9" transparent opacity={0.7} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
          </mesh>
        );
      })}
    </group>
  );
}