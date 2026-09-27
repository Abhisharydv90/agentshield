"use client";

import { Canvas, useFrame } from "@react-three/fiber";
import { useRef } from "react";
import * as THREE from "three";

function ShieldShape() {
  const groupRef = useRef<THREE.Group>(null!);

  useFrame((state) => {
    if (groupRef.current) {
      groupRef.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.6) * 0.4;
      groupRef.current.position.y = Math.sin(state.clock.elapsedTime * 1.2) * 0.08;
    }
  });

  return (
    <group ref={groupRef}>
      {/* Outer shield outline — extruded shape */}
      <mesh>
        <cylinderGeometry args={[0.9, 0.9, 0.15, 6]} />
        <meshStandardMaterial
          color="#10b981"
          emissive="#10b981"
          emissiveIntensity={0.8}
          metalness={0.9}
          roughness={0.15}
          wireframe
        />
      </mesh>
      {/* Inner glow */}
      <mesh scale={0.7}>
        <cylinderGeometry args={[0.9, 0.9, 0.15, 6]} />
        <meshStandardMaterial
          color="#10b981"
          emissive="#10b981"
          emissiveIntensity={0.4}
          transparent
          opacity={0.25}
        />
      </mesh>
      {/* Ring */}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[1.15, 0.02, 8, 64]} />
        <meshBasicMaterial color="#34d399" transparent opacity={0.6} />
      </mesh>
    </group>
  );
}

export function ShieldLogo() {
  return (
    <div className="w-24 h-24 mx-auto mb-4">
      <Canvas
        camera={{ position: [0, 0, 3.5], fov: 45 }}
        dpr={[1, 2]}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight intensity={0.4} />
        <pointLight position={[5, 5, 5]} intensity={1.5} color="#10b981" />
        <pointLight position={[-5, -5, 5]} intensity={0.8} color="#38bdf8" />
        <ShieldShape />
      </Canvas>
    </div>
  );
}