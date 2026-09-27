"use client";

import { useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

function TickRing({
  radius,
  count,
  majorEvery,
  color,
  opacity = 0.6,
  thickness = 0.02,
}: {
  radius: number;
  count: number;
  majorEvery: number;
  color: string;
  opacity?: number;
  thickness?: number;
}) {
  const ref = useRef<THREE.Group>(null!);
  useFrame((state) => {
    if (ref.current) ref.current.rotation.z = state.clock.elapsedTime * 0.04;
  });
  return (
    <group ref={ref}>
      {Array.from({ length: count }).map((_, i) => {
        const angle = (i / count) * Math.PI * 2;
        const isMajor = i % majorEvery === 0;
        const len = isMajor ? 0.35 : 0.15;
        const x = Math.cos(angle) * radius;
        const y = Math.sin(angle) * radius;
        return (
          <mesh key={i} position={[x, y, 0]} rotation={[0, 0, angle + Math.PI / 2]}>
            <planeGeometry args={[thickness, len]} />
            <meshBasicMaterial
              color={color}
              transparent
              opacity={isMajor ? opacity : opacity * 0.5}
              blending={THREE.AdditiveBlending}
              side={THREE.DoubleSide}
              depthWrite={false}
            />
          </mesh>
        );
      })}
    </group>
  );
}

function Arc({
  innerRadius,
  outerRadius,
  startAngle,
  endAngle,
  color,
  opacity = 0.6,
  speed = 0,
}: {
  innerRadius: number;
  outerRadius: number;
  startAngle: number;
  endAngle: number;
  color: string;
  opacity?: number;
  speed?: number;
}) {
  const ref = useRef<THREE.Mesh>(null!);
  useFrame((state) => {
    if (ref.current && speed) ref.current.rotation.z = state.clock.elapsedTime * speed;
  });
  const arcLength = endAngle - startAngle;
  return (
    <mesh ref={ref}>
      <ringGeometry args={[innerRadius, outerRadius, 64, 1, startAngle, arcLength]} />
      <meshBasicMaterial
        color={color}
        transparent
        opacity={opacity}
        side={THREE.DoubleSide}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </mesh>
  );
}

function Orbiter({
  radius,
  speed,
  color,
  size = 0.08,
  trail = false,
}: {
  radius: number;
  speed: number;
  color: string;
  size?: number;
  trail?: boolean;
}) {
  const ref = useRef<THREE.Mesh>(null!);
  const trailRef = useRef<THREE.Mesh>(null!);
  const t = useRef(Math.random() * Math.PI * 2);
  useFrame((_, d) => {
    t.current += d * speed;
    const x = Math.cos(t.current) * radius;
    const y = Math.sin(t.current) * radius;
    if (ref.current) ref.current.position.set(x, y, 0);
    if (trailRef.current) {
      trailRef.current.position.set(x, y, 0);
      trailRef.current.rotation.z = t.current;
    }
  });
  return (
    <>
      <mesh ref={ref}>
        <circleGeometry args={[size, 12]} />
        <meshBasicMaterial color={color} transparent opacity={1} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      {trail && (
        <mesh ref={trailRef}>
          <planeGeometry args={[size * 12, size * 0.6]} />
          <meshBasicMaterial color={color} transparent opacity={0.4} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
        </mesh>
      )}
    </>
  );
}

function Spokes({
  innerRadius,
  outerRadius,
  count,
  color,
  opacity = 0.4,
}: {
  innerRadius: number;
  outerRadius: number;
  count: number;
  color: string;
  opacity?: number;
}) {
  const ref = useRef<THREE.Group>(null!);
  useFrame((state) => {
    if (ref.current) ref.current.rotation.z = -state.clock.elapsedTime * 0.06;
  });
  return (
    <group ref={ref}>
      {Array.from({ length: count }).map((_, i) => {
        const angle = (i / count) * Math.PI * 2;
        const mid = (innerRadius + outerRadius) / 2;
        const len = outerRadius - innerRadius;
        return (
          <mesh key={i} position={[Math.cos(angle) * mid, Math.sin(angle) * mid, 0]} rotation={[0, 0, angle]}>
            <planeGeometry args={[len, 0.02]} />
            <meshBasicMaterial color={color} transparent opacity={opacity} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
          </mesh>
        );
      })}
    </group>
  );
}

function ReactorCore() {
  const ref = useRef<THREE.Group>(null!);
  const glowRef = useRef<THREE.Mesh>(null!);
  const ringRef = useRef<THREE.Mesh>(null!);
  useFrame((state) => {
    const t = state.clock.elapsedTime;
    if (ref.current) ref.current.rotation.z = t * 0.4;
    if (glowRef.current) {
      const s = 1 + Math.sin(t * 1.8) * 0.15;
      glowRef.current.scale.set(s, s, s);
      (glowRef.current.material as THREE.MeshBasicMaterial).opacity = 0.3 + Math.sin(t * 1.8) * 0.15;
    }
    if (ringRef.current) {
      const s = 1 + Math.sin(t * 2.2) * 0.2;
      ringRef.current.scale.set(s, s, s);
      (ringRef.current.material as THREE.MeshBasicMaterial).opacity = 0.5 - Math.sin(t * 2.2) * 0.2;
    }
  });
  return (
    <group ref={ref}>
      <mesh>
        <circleGeometry args={[0.55, 32]} />
        <meshBasicMaterial color="#e0f7ff" transparent opacity={0.95} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh ref={glowRef} position={[0, 0, -0.01]}>
        <circleGeometry args={[1.1, 32]} />
        <meshBasicMaterial color="#22d3ee" transparent opacity={0.4} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh ref={ringRef} position={[0, 0, -0.02]}>
        <ringGeometry args={[1.15, 1.28, 48]} />
        <meshBasicMaterial color="#67e8f9" transparent opacity={0.4} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
    </group>
  );
}

export function ArcReactor() {
  const groupRef = useRef<THREE.Group>(null!);
  useFrame((state) => {
    if (groupRef.current) {
      const t = state.clock.elapsedTime;
      groupRef.current.rotation.z = t * 0.015;
      groupRef.current.position.y = Math.sin(t * 0.3) * 0.12;
    }
  });

  return (
    <group ref={groupRef} position={[0, 0, -9]} scale={1}>
      {/* Outer rings — big enough to frame the card, but the CORE sits ABOVE it visually */}
      <mesh>
        <ringGeometry args={[4.2, 4.24, 128]} />
        <meshBasicMaterial color="#22d3ee" transparent opacity={0.32} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <TickRing radius={4.05} count={72} majorEvery={9} color="#22d3ee" opacity={0.7} thickness={0.024} />
      <TickRing radius={3.65} count={54} majorEvery={6} color="#67e8f9" opacity={0.5} thickness={0.02} />

      <Arc innerRadius={3.3} outerRadius={3.34} startAngle={0.2} endAngle={1.6} color="#22d3ee" opacity={0.9} />
      <Arc innerRadius={3.3} outerRadius={3.34} startAngle={2.1} endAngle={3.5} color="#22d3ee" opacity={0.9} />
      <Arc innerRadius={3.3} outerRadius={3.34} startAngle={3.9} endAngle={5.2} color="#22d3ee" opacity={0.9} />

      <Arc innerRadius={2.75} outerRadius={2.82} startAngle={0} endAngle={1.2} color="#f59e0b" opacity={0.75} speed={0.08} />
      <Arc innerRadius={2.75} outerRadius={2.82} startAngle={2.2} endAngle={3.0} color="#f59e0b" opacity={0.75} speed={0.08} />
      <Arc innerRadius={2.75} outerRadius={2.82} startAngle={4.0} endAngle={5.4} color="#f59e0b" opacity={0.75} speed={0.08} />

      <Spokes innerRadius={2.3} outerRadius={2.65} count={12} color="#22d3ee" opacity={0.4} />

      <mesh>
        <ringGeometry args={[2.15, 2.17, 96]} />
        <meshBasicMaterial color="#67e8f9" transparent opacity={0.5} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh>
        <ringGeometry args={[1.55, 1.57, 96]} />
        <meshBasicMaterial color="#f59e0b" transparent opacity={0.35} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>

      <Orbiter radius={4.05} speed={0.35} color="#67e8f9" size={0.09} trail />
      <Orbiter radius={3.65} speed={-0.5} color="#f59e0b" size={0.07} />
      <Orbiter radius={2.75} speed={0.7} color="#22d3ee" size={0.06} />
      <Orbiter radius={2.15} speed={-0.4} color="#a5f3fc" size={0.05} />

      <ReactorCore />
    </group>
  );
}