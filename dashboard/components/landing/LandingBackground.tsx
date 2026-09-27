"use client";

import { Canvas, useFrame } from "@react-three/fiber";
import { useRef, useMemo } from "react";
import * as THREE from "three";

/* Dense particle stream — visible and alive */
function ParticleField({ count = 600 }: { count?: number }) {
  const ref = useRef<THREE.Points>(null!);
  const positions = useMemo(() => {
    let seed = 8888;
    const rand = () => {
      seed = (seed * 9301 + 49297) % 233280;
      return seed / 233280;
    };
    const arr = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      arr[i * 3] = (rand() - 0.5) * 70;
      arr[i * 3 + 1] = (rand() - 0.5) * 50;
      arr[i * 3 + 2] = (rand() - 0.5) * 30 - 10;
    }
    return arr;
  }, [count]);

  useFrame((_, d) => {
    if (!ref.current) return;
    ref.current.rotation.y += d * 0.02;
    ref.current.rotation.x += d * 0.005;
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={0.08}
        color="#00e5ff"
        transparent
        opacity={0.9}
        sizeAttenuation
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  );
}

/* Big glowing color orbs — actually visible now */
function GlowOrbs() {
  const groupRef = useRef<THREE.Group>(null!);
  const orbs = useMemo(
    () => [
      { pos: [-14, 6, -18] as [number, number, number], color: "#00e5ff", size: 8, speed: 0.3 },
      { pos: [14, -4, -20] as [number, number, number], color: "#ffb800", size: 7, speed: 0.4 },
      { pos: [0, -14, -22] as [number, number, number], color: "#00ffa3", size: 9, speed: 0.25 },
      { pos: [18, 10, -24] as [number, number, number], color: "#00e5ff", size: 6, speed: 0.5 },
      { pos: [-18, -8, -22] as [number, number, number], color: "#a855f7", size: 6, speed: 0.35 },
    ],
    []
  );

  useFrame((state) => {
    if (!groupRef.current) return;
    groupRef.current.children.forEach((child, i) => {
      const orb = orbs[i];
      const s = 1 + Math.sin(state.clock.elapsedTime * orb.speed) * 0.2;
      child.scale.set(s, s, s);
      const mat = (child as THREE.Mesh).material as THREE.MeshBasicMaterial;
      mat.opacity = 0.15 + Math.sin(state.clock.elapsedTime * orb.speed) * 0.05;
    });
  });

  return (
    <group ref={groupRef}>
      {orbs.map((o, i) => (
        <mesh key={i} position={o.pos}>
          <sphereGeometry args={[o.size, 32, 32]} />
          <meshBasicMaterial
            color={o.color}
            transparent
            opacity={0.15}
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </mesh>
      ))}
    </group>
  );
}

/* Flowing wave of light that pulses across the background */
function LightWave() {
  const ref = useRef<THREE.Mesh>(null!);
  const uniforms = useMemo(
    () => ({
      uTime: { value: 0 },
      uColorA: { value: new THREE.Color("#00e5ff") },
      uColorB: { value: new THREE.Color("#ffb800") },
    }),
    []
  );

  useFrame((state) => {
    if (ref.current) {
      (ref.current.material as THREE.ShaderMaterial).uniforms.uTime.value =
        state.clock.elapsedTime;
    }
  });

  return (
    <mesh ref={ref} position={[0, 0, -28]}>
      <planeGeometry args={[120, 60]} />
      <shaderMaterial
        uniforms={uniforms}
        transparent
        depthWrite={false}
        blending={THREE.AdditiveBlending}
        vertexShader={`
          varying vec2 vUv;
          void main() {
            vUv = uv;
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }
        `}
        fragmentShader={`
          uniform float uTime;
          uniform vec3 uColorA;
          uniform vec3 uColorB;
          varying vec2 vUv;
          void main() {
            float t = uTime * 0.15;
            vec2 c = vUv - 0.5;
            float r = length(c);
            // Wave rings emanating from center
            float wave = sin(r * 8.0 - t * 3.0) * 0.5 + 0.5;
            wave = pow(wave, 3.0) * (1.0 - smoothstep(0.3, 0.5, r));
            // Color mixing
            float mixVal = sin(vUv.x * 3.0 + t) * 0.5 + 0.5;
            vec3 col = mix(uColorA, uColorB, mixVal);
            gl_FragColor = vec4(col, wave * 0.15);
          }
        `}
      />
    </mesh>
  );
}

export function LandingBackground() {
  return (
    <div className="fixed inset-0 pointer-events-none z-0">
      <Canvas
        camera={{ position: [0, 0, 15], fov: 55 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
      >
        <ParticleField count={600} />
        <GlowOrbs />
        <LightWave />
      </Canvas>
    </div>
  );
}