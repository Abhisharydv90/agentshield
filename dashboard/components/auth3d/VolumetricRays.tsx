"use client";

import { useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

/**
 * Vertical shafts of light — like god rays from a source above.
 * Cone geometry with additive shader, very low opacity.
 */
function Ray({
  position,
  angle,
  length,
  width,
  color,
  opacity = 0.08,
}: {
  position: [number, number, number];
  angle: number;
  length: number;
  width: number;
  color: string;
  opacity?: number;
}) {
  const matRef = useRef<THREE.ShaderMaterial>(null!);

  useFrame((state) => {
    if (matRef.current) {
      matRef.current.uniforms.uTime.value = state.clock.elapsedTime;
    }
  });

  const uniforms = useMemo(
    () => ({
      uTime: { value: 0 },
      uColor: { value: new THREE.Color(color) },
      uOpacity: { value: opacity },
    }),
    [color, opacity]
  );

  return (
    <mesh position={position} rotation={[Math.PI, 0, angle]}>
      <coneGeometry args={[width, length, 24, 1, true]} />
      <shaderMaterial
        ref={matRef}
        uniforms={uniforms}
        transparent
        depthWrite={false}
        side={THREE.DoubleSide}
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
          uniform vec3 uColor;
          uniform float uOpacity;
          varying vec2 vUv;

          void main() {
            // Fade along length
            float fadeY = 1.0 - vUv.y;
            // Fade at edges
            float fadeX = 1.0 - abs(vUv.x - 0.5) * 2.0;
            // Subtle breathing
            float breathe = 0.85 + 0.15 * sin(uTime * 0.8);
            float alpha = uOpacity * fadeY * fadeX * breathe;
            gl_FragColor = vec4(uColor, alpha);
          }
        `}
      />
    </mesh>
  );
}

export function VolumetricRays() {
  return (
    <group position={[0, 4, -20]}>
      <Ray position={[0, 0, 0]} angle={0} length={30} width={4} color="#34d399" opacity={0.06} />
      <Ray position={[-6, 0, -2]} angle={-0.25} length={26} width={2.5} color="#38bdf8" opacity={0.05} />
      <Ray position={[6, 0, -2]} angle={0.25} length={26} width={2.5} color="#34d399" opacity={0.05} />
      <Ray position={[-10, 0, -4]} angle={-0.4} length={22} width={2} color="#a78bfa" opacity={0.04} />
      <Ray position={[10, 0, -4]} angle={0.4} length={22} width={2} color="#38bdf8" opacity={0.04} />
    </group>
  );
}