"use client";

import { useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

/* ============================================================
   The shield shape — extruded 3D geometry
   ============================================================ */
function useShieldGeometry() {
  return useMemo(() => {
    const shape = new THREE.Shape();
    // Outline of a shield: flat-ish top, curved sides, point at bottom
    shape.moveTo(0, 1.05);
    shape.bezierCurveTo(0.35, 1.05, 0.75, 0.95, 0.82, 0.55);
    shape.bezierCurveTo(0.88, 0.2, 0.85, -0.25, 0.55, -0.72);
    shape.bezierCurveTo(0.3, -1.05, 0.1, -1.2, 0, -1.28);
    shape.bezierCurveTo(-0.1, -1.2, -0.3, -1.05, -0.55, -0.72);
    shape.bezierCurveTo(-0.85, -0.25, -0.88, 0.2, -0.82, 0.55);
    shape.bezierCurveTo(-0.75, 0.95, -0.35, 1.05, 0, 1.05);

    const extrudeSettings = {
      depth: 0.18,
      bevelEnabled: true,
      bevelThickness: 0.06,
      bevelSize: 0.06,
      bevelSegments: 6,
      curveSegments: 32,
    };

    const geo = new THREE.ExtrudeGeometry(shape, extrudeSettings);
    geo.center();
    return geo;
  }, []);
}

/* ============================================================
   Surface shader — hex mesh + scan line + edge glow + pulse
   ============================================================ */
function ShieldSurface({ geometry }: { geometry: THREE.BufferGeometry }) {
  const matRef = useRef<THREE.ShaderMaterial>(null!);

  const uniforms = useMemo(
    () => ({
      uTime: { value: 0 },
      uColorCore: { value: new THREE.Color("#10b981") },
      uColorEdge: { value: new THREE.Color("#a7f3d0") },
      uColorAccent: { value: new THREE.Color("#38bdf8") },
      uScanY: { value: 0 },
    }),
    []
  );

  useFrame((state) => {
    if (!matRef.current) return;
    const t = state.clock.elapsedTime;
    matRef.current.uniforms.uTime.value = t;
    // scan sweeps top to bottom every ~4s
    matRef.current.uniforms.uScanY.value = (Math.sin(t * 0.8) + 1) / 2;
  });

  return (
    <mesh geometry={geometry}>
      <shaderMaterial
        ref={matRef}
        uniforms={uniforms}
        transparent
        side={THREE.DoubleSide}
        vertexShader={`
          varying vec3 vNormal;
          varying vec3 vWorldPos;
          varying vec2 vUv;
          void main() {
            vec4 wp = modelMatrix * vec4(position, 1.0);
            vWorldPos = wp.xyz;
            vNormal = normalize(mat3(modelMatrix) * normal);
            vUv = uv;
            gl_Position = projectionMatrix * viewMatrix * wp;
          }
        `}
        fragmentShader={`
          uniform float uTime;
          uniform float uScanY;
          uniform vec3 uColorCore;
          uniform vec3 uColorEdge;
          uniform vec3 uColorAccent;
          varying vec3 vNormal;
          varying vec3 vWorldPos;
          varying vec2 vUv;

          float hash(vec2 p) {
            return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453);
          }

          // hex grid distance approximation
          float hexGrid(vec2 p, float s) {
            vec2 q = p / s;
            vec2 i = floor(q);
            vec2 f = fract(q);
            float a = max(abs(f.x - 0.5), abs(f.y - 0.5));
            float b = max(abs(f.x + f.y - 1.0) * 0.5, abs(f.x - f.y));
            return min(a, b);
          }

          void main() {
            // View direction and fresnel
            vec3 viewDir = normalize(cameraPosition - vWorldPos);
            float fres = pow(1.0 - abs(dot(viewDir, vNormal)), 2.2);

            // Base color — dark inner, bright edges
            vec3 col = mix(vec3(0.02, 0.06, 0.05), uColorCore * 0.35, fres);

            // Hex mesh pattern on surface
            vec2 uv = vUv * 8.0;
            uv.x += uTime * 0.05;
            uv.y += uTime * 0.02;
            float hex = hexGrid(uv, 1.0);
            float hexMask = smoothstep(0.08, 0.0, hex);

            // modulated by fresnel so mesh is visible but not overpowering
            col += uColorAccent * hexMask * (0.15 + fres * 0.3);

            // Circuit-like horizontal lines
            float lines = smoothstep(0.9, 1.0, sin(vUv.y * 90.0 + uTime * 1.2));
            col += uColorEdge * lines * 0.08;

            // Scan line sweeping down
            float scanDist = abs(vUv.y - uScanY);
            float scan = smoothstep(0.02, 0.0, scanDist);
            col += uColorEdge * scan * 1.5;

            // Edge glow — brigh on rim
            col += uColorEdge * fres * 0.9;

            // Subtle inner pulse
            float pulse = 0.5 + 0.5 * sin(uTime * 1.4);
            col += uColorCore * 0.06 * pulse;

            float alpha = 0.45 + fres * 0.5 + scan * 0.5;
            alpha = clamp(alpha, 0.0, 1.0);

            gl_FragColor = vec4(col, alpha);
          }
        `}
      />
    </mesh>
  );
}

/* ============================================================
   Wireframe overlay — sits on top of the surface mesh
   ============================================================ */
function ShieldWireframe({ geometry }: { geometry: THREE.BufferGeometry }) {
  const ref = useRef<THREE.LineSegments>(null!);
  const wireGeo = useMemo(() => new THREE.WireframeGeometry(geometry), [geometry]);

  useFrame((state) => {
    if (ref.current) {
      const mat = ref.current.material as THREE.LineBasicMaterial;
      mat.opacity = 0.15 + Math.sin(state.clock.elapsedTime * 1.2) * 0.06;
    }
  });

  return (
    <lineSegments ref={ref} geometry={wireGeo}>
      <lineBasicMaterial
        color="#a7f3d0"
        transparent
        opacity={0.18}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </lineSegments>
  );
}

/* ============================================================
   Orbital rings around the shield
   ============================================================ */
function OrbitRing({
  radius,
  tilt,
  speed,
  color,
  opacity = 0.5,
  segments = 128,
}: {
  radius: number;
  tilt: [number, number, number];
  speed: number;
  color: string;
  opacity?: number;
  segments?: number;
}) {
  const ref = useRef<THREE.Group>(null!);
  const ticks = useMemo(() => Array.from({ length: 32 }, (_, i) => i), []);

  useFrame((_, d) => {
    if (ref.current) ref.current.rotation.z += d * speed;
  });

  return (
    <group rotation={tilt}>
      <group ref={ref}>
        <mesh>
          <torusGeometry args={[radius, 0.012, 8, segments]} />
          <meshBasicMaterial
            color={color}
            transparent
            opacity={opacity}
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </mesh>
        {ticks.map((i) => {
          const angle = (i / 32) * Math.PI * 2;
          const isMajor = i % 4 === 0;
          const len = isMajor ? 0.35 : 0.15;
          return (
            <mesh
              key={i}
              position={[Math.cos(angle) * radius, Math.sin(angle) * radius, 0]}
              rotation={[0, 0, angle]}
            >
              <boxGeometry args={[len, 0.02, 0.02]} />
              <meshBasicMaterial
                color={color}
                transparent
                opacity={isMajor ? 0.7 : 0.35}
                blending={THREE.AdditiveBlending}
                depthWrite={false}
              />
            </mesh>
          );
        })}
      </group>
    </group>
  );
}

/* ============================================================
   Main hologram
   ============================================================ */
export function ShieldHologram() {
  const geometry = useShieldGeometry();
  const groupRef = useRef<THREE.Group>(null!);

  useFrame((state, d) => {
    if (groupRef.current) {
      // gentle sway
      groupRef.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.25) * 0.35;
      groupRef.current.position.y =
        -1 + Math.sin(state.clock.elapsedTime * 0.4) * 0.15;
    }
  });

  return (
    <group ref={groupRef} position={[0, -1, -14]} scale={5.5}>
      <ShieldSurface geometry={geometry} />
      <ShieldWireframe geometry={geometry} />

      {/* Orbital rings */}
      <OrbitRing
        radius={1.9}
        tilt={[1.2, 0, 0]}
        speed={0.15}
        color="#34d399"
        opacity={0.55}
      />
      <OrbitRing
        radius={2.15}
        tilt={[-0.9, 0.5, 0]}
        speed={-0.12}
        color="#38bdf8"
        opacity={0.42}
      />
      <OrbitRing
        radius={2.4}
        tilt={[0.4, -0.7, 0]}
        speed={0.09}
        color="#a78bfa"
        opacity={0.32}
      />
      <OrbitRing
        radius={2.7}
        tilt={[-0.3, 0.9, 0]}
        speed={-0.06}
        color="#f59e0b"
        opacity={0.22}
      />

      {/* Inner glow sphere — pushes light through the shield shape */}
      <mesh scale={1.4}>
        <sphereGeometry args={[1, 32, 32]} />
        <meshBasicMaterial
          color="#34d399"
          transparent
          opacity={0.05}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
      <mesh scale={1.9}>
        <sphereGeometry args={[1, 24, 24]} />
        <meshBasicMaterial
          color="#10b981"
          transparent
          opacity={0.02}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
    </group>
  );
}