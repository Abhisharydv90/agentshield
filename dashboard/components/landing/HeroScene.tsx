"use client";

import { Canvas, useFrame } from "@react-three/fiber";
import { useRef, useMemo } from "react";
import * as THREE from "three";

/* Background particle stream — subtle, moves across screen */
function StreamField({ count = 300 }: { count?: number }) {
  const ref = useRef<THREE.Points>(null!);
  const { positions, speeds } = useMemo(() => {
    let seed = 4421;
    const rand = () => {
      seed = (seed * 9301 + 49297) % 233280;
      return seed / 233280;
    };
    const pos = new Float32Array(count * 3);
    const spd = new Float32Array(count);
    for (let i = 0; i < count; i++) {
      pos[i * 3] = (rand() - 0.5) * 30;
      pos[i * 3 + 1] = (rand() - 0.5) * 18;
      pos[i * 3 + 2] = (rand() - 0.5) * 12;
      spd[i] = 0.2 + rand() * 0.5;
    }
    return { positions: pos, speeds: spd };
  }, [count]);

  useFrame((_, d) => {
    if (!ref.current) return;
    const attr = ref.current.geometry.attributes.position as THREE.BufferAttribute;
    const arr = attr.array as Float32Array;
    for (let i = 0; i < count; i++) {
      arr[i * 3] += speeds[i] * d * 0.8;
      if (arr[i * 3] > 15) arr[i * 3] = -15;
    }
    attr.needsUpdate = true;
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={0.03}
        color="#00e5ff"
        transparent
        opacity={0.6}
        sizeAttenuation
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  );
}

/* Small wireframe shield — floating in the top right, subtle */
function FloatingShield({ position }: { position: [number, number, number] }) {
  const groupRef = useRef<THREE.Group>(null!);

  const geometry = useMemo(() => {
    const shape = new THREE.Shape();
    shape.moveTo(0, 1);
    shape.bezierCurveTo(0.35, 1, 0.75, 0.9, 0.85, 0.5);
    shape.bezierCurveTo(0.92, 0.1, 0.85, -0.35, 0.5, -0.75);
    shape.bezierCurveTo(0.28, -1.05, 0.1, -1.15, 0, -1.2);
    shape.bezierCurveTo(-0.1, -1.15, -0.28, -1.05, -0.5, -0.75);
    shape.bezierCurveTo(-0.85, -0.35, -0.92, 0.1, -0.85, 0.5);
    shape.bezierCurveTo(-0.75, 0.9, -0.35, 1, 0, 1);
    const geo = new THREE.ExtrudeGeometry(shape, {
      depth: 0.1,
      bevelEnabled: true,
      bevelThickness: 0.03,
      bevelSize: 0.03,
      bevelSegments: 3,
      curveSegments: 20,
    });
    geo.center();
    return geo;
  }, []);

  useFrame((state) => {
    if (groupRef.current) {
      const t = state.clock.elapsedTime;
      groupRef.current.rotation.y = Math.sin(t * 0.5) * 0.5;
      groupRef.current.rotation.x = Math.sin(t * 0.3) * 0.15;
      groupRef.current.position.y =
        position[1] + Math.sin(t * 0.7) * 0.2;
    }
  });

  return (
    <group ref={groupRef} position={position} scale={0.6}>
      <lineSegments geometry={new THREE.WireframeGeometry(geometry)}>
        <lineBasicMaterial
          color="#00e5ff"
          transparent
          opacity={0.5}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </lineSegments>
      <mesh scale={0.85}>
        <circleGeometry args={[0.55, 24]} />
        <meshBasicMaterial
          color="#00e5ff"
          transparent
          opacity={0.35}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
      <OrbitRing radius={1.5} tilt={[1.1, 0, 0]} speed={0.5} color="#00e5ff" />
      <OrbitRing radius={1.75} tilt={[-0.8, 0.5, 0]} speed={-0.35} color="#ffb800" />
    </group>
  );
}

function OrbitRing({
  radius,
  tilt,
  speed,
  color,
}: {
  radius: number;
  tilt: [number, number, number];
  speed: number;
  color: string;
}) {
  const ref = useRef<THREE.Group>(null!);
  useFrame((_, d) => {
    if (ref.current) ref.current.rotation.z += d * speed;
  });
  return (
    <group rotation={tilt}>
      <group ref={ref}>
        <mesh>
          <torusGeometry args={[radius, 0.005, 6, 80]} />
          <meshBasicMaterial
            color={color}
            transparent
            opacity={0.55}
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </mesh>
        <OrbitNode radius={radius} color={color} />
      </group>
    </group>
  );
}

function OrbitNode({ radius, color }: { radius: number; color: string }) {
  const ref = useRef<THREE.Mesh>(null!);
  const t = useRef(Math.random() * Math.PI * 2);
  useFrame((_, d) => {
    t.current += d * 1.2;
    if (ref.current)
      ref.current.position.set(
        Math.cos(t.current) * radius,
        Math.sin(t.current) * radius,
        0
      );
  });
  return (
    <mesh ref={ref}>
      <circleGeometry args={[0.04, 10]} />
      <meshBasicMaterial
        color={color}
        transparent
        opacity={1}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </mesh>
  );
}

function Scene() {
  return (
    <>
      <color attach="background" args={["#000000"]} />
      <fog attach="fog" args={["#000000", 6, 16]} />
      <ambientLight intensity={0.6} />
      <pointLight position={[5, 5, 5]} intensity={1.5} color="#00e5ff" />
      <pointLight position={[-5, -3, 3]} intensity={0.6} color="#ffb800" />

      <StreamField count={300} />
      <FloatingShield position={[4.5, 0.5, 0]} />
      <FloatingShield position={[-4.5, -0.8, -1]} />
    </>
  );
}

export function HeroScene() {
  return (
    <div className="absolute inset-0 pointer-events-none">
      <Canvas
        camera={{ position: [0, 0, 8], fov: 50 }}
        dpr={[1, 1.75]}
        gl={{ antialias: true, alpha: true }}
      >
        <Scene />
      </Canvas>
    </div>
  );
}