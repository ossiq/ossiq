// The glass double helix behind the landing page: its look, shape and camera path.
// landing.js feeds it the scroll position; nothing in here touches the page.
// three.js is resolved through the import map in landing.html and is pinned to r160.
import * as THREE from "three";
import { RoomEnvironment } from "three/addons/environments/RoomEnvironment.js";
import { BokehPass } from "three/addons/postprocessing/BokehPass.js";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";

// ---------- look ----------

// A rung is "cold" until the probe light has passed it, then "strand" (healthy) or "flag"
// (at risk). The states are also the palette keys that color them.
const RUNG_STATES = ["strand", "flag", "cold"];

const THEMES = {
  dark: {
    background: 0x05070a,
    fogDensity: 0.026,
    exposure: 1.02,
    palette: { strand: "#2BE38B", flag: "#FF8A3D", probe: "#4FD8FF", cold: "#5C7C88" },
    glass: { color: 0xa8ccc2, attenuationColor: 0x1d5249, attenuationDistance: 1.5 },
    rodAttenuationDistance: 0.75,
    rodEmissive: { strand: 0.85, flag: 0.95, cold: 0.1 },
    coreEmissive: { strand: 2.6, flag: 2.9, cold: 0.25 },
    ambientLight: { color: 0x1b2a31, intensity: 0.5 },
    keyLight: { color: 0xd8ecf5, intensity: 1.5 },
    rimLightIntensity: 1.5,
    probeLightIntensity: 42,
    bloom: { strength: 0.62, radius: 0.42, threshold: 0.55 },
    dustOpacity: 0.26,
  },
  light: {
    background: 0xf2f5f4,
    fogDensity: 0.02,
    exposure: 1.06,
    palette: { strand: "#0FA968", flag: "#DC5F06", probe: "#2E9BD6", cold: "#9FB0B8" },
    glass: { color: 0xf4fbf8, attenuationColor: 0x9cc3b8, attenuationDistance: 3 },
    rodAttenuationDistance: 0.38,
    rodEmissive: { strand: 0.08, flag: 0.1, cold: 0.02 },
    coreEmissive: { strand: 0.3, flag: 0.34, cold: 0.05 },
    ambientLight: { color: 0xe7f0f5, intensity: 1.5 },
    keyLight: { color: 0xffffff, intensity: 2 },
    rimLightIntensity: 1.1,
    probeLightIntensity: 10,
    bloom: { strength: 0.16, radius: 0.6, threshold: 0.92 },
    dustOpacity: 0.1,
  },
};

// ---------- shape ----------

const HELIX_RADIUS = 4.8;
const HELIX_PITCH = 14; // depth (z) covered by one full turn
const HELIX_TURNS = 26;
const HELIX_LENGTH = HELIX_PITCH * HELIX_TURNS;
const RUNGS_PER_TURN = 10;
const RUNG_COUNT = HELIX_TURNS * RUNGS_PER_TURN;
const RUNG_GAP = 0.2; // share of a rung left open in the middle, between its two halves
const FLAGGED_SHARE = 0.16;
const ROD_RADIUS = 0.26;
const CORE_RADIUS = 0.115;

/** Centerline of the helix: a slow wander around the z axis. */
function spinePoint(z) {
  return new THREE.Vector3(Math.sin(z * 0.0125) * 5.5, Math.cos(z * 0.0091) * 4, z);
}

/** Point at depth `z` on one of the two backbones (`strand` is 0 or 1). */
function backbonePoint(z, strand) {
  const center = spinePoint(z);
  const angle = (z / HELIX_PITCH) * Math.PI * 2 + strand * Math.PI;
  return new THREE.Vector3(
    center.x + Math.cos(angle) * HELIX_RADIUS,
    center.y + Math.sin(angle) * HELIX_RADIUS,
    center.z,
  );
}

/** Repeatable 0..1 noise, so the same rungs are flagged on every visit. */
function hash(a, b) {
  const value = Math.sin(a * 127.1 + b * 311.7) * 43758.5453;
  return value - Math.floor(value);
}

// ---------- camera path ----------

// One shot per row; `at` is the scroll progress (0..1) the shot is reached at.
// dist: distance from the helix · fov: degrees · orbit, roll: radians
// focus, blur: depth of field (focus distance and maximum blur)
const CAMERA_KEYFRAMES = [
  { at: 0, dist: 27, fov: 40, orbit: 0, roll: -0.3, focus: 25, blur: 0.011 },
  { at: 0.2, dist: 24, fov: 34, orbit: 0.9, roll: -0.14, focus: 23, blur: 0.012 },
  { at: 0.4, dist: 20, fov: 30, orbit: 1.9, roll: 0.22, focus: 19, blur: 0.014 },
  { at: 0.6, dist: 26, fov: 36, orbit: 3, roll: -0.36, focus: 25, blur: 0.012 },
  { at: 0.8, dist: 22, fov: 42, orbit: 3.9, roll: 0.16, focus: 21, blur: 0.013 },
  { at: 1, dist: 33, fov: 42, orbit: 4.9, roll: -0.26, focus: 31, blur: 0.009 },
];

const clamp01 = (value) => Math.min(1, Math.max(0, value));
const smoothstep = (t) => t * t * (3 - 2 * t);

/** The shot at `progress`, eased between the two keyframes around it. */
function cameraAt(progress) {
  let index = 0;
  while (index < CAMERA_KEYFRAMES.length - 2 && progress > CAMERA_KEYFRAMES[index + 1].at) index++;
  const from = CAMERA_KEYFRAMES[index];
  const to = CAMERA_KEYFRAMES[index + 1];
  const t = smoothstep(clamp01((progress - from.at) / (to.at - from.at)));
  const mix = (key) => from[key] + (to[key] - from[key]) * t;
  return {
    dist: mix("dist"),
    fov: mix("fov"),
    orbit: mix("orbit"),
    roll: mix("roll"),
    focus: mix("focus"),
    blur: mix("blur"),
  };
}

// ---------- scene parts ----------

function glassMaterial(refract, overrides) {
  return new THREE.MeshPhysicalMaterial({
    roughness: 0.045,
    ior: 1.46,
    transmission: refract ? 1 : 0,
    transparent: !refract,
    opacity: refract ? 1 : 0.45,
    thickness: 1.1,
    clearcoat: 1,
    clearcoatRoughness: 0.03,
    envMapIntensity: 1.2,
    ...overrides,
  });
}

function addBackbones(scene, material) {
  for (let strand = 0; strand < 2; strand++) {
    const points = [];
    for (let z = 0; z <= HELIX_LENGTH; z += HELIX_PITCH / 30) points.push(backbonePoint(z, strand));
    const curve = new THREE.CatmullRomCurve3(points);
    scene.add(new THREE.Mesh(new THREE.TubeGeometry(curve, points.length, 0.4, 20), material));
  }
}

/**
 * Adds the rungs: each is two halves reaching in from the backbones, a glass rod around a
 * glowing core with a glass joint where it meets the backbone.
 */
function addRungs(scene, rodMaterial, coreMaterial, jointMaterial) {
  // Both capsules are shifted to start at the origin, so scaling y stretches them away from
  // the backbone instead of growing in both directions.
  const rodGeometry = new THREE.CapsuleGeometry(ROD_RADIUS, 1, 6, 20);
  rodGeometry.translate(0, 0.5 + ROD_RADIUS, 0);
  const coreGeometry = new THREE.CapsuleGeometry(CORE_RADIUS, 1, 4, 12);
  coreGeometry.translate(0, 0.5 + CORE_RADIUS, 0);
  const jointGeometry = new THREE.SphereGeometry(0.3, 20, 14);

  const rungs = [];
  for (let index = 0; index < RUNG_COUNT; index++) {
    const z = (index / RUNGS_PER_TURN) * HELIX_PITCH;
    const ends = [backbonePoint(z, 0), backbonePoint(z, 1)];
    const middle = ends[0].clone().lerp(ends[1], 0.5);
    const halfLength = ends[0].distanceTo(ends[1]) * 0.5 * (1 - RUNG_GAP) - ROD_RADIUS;

    const halves = ends.map((end) => {
      const group = new THREE.Group();
      group.position.copy(end);
      group.lookAt(middle);
      group.rotateX(Math.PI / 2);
      const rod = new THREE.Mesh(rodGeometry, rodMaterial);
      rod.scale.y = halfLength;
      const core = new THREE.Mesh(coreGeometry, coreMaterial);
      core.scale.y = halfLength * 0.94;
      group.add(rod, core, new THREE.Mesh(jointGeometry, jointMaterial));
      scene.add(group);
      return { group, rod, core };
    });

    rungs.push({
      z,
      flagged: hash(index * 3.1, 7.7) < FLAGGED_SHARE,
      // How far the closing "resolve" stretch must get before a flagged rung turns healthy.
      resolveAt: hash(index * 11.3, 2.4),
      halves,
      state: null,
    });
  }
  return rungs;
}

function addDust(scene) {
  const count = window.innerWidth < 700 ? 260 : 800;
  const positions = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    positions[i * 3] = (Math.random() - 0.5) * 46;
    positions[i * 3 + 1] = (Math.random() - 0.5) * 46;
    positions[i * 3 + 2] = Math.random() * HELIX_LENGTH;
  }
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  const material = new THREE.PointsMaterial({
    size: 0.07,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
  });
  const dust = new THREE.Points(geometry, material);
  scene.add(dust);
  return dust;
}

function addLights(scene) {
  const ambient = new THREE.AmbientLight();
  const key = new THREE.DirectionalLight();
  key.position.set(-1, 1.5, 1);
  const rim = new THREE.DirectionalLight();
  rim.position.set(1.3, -0.7, -1);
  // Travels down the helix ahead of the camera, see update(); reaches 30 units.
  const probe = new THREE.PointLight(0xffffff, 1, 30, 2);
  scene.add(ambient, key, rim, probe);
  return { ambient, key, rim, probe };
}

/** Render, then depth of field, then bloom, then tone mapping to the screen. */
function createComposer(renderer, scene, camera) {
  const composer = new EffectComposer(renderer);
  // Focus and blur follow the camera keyframes, see update().
  const bokeh = new BokehPass(scene, camera, { aperture: 0.00042 });
  const bloom = new UnrealBloomPass();
  for (const pass of [new RenderPass(scene, camera), bokeh, bloom, new OutputPass()]) {
    composer.addPass(pass);
  }
  return { composer, bokeh, bloom };
}

// ---------- the scene ----------

/**
 * Builds the helix scene on `canvas`.
 *
 * Returns the handles landing.js drives it with: `setProgress(progress, drift)` on scroll,
 * `update(timeMs)` once per frame, `setTheme(name)` on a theme switch, and `debug()`.
 */
export function createStrand(canvas, { theme }) {
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
  // Transmission renders the scene an extra time per frame, so narrow (phone) screens get
  // plain translucent glass instead of refraction.
  const refract = window.innerWidth >= 760;

  const renderer = new THREE.WebGLRenderer({ canvas, powerPreference: "high-performance" });
  renderer.toneMapping = THREE.ACESFilmicToneMapping;

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2();
  const camera = new THREE.PerspectiveCamera(38, 1, 0.5, 400);
  // The glass needs something to reflect: a studio room baked into an environment map.
  scene.environment = new THREE.PMREMGenerator(renderer).fromScene(
    new RoomEnvironment(renderer),
    0.04,
  ).texture;

  const backboneGlass = glassMaterial(refract, { thickness: 1.6 });
  addBackbones(scene, backboneGlass);

  // One rod and one core material per state; update() swaps them onto the rungs.
  const rodMaterials = {};
  const coreMaterials = {};
  for (const state of RUNG_STATES) {
    rodMaterials[state] = glassMaterial(refract, { thickness: 1.5 });
    coreMaterials[state] = new THREE.MeshStandardMaterial({ color: 0x000000, roughness: 0.3 });
  }
  const jointGlass = glassMaterial(refract, { thickness: 0.7, attenuationDistance: 1.6 });
  const rungs = addRungs(scene, rodMaterials.cold, coreMaterials.cold, jointGlass);

  const dust = addDust(scene);
  const lights = addLights(scene);
  const { composer, bokeh, bloom } = createComposer(renderer, scene, camera);

  let look = THEMES.dark;
  let progress = 0;
  let drift = 0;

  function resize() {
    const width = canvas.clientWidth || window.innerWidth;
    const height = canvas.clientHeight || window.innerHeight;
    // The full-screen blur and bloom passes get expensive fast on dense displays.
    const pixelRatio = Math.min(devicePixelRatio || 1, width > 900 ? 1.5 : 1.2);
    renderer.setPixelRatio(pixelRatio);
    renderer.setSize(width, height, false);
    composer.setPixelRatio(pixelRatio);
    composer.setSize(width, height);
    camera.aspect = width / height;
  }

  /**
   * `nextProgress` is how far the page has scrolled through the acts (clamped to 0..1).
   * `nextDrift` (-1..1) says which side the visible copy is on; the camera aims off-center
   * by that much.
   */
  function setProgress(nextProgress, nextDrift) {
    progress = clamp01(nextProgress);
    drift = nextDrift;
  }

  function setTheme(name) {
    look = THEMES[name === "light" ? "light" : "dark"];
    const { palette } = look;

    // Linearized a second time on top of what Color() already does. Carried over from the
    // original bundle: it is what makes the backdrop this dark.
    const backdrop = new THREE.Color(look.background).convertSRGBToLinear();
    renderer.setClearColor(backdrop, 1);
    renderer.toneMappingExposure = look.exposure;
    scene.fog.color.copy(backdrop);
    scene.fog.density = look.fogDensity;

    for (const glass of [backboneGlass, jointGlass]) {
      glass.color.set(look.glass.color);
      glass.attenuationColor.set(look.glass.attenuationColor);
    }
    backboneGlass.attenuationDistance = look.glass.attenuationDistance;

    // Rods stay clear on the surface; their color is the tint light picks up passing through,
    // plus the glow whose strength update() sets every frame.
    for (const state of RUNG_STATES) {
      rodMaterials[state].attenuationColor.set(palette[state]);
      rodMaterials[state].attenuationDistance = look.rodAttenuationDistance;
      rodMaterials[state].emissive.set(palette[state]);
      coreMaterials[state].emissive.set(palette[state]);
    }

    lights.ambient.color.set(look.ambientLight.color);
    lights.ambient.intensity = look.ambientLight.intensity;
    lights.key.color.set(look.keyLight.color);
    lights.key.intensity = look.keyLight.intensity;
    lights.rim.color.set(palette.probe);
    lights.rim.intensity = look.rimLightIntensity;
    lights.probe.color.set(palette.probe);
    lights.probe.intensity = look.probeLightIntensity;

    Object.assign(bloom, look.bloom);
    dust.material.color.set(palette.probe);
    dust.material.opacity = look.dustOpacity;
  }

  /** Places the camera and the probe light for the current progress and renders a frame. */
  function update(timeMs) {
    const shot = cameraAt(progress);
    // The camera stays clear of both ends: it starts 40 units in and stops 90 short.
    const cameraZ = 40 + progress * (HELIX_LENGTH - 130);
    // The probe light leads the camera and pulls further ahead between progress 0.05 and 0.6.
    const probeZ = cameraZ + 26 + clamp01((progress - 0.05) / 0.55) * (HELIX_LENGTH * 0.55);
    // Closing stretch (progress 0.58 to 0.88): flagged rungs turn healthy one by one.
    const resolved = clamp01((progress - 0.58) / 0.3);

    // The scroll-driven angle plus a slow idle rotation. Squashing the vertical part to 62%
    // and rescaling keeps the camera `dist` away while making it linger at the sides of the
    // helix and pass quickly over its top and bottom.
    const orbit = shot.orbit + (reducedMotion ? 0 : timeMs * 0.00004);
    const center = spinePoint(cameraZ);
    const dx = Math.cos(orbit);
    const dy = Math.sin(orbit) * 0.62;
    const length = Math.hypot(dx, dy) || 1;
    camera.position.set(
      center.x + (dx / length) * shot.dist,
      center.y + (dy / length) * shot.dist,
      center.z - shot.dist * 0.22,
    );

    // Aim slightly ahead, and off-center while copy is on screen (see setProgress).
    const target = spinePoint(cameraZ + shot.dist * 0.16);
    target.x -= drift * shot.dist * 0.3;
    target.y += drift * shot.dist * 0.05;
    camera.lookAt(target);
    camera.rotateZ(shot.roll);
    camera.fov = shot.fov;
    camera.updateProjectionMatrix();

    lights.probe.position.copy(spinePoint(probeZ));
    bokeh.uniforms.focus.value = shot.focus;
    bokeh.uniforms.maxblur.value = shot.blur;

    // Glow weakens as the camera closes in, so close-ups do not blow out. Only shots nearer
    // than about 20 units drop below the 1.1 cap.
    const glow = Math.max(0.45, Math.min(1.1, 0.32 + shot.dist / 26));
    for (const state of RUNG_STATES) {
      rodMaterials[state].emissiveIntensity = look.rodEmissive[state] * glow;
      coreMaterials[state].emissiveIntensity = look.coreEmissive[state] * glow;
    }

    const viewDepth = shot.dist * 2 + 26;
    for (const rung of rungs) {
      const visible = Math.abs(rung.z - cameraZ) < viewDepth;
      for (const half of rung.halves) half.group.visible = visible;
      if (!visible) continue;

      let state = "cold";
      if (rung.z < probeZ) state = rung.flagged && resolved <= rung.resolveAt ? "flag" : "strand";
      if (state === rung.state) continue;
      rung.state = state;
      for (const half of rung.halves) {
        half.rod.material = rodMaterials[state];
        half.core.material = coreMaterials[state];
      }
    }

    composer.render();
  }

  function debug() {
    return {
      progress,
      drift,
      refract,
      dist: +cameraAt(progress).dist.toFixed(1),
      camera: camera.position.toArray().map((value) => +value.toFixed(1)),
      visibleRungs: rungs.filter((rung) => rung.halves[0].group.visible).length,
    };
  }

  window.addEventListener("resize", resize);
  resize();
  setTheme(theme);

  return { setProgress, update, setTheme, debug };
}
