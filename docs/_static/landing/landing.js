// Landing page behavior: theme switch, scroll-driven panels, and the frame loop that drives
// the helix in strand.js. three.js is only reached through strand.js, loaded at the bottom,
// so the copy shows and the theme switch works even when the CDN or WebGL is unavailable.

const THEME_KEY = "ossiq-theme";
// Browser chrome color, <meta name="theme-color">.
const THEME_COLORS = { dark: "#05070a", light: "#f3f5f4" };

// A panel is fully visible when its act is centered in the viewport and gone once the act's
// center is this many viewport heights away.
const PANEL_REACH = 0.62;
// Panels fainter than this stop pulling the camera to their side.
const DRIFT_THRESHOLD = 0.05;
// Past the acts the canvas fades out over this much scroll, down to a floor per theme.
const CANVAS_FADE_PX = 560;
const CANVAS_FLOOR = { dark: 0.08, light: 0 };
// Scroll distance after which the header gets its backdrop.
const HEADER_STUCK_PX = 40;

const canvas = document.getElementById("strandCanvas");
const header = document.getElementById("hdr");
const actsContainer = document.getElementById("acts");
const themeButtons = document.querySelectorAll("[data-theme-set]");
const acts = Array.from(document.querySelectorAll(".act"), (element) => ({
  element,
  panel: element.querySelector(".panel"),
  // The camera's drift while this act is on screen: copy on the left is +1, on the right -1.
  side: element.classList.contains("right") ? -1 : element.classList.contains("mid") ? 0 : 1,
}));

let scene = null;

// ---------- theme ----------

// localStorage throws when site data is blocked; the choice then lasts for this visit only.
function storedTheme() {
  try {
    return localStorage.getItem(THEME_KEY);
  } catch {
    return null;
  }
}

function storeTheme(value) {
  try {
    localStorage.setItem(THEME_KEY, value);
  } catch {}
}

// The same lookup as the inline script in <head>, which runs first to avoid a flash.
let theme =
  storedTheme() || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");

function setTheme(next) {
  theme = next === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  for (const button of themeButtons) {
    button.setAttribute("aria-pressed", String(button.dataset.themeSet === theme));
  }
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLORS[theme]);
  scene?.setTheme(theme);
  storeTheme(theme);
}

for (const button of themeButtons) {
  button.addEventListener("click", () => setTheme(button.dataset.themeSet));
}
setTheme(theme);

// ---------- menu ----------

const menuButton = document.querySelector(".menu-btn");

function setMenu(open) {
  header.classList.toggle("open", open);
  menuButton.setAttribute("aria-expanded", String(open));
}

menuButton.addEventListener("click", () => setMenu(!header.classList.contains("open")));
// #product and #features scroll the page under the drawer, so any link closes it.
for (const link of header.querySelectorAll("nav a")) {
  link.addEventListener("click", () => setMenu(false));
}
addEventListener("keydown", (event) => event.key === "Escape" && setMenu(false));

// ---------- scroll ----------

/** Fades the panels in and out and tells the scene how far the page has scrolled. */
function readScroll() {
  const scrollRange = Math.max(1, actsContainer.offsetHeight - innerHeight);

  let drift = 0;
  for (const act of acts) {
    const rect = act.element.getBoundingClientRect();
    const offCenter =
      Math.abs(rect.top + rect.height / 2 - innerHeight / 2) / (innerHeight * PANEL_REACH);
    const visibility = Math.max(0, 1 - offCenter * offCenter);
    act.panel.style.setProperty("--vis", visibility.toFixed(3));
    if (visibility > DRIFT_THRESHOLD) drift += act.side * visibility;
  }
  scene?.setProgress(scrollY / scrollRange, Math.max(-1, Math.min(1, drift)));

  const pastActs = scrollY - scrollRange;
  canvas.style.opacity =
    pastActs <= 0 ? 1 : Math.max(CANVAS_FLOOR[theme], 1 - pastActs / CANVAS_FADE_PX);
  header.classList.toggle("stuck", scrollY > HEADER_STUCK_PX);
}

// ---------- frame loop ----------

// Console handle for checking a change: set `paused`, scroll, then step(0) renders one
// repeatable frame and debug() reports where the camera ended up.
const strand = (window.__strand = {
  paused: false,
  step(timeMs = performance.now()) {
    readScroll();
    scene?.update(timeMs);
  },
  debug: () => scene?.debug(),
});

function frame(timeMs) {
  if (!strand.paused) strand.step(timeMs);
  requestAnimationFrame(frame);
}

readScroll();
requestAnimationFrame(frame);

// ---------- scene ----------

try {
  // Same breakpoint as the stacked layout in landing.html, where the canvas is hidden. Checked once
  // at load, so widening the window later needs a reload to start the helix.
  if (!matchMedia("(max-width: 900px)").matches) {
    const { createStrand } = await import("./strand.js");
    scene = createStrand(canvas, { theme });
  }
} catch (error) {
  console.warn("Landing animation unavailable:", error);
}
