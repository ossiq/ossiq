# Transitive Dependency Explorer

The Explorer is a D3-based interactive tree visualization for transitive dependency analysis.
Key files: `src/composables/useD3Tree.ts`, `src/views/TransitiveDependenciesView.vue`.

---

## Node Color Coding

Semantic pastel colors are applied in priority order (first match wins):

| Condition | Fill | Stroke |
|---|---|---|
| Has CVEs (`severity` set) | amber `#fde68a` | `#d97706` |
| Pinned version (e.g. `1.2.3`, no operators) | yellow `#fef08a` | `#a16207` |
| Upper-bound constraint (contains `<`) | red `#fecaca` | `#dc2626` |
| Default | blue `#bfdbfe` | `#1d4ed8` |

CVE severity is populated from the report's `cve[]` arrays (highest severity wins per package).
Pinned/UBC coloring activates when `version_defined` is present on the `DependencyNode`
— this field requires backend wiring to be populated (not yet in export schema).

### Solid-fill state (focus)

When any node is clicked it switches to a **solid** appearance — fill equals the stroke color,
making the circle a flat dark disc. Both the clicked node and all its same-version duplicates
receive this treatment:

| Node type | Solid fill color |
|---|---|
| CVE (amber) | `#d97706` (amber-600) |
| Pinned (yellow) | `#a16207` (yellow-700) |
| UBC (red) | `#dc2626` (red-600) |
| Default (blue) | `#1d4ed8` (blue-700) |

Logic lives in `resolveNodeStyle` in `src/explorer/nodeStyle.ts`.

---

## CVE Warning Indicator

Nodes with `severity` set render an orange triangle warning badge to the left of the circle
(SVG polygon at `translate(-22, 0)`, points `0,-9 8,5 -8,5`) with a bold `!` glyph.
Colors: fill `#fdba74`, stroke `#ea580c`, text `#7c2d12`.

---

## Collapsed Branch Indicator

When a branch is folded, the node circle:
- Grows from `r=6` → `r=8`
- Fills with its semantic stroke color (solid dark), losing the pastel fill

This makes folded subtrees immediately visually distinct at a glance.

---

## Interactions

| Gesture | Action |
|---|---|
| **Click** a node | Enters focus mode for that node; opens sidebar |
| **Alt+Click** a node | Folds / unfolds that node's subtree (500ms animated) |
| **Click** a same-version dashed link | Identical to clicking the source endpoint node |
| **Click** a tree edge (solid link) | Identical to clicking the child (target) endpoint node |
| **Click** SVG background | Exits focus mode; restores all highlights; closes sidebar |

Tree edges have a 12px transparent hit-target overlay (`.link-hit`) for easier clicking,
mirroring the same-version dashed link pattern.

---

## Tree Edge Color Coding

Tree edges carry semantic colors in **both** normal and focus states.

### Normal state (no focus)

| Target node type | Edge color |
|---|---|
| Has CVE (`severity` set) | light red `#fecaca` (red-200) |
| Pinned or UBC (`version_defined` set) | light orange `#fed7aa` (orange-200) |
| Default | slate `#cbd5e1` (CSS default) |

This gives an at-a-glance risk map of the tree even before any interaction.

### Focus state (ancestor path)

When a node is clicked, its path to the root is highlighted:

| Condition | Ancestor edge color |
|---|---|
| Any node in the path has CVE (`hasCveInPath`) | `#fca5a5` (red-300), 3px, full opacity |
| No CVE in path | `#1d4ed8` (blue-700), 3px, full opacity |
| Not on ancestor path | CSS default color, `opacity: 0.15` (dimmed) |

`hasCveInPath` is all-or-nothing — a single CVE node anywhere in the focused path
turns all ancestor edges red. Computed in `useHighlightState.collectAncestorInfo`.

---

## Focus Mode

Clicking a node, a same-version dashed link, or a tree edge triggers unified focus mode,
showcasing all paths the dependency is used across the tree:

- **Clicked node** → solid fill (fill = its semantic stroke color), border 3.5px
- **Duplicate nodes** (same `name@version_installed`) → solid fill (fill = their semantic stroke color), border 3.5px
- **Ancestor nodes** (path to root for every focused node) → full opacity, default semantic color
- **All other nodes** → `opacity: 0.15` (dimmed)
- **Tree links on ancestor paths** → 3px, full opacity; blue `#1d4ed8` or red `#fca5a5` (see above)
- **All other tree links** → `opacity: 0.15` (dimmed)
- **Same-version dashed links for the focused package** → orange `#f97316`, 3px, 85% opacity (remain dashed)
- **All other dashed links** → `opacity: 0.1` (dimmed)

Clicking the SVG background exits focus mode and restores all nodes and links to their default state.

---

## Same-Version Links

Nodes sharing an identical `name@version_installed` across different subtrees are connected
by curved dashed lines (quadratic bezier, control point offset 40px perpendicular to the line).

Each link is rendered as two stacked SVG paths:
- **Visual** (`.link-same-version`): dashed `#94a3b8`, 1px, 30% opacity, `stroke-dasharray: 4 6`;
  when highlighted: orange `#f97316`, 3px, 85% opacity — still dashed
- **Hit target** (`.link-same-version-hit`): 12px transparent stroke — makes clicking easy

---

## Tree Structure Rules

- **Duplicates allowed**: the same package can appear in multiple subtrees simultaneously
- **Cycle detection**: each recursive `transformToD3` call passes an ancestor `Set<string>`;
  a dependency is skipped only if it is its own ancestor (true cycle), not just a repeat
- **Unique D3 keys**: nodes are keyed by their full ancestor path (`root/react/lodash`)
  rather than bare name, preventing D3 enter/update/exit corruption for duplicate packages

---

## Zoom & Resize

- Pan and zoom via D3's built-in zoom behavior, `scaleExtent: [0.1, 3]`
- Cursor switches to `grabbing` while panning
- Controls: `zoomIn()` / `zoomOut()` scale by ×1.3; `resetZoom()` returns to scale 1
- Window `resize` events update SVG dimensions and re-center the root group

---

## CSS vs D3 Styling Note

Vue's `:deep(.link)` and `:deep(.link-same-version)` rules define `stroke`, `stroke-width`,
and `opacity` as **CSS properties**. SVG presentation attributes set via D3's `.attr()` are
overridden by CSS. All dynamic style mutations in `applyTreeLinkStyles` and
`applySameVersionLinkStyles` therefore use `.style()` (inline styles), which take precedence
over stylesheet rules. Passing `null` to `.style()` removes the override and restores the
CSS-defined default.
