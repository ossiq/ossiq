# Transitive Dependency Explorer

The Explorer is a D3-based interactive tree visualization for transitive dependency analysis.
Key files: `src/views/TransitiveDependenciesView.vue`, `src/composables/useD3Tree.ts` (orchestrator),
`src/composables/useHighlightState.ts`, `src/composables/useTreeZoom.ts`,
`src/explorer/` — rendering modules: `config.ts`, `nodeStyle.ts`, `renderNodes.ts`,
`renderTreeLinks.ts`, `renderSameVersionLinks.ts`, `transform.ts`.

---

## Node Color Coding

Nodes are styled with **both color and a stroke pattern** so the constraint type is
distinguishable without relying on color alone (colorblind-friendly). Rules are evaluated
first-match-wins inside `NODE_COLOR_RULES` in `src/explorer/nodeStyle.ts`.

| Priority | Condition | Fill | Stroke | `stroke-dasharray` | Expanded radius |
|---|---|---|---|---|---|
| 1 | Has CVEs (`severity` set) | red `#fecaca` | `#dc2626` | solid | 6 |
| 2 | `constraint_type === 'OVERRIDE'` | orange `#fed7aa` | `#ea580c` | `7,2,2,2` (dash-dot) | 8 |
| 3 | `constraint_type === 'ADDITIVE'` | green `#bbf7d0` | `#16a34a` | `2,2.5` (dotted) | 6 |
| 4 | `constraint_type === 'PINNED'` or `isPinned(version_defined)` | orange `#ffedd5` | `#c2410c` | solid thick (3 px) | 7 |
| 5 | `constraint_type === 'NARROWED'` or `hasUpperConstraint(version_defined)` | yellow `#fef08a` | `#a16207` | `5,3` (dashed) | 6 |
| 6 | Default / DECLARED | blue `#bfdbfe` | `#1d4ed8` | solid | 6 |

OVERRIDE and PINNED share an orange family but are distinguishable by their stroke patterns
(dash-dot vs solid thick) and slightly different shades (orange-200 vs orange-100).

The `isPinned` / `hasUpperConstraint` heuristics act as **fallbacks** for pre-v1.2 reports that
lack a `constraint_type` field. CVE severity is derived from the report's `cve[]` arrays
(highest severity wins per package name).

### Solid-fill state (focus)

When a node is clicked it switches to a **solid** appearance — fill equals its stroke color,
making the circle a flat dark disc. The stroke pattern (dasharray) is retained, so constraint
type remains readable even in focused state. Both the clicked node and all same-version
duplicates receive this treatment:

| Node type | Solid fill | Stroke pattern retained |
|---|---|---|
| CVE (red) | `#dc2626` | solid |
| OVERRIDE (orange) | `#ea580c` | `7,2,2,2` |
| ADDITIVE (green) | `#16a34a` | `2,2.5` |
| PINNED (orange) | `#c2410c` | solid thick |
| NARROWED (yellow) | `#a16207` | `5,3` |
| Default/DECLARED (blue) | `#1d4ed8` | solid |

Logic lives in `resolveNodeStyle` in `src/explorer/nodeStyle.ts`.

---

## CVE Warning Indicator

Nodes with `severity` set render an orange triangle warning badge to the left of the circle
(SVG polygon at `translate(-22, 0)`, points `0,-9 8,5 -8,5`) with a bold `!` glyph.
Colors: fill `#fdba74`, stroke `#ea580c`, text `#7c2d12`.

---

## Collapsed Branch Indicator

When a branch is folded, the node circle:
- Grows to `r=8` (`radiusCollapsed`) regardless of constraint type
- Fills with its semantic stroke color (solid dark), losing the pastel fill
- Retains its stroke-dasharray pattern, so constraint type is still readable

Note: PINNED nodes have an expanded radius of 7 and OVERRIDE nodes 8, so a collapsed PINNED
node will look the same size as a collapsed default node. The stroke pattern and color remain
the distinguishing signals. This makes folded subtrees immediately visually distinct at a glance.

---

## Interactions

| Gesture | Action |
|---|---|
| **Click** a node | Enters focus mode for that node; opens sidebar |
| **Alt+Click** a node | Folds / unfolds that node's subtree (500ms animated) |
| **Click** a same-version dashed link | Identical to clicking the source endpoint node |
| **Click** a tree edge (solid link) | Identical to clicking the child (target) endpoint node |
| **Click** SVG background | Exits focus mode; restores all highlights; closes sidebar |
| `selectNodeByName(name)` | Programmatically focuses a node by package name; called from `DependencyDetailPanel` via `@select-node` |

Tree edges have a 12px transparent hit-target overlay (`.link-hit`) for easier clicking,
mirroring the same-version dashed link pattern.

---

## Tree Edge Color Coding

Tree edges carry semantic colors in **both** normal and focus states.

### Normal state (no focus)

| Target node type | Edge color |
|---|---|
| Has CVE (`severity` set) | light red `#fecaca` (red-200) |
| PINNED or NARROWED (`version_defined` set) | light orange `#fed7aa` (orange-200) |
| Default | slate `#cbd5e1` (CSS default) |

This gives an at-a-glance risk map of the tree even before any interaction.

### Focus state (ancestor path)

When a node is clicked, its path to the root is highlighted. Each edge is colored
individually based on its **target node's** exceptional state:

| Target node type | Ancestor edge color |
|---|---|
| Has CVE (`severity` set) | `#fca5a5` (red-300), 3px, full opacity |
| PINNED or NARROWED (`version_defined` set) | `#fed7aa` (orange-200), 3px, full opacity |
| Default | `#1d4ed8` (blue-700), 3px, full opacity |
| Not on ancestor path | CSS default color, `opacity: 0.15` (dimmed) |

---

## Toolbar Controls

The toolbar (top-right) contains the search field, filter toggles, a **Clear** button, and an **Info** button.

### Clear filters button

A "Clear" pill button appears automatically whenever any search query or toggle filter is active. Clicking it resets `searchQuery`, `filterCve`, `filterPinned`, and `filterUpperBound` to their defaults in one action. The button is hidden when no filters are active.

Implemented via `hasActiveFilters` (computed) and `clearFilters()` exposed by `useTreeFilters`.

### Legend panel (Info button)

The `ℹ` icon button at the far right of the toolbar toggles a floating legend card (`showLegend` ref in `TransitiveDependenciesView.vue`). The card is positioned `top-18 right-6` (below the toolbar row) and contains three sections:

1. **Node colors** — color swatches with fill/stroke matching `TREE_CONFIG.colors`, one row per rule
2. **Interactions** — edge click, dashed-line click, Alt+Click, background click
3. **Duplicate packages** — explains same-version dashed links

The card has its own close button and also closes by toggling the Info button again.

The legend circles in `ReportLegend.vue` use the same `constraintCircleClasses()` helper from
`src/explorer/nodeStyle.ts` that drives the table indicators, so they stay in sync automatically.
The inline floating legend in `TransitiveDependenciesView.vue` uses matching inline styles.

---

## Search & Filters

The toolbar exposes a fuzzy search input and three toggle buttons that prune the visible tree to branches of interest. All filter logic lives in `src/composables/useTreeFilters.ts`; the D3 rendering layer is unaware of filtering.

### Search (Fuse.js)

Typing in the search input fuzzy-matches against all package names in the tree (Fuse.js, threshold `0.35`, min 2 chars). The tree is re-evaluated **50 ms after the last keystroke** (debounced). Only branches containing at least one name match are shown; ancestors of matching nodes are preserved to maintain the path to root.

### Toggle filters

| Button | Condition | Active color |
|---|---|---|
| **CVE** | Node has `severity` set | red `#DE4514` |
| **Narrowed** | `constraint_type === 'NARROWED'` or `version_defined` contains `<` | yellow `#a16207` |
| **Override/Pinned** | `constraint_type === 'OVERRIDE'` or `constraint_type === 'PINNED'` or `version_defined` matches bare semver | orange `#ea580c` |

Multiple active toggles use **OR** logic — a branch is shown if it contains a node satisfying any active toggle.

### Combined search + toggles

When both a search query and one or more toggles are active, **AND** logic applies: a node must match the search query _and_ satisfy at least one active toggle to be kept.

### Adding a new filter

To introduce a new toggle filter, only `useTreeFilters.ts` needs to change:
1. Add an entry to `TOGGLE_FILTERS` with a `key` and `test` predicate.
2. Add a `ref(false)` for it in the composable and expose it in the return value.
3. Register it in the internal `toggleMap`.
4. Add the toggle button in `TransitiveDependenciesView.vue`.

`pruneTree` and `buildPredicate` are untouched.

---

## Focus Mode

Clicking a node, a same-version dashed link, or a tree edge triggers unified focus mode,
showcasing all paths the dependency is used across the tree:

- **Clicked node** → solid fill (fill = its semantic stroke color), border 3.5px
- **Duplicate nodes** (same `name@version_installed`) → solid fill (fill = their semantic stroke color), border 3.5px
- **Ancestor nodes** (path to root for every focused node) → full opacity, default semantic color
- **Descendant nodes** (all children/grandchildren of focused nodes) → full opacity, default semantic color
- **All other nodes** → `opacity: 0.15` (dimmed)
- **Tree links on ancestor paths** → 3px, full opacity; blue `#1d4ed8` or red `#fca5a5` (see above)
- **Tree links on descendant paths** → 3px, full opacity; color depends on target node exceptional state (see below)
- **All other tree links** → `opacity: 0.15` (dimmed)
- **Same-version dashed links for the focused package** → orange `#f97316`, 3px, 85% opacity (remain dashed)
- **All other dashed links** → `opacity: 0.1` (dimmed)

### Descendant path edge colors

| Target node type | Descendant edge color |
|---|---|
| Has CVE (`severity` set) | `#fca5a5` (red-300) |
| PINNED or NARROWED (`version_defined` set) | `#fed7aa` (orange-200) |
| Default | `#97c2f7` (blue-400) |

Descendant node circles keep their normal semantic pastel fill — no solid fill — which visually
distinguishes them from the selected (solid) primary node.

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
- Zoom buttons (+/−/1:1) rendered at **bottom-right** of the canvas, separate from the top toolbar
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
