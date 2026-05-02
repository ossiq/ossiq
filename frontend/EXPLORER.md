# Transitive Dependency Explorer

The Explorer is a D3-based interactive tree visualization for transitive dependency analysis.
Key files: `src/views/TransitiveDependenciesView.vue`, `src/composables/useD3Tree.ts` (orchestrator),
`src/composables/useHighlightState.ts`, `src/composables/useTreeZoom.ts`,
`src/explorer/` — rendering modules: `config.ts`, `nodeStyle.ts`, `renderNodes.ts`,
`renderTreeLinks.ts`, `renderSameVersionLinks.ts`, `renderAggregateLinks.ts`, `transform.ts`,
`visibleState.ts`, `registry.ts`.

---

## Node Types

The tree renders four visually distinct node categories. Visual priority is evaluated in this order:
Super Node → collapsed normal node → expanded node (semantic rules).

### Super Node (folded subtree)

A **Super Node** represents a subtree that has been automatically folded because it exceeds the
current `maxDepth`. Its appearance encodes how many hidden descendants it carries via three tiers
keyed on `_hiddenChildCount`. The `_isFolded` flag on the data object triggers this path in
`resolveBaseStyle` — it takes priority over all semantic color rules.

| Tier | `_hiddenChildCount` | Radius | Fill | Stroke |
|---|---|---|---|---|
| Small | ≤ 10 | 10 | indigo-100 `#e0e7ff` | indigo-700 `#4338ca` |
| Medium | 11–50 | 12 | orange-200 `#fed7aa` | orange-600 `#ea580c` |
| Large | > 50 | 14 | red-200 `#fecaca` | red-600 `#dc2626` |

All Super Nodes share: `stroke-dasharray: 4,2`, `stroke-width: 2`.

#### CVE highlight for Super Nodes (`_hasChildCve`)

When the hidden subtree of a Super Node contains at least one CVE-affected package, the node's
**fill and stroke are overridden to CVE red** regardless of size tier:

| Condition | Fill | Stroke |
|---|---|---|
| `_hasChildCve === true` | red-200 `#fecaca` | red-600 `#dc2626` |
| _(no CVE — tier-based)_ | see tier table above | see tier table above |

The **radius stays tier-based** (`_hiddenChildCount`) even when `_hasChildCve` is set — the size
still communicates how many packages are hidden.

`_hasChildCve` is computed in `transform.ts` (`buildD3DataFromVisibleState`) via a BFS traversal
(`hasCveInSubtree`) of the registry graph rooted at the Super Node's immediate children. It is
set at build time so `resolveBaseStyle` in `nodeStyle.ts` can check it without traversing the tree
again at render time.

A bold **`+N` badge** (white text colored by the stroke, `font-size: 8px`) is rendered at the
center of the circle, showing the exact hidden child count.

Clicking a Super Node in the tree **navigates into** that subtree (shift-and-expand); the circle
itself is not treated as a regular focus target.

### Collapsed Normal Node

A regular node whose subtree has been manually folded by the user via Alt+Click. The node
retains its semantic color identity but switches to a "solid dark" appearance to signal that
children are hidden:

- **Radius**: 8 (`radiusCollapsed`) — same for all constraint types
- **Fill**: equals its semantic stroke color (solid dark disc)
- **Stroke**: semantic stroke color (unchanged)
- **`stroke-dasharray`**: retained — constraint type is still readable at a glance

Note: OVERRIDE (r=8 expanded) and a collapsed default node (r=8) end up the same size, so the
stroke pattern and color remain the primary distinguishing signals for collapsed nodes.

### Expanded Normal Node (semantic color rules)

An ordinary visible node with no children hidden. Appearance is driven by `NODE_COLOR_RULES`
(first-match-wins) in `src/explorer/nodeStyle.ts`. Rules are evaluated in priority order:

| Priority | Condition | Fill | Stroke | `stroke-dasharray` | Radius |
|---|---|---|---|---|---|
| 1 | Has CVEs (`severity` set) | red `#fecaca` | `#dc2626` | solid | 6 |
| 2 | `is_yanked` | purple `#f3e8ff` | `#7e22ce` | `3,2` | 7 |
| 3 | `constraint_type === 'OVERRIDE'` | orange `#fed7aa` | `#ea580c` | `7,2,2,2` (dash-dot) | 8 |
| 4 | `constraint_type === 'ADDITIVE'` | green `#bbf7d0` | `#16a34a` | `2,2.5` (dotted) | 6 |
| 5 | `constraint_type === 'PINNED'` or `isPinned(version_defined)` | orange `#ffedd5` | `#c2410c` | solid 3 px | 7 |
| 6 | `constraint_type === 'NARROWED'` or `hasUpperConstraint(version_defined)` | yellow `#fef08a` | `#a16207` | `5,3` (dashed) | 6 |
| 7 | `is_prerelease` | amber `#fef3c7` | `#b45309` | `2,2` (dotted) | 6 |
| 8 | Default / DECLARED | blue `#bfdbfe` | `#1d4ed8` | solid | 6 |

OVERRIDE and PINNED share an orange family but are distinguishable by their stroke patterns
(dash-dot vs solid thick) and slightly different shades (orange-200 vs orange-100).

The `isPinned` / `hasUpperConstraint` heuristics act as **fallbacks** for pre-v1.2 reports that
lack a `constraint_type` field.

### Node with CVEs

Any node whose package has `severity` set (highest severity wins per package name, derived from
the report's `cve[]` arrays) gets the CVE visual treatment on top of its normal circle:

- Circle: red-200 fill `#fecaca`, red-600 stroke `#dc2626`, solid, r=6
- **Warning triangle badge**: SVG `<polygon>` at `translate(-22, 0)`, points `0,-9 8,5 -8,5`
  - Fill `#fdba74` (orange-300), stroke `#ea580c` (orange-600), 1.5 px
  - Bold `!` glyph, fill `#7c2d12` (orange-900), `font-size: 9px`

CVE takes the highest visual priority — a node that is both CVE-affected and OVERRIDE renders
with the CVE red style, not the OVERRIDE orange.

### Solid-fill state (focus)

When a node is clicked it switches to a **solid** appearance — fill equals its stroke color.
The stroke pattern (`stroke-dasharray`) is retained so constraint type stays readable. Both the
primary (clicked) node and same-version duplicates receive this treatment:

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

## Edge Types

### Tree Edge (`.link`)

Solid horizontal bezier paths connecting a parent node to each of its children.
Also has a 12 px transparent `.link-hit` overlay for easier clicking.

**Normal state** (no focus active):

| Target node condition | Edge color |
|---|---|
| Has CVE (`severity` set) | light red `#fecaca` (red-200) |
| PINNED or NARROWED (`version_defined` set) | light orange `#fed7aa` (orange-200) |
| Default | slate `#cbd5e1` (CSS default) |

**Focus state — ancestor path** (edge leads toward the root from the focused node):

| Target node condition | Color | Width |
|---|---|---|
| Has CVE | `#fca5a5` (red-300) | 3 px |
| PINNED or NARROWED | `#fed7aa` (orange-200) | 3 px |
| Default | `#1d4ed8` (blue-700) | 3 px |
| Not on any path | CSS default | `opacity: 0.15` |

**Focus state — descendant path** (edge leads away from the focused node into its subtree):

| Target node condition | Color | Width |
|---|---|---|
| Has CVE | `#fca5a5` (red-300) | 3 px |
| PINNED or NARROWED | `#fed7aa` (orange-200) | 3 px |
| Default | `#97c2f7` (blue-400) | 3 px |

All tree link styles are applied via `.style()` (inline) so they take precedence over the
Vue `:deep(.link)` CSS rules. Passing `null` restores the CSS default.

### Same-Version Dashed Link (`.link-same-version`)

Curved quadratic bezier arcs connecting nodes that share an identical `name@version_installed`
across different subtrees. Each arc is rendered as two stacked paths:

- **Visual** (`.link-same-version`): slate-400 `#94a3b8`, 1 px, `stroke-dasharray: 4 6`, 30% opacity
- **Hit target** (`.link-same-version-hit`): 12 px transparent — makes clicking easy

**Focus state**:
- Arc for the focused package: orange `#f97316`, 3 px, 85% opacity — still dashed
- All other arcs: `opacity: 0.1` (dimmed)

Clicking either the arc or its hit target focuses the source endpoint node (same as clicking the
node directly). Full teardown-rebuild on each tree render; no D3 diff.

### Aggregate Link (`.link-aggregate`)

Curved dashed arcs drawn from a **Super Node** to a dependency that is already visible elsewhere
in the tree. They appear when the Super Node's hidden children overlap with visible nodes,
providing cross-tree context without expanding the subtree.

Two variants exist depending on how many Super Nodes point to the same visible target:

**Single arc** (one Super Node → one visible target):
- Stroke: slate-400 `#94a3b8`, 1.5 px, `stroke-dasharray: 6,3`, 50% opacity

**Bundle arc** (multiple Super Nodes → same visible target):
- Drawn from the centroid of all source positions to the shared target
- Carries a `(N)` source-count badge at the arc midpoint (`font-size: 7px`)
- Same default appearance as single arc; styling config for a distinct bundle style
  (`bundleStroke`, `bundleStrokeWidth`) exists in `TREE_CONFIG.aggregateLink` but is
  not yet applied at render time

Both variants include a 10 px transparent `.link-aggregate-hit` overlay. Clicking focuses the
source Super Node (single) or the first source (bundle).

**Focus state**:
- Arc relevant to the focused node: orange `#f97316`, 3 px, 85% opacity
- All other arcs: `opacity: 0.1` (dimmed)

Full teardown-rebuild on each tree render (aggregate topology changes with every expand/filter).

---

## Focus Mode

Clicking a node, a same-version dashed link, or a tree edge triggers unified focus mode.
The highlight state is managed exclusively in `src/composables/useHighlightState.ts`.

### Node roles in focus mode

| Role | Trigger | Visual treatment |
|---|---|---|
| **Primary** | The clicked node | Solid fill (fill = semantic stroke color), 3.5 px border, full opacity |
| **Secondary** | All nodes sharing `name@version_installed` with the primary | Same solid fill as primary, 3.5 px border, full opacity |
| **Ancestor** | Nodes on the path from any primary/secondary up to the root | Normal semantic pastel fill, full opacity |
| **Descendant** | All children/grandchildren of primary and secondary nodes | Normal semantic pastel fill (NOT solid), full opacity |
| **Super Node (dimmed)** | Any Super Node not on an ancestor or descendant path | `opacity: 0.15` |
| **Collapsed node (dimmed)** | Any manually collapsed node not on a relevant path | `opacity: 0.15` |
| **Other nodes** | Any node not in the above categories | `opacity: 0.15` |

Descendant nodes keep their pastel fill (not solid), which visually distinguishes them from the
selected primary/secondary nodes even though both are full opacity.

### Edge behavior in focus mode

| Edge | On ancestor path | On descendant path | Otherwise |
|---|---|---|---|
| Tree edge | 3 px, full opacity, semantic color (see table above) | 3 px, full opacity, semantic color (see table above) | `opacity: 0.15` |
| Same-version dashed link | orange `#f97316`, 3 px, 85% opacity (focused package) | — | `opacity: 0.1` |
| Aggregate link | orange `#f97316`, 3 px, 85% opacity (source is focused) | — | `opacity: 0.1` |

Clicking the SVG background exits focus mode and restores all nodes and edges to their default state.

---

## CVE Warning Indicator

Nodes with `severity` set render an orange triangle warning badge to the left of the circle
(SVG polygon at `translate(-22, 0)`, points `0,-9 8,5 -8,5`) with a bold `!` glyph.
Colors: fill `#fdba74`, stroke `#ea580c`, text `#7c2d12`.

## Yanked Version Indicator

Nodes where `is_yanked` is true render a filled purple circle badge to the right of the node
circle (SVG circle `r=6` at `translate(+18, 0)`) with a bold `✕` glyph in white (`font-size: 8px`).
Circle fill: `#7e22ce` (purple-800). This badge is composable with the CVE triangle — a yanked
node with a CVE will show both the triangle on the left and the `✕` circle on the right.

---

## Collapsed Branch Indicator

When a branch is folded via Alt+Click (collapsed normal node), the node circle:
- Grows to `r=8` (`radiusCollapsed`) regardless of constraint type
- Fills with its semantic stroke color (solid dark), losing the pastel fill
- Retains its stroke-dasharray pattern, so constraint type is still readable

Note: PINNED nodes have an expanded radius of 7 and OVERRIDE nodes 8, so a collapsed PINNED
node will look the same size as a collapsed default node. The stroke pattern and color remain
the distinguishing signals.

---

## Interactions

| Gesture | Action |
|---|---|
| **Click** a node | Enters focus mode for that node; opens sidebar |
| **Alt+Click** a node | Folds / unfolds that node's subtree (500ms animated) |
| **Click** a same-version dashed link | Identical to clicking the source endpoint node |
| **Click** a tree edge (solid link) | Identical to clicking the child (target) endpoint node |
| **Click** an aggregate link | Focuses the source Super Node (or first source in a bundle) |
| **Click** SVG background | Exits focus mode; restores all highlights; closes sidebar |
| `selectNodeByName(name)` | Programmatically focuses a node by package name; called from `DependencyDetailPanel` via `@select-node` |

Tree edges and aggregate links have transparent hit-target overlays (12 px and 10 px respectively)
for easier clicking, mirroring the same-version dashed link pattern.

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
