# Transitive Dependency Explorer

The Explorer is a D3-based interactive tree visualization for transitive dependency analysis.
Key files:
- `src/views/TransitiveDependenciesView.vue` — top-level view, toolbar, sidebar
- `src/composables/useD3Tree.ts` — orchestrator (build, update, highlight cycle)
- `src/composables/useHighlightState.ts` — all focus state; nothing else mutates it
- `src/composables/useTreeZoom.ts` — pan/zoom, zoom buttons
- `src/composables/useNavigationStack.ts` — subtree navigation breadcrumb
- `src/explorer/` — pure rendering modules:
  `config.ts`, `nodeStyle.ts`, `renderNodes.ts`, `renderTreeLinks.ts`,
  `renderSameVersionLinks.ts`, `renderAggregateLinks.ts`, `transform.ts`,
  `visibleState.ts`, `registry.ts`

---

## Node Types

The tree renders four visually distinct node categories. Visual priority is evaluated in this order:
Super Node → collapsed normal node → expanded node (semantic rules).

### Super Node (folded subtree)

A **Super Node** represents a subtree automatically folded because it exceeds the current
`maxDepth`. Its appearance encodes how many hidden descendants it carries via three tiers
keyed on `_hiddenChildCount`. The `_isFolded` flag triggers this path in `resolveBaseStyle`
— it takes priority over all semantic color rules.

| Tier | `_hiddenChildCount` | Radius | Fill | Stroke |
|---|---|---|---|---|
| Small | ≤ 10 | 10 | indigo-100 `#e0e7ff` | indigo-700 `#4338ca` |
| Medium | 11–50 | 12 | orange-200 `#fed7aa` | orange-600 `#ea580c` |
| Large | > 50 | 14 | red-200 `#fecaca` | red-600 `#dc2626` |

All Super Nodes share: `stroke-dasharray: 4,2`, `stroke-width: 2`.

#### CVE highlight for Super Nodes (`_hasChildCve`)

When the hidden subtree of a Super Node contains at least one CVE-affected package, fill and
stroke are overridden to CVE red regardless of size tier. The radius stays tier-based.

| Condition | Fill | Stroke |
|---|---|---|
| `_hasChildCve === true` | red-200 `#fecaca` | red-600 `#dc2626` |
| *(no CVE — tier-based)* | see tier table above | see tier table above |

`_hasChildCve` is computed in `transform.ts` (`buildD3DataFromVisibleState`) via BFS
(`hasCveInSubtree`) at build time so `resolveBaseStyle` can check it without re-traversing.

A bold **`+N` badge** (white text colored by the stroke, `font-size: 8px`) is rendered at
the center of the circle, showing the exact hidden child count.

Clicking a Super Node **navigates into** that subtree (see [Navigation Stack](#navigation-stack)).

### Collapsed Normal Node

A regular node whose subtree has been manually folded by the user via Alt+Click. The node
retains its semantic color identity but switches to a "solid dark" appearance:

- **Radius**: 8 (`radiusCollapsed`) — same for all constraint types
- **Fill**: equals its semantic stroke color (solid dark disc)
- **Stroke**: semantic stroke color (unchanged)
- **`stroke-dasharray`**: retained — constraint type is still readable at a glance

### Expanded Normal Node (semantic color rules)

An ordinary visible node with no children hidden. Appearance is driven by `NODE_COLOR_RULES`
(first-match-wins) in `src/explorer/nodeStyle.ts`.

| Priority | Condition | Fill | Stroke | `stroke-dasharray` | Radius |
|---|---|---|---|---|---|
| 1 | Has CVEs (`severity` set) | red-200 `#fecaca` | `#dc2626` | solid | 6 |
| 2 | `is_package_unpublished` | red-100 `#fee2e2` | red-700 `#b91c1c` | `4,2` | 7 |
| 3 | `is_yanked` | purple-100 `#f3e8ff` | purple-800 `#7e22ce` | `3,2` | 7 |
| 4 | `is_deprecated` | yellow-100 `#fef9c3` | yellow-700 `#a16207` | `2,3` | 6 |
| 5 | `constraint_type === 'OVERRIDE'` | orange-200 `#fed7aa` | `#ea580c` | `7,2,2,2` (dash-dot) | 8 |
| 6 | `constraint_type === 'ADDITIVE'` | green-200 `#bbf7d0` | `#16a34a` | `2,2.5` (dotted) | 6 |
| 7 | `constraint_type === 'PINNED'` or `isPinned(version_defined)` | orange-100 `#ffedd5` | `#c2410c` | solid 3 px | 7 |
| 8 | `constraint_type === 'NARROWED'` | yellow-200 `#fef08a` | `#a16207` | `5,3` (dashed) | 6 |
| 9 | `is_prerelease` | amber-100 `#fef3c7` | amber-700 `#b45309` | `2,2` (dotted) | 6 |
| 10 | Default / DECLARED | blue-200 `#bfdbfe` | blue-700 `#1d4ed8` | solid | 6 |

**Notes:**
- CVE takes highest visual priority — a CVE-affected OVERRIDE node renders red, not orange.
- Unpublished (entire package removed from registry) takes priority over yanked (single version retracted).
- OVERRIDE and PINNED share an orange family but differ by stroke pattern (dash-dot vs solid thick) and shade (orange-200 vs orange-100).
- Deprecated and NARROWED share the same stroke color (`#a16207`) but differ in fill (yellow-100 vs yellow-200) and dasharray.
- PINNED falls back to `isPinned(version_defined)` (bare semver heuristic) for pre-v1.2 reports. NARROWED has no such fallback.

### Node with CVEs

Any node whose package has `severity` set gets the CVE visual treatment on top of its circle:

- Circle: red-200 fill `#fecaca`, red-600 stroke `#dc2626`, solid, r=6
- **Warning triangle badge**: SVG `<polygon>` at `translate(-22, 0)`, points `0,-9 8,5 -8,5`
  - Fill `#fdba74` (orange-300), stroke `#ea580c` (orange-600), 1.5 px
  - Bold `!` glyph, fill `#7c2d12` (orange-900), `font-size: 9px`

### Solid-fill state (focus)

When a node is clicked it switches to a **solid** appearance — fill equals its stroke color.
The stroke pattern (`stroke-dasharray`) is retained so constraint type stays readable. Both the
primary (clicked) node and same-version duplicates receive this treatment.

| Node type | Solid fill |
|---|---|
| CVE (red) | `#dc2626` |
| Unpublished | `#b91c1c` |
| Yanked | `#7e22ce` |
| Deprecated | `#a16207` |
| OVERRIDE (orange) | `#ea580c` |
| ADDITIVE (green) | `#16a34a` |
| PINNED (orange) | `#c2410c` |
| NARROWED (yellow) | `#a16207` |
| Prerelease (amber) | `#b45309` |
| Default/DECLARED (blue) | `#1d4ed8` |

Logic lives in `resolveNodeStyle` in `src/explorer/nodeStyle.ts`.

---

## Visual Badges

### CVE Warning Triangle

Nodes with `severity` set render an orange triangle badge to the left of the circle
(`translate(-22, 0)`, points `0,-9 8,5 -8,5`) with a bold `!` glyph.
Colors: fill `#fdba74`, stroke `#ea580c`, text `#7c2d12`.

### Yanked Version Badge

Nodes where `is_yanked` is true render a filled purple circle badge to the right
(`translate(+18, 0)`, r=6) with a bold `✕` glyph in white (`font-size: 8px`).
Fill: `#7e22ce` (purple-800). Composable with the CVE triangle — a yanked CVE node shows both.

### `↩` Ancestor-Ref Badge

In navigated views, nodes whose package name appears anywhere in the navigation breadcrumb
(i.e., the package is an ancestor view) render a small `↩` glyph centered above the circle
(`dy: -1.6em`, `font-size: 9px`). The badge is full opacity only when the node is the primary
focus target; otherwise it fades to 0.3 opacity. Badge color tracks the node's stroke color.

---

## Collapsed Branch Indicator

When a branch is folded via Alt+Click:
- Circle grows to `r=8` (`radiusCollapsed`) regardless of constraint type
- Fills with its semantic stroke color (solid dark)
- Retains its `stroke-dasharray` pattern

---

## Edge Types

### Tree Edge (`.link`)

Solid horizontal bezier paths connecting a parent node to each of its children.
Also has a 12 px transparent `.link-hit` overlay for easier clicking.

**Normal state** (no focus active):

| Target node condition | Edge color |
|---|---|
| Has CVE (`severity` set) | light red `#fecaca` (red-200) |
| `version_defined` contains `<` or is bare semver | light orange `#fed7aa` (orange-200) |
| Default | slate `#cbd5e1` (CSS default) |

**Focus state — ancestor path** (edge leads toward the root from the focused node):

| Target node condition | Color | Width |
|---|---|---|
| Has CVE | `#fca5a5` (red-300) | 3 px |
| `version_defined` contains `<` or is bare semver | `#fed7aa` (orange-200) | 3 px |
| Default | `#1d4ed8` (blue-700) | 3 px |
| Not on any path | CSS default | `opacity: 0.15` |

**Focus state — descendant path** (edge leads away from the focused node):

| Target node condition | Color | Width |
|---|---|---|
| Has CVE | `#fca5a5` (red-300) | 3 px |
| `version_defined` contains `<` or is bare semver | `#fed7aa` (orange-200) | 3 px |
| Default | `#97c2f7` (blue-400) | 3 px |

All tree link styles are applied via `.style()` (inline) so they take precedence over
Vue `:deep(.link)` CSS rules. Passing `null` restores the CSS default.

### Same-Version Dashed Link (`.link-same-version`)

Curved quadratic bezier arcs connecting nodes that share an identical `name@version_installed`
across different subtrees. Each arc is rendered as two stacked paths:

- **Visual** (`.link-same-version`): slate-400 `#94a3b8`, 1 px, `stroke-dasharray: 4 6`, 30% opacity
- **Hit target** (`.link-same-version-hit`): 12 px transparent — makes clicking easy

**Focus state**:
- Arc for the focused package: orange `#f97316`, 3 px, 85% opacity — still dashed
- All other arcs: `opacity: 0.1` (dimmed)

Clicking either the arc or its hit target focuses the source endpoint node (same as clicking
the node directly). Full teardown-rebuild on each tree render.

### Aggregate Link (`.link-aggregate`)

Curved dashed arcs drawn from visible dep nodes to Super Nodes (or the phantom root in
navigated views) that contain them as hidden children, providing cross-tree context without
expanding the subtree. Full teardown-rebuild on each tree render.

**Three routing cases** (evaluated per edge in `renderAggregateLinks.ts`):

1. **Same-branch** (source and target Super Node share the same depth-1 ancestor): arc is drawn directly from the visible dep to the Super Node.
2. **Cross-branch, but the Super Node already has a same-branch visible dep**: arc is skipped — the same-version dashed link already connects the two occurrences and a second arc would be redundant.
3. **Cross-branch, no same-branch dep**: arc is drawn between depth-1 ancestors (e.g. `root>A → root>B`) and the source-count badge shows how many underlying deps are bundled.

**Phantom root** (navigated views only): leaf nodes that also appear as children of other
direct deps in the outer tree get individual arcs to a phantom root node one column left of
the current root.

**Single arc** (count = 1):
- Stroke: slate-400 `#94a3b8`, 1.5 px, `stroke-dasharray: 6,3`, 50% opacity

**Bundle arc** (count > 1):
- Stroke: slate-400 `#94a3b8`, 2.5 px, `stroke-dasharray: 8,3`, 65% opacity

Both variants include a `(N)` count badge at the arc midpoint (`font-size: 7px`) and a
10 px transparent `.link-aggregate-hit` overlay. Clicking focuses the arc's anchor node
(the visible dep for same-branch arcs; the depth-1 ancestor for cross-branch arcs).

**Focus state**:
- Arc anchored on the focused node: orange `#f97316`, 3 px, 85% opacity
- All other arcs: `opacity: 0.1` (dimmed)

When an aggregate arc is highlighted, its target node and the full ancestor path to that
target are also added to the highlight state (`ancestorKeys` / `treeLinkTargetKeys`), so the
path from the focused dep back through the Super Node to root is lit up.

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
| **Descendant** | All children/grandchildren of primary and secondary nodes | Normal semantic pastel fill (not solid), full opacity |
| **Super Node (dimmed)** | Any Super Node not on an ancestor or descendant path | `opacity: 0.15` |
| **Other nodes** | Any node not in the above categories | `opacity: 0.15` |

Descendant nodes keep their pastel fill (not solid), visually distinguishing them from the
selected primary/secondary nodes even though both are full opacity.

### Edge behavior in focus mode

| Edge | On ancestor path | On descendant path | Otherwise |
|---|---|---|---|
| Tree edge | 3 px, full opacity, semantic color | 3 px, full opacity, semantic color | `opacity: 0.15` |
| Same-version dashed link | orange `#f97316`, 3 px, 85% opacity (focused package) | — | `opacity: 0.1` |
| Aggregate link | orange `#f97316`, 3 px, 85% opacity (anchor is focused) | — | `opacity: 0.1` |

Clicking the SVG background exits focus mode and restores all nodes and edges to their
default state.

---

## Navigation Stack

The Explorer supports navigating **into** the subtree of any Super Node, building a
breadcrumb stack managed by `src/composables/useNavigationStack.ts`.

### How navigation works

1. **Enter**: clicking a Super Node calls `onFoldedNodeExpand`, which pushes a `NavFrame`
   onto the stack and rebuilds the tree rooted at that package's children.
2. **Breadcrumb**: the toolbar shows the current path (project → package → …). Clicking any
   ancestor in the breadcrumb jumps (`jumpTo`) back to that level.
3. **Back edge**: in navigated views, a dashed line is drawn from a phantom root circle
   (one column left of the current root) to the current root node. Clicking the line or
   the phantom circle calls `onNavigateBack`.

### Phantom root node

The phantom root is a virtual node rendered in navigated views:
- Circle: r=6, default fill `#bfdbfe` / stroke `#1d4ed8`, `stroke-dasharray: 4,2`
- Label: `actualProjectName` right-aligned at `x=-12` (left of the circle)
- Back edge: dashed horizontal line, slate-400 `#94a3b8`, 2 px, `stroke-dasharray: 8,4`, 60% opacity, 14 px transparent hit target

### Depth-1 margin

When navigated, the tree layout shifts right by one column width (`marginLeft + nodeSize[1]`)
to leave room for the phantom root column.

### `_isAncestorRef` flag

Nodes whose package name matches any frame in the current breadcrumb get `_isAncestorRef: true`
in `buildD3DataFromVisibleState`. These nodes render the `↩` badge (see [Visual Badges](#visual-badges)).

---

## Interactions

| Gesture | Action |
|---|---|
| **Click** a regular node | Enters focus mode; opens sidebar panel |
| **Click** a Super Node | Navigates into that package's subtree (pushes to nav stack) |
| **Alt+Click** a regular node with children | Folds / unfolds subtree (500ms animated) |
| **Click** a same-version dashed link | Identical to clicking the source endpoint node |
| **Click** a tree edge | Identical to clicking the child (target) endpoint node |
| **Click** an aggregate link | Focuses the arc's anchor node |
| **Click** phantom root / back edge | Navigates back one level in the breadcrumb stack |
| **Click** SVG background | Exits focus mode; restores all highlights; closes sidebar |
| `selectNodeByName(name)` | Programmatically focuses a node by package name; called from `DependencyDetailPanel` via `@select-node` |

Tree edges and aggregate links have transparent hit-target overlays (12 px and 10 px respectively).

---

## Toolbar Controls

The toolbar (top-right) contains the search field, filter toggles, a **Clear** button, and an **Info** button.

### Clear filters button

Appears automatically whenever any search query or toggle filter is active. Clicking resets
`searchQuery`, `filterCve`, `filterNarrowed`, and `filterOverridePinned` to defaults in one
action. Hidden when no filters are active.

Implemented via `hasActiveFilters` (computed) and `clearFilters()` in `useTreeFilters`.

### Legend panel (Info button)

The `ℹ` icon button toggles a floating legend card (`showLegend` ref). The card contains:

1. **Node colors** — color swatches matching `TREE_CONFIG.colors`, one row per rule
2. **Interactions** — edge click, dashed-line click, Alt+Click, background click
3. **Duplicate packages** — explains same-version dashed links

Legend circles in `ReportLegend.vue` use `constraintCircleClasses()` from `src/explorer/nodeStyle.ts`,
so they stay in sync with the tree automatically.

---

## Search & Filters

All filter logic lives in `src/composables/useTreeFilters.ts`; the D3 rendering layer is
unaware of filtering.

### Search (Fuse.js)

Fuzzy-matches against all package names (threshold `0.35`, min 2 chars). Tree is re-evaluated
**50 ms after the last keystroke** (debounced). Only branches containing at least one name
match are shown; ancestors of matching nodes are preserved to maintain the path to root.

### Toggle filters

| Button | Condition | Active color |
|---|---|---|
| **CVE** | `severity` set | red `#DE4514` |
| **Narrowed** | `constraint_type === 'NARROWED'` or `version_defined` contains `<` | yellow `#a16207` |
| **Override/Pinned** | `constraint_type === 'OVERRIDE'` or `constraint_type === 'PINNED'` or `version_defined` matches bare semver | orange `#ea580c` |

Multiple active toggles use **OR** logic. When both search and toggles are active, **AND** logic applies.

### Adding a new filter

Only `useTreeFilters.ts` needs to change:
1. Add an entry to `TOGGLE_FILTERS` with a `key` and `test` predicate.
2. Add a `ref(false)` and expose it in the return value.
3. Register it in `toggleMap`.
4. Add the toggle button in `TransitiveDependenciesView.vue`.

`pruneTree` and `buildPredicate` are untouched.

---

## Same-Version Links

Nodes sharing an identical `name@version_installed` across different subtrees are connected
by curved dashed quadratic bezier arcs (control point offset: min of `bezierOffsetMax=120` and
max of `bezierOffset=40` vs `distance × bezierOffsetScale=0.15`).

Each link is two stacked SVG paths:
- **Visual** (`.link-same-version`): dashed `#94a3b8`, 1px, 30% opacity, `stroke-dasharray: 4 6`; when highlighted: orange `#f97316`, 3px, 85% opacity
- **Hit target** (`.link-same-version-hit`): 12px transparent stroke

---

## Tree Structure Rules

- **Duplicates allowed**: the same package can appear in multiple subtrees simultaneously
- **Cycle detection**: a dependency is skipped only if it is its own ancestor (true cycle), not just a repeat
- **Unique D3 keys**: nodes are keyed by their full ancestor path (`root>react>lodash`) to prevent D3 enter/update/exit corruption for duplicate packages

---

## Zoom & Resize

- Pan and zoom via D3's built-in zoom behavior, `scaleExtent: [0.1, 3]`
- Cursor switches to `grabbing` while panning
- Zoom buttons (+/−/1:1) at **bottom-right** of the canvas
- `zoomIn()` / `zoomOut()` scale by ×1.3; `resetZoom()` returns to scale 1
- Window `resize` events update SVG dimensions and re-center the root group

---

## CSS vs D3 Styling Note

Vue's `:deep(.link)` and `:deep(.link-same-version)` rules define `stroke`, `stroke-width`,
and `opacity` as **CSS properties**. SVG presentation attributes set via D3's `.attr()` are
overridden by CSS. All dynamic style mutations in `applyTreeLinkStyles`,
`applySameVersionLinkStyles`, and `applyAggregateLinkStyles` therefore use `.style()` (inline
styles), which take precedence over stylesheet rules. Passing `null` removes the override and
restores the CSS-defined default.
