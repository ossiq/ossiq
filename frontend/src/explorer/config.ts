export const TREE_CONFIG = {
  layout: {
    nodeSize: [60, 300] as [number, number],
    marginLeft: 50,
    densityThreshold: 10,
    maxNodeSpacing: 90,
  },
  zoom: {
    scaleExtent: [0.1, 3] as [number, number],
    stepFactor: 1.3,
    transitionDuration: 300,
  },
  animation: {
    nodeTransition: 500,
    linkTransition: 500,
    fadeDuration: 120,
  },
  node: {
    radiusDefault: 6,
    radiusCollapsed: 8,
    strokeWidth: 2,
    strokeWidthHighlighted: 3.5,
    opacityDimmed: 0.15,
  },
  colors: {
    // Base node states (first-match-wins in NODE_COLOR_RULES)
    cveFill: '#fecaca',      // red-200
    cveStroke: '#dc2626',    // red-600
    pinnedFill: '#ffedd5',   // orange-100
    pinnedStroke: '#c2410c', // orange-700
    // Constrained: NARROWED (explicit range with bounds — >=x <y, ~=x, ==x.*, compound)
    ubcFill: '#fef08a',          // yellow-200  (legacy alias — same as narrowedFill)
    ubcStroke: '#a16207',        // yellow-700  (legacy alias — same as narrowedStroke)
    narrowedFill: '#fef08a',     // yellow-200
    narrowedStroke: '#a16207',   // yellow-700
    // Constrained: ADDITIVE (narrows range via constraints file)
    constrainedFill: '#bbf7d0',  // green-200
    constrainedStroke: '#16a34a', // green-600
    // Constrained: OVERRIDE (forces version regardless of other requirements)
    overriddenFill: '#fed7aa',   // orange-200
    overriddenStroke: '#ea580c', // orange-600
    // Unpublished — entire package removed from the registry (higher priority than yanked)
    unpublishedFill: '#fee2e2',      // red-100
    unpublishedStroke: '#b91c1c',    // red-700
    // Deprecated — package/version marked deprecated by publisher
    deprecatedFill: '#fef9c3',       // yellow-100
    deprecatedStroke: '#a16207',     // yellow-700
    // Yanked — version was retracted by the publisher
    yankedFill: '#f3e8ff',       // purple-100
    yankedStroke: '#7e22ce',     // purple-800
    // Prerelease — installed version is alpha/beta/rc
    prereleaseFill: '#fef3c7',   // amber-100
    prereleaseStroke: '#b45309', // amber-700
    defaultFill: '#bfdbfe',      // blue-200
    defaultStroke: '#1d4ed8',    // blue-700
    // Highlight overrides
    primaryFill: '#dbeafe',   // blue-100
    primaryStroke: '#1d4ed8', // blue-700
    secondaryFill: '#fef3c7', // amber-100
    secondaryStroke: '#d97706', // amber-600
    ancestorLinkStroke: '#1d4ed8', // blue-700
    // CVE warning triangle
    cveIndicatorFill: '#fdba74',   // orange-300
    cveIndicatorStroke: '#ea580c', // orange-600
    cveIndicatorText: '#7c2d12',   // orange-900
    // Same-version dashed links
    dashedLinkDefault: '#94a3b8',              // slate-400
    dashedLinkHighlighted: '#2563eb',          // blue-600
    dashedLinkDuplicateHighlighted: '#f97316', // orange-500 — dashed links between focused duplicates
    // Tree edge semantic coloring (normal state — always visible)
    cvePathLinkStrokeNormal: '#fecaca',        // red-200   — edge leads to CVE node
    pinnedUbcPathLinkStroke: '#fed7aa',        // orange-200 — edge leads to pinned/UBC node
    // Ancestor path edges in focus mode
    cvePathLinkStroke: '#fca5a5',              // red-300   — focused ancestor path, CVE present
    // Descendant path edges in focus mode
    descendantLinkStroke: '#97c2f7',           // blue-400 — default descendant path edges
  },
  sameVersionLink: {
    bezierOffset: 40,          // minimum perpendicular offset (px) for quadratic bezier control point
    bezierOffsetScale: 0.15,   // scales offset with node-pair distance when distance is large
    bezierOffsetMax: 120,      // cap so curves don't extend too far on very long spans
    hitTargetWidth: 12,        // transparent overlay for easier clicking
    opacityHighlighted: 0.85,
    opacityDimmed: 0.1,
  },
  foldedNode: {
    // Radius tiers keyed by hidden child count
    radiusSmall:  10,  // hiddenChildCount ≤ 10
    radiusMedium: 12,  // hiddenChildCount 11–50
    radiusLarge:  14,  // hiddenChildCount > 50
    // Fill colors (pastel)
    fillSmall:   '#e0e7ff',  // indigo-100
    fillMedium:  '#fed7aa',  // orange-200
    fillLarge:   '#fecaca',  // red-200
    // Stroke colors (dark)
    strokeSmall:  '#4338ca', // indigo-700
    strokeMedium: '#ea580c', // orange-600
    strokeLarge:  '#dc2626', // red-600
    strokeDash:   '4,2',
    strokeWidth:  2,
    badgeFontSize: '8px',
  },
  aggregateLink: {
    bezierOffset: 220,
    stroke: '#818cf8',            // indigo-400
    strokeHighlighted: '#4f46e5', // indigo-600
    strokeDash: '6,3',
    strokeWidth: 1.5,
    hitTargetWidth: 10,
    opacityNormal: 0.5,
    opacityDimmed: 0.1,
    bundleStroke: '#6366f1',      // indigo-500 — slightly darker than single arcs
    bundleStrokeWidth: 2.5,
    bundleStrokeDash: '8,3',
    bundleOpacity: 0.65,
    bundleBadgeFontSize: '7px',
  },
} as const
