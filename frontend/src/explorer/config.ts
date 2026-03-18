export const TREE_CONFIG = {
  layout: {
    nodeSize: [60, 220] as [number, number],
    marginLeft: 100,
  },
  zoom: {
    scaleExtent: [0.1, 3] as [number, number],
    stepFactor: 1.3,
    transitionDuration: 300,
  },
  animation: {
    nodeTransition: 500,
    linkTransition: 500,
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
    cveFill: '#fde68a',      // amber-200
    cveStroke: '#d97706',    // amber-600
    pinnedFill: '#fef08a',   // yellow-200
    pinnedStroke: '#a16207', // yellow-700
    ubcFill: '#fecaca',      // red-200
    ubcStroke: '#dc2626',    // red-600
    defaultFill: '#bfdbfe',  // blue-200
    defaultStroke: '#1d4ed8', // blue-700
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
    bezierOffset: 40,        // perpendicular offset (px) for quadratic bezier control point
    hitTargetWidth: 12,      // transparent overlay for easier clicking
    opacityHighlighted: 0.85,
    opacityDimmed: 0.1,
  },
} as const
