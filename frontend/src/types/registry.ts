import type { CVEInfo } from './report'

export type ConstraintType = 'DECLARED' | 'NARROWED' | 'PINNED' | 'ADDITIVE' | 'OVERRIDE'
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface EdgeData {
  ct: ConstraintType
  version_constraint?: string
  dependency_name?: string
  extras?: string[]
}

export interface RegistryEntry {
  id: number
  package_name: string
  installed_version: string
  latest_version: string | null
  time_lag_days: number | null
  releases_lag: number | null
  cve: CVEInfo[]
  severity: Severity | null
  constraint_source_file?: string
  repo_url: string | null
  homepage_url: string | null
  package_url: string | null
  license: string[] | null
  purl: string | null
  is_yanked: boolean
  is_prerelease: boolean
  childEdges: Map<number, EdgeData>
}

export interface DirectEntry {
  package_name: string
  installed_version: string
  latest_version: string | null
  time_lag_days: number | null
  releases_lag: number | null
  cve: CVEInfo[]
  severity: Severity | null
  constraint_type: ConstraintType | null
  constraint_source_file: string | null
  version_constraint: string | null
  is_yanked: boolean
  is_prerelease: boolean
  childRefs: Array<{ ref: number; edgeData: EdgeData }>
}

export interface PackageRegistry {
  byId: Map<number, RegistryEntry>
  directEntries: Map<string, DirectEntry>
  constraintTypeMap: string[]
}

export interface VisibleNode {
  key: string
  registryId: number | null
  directName: string | null
  depth: number
  isFolded: boolean
  hiddenChildCount: number
}

export interface VisibleEdge {
  sourceKey: string
  targetKey: string
  edgeData: EdgeData
  isAggregate: boolean
}

export interface VisibleState {
  nodes: Map<string, VisibleNode>
  edges: VisibleEdge[]
  rootKey: string
  maxDepth: number
  projectName: string
  isNavigated: boolean
  actualProjectName: string
}

/**
 * One entry in the navigation stack. Represents the "root" of a navigated sub-tree view.
 * Exactly one of registryId / directName is non-null, mirroring VisibleNode identity fields.
 */
export interface NavFrame {
  label: string              // package_name — display label for breadcrumb
  registryId: number | null  // non-null when navigated root is a transitive package
  directName: string | null  // non-null when navigated root is a direct production dep
}
