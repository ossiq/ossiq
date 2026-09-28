# CHANGELOG



## v0.1.12 (2026-09-28)


### Fix

* fix: fixed binary name for the OSS IQ quality gate (GH-122) ([`85b9f88`](https://github.com/ossiq/ossiq/commit/85b9f8827a2e2235aa75a352ff67f4afd27f6514))

* fix(release): draft the release so binaries attach before it locks (GH-122) ([`6f2e598`](https://github.com/ossiq/ossiq/commit/6f2e598ac6dad9810a647361b048a32e9c30ee68))
Release immutability refused the v0.1.11 binaries because the
release was created already published, so release.py now drafts it,
publishing hangs off the version tag push, and binaries.yml
publishes the draft once the assets are attached. npm publish also
gets ./-prefixed paths, since npm read npm/<file>.tgz as a GitHub
shorthand and refused it with EALLOWGIT.


### Chore

* chore: fixed line endings ([`80b2eef`](https://github.com/ossiq/ossiq/commit/80b2eef29e626c53182f8b3a62c46c59bcf6a219))

## v0.1.11 (2026-09-28)


### Feature

* feat(release): sign SLSA Build L3 provenance for every published artifact (GH-122) ([`de658f9`](https://github.com/ossiq/ossiq/commit/de658f977e9915081ad10be3699a180a9cf9093b))
Builds move into new reusable workflows (reusable-build-dist/binaries/npm)
so provenance is signed under an identity the calling workflow cannot forge;
release.yml and binaries.yml now only download those attested artifacts,
verify them with gh attestation verify, and publish, never build. npm
publish order (platform packages before the launcher) now comes from a
manifest.json build_npm_packages.py writes, rather than a directory glob.

* feat(packaging): stop shelling out to npm at package time (GH-122) ([`04836d1`](https://github.com/ossiq/ossiq/commit/04836d1f65d5c63c4676ff72d014e6e7c3b4278a))
The hatchling build hook ran npm install/build whenever npm happened to be on
PATH, making uv build network-dependent and leaving a regenerated template in
src/; it now only verifies the committed spa_app.html is present and
non-empty, and just frontend-build is the one place that regenerates it.
just build now also passes --no-build-isolation so it resolves hatchling from
uv.lock instead of a fresh PEP 517 install.

* feat(ci): fail the build when frontend/ changes without a regenerated template (GH-122) ([`4a90e2d`](https://github.com/ossiq/ossiq/commit/4a90e2d49a348b63e6da287ebacad1764d6fd49d))
spa_app.html is committed and packaging only ever reads it, so a frontend/
change that skips `just frontend-build` would silently ship a stale report.
The new job compares which paths a pull request touched, so it needs no
Node or build step of its own.

* feat(html): regenerate report types for the export profiles (GH-143) ([`272dbca`](https://github.com/ossiq/ossiq/commit/272dbca35a8261fa8fbd396e0e9392eec7621aa0))
The SPA's report types pick up the new optional export fields and
the provided engine source, and the report template is rebuilt.

* feat(cli): add export --full (GH-143) ([`25743ae`](https://github.com/ossiq/ossiq/commit/25743aea799f2d027061d2c97643d4f467a15299))
ossiq export writes the standard profile unless --full is given, and
names the profile in its settings panel.

* feat(export): add standard and full export profiles (GH-143) ([`ceb4868`](https://github.com/ossiq/ossiq/commit/ceb48681bc65109c81a7f72b2ff2e9a537e318bf))
The default standard profile keeps every direct dependency, the
transitives that need attention and decision fields only; full keeps
everything, and each has its own schema, held in step by a test
over the fields tagged full-only. Both gain CVE ranges and fixes,
transitive recommendations and roots, the runtime pin mismatch,
ignored packages, upgrade paths and the provided engine source.
The HTML report always embeds the full profile.

* feat(html): show the module-line ladder row and dependency_health_action (GH-143) ([`e97636b`](https://github.com/ossiq/ossiq/commit/e97636bbfed2d0071670d02fd4a1f91877fa33b9))
The SPA reads the renamed field, adds a Same module system rung and
the ESM note to the version ladder, and the report template is
rebuilt.

* feat(export): add module-line fields, rename triage_action (GH-143) ([`14fe6f5`](https://github.com/ossiq/ossiq/commit/14fe6f575ad6e3bce26909b755f2c2d478fb5293))
Export and console show latest_preserving_module_system,
module_system_note and the runtime pin mismatch. triage_action
becomes dependency_health_action in schema 1.5, which is unreleased.

* feat(mcp): require a runtime on MCP tools and add --engine to the CLI (GH-143) ([`4a0e33b`](https://github.com/ossiq/ossiq/commit/4a0e33b27d5f2978dbfe634652c3f6021e0433c5))
The three scanning MCP tools require runtime (an object or
"unknown") and never probe the server's own PATH. The CLI keeps
probing by default, and --engine ENGINE=VERSION states the runtime
instead.

* feat(strategy): add compare_target to judge a proposed update target (GH-143) ([`569ba93`](https://github.com/ossiq/ossiq/commit/569ba93d7d35282f252f762b957b907b0cfd6cc5))
Return a verdict (recommended, suboptimal, breaking, vulnerable,
deprecated, beyond_recommendation) with reasons and the better
version to take. It compares against recommended_version and never
picks a target itself.

* feat(runtime): let a stated runtime replace the PATH probe (GH-143) ([`59a8ce5`](https://github.com/ossiq/ossiq/commit/59a8ce5126fb002d47f0fafec2c2bb4068e6b7f8))
detect_engine_context takes a provided runtime that replaces the
probe but is still held to the manifest floor. A project pin that
disagrees with the runtime becomes a RuntimeMismatch value, and
settings_with_stated_runtime turns an MCP runtime argument into
settings.

* feat(runtime): add caller-stated runtime types and runtime pins (GH-143) ([`bd11813`](https://github.com/ossiq/ossiq/commit/bd11813597a6bb4d4ccfb3aea2bddcd04f103b04))
Add ProvidedRuntime, RuntimeMismatch, the PROVIDED engine source and
the Runtime Not Provided / Invalid Runtime errors. Settings carries
the stated runtime next to probe_runtime, and
sources/runtime_pins.py reads the version pins a project keeps
(.nvmrc, .tool-versions, mise.toml, volta, .python-version, .venv).

* feat(scan): name the packages a scan could not assess, and why (GH-127) ([`e3ad73c`](https://github.com/ossiq/ossiq/commit/e3ad73c0dd01994920892828148bee49f61a56d9))
SignalCoverage records whether each package's upstream signals were readable and
what stopped them - no repository, a non-GitHub host, a repository that returned
nothing, or a commit history that did not - so "7 unassessed" can name its seven.
RejectionDetail splits a rejection headline from its specs so a console table can
elide a dozen version strings instead of widening its first column, and
GITHUB_URL_RE no longer truncates a repository name at the first dot, which had
been 404ing every repo like `mustache.js`.

* feat(github): report why a source degraded and what quota is left (GH-127) ([`30e2f1e`](https://github.com/ossiq/ossiq/commit/30e2f1eeb80e16af9f7cca7a4d0cf02824fdfac6))
A bare `partial` could not tell three renamed repositories from an exhausted
quota, so fetches now carry a DegradeReason count and the rate-limit headers
they saw, surfaced in the console warning, agent/MCP payload and export. A free
/rate_limit pre-flight warns before a scan starts spending a quota too thin to
cover it.

* feat(strategy): withhold an update that is still inside its cooldown (GH-127) ([`7b7b296`](https://github.com/ossiq/ossiq/commit/7b7b296f4ccf7fe26d7936abf5229b0d2443c5be))
select_target now drops candidates younger than the cooldown period and reports
a CooldownHold when that leaves no target, so status stops promising an update
that apply would refuse. An exploitable CVE or end-of-life package bypasses the
wait and marks the pick cooldown_bypassed.

* feat(cli): refuse a security-tier answer built on missing vulnerability data ([`a1e4021`](https://github.com/ossiq/ossiq/commit/a1e402101695c6f06ddc6cdbe7c380ac0d2bd6ef))
--update-strategy security and deprecation move a package only on a qualifying
CVE or end-of-life marker. With OSV unreachable they find no motive anywhere and
print "No packages need updates under --update-strategy security — nothing to
do." — character for character what a clean project prints. The stderr warning
and data_completeness both said so, but nothing stopped the empty result being
read as an all-clear.
status, plan, export and the MCP evaluate_updates tool now refuse that answer:
non-zero exit with a titled SecurityDataIncomplete error on the CLI, the same
error as a payload over MCP. --allow-partial / allow_partial opts back in.
Deliberately narrow, because docs/recommendations.md §3 says ossiq status is not
a CI gate and any gate belongs in the consumer's own check over the export. This
is not a gate but a refusal to answer, and only for the two tiers whose result
goes empty rather than thin. Freshness tiers still exit 0 on a degraded run, and
a degraded repositories step is never grounds for refusing — GitHub thins
deprecation's coverage rather than emptying its result.
The rule lives in service/completeness.py so both front doors apply one
definition. Verified with OSV pointed at a dead host: security exits 1 and MCP
returns isError, --allow-partial and standard exit 0.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* feat(engines): check engines.npm, which nothing ever evaluated ([`56a29ab`](https://github.com/ossiq/ossiq/commit/56a29ab41ba0ad158aec2d9389a7ae0e7d273b71))
A release declaring `engines.npm` was unenforced by two independent routes.
engine_version_satisfies_requirement dispatched only python and node and
returned True for every other key; and engine_mismatch_reason iterates context
keys, while the context only ever carried node (probed) or the manifest's node
floor (declared). So neither half of the check could reach an npm requirement,
however far the installed CLI was from it.
npm, pnpm and yarn now dispatch through the npm semver matcher — they share one
range grammar with node. detect_actual_npm_cli_version was already being called
for display; its result now also enters the context. declared_engine_floors
replaces the inline node-only parse, so the --no-probe-runtime path carries the
same keys.
The npm probe deliberately does not select `detected` on its own: an npm-only
context would discard the project's declared node floor, which on a failed Node
probe is the only thing left to check against.
pnpm and yarn are dispatchable but unprobed, so they are checked only against a
declared floor. Documented rather than papered over.
Swept testdata/npm/* before and after: no new mismatches fire against npm 12.0.2,
and the agent payload now reports engine_versions {node, npm}.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* feat(report): draw the degraded-data banner the HTML report was missing ([`f3c5cfe`](https://github.com/ossiq/ossiq/commit/f3c5cfeabce3e13e9d70c0afbaed36e8f676f77f))
metadata.data_completeness was embedded in every HTML report and declared in the
generated TypeScript, but a grep across frontend/src found the type declaration
and nothing else — so an HTML report built on a rate-limited or firewalled scan
looked exactly like a clean one. metadata.warnings had no reader either.
New ReportBanner component, drawn above the table only when a source did not
come back ok or a warning was recorded. It names each degraded source with the
host it stands for (OSV.dev, GitHub, api.first.org) and what its status means,
since "partial" alone does not tell a reader what they have lost.
Verified against a report built with the OSV host unreachable: the payload
carries overall=unreachable and the banner is in the bundle.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* feat(export): carry next_action and requires_constraint_widening ([`5107276`](https://github.com/ossiq/ossiq/commit/5107276804caccbf4beaf3e43de2834eb49866e5))
Both are derived from data already on the record, but every consumer had to
re-derive them — and the HTML report's copy of the next-action rules had
drifted. Exporting them makes next_action_label the single writer.
next_action declares an enum of the six labels, so the generated TypeScript
union is the label set rather than a second list maintained by hand.
Amended into export_schema_v1.5.json in place, both optional and neither in
required; README.md now records that exception and when it expires.

* feat(ui): show the version ladder in the info Policy Compliance block ([`9a37128`](https://github.com/ossiq/ossiq/commit/9a371287fa07a702498e5795ca816a4563765f62))
The block named the declared constraint, the installed version, the latest
and the recommendation — plus a "requires widening" caveat pointing at a
ladder it never showed. It now lists In Range / In Major / Compatible Major
between Resolved and Latest, and marks the rung the recommendation came from.
A rung equal to the installed version is rendered dimmed rather than dropped:
"nothing to do" is an explicit equality here, never a missing row. Compatible
Major is omitted only when it restates In Major, i.e. when no known break
sits in between.

* feat: update-context command and MCP tool; consolidate CLI strategy options ([`c34643c`](https://github.com/ossiq/ossiq/commit/c34643c6a0617cbe4fe2bd92450e346990bcf1fc))
New `ossiq update-context` command and `ossiq_update_context` MCP tool: diff
a package's installed (or prospective) version against an arbitrary target
version — module-system/API breaking changes, engine (Node/Python)
compatibility against the detected or declared runtime, and structural
rejections along the way. Unlike `recommended_version`, the target need not
be OSS IQ's own pick, so an agent can ask "what changes if I go to 6.0.0"
before applying an update to a version other than the recommended one. Both
front doors call the same service.update_context.build_update_context_payload,
which itself is built from the service.agent.build_update_context /
service.package.build_installed_detail helpers.
Alongside it, consolidate the six CLI commands (status/html/export/info/plan/
apply) that each hand-declared `--update-strategy`/`--strategy-override` and
re-derived the same parse-then-validate sequence: UpdateStrategyOption /
StrategyOverrideOption are now declared once and reused, and
cli.resolve_strategy() replaces the per-command parse_update_strategy /
parse_strategy_overrides / check_strategy_override_ignore_conflict sequence
with one call. `ossiq status --allow-partial` is dropped along with it.
commands/plan.py gains confirm_acknowledged(), replacing the
widening-only confirmation prompt: a pick now needs explicit
acknowledgement if it widens the declared constraint *or* carries a known
API/module-system break, since a break can sit inside the declared range and
previously skipped the second look entirely.

* feat: added runtime probe and engine constraints (GH-127) ([`4c266bf`](https://github.com/ossiq/ossiq/commit/4c266bf13a82bcf774e34cee673c77207df7cb4c))

* feat: added breaking change concept for NPM and bit of python (GH-127) ([`5507b85`](https://github.com/ossiq/ossiq/commit/5507b85a7e3922f1972b8c80d57cb169c10ae3bd))
There was a specific case when a package switched module system
and it caused a wrong suggestion. Now it detects such kind of
changes and corrects recommendations.

* feat: PEP621 support (no lockfile), version constraint LWW (GH-127) ([`ec48d3b`](https://github.com/ossiq/ossiq/commit/ec48d3b9bfef929c068ee2b83c73bc0b4ef86442))
Added bare pyproject.toml support (PEP 621) for python projects
and fixed constraint provenance (there was last-write-wins situation
for constraint - transitive dependency was able to override
direct dependency constraint).

* feat: integrated strategy into TUI, MCP/Skills and export (GH-127) ([`78a2d37`](https://github.com/ossiq/ossiq/commit/78a2d3788ffa02414bbcfdf01359f9a6228f3e25))
Integrated Update Strategy concept across all input
and output parameters/interfaces.

* feat: introduced update strategy concept (GH-127) ([`982a8b7`](https://github.com/ossiq/ossiq/commit/982a8b7abda7a4acf4f7a66329f3f69a019a8abe))
This is necessary step to fix many bugs which are
not bugs, but rather ambiguities between different
update strategies. With Update Strategy now there
are four distinct categories to express how
much risk user wants to take applying updates.

* feat: updated HTML report to show what's next (GH-60) ([`42171d2`](https://github.com/ossiq/ossiq/commit/42171d2ccbd9b988c1fccd1e57d8c7a4dd7a00c5))
Align HTML report with the CLI/SKILL.md output
to show what to do next with each dependency.

* feat: updated UI/UX, MCP and SKILL.md with repository stability (GH-60) ([`441dffc`](https://github.com/ossiq/ossiq/commit/441dffcb1f77d12d8d32c51449096d2931dea84d))
Updated console UI/UX to show clearly new action, changed
default report to show just what needs to be updated and
introduced --full mode to show the rest.
Also, updated SKILL.md template and changed lingo
from verdict to next_action to instruct clearly
what LLM needs to do next.

* feat: updated export schema fields to match CSI and EPSSg (GH-60) ([`25caf1b`](https://github.com/ossiq/ossiq/commit/25caf1ba3852ca6d9cc260d1d03f4838d19f986c))

* feat: wired CSI and EPSSg into HTML renderer (GH-60) ([`5d4d6a9`](https://github.com/ossiq/ossiq/commit/5d4d6a94005606baf1f9a7b9b565054d581ac915))

* feat: wired EPSSg and CSI into UI renderers (GH-60) ([`e9a4731`](https://github.com/ossiq/ossiq/commit/e9a4731c7a51f870186dce129a790ad9877b0757))

* feat: wired stability into respective service entities (GH-60) ([`6d23e5a`](https://github.com/ossiq/ossiq/commit/6d23e5a9ba4d2c08d2c6c42ee491b1a856ed0374))
Wired stability to properly fetch and propogate
data about CSI and interpret maintenance signals.

* feat: added github commits/readme/graphql pull (GH-60) ([`c7225e1`](https://github.com/ossiq/ossiq/commit/c7225e11da461155069ce07c7053a9c8b9cf732e))
Added new fetching logic to the github client
to pull PR/comments/commits/README.md as well
as updated batch logic to accomodate more
github API behavior.

* feat: refactored risk module to use CSI stability index (GH-60) ([`b0afb01`](https://github.com/ossiq/ossiq/commit/b0afb0110023815c14f8a5f177ee9c88d990c07e))
Refactored Health Score to use second metric
Composite Stability Index (CSI) with some additional
tweaks to accomodate Github requests budgets.

* feat: finished health score integration (GH-60) ([`0839fd5`](https://github.com/ossiq/ossiq/commit/0839fd58cd71cde2fef52dd631b52c19b25afd96))

* feat: added remaining health score related fields to the HTML report (GH-65) ([`fe90d49`](https://github.com/ossiq/ossiq/commit/fe90d499c13efc2cd1cc846fa8abd4427f42acd5))

* feat: updated frontend schema version/types and added fitness field (GH-65) ([`d7937db`](https://github.com/ossiq/ossiq/commit/d7937db38bba70f7eb0a7763e45ea6f34097e254))

* feat: expose health metrics via console UI (GH-65) ([`fdabf23`](https://github.com/ossiq/ossiq/commit/fdabf2302bd184cfc19d5322c14cefe85f65344a))

* feat: added 1.5 to the cli and integration tests (GH-65) ([`62c0003`](https://github.com/ossiq/ossiq/commit/62c000364d67aeff114ea17f4f363e17275ae984))

* feat: added CSV export version 1.5 (GH-65) ([`d3580bb`](https://github.com/ossiq/ossiq/commit/d3580bbc53f272c53244c28032761f764014082f))
Added new health score fields to the new
CSV export schema v1.5

* feat: added new 1.5 version for json schema (GH-65) ([`60f37af`](https://github.com/ossiq/ossiq/commit/60f37af9ca23c5ee151536322e4fd46709c1af06))
Added new JSON Schema 1.5 version for export to
JSON feature and wired all the health score metrics.

* feat: added new schema version for JSON export (GH-65) ([`d26267d`](https://github.com/ossiq/ossiq/commit/d26267de283a19ebf208779b5d81c24ee9ed2a4d))

* feat: integrated dependency tree packages metrics into project scan (GH-64) ([`2856174`](https://github.com/ossiq/ossiq/commit/2856174587bf45c2b579bcada3d77c9ce67d1a42))
Integrated calculation of currently implemented Health Score
metrics into ScanRecord in scan.py

* feat: Transitive dependencies aggregated counter (GH-64) ([`fadd414`](https://github.com/ossiq/ossiq/commit/fadd41476a5b1aa16e1bf0dc8bc67410e5848e19))
Aggregation graph walker to collect transitive
dependencies counts.

* feat: added impact, incident probability and expected exposure (GH-61) ([`c0b7fa2`](https://github.com/ossiq/ossiq/commit/c0b7fa2605efa77d911f1b4dfb339c18b5b9da5d))
Added few more components to the Health Score as well as
new input information in PackageVersion related to
pre/post install scripts execution or implicit dependencies
requires to build on the target machine (node gyp).

* feat: added P_vuln computation function and model fields (GH-100) ([`8f898bc`](https://github.com/ossiq/ossiq/commit/8f898bc8eef18ca6893e53f8dc9e2b8ac9eb3940))
Compute the probability that a known vulnerability gets
exploited against the installed package over
a 365-day horizon, from EPSS and the Exposure Window
Note, that Reachability analysis doesn't exist in this repo yet.

* feat: Added P_supplychain to quantify unvetted dependency risk (GH-101) ([`5530eac`](https://github.com/ossiq/ossiq/commit/5530eacbbc652426927a621982b870f1ee4ab42f))
First iteration of supplychain probability to quantify unvetted
depenency risks independently from the known CVEs.

* feat: added gate decision to provide useful explanation to the user (GH-102) ([`a78e3a8`](https://github.com/ossiq/ossiq/commit/a78e3a8fb064031d75b8c7d9c970ad4ba749ab41))
Added special function get_gate_decision to explicitly
provide state (block/pass/quarantine) of the gate and
comprehensive message to the end user about why specific
version is gated.

* feat: integrated exposure_window_days into ScanRecord (GH-99) ([`ebd8ab0`](https://github.com/ossiq/ossiq/commit/ebd8ab02f6aab246d58e21ad1689d39beb48a2d7))
Added computation of exposure window to the ScanRecord,
but without actual exposure via UI or export interfaces.

* feat: aded computed exposure window estimate (GH-99) ([`4a477a0`](https://github.com/ossiq/ossiq/commit/4a477a0c69b139f569150cc14be7b830f8e9e1f0))
Added estimated number of days needed to
remediate a dependency based on a specific
range for an ecosystem (NPM, PyPI).

* feat: added CVE details strategy and EPSS score (GH-50) ([`5d45902`](https://github.com/ossiq/ossiq/commit/5d45902471969037542df953b915a2f827ae1adc))
Since /querybatch api from osv.dev doesn't return
CVE aliases, there was no way to map CVE to
EPSS score, hence new OSV strategy was added
to pull specific CVE, so that there's mapping
between main CVE id and its aliases. EPSS
scores are enriched and passed in scan, but
not used anywhere just yet.
Additionally, refactored Batch to allow
hand off queue control to a particular
strategy, so that pagination could be
handled properly. Fixed crafty pagination
in OSV /querybatch strategy.

* feat: added EPSS scores enrichment for CVE initial implementation (GH-50) ([`0936fdd`](https://github.com/ossiq/ossiq/commit/0936fdd334767af98c4f24dee7cda88153cefe54))
Added EPSS enrichment data and some additional
logic around fix version selection.

* feat: wired epss scores to the ProjectSources (GH-50) ([`cfaf3e0`](https://github.com/ossiq/ossiq/commit/cfaf3e034d023a03123e278d1a84c2f6f6f67186))
Wired EPSS score API client next to cve_database
in ProjectSources.

* feat: added EPSS score API adapter and client (GH-50) ([`9a450c7`](https://github.com/ossiq/ossiq/commit/9a450c792f2d0a5c54476933da405fa1986d5543))
Added first.org's EPSS API client and API adapter
to pull epsss score from the api.first.org
(see more on https://www.first.org/epss/ )


### Fix

* fix(release): base the changelog on the current version's tag ([`f4cf449`](https://github.com/ossiq/ossiq/commit/f4cf4498dbbe4f4a0b1fcb2452c6ad8ed7a779cf))
A stray v1.0.0 tag outranked v0.1.10, so the changelog reached back
to March and the release body exceeded GitHub's size limit. Add
--since-tag, name the rejected field on a failed release, and
require the token before anything is tagged.

* fix(ci): build macOS binaries on hosted runners that still exist (GH-122) ([`75b1944`](https://github.com/ossiq/ossiq/commit/75b1944f1bbe0fa7bc9dd314594fe65a9484bf38))
macos-13 is retired and macos-14 deprecated, so darwin-x64 queued
forever; both targets move to macos-15 and macos-15-intel. The
Package step also picks bsdtar's --uid/--gid over GNU's
--owner/--group, which bsdtar rejects.

* fix(packaging): track the pyinstaller spec file (GH-122) ([`149c32a`](https://github.com/ossiq/ossiq/commit/149c32a53cbef805c10dc93c9aead25edcd953fb))
The blanket *.spec rule in .gitignore kept ossiq.spec out of the
repo, so every binaries.yml build failed with the spec not found.
An exception for this one hand-written file keeps generated specs
ignored.

* fix(release): strip non-distribution files in testpypi rehearsal (GH-122) ([`0468095`](https://github.com/ossiq/ossiq/commit/0468095fd982cc456eb53f4620760ffa86b40566))
Mirrors the rm -f SHA256SUMS/sbom step the real publish job already
does; pypa/gh-action-pypi-publish rejects them as an unknown
distribution format.

* fix(tests): key MaintenanceState posterior fixtures by .value (GH-122) ([`556a327`](https://github.com/ossiq/ossiq/commit/556a327018ef7bc8352cbeb27345bafec978fe75))
make_maintenance built its posterior dict from StrEnum members directly, but
MaintenanceAssessment.posterior is typed dict[str, float] and dict key types
are invariant, so ty flagged every call site. Keys are now s.value.

* fix(install): write skill files as UTF-8 (GH-143) ([`587fd1e`](https://github.com/ossiq/ossiq/commit/587fd1eb39d9d1f604dbbd147222421229f8feef))
install skills reads and writes SKILL.md, mcp.json and the Copilot
instructions as UTF-8 rather than the locale encoding, so Windows no
longer fails on the skill's non-cp1252 characters. The install tests
read the files back as UTF-8, and test_install.py moves to LF line
endings as .gitattributes requires.

* fix(agent): judge fixes by advisory ranges, add fixed_in (GH-143) ([`1785075`](https://github.com/ossiq/ossiq/commit/1785075210a8062c9582ef0382bf4ca03e6143c0))
recommendation_clears_cves and the update-context verdict use
cve_affects_version, so a target inside an npm advisory range is no
longer called a fix. Each CVE in the agent payload lists fixed_in,
the releases that close it.

* fix(strategy): step over releases inside an advisory range (GH-143) ([`162fe72`](https://github.com/ossiq/ossiq/commit/162fe727478bdfc65b11ab3515495179c3823c41))
The candidate ladder flags a release as carrying a qualifying CVE
when cve_affects_version says so. Under the security tier an npm
package no longer moves to the nearest release that is still inside
its advisory's range.

* fix(solver): judge CVE exposure by advisory ranges (GH-143) ([`613d379`](https://github.com/ossiq/ossiq/commit/613d379ca91fd5be9fac6d7722a8b2ae3ae96f85))
cve_affects_version checks a release against a CVE's enumerated
versions and its ranges, and counts an unparseable version or bound
as affected. The transitive solve forbids candidates by that check
instead of by enumerated versions alone, which never forbade an npm
release.

* fix(osv): read advisory ranges, match only the queried package (GH-143) ([`55233ad`](https://github.com/ossiq/ossiq/commit/55233adeb64e7c5cdd96998b475968788f4c4f6f))
parse_cve_response keeps an advisory's SEMVER and ECOSYSTEM ranges
as CVE.affected_ranges, pairing each introduced event with the next
fixed or last_affected. Versions, ranges and fixes now come only
from the affected entries for the queried package in its own
ecosystem, with PyPI names compared after normalisation. npm
advisories enumerate no versions, so the ranges are the only record
of what they affect.

* fix(agent): judge update-context targets, align next_action with to (GH-143) ([`5ad345e`](https://github.com/ossiq/ossiq/commit/5ad345e05ff2557dded38a20e971a63f6d537f5c))
update_context returns a comparison against the recommendation, so a
deprecated older target no longer reads as approval. Check for the
Fix now fires only when the recommendation does not clear the CVE,
triage is exposed as dependency_health with a question hint, and CVE
entries carry their EPSS score.

* fix(triage): name EPSS-suppressed CVEs in the retain reason (GH-143) ([`f717b4c`](https://github.com/ossiq/ossiq/commit/f717b4c2528f5eef4357db62819bab7145416134))
A retain verdict with CVEs scored below the EPSS noise floor now
says how many, instead of claiming there is no exploit signal.

* fix(scan): keep cutoff latest_version stable; pass stated runtime (GH-143) ([`b72d697`](https://github.com/ossiq/ossiq/commit/b72d6979cef52fbdb196db66f0ec408936961b4f))
apply_cutoff_date skips pre-releases unless they are allowed for the
package, so --cutoff-date no longer reports a pre-release as
latest_version. The scan passes the stated runtime and the project's
ESM flag to the record builders, and reports the runtime pin
mismatch on ScanResult.

* fix(strategy): keep CommonJS projects on their module line (GH-143) ([`eefcb9a`](https://github.com/ossiq/ossiq/commit/eefcb9ac11e95d883d07122d21b44b4da3e0967c))
A per-release module_system_gate keeps ESM-only releases away from
CommonJS projects unless the tier is latest/cutting-edge and Node
supports require(esm); a CVE or end-of-life motive with no clean fix
left still crosses, flagged. breaking_change no longer depends on
the runtime, unpublished releases no longer unflag an ESM-only
major, and records gain latest_preserving_module_system and
module_system_note.

* fix(osv): fall back to details when an advisory has no summary (GH-143) ([`4e34e64`](https://github.com/ossiq/ossiq/commit/4e34e6412dd4a532f3f019dfd454677c06ef16d5))
PYSEC records carry their text in details only, which left CVE
summaries empty. Use the first line of details, capped at 200
characters.

* fix(N3): Node's require(esm) support was detected but never consulted for ESM-only breaking-change decisions ([`22b77df`](https://github.com/ossiq/ossiq/commit/22b77df915de780ad77e3c45df7e1bf96f8ab613))
Confirmed by directly reproducing the reported scenario before writing any fix:
compute_latest_compatible_major on a uuid-shaped release history (installed on a
CJS major, every release in the next major ESM-only) stayed stuck at the installed
version regardless of the consuming project's actual Node version. With Node
22.12+ (Node's own release notes: https://nodejs.org/en/blog/release/v22.12.0,
backported to the 20.x LTS line at 20.19.0), require() can load a synchronous ES
module directly - so ESM-only is not automatically a break for a CommonJS
consumer on a sufficiently new runtime, which the code had no way to know.
Root cause: EngineContext already detects the real Node version (via
adapters.runtime_environment) and is threaded through scan.py, strategy.py,
recommendations.py and agent.py for an existing, unrelated check
(engine_mismatch_gate's engines.node floor). service/project/breaking_changes.py -
the module that actually decides whether an ESM-only major counts as breaking -
never imported or referenced it at all, so a Node version detection that already
existed simply never reached the one decision it was most relevant to.
Fix:
- breaking_changes.py: new node_supports_require_esm(), and breaking_majors now
  takes an optional node_version and skips flagging an ESM-only major when the
  detected/declared Node floor supports require(esm). Necessary, not sufficient:
  this cannot rule out the target's ESM build using top-level `await`, which would
  still fail under require() regardless of Node version, and no static
  package.json field records that - documented directly in the docstring as a
  real, irreducible gap rather than silently ignored.
- Threaded node_version through all 5 call sites: records.py (scan_record's core
  ladder computation - the one that actually determines what gets recommended),
  target_facts.py and agent.py's build_update_context (already received
  engine_context, just weren't passing it through), and strategy.py's candidate
  selection.
- Caught and fixed an ordering bug introduced while threading this through
  scan.py: one build_records call (building transitive records) ran before
  engine_context was computed, which would have been a NameError. Fixed by moving
  detect_engine_context() earlier in scan() - safe since it has no dependency on
  build_records' output (confirmed: it only reads project_info, project_path, and
  probe_runtime).
Verified directly: compute_latest_compatible_major on the uuid-shaped scenario
with node_version=None stays at the installed version (matching the pre-fix,
reported-wrong behavior); with node_version="22.22.2" it correctly reaches the
newest release, matching what was reported as the correct pre-regression result.
Scope note: the chalk-specific sub-claim in the original report ("dates chalk's
ESM switch to 6.0.0, actually 5.0.0") is not addressed here - direct testing with
realistic synthetic release data could not reproduce it (both majors were
correctly flagged independently), and I don't have live npm access from this
environment to rule out a real-data-specific issue. This fix addresses the
Node-awareness gap only, which is independently confirmed and does not depend on
how the chalk question resolves.
Tests: tests/service/test_breaking_changes.py - node_supports_require_esm's
version-threshold boundaries (22.12.0, 20.19.0, 21.x conservatively unsupported,
unparseable/None input), breaking_majors' new node-aware flagging (including that
it is npm-only and stays conservative when node_version is unknown, matching the
pre-fix default), the uuid-shaped regression through
compute_latest_compatible_major end to end, and module_system_label's note
suppression on modern vs. old Node. Confirmed these tests actually catch the
regression: temporarily hardcoded node_covers_require_esm to False (simulating
the pre-fix behavior while keeping the module's public API intact) and reran -
exactly the 3 tests that depend on the fix working failed, including the uuid
regression test showing the literal pre-fix result ('9.0.1' instead of
'14.0.2'); the 5 tests asserting old-Node/unknown-Node/PyPI behavior correctly
still passed, since those paths were never touched by the fix. Full suite: 2109
passed, 1 skipped, zero regressions.
Ref: N3 (review findings).

* fix(N2): CVSS vector strings were never parsed, so every CVE severity fell back to MEDIUM ([`f0f0955`](https://github.com/ossiq/ossiq/commit/f0f095559fbe7a6c3bec98d0466c2d5f98975ad0))
Confirmed by direct reproduction before writing any fix: a real CVSS 9.8 CRITICAL
vector string through the unmodified map_cve_severity returned MEDIUM. A bare
numeric string worked fine (float("9.8") -> 9.8), which is why this went
unnoticed - it only breaks on the input shape OSV actually sends.
Root cause: OSV's severity[].score field is a bare number for some severity
types, but for CVSS_V3/CVSS_V4 - the type essentially all real CVE data uses,
since that's what GHSA-sourced advisories carry - it's a full CVSS vector string
("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). The numeric score is never
present in the vector itself; it has to be *computed* from the vector via the
CVSS formula. map_cve_severity called float() directly on it, caught the
resulting ValueError, and silently dropped the entry - so scores ended up empty
and every CVE fell back to the hardcoded MEDIUM default, regardless of actual
severity. The existing test suite's only severity test used bare Python floats
(`{"score": 9.5}`), which is not the shape OSV sends and never exercised this
path at all.
Fix: new module adapters/cvss.py implements the CVSS v3.0/v3.1 base score
formula (FIRST's spec, section 7.1/7.4) and the CVSS v2.0 formula (the v2 guide,
section 3.2.1) directly - no third-party CVSS library is a project dependency,
and adding one felt like a bigger, separate decision than this fix warranted.
map_cve_severity now tries float() first (for whatever severity types genuinely
do send a bare number), then falls through to the new parser for anything that
looks like a CVSS vector. CVSS v4.0 is deliberately not implemented: v4.0
scoring is a MacroVector/lookup-table system, materially more complex than v2/v3's
closed-form formulas, and adoption in OSV data is still rare - a v4.0 vector
returns None and falls back to MEDIUM, the same honest "couldn't determine"
result an unparseable vector already produced before this fix, not a silently
wrong number.
Correctness: verified against real, checkable reference values before wiring
anything in - not invented test data. CVE-2021-44228 (Log4Shell) scores exactly
10.0, matching its actual published CVSS v3.1 base score and exercising the
formula's more error-prone scope-changed branch (the 7.52/3.25/^15 term). The
CVSS v2 guide's own two worked examples (10.0 and 7.8) both match exactly. One
test value (1.8, for a low-severity local vector) had no real published source
to check against - I hand-derived it from the spec formula by hand and confirmed
the parser's output matches that derivation; the test docstring shows the work
rather than asserting an unverified number silently.
Tests: tests/adapters/test_cvss.py (new) - the parser in isolation, all of the
above reference vectors plus edge cases (missing/unrecognised metrics, v4.0,
garbage input, leading/trailing whitespace). tests/adapters/test_api_osv.py -
extended the existing (unrealistic, bare-float) severity test with a parallel
one using real CVSS vector strings, a v4.0-fallback case, and a case mixing a
CVSS vector with a bare-numeric entry from a different severity type to confirm
the max-across-both-parsing-paths logic. Confirmed these new tests actually
catch the regression: reverted just the api_osv.py change and reran - 4 of 5
vector-string cases failed loudly (the 5th "passed" only by coincidence, since
MEDIUM is the broken fallback value itself). Full suite: 2094 passed, 1 skipped,
zero regressions.

* fix: maintenance verdicts reached agents with no indication they were based on partial data ([`9bdb975`](https://github.com/ossiq/ossiq/commit/9bdb975c482414e013d5e6e35b52637b339e2f3b))
Confirmed by direct code reading: risk/maintenance.py's assess_maintenance only
returns None when *zero* observations are present - one weak signal out of
however many possible is enough to produce a full posterior and confidently pick
a state. That is arguably correct model behaviour (see below for why I did not
change it), but the resulting MaintenanceAssessment carried nothing to say so:
a package assessed from one signal and a package assessed from a full set
produced identically-shaped output.
Considered and rejected: adding a raw "N of 5 observations present" count
directly to assess_maintenance. gated_observations (risk/maintenance.py)
deliberately collapses the observation set for reasons that have nothing to do
with missing data - a strong deprecation marker intentionally drops every other
signal because it is treated as near-deterministic, and flow_trend/release_age
are dropped on a freshly-pushed repo to avoid double-counting the same fact. A
bare observation count would make those *correctly* confident verdicts look
artificially low-coverage, which is a worse kind of dishonesty than the one this
is trying to fix.
Used what already existed and was already correct instead: SignalCoverage
(domain/common.py) specifically measures whether the underlying repo data could
be fetched at all (FULL / NO_REPOSITORY / UNSUPPORTED_HOST /
REPOSITORY_UNAVAILABLE / ACTIVITY_UNAVAILABLE), independent of the model's own
gating logic. It was already being computed correctly on every record - but
consulted only by the console renderer's separate aggregate "N unassessed"
count (status/console.py), never inside the maintenance computation, and never
exposed to an agent reading one record over MCP or --format agent at all.
Fix: service/agent.py's triage_summary now adds `maintenance_signal_coverage`
whenever a maintenance verdict is present and record.signal_coverage is not
FULL. Applied uniformly regardless of which state was assessed - a "maintained"
verdict from partial data gets the same transparency as an "abandoned" one, not
just the alarming ones. Omitted (not `false`/"full") when coverage is complete,
matching the sparse-field convention already used for suppressed_cves and
cve_data_unavailable elsewhere in this same function.
Tests: tests/service/test_agent_decision.py - the reported scenario (a strong
verdict from degraded data reaches the agent JSON with the coverage gap
attached), the field is correctly omitted when coverage is full, and a healthy
"maintained" state still surfaces a coverage gap when one exists. Confirmed
these tests catch the regression: reverted just the new conditional block and
reran - exactly the 2 tests checking the field's presence failed with a
KeyError; the "omitted when full" test correctly still passed, since asserting
absence is trivially true when the field never exists at all. Full suite: 2129
passed, 1 skipped, zero regressions.
Ref: review findings, "maintenance verdicts at low data coverage".

* fix(N1): triage claimed "no exploit signal" when CVE data was unreachable, not just genuinely clean ([`dbe042a`](https://github.com/ossiq/ossiq/commit/dbe042a26c0abf567483e5cc7879b638ad587cd4))
Confirmed by direct code tracing before writing any fix: risk/triage.py's
triage(cves, unstable) takes `unstable: bool | None` with careful, explicitly
documented handling - "Unknown is not unstable: such a package keeps its
exploit-driven action and is never marked for refactoring on absent evidence."
There was no equivalent on the CVE side: an empty `cves` list read identically
whether OSV was reachable and genuinely found nothing, or was firewalled and
found nothing because it was never asked. Traced the only call site
(service/project/stability.py's populate_stability: `triage(record.cve,
unstable)`) and confirmed it has zero access to data_completeness - the B4
infrastructure that already tracks exactly this (DataCompleteness.status_for
(ScanStep.VULNERABILITIES)) existed and was simply never consulted here.
Fix: triage() takes a new `cve_data_unavailable: bool = False`, mirroring
`unstable`'s None handling as directly as the two concepts allow. Scoped
carefully, not a blanket disclaimer: only the final fallback branch (no exploit
evidence, no instability - what used to unconditionally say "No significant
exploit or stability signal") changes its wording; a package that genuinely
scored above the exploit threshold still gets evict/patch exactly as before; a
scan-level "partial" status does not mean *this* package's own chunk failed, so
real evidence found for it is never overridden. The new
TriageResult.cve_data_unavailable field is always set regardless of which branch
fired, so a consumer does not have to parse reason text to find this out.
Threaded from where the signal already existed: scan.py reads
prefetched.data_completeness.status_for(ScanStep.VULNERABILITIES) (unchanged,
already computed earlier in the pipeline) and passes it into
populate_stability's new cve_data_unavailable parameter, which forwards it to
every triage() call. service/agent.py's triage_summary (which feeds both
--format agent and both MCP tools) now surfaces the field too, so this is
visible to an agent as a discrete boolean, not just a change to a sentence a
human reads in a console table.
Tests: tests/risk/test_triage.py - the report's own scenario (empty cves from a
degraded fetch), that the default preserves the exact old wording unchanged, that
the field is set regardless of which action fired, and that real per-package
evidence is never overridden by a scan-level partial status. tests/service/
test_stability.py - the same forwarding through populate_stability into every
record's triage. tests/service/test_agent_decision.py - the field actually
reaches the agent/MCP JSON output, and is omitted (not `false`) when nothing was
degraded, matching the existing sparse-field convention for suppressed_cves/
deprecation_signals. Confirmed these tests catch the regression: temporarily
reverted just the reason-text branch to the old unconditional string and reran -
exactly the 2 tests checking that specific wording failed, showing the literal
old misleading message even with cve_data_unavailable=True; the other 6 (field
presence, default, action-independence) correctly still passed, since they don't
depend on that one branch. Full suite: 2117 passed, 1 skipped, zero regressions.
Ref: N1 (review findings).

* fix: latest_version showed a prerelease whenever it was the most recent upload, even without --allow-prerelease ([`1e9277e`](https://github.com/ossiq/ossiq/commit/1e9277eb5bc97a78420994fb6021f5ef765096cb))
Confirmed by direct code reading: PyPI's `info.version` field is simply the
maintainer's most recent upload - it applies no stability filtering of its own.
_map_raw_to_package used it directly as Package.latest_version, so a package
whose newest upload happened to be a beta (e.g. pydantic 2.14.0b2) reported that
as "latest" unconditionally - something `pip install pydantic` without --pre
would never resolve to.
The existing update_latest_versions_for_prerelease (prefetch.py) looked at first
like it should have caught this, but it does the opposite of what's needed here:
it *skips* every package unless --allow-prerelease / --allow-prerelease-packages
is set, so it only ever widens latest_version to include prereleases when opted
in - it never had a path to *exclude* one from the default, unopted-in case.
There was no mechanism anywhere that corrected the raw PyPI value back to the
newest stable release.
Fix: new _latest_stable_version(info_version, releases) on
PackageRegistryApiPypi. When info.version parses as a prerelease, falls back to
the newest non-prerelease version among `releases` - the same raw JSON payload
already fetched, no extra request - matching what an actual install would pick.
Returns info_version unchanged when it's already stable, unparseable, or when
the package genuinely has no stable release at all yet (showing the prerelease
is more informative than nothing in that case). This only corrects the default
value; update_latest_versions_for_prerelease needs no change and continues to
widen it back to the true overall newest exactly as before when prereleases are
explicitly opted into.
Tests: tests/adapters/test_api_pypi.py - TestLatestStableVersion (7 cases: the
reported pydantic-shaped scenario, already-stable is a no-op, no-stable-release-
exists, unparseable info_version, unparseable entries within releases skipped
rather than fatal, rc/alpha variants, empty releases dict), plus two end-to-end
cases through packages_info_batch itself (prerelease corrected, stable
unaffected). Confirmed these tests catch the regression: reverted the fix and
reran - 8 of 9 failed (AttributeError, the method no longer exists), the one
exception being the "already stable" case which correctly never depended on the
fix in the first place. Full suite: 2126 passed, 1 skipped, zero regressions.
Ref: review findings, "latest_version shows prereleases".

* fix(maintenance): a quiet six weeks were enough to call a package winding down (GH-127) ([`bc8ec2d`](https://github.com/ossiq/ossiq/commit/bc8ec2d28fdd1ab3ebba91e5b62aa4826ca455a8))
The `recent` push bucket was fitted on three dormant PyPI repos and leaned 0.60
to 0.18 against `maintained`, so a package that had pushed 42 days earlier and
shipped a release six weeks before that came out winding_down at P=0.92 with
every other signal neutral - and one day either side of the 30-day boundary
flipped the verdict by 87 points. The boundary moves to 45 days, `recent` and
the unfitted `flow_trend` rows are refit against the corpus, and a new
`release_age` observation reads the registry clock so a library that is
finished can be told from one that is dying. Corpus accuracy 87.3% -> 88.9%,
Brier 0.269 -> 0.264.

* fix(stability): an inbound pull-request spike read as maintainer silence (GH-127) ([`133635d`](https://github.com/ossiq/ossiq/commit/133635d3e896738a00d575c676f7475a6f129bca))
flow_ratio divides by items opened, so a burst of unsolicited PRs drove the
ratio to zero and forced `declining` on a repo whose maintainers had not slowed
down at all - bot filtering cannot catch it because the authors are human.
flow_ratios now caps each bucket's denominator at twice the median inflow and
reports buckets under three items as unmeasured instead of as a confident zero,
and a pull request counts as outflow when it closes rather than only when it
merges.

* fix(github): a null node in a partial GraphQL response crashed every scan (GH-127) ([`48bc342`](https://github.com/ossiq/ossiq/commit/48bc34276e315847f394240adb64eb62d7c5ed55))
GitHub answers a per-node INTERNAL error with HTTP 200 and a null inside
`nodes`, which reached stability's tally as None. The response is cached for the
stability TTL, so one bad node broke every scan of that project for a week.

* fix: fixed engine constraint for python (GH-127) ([`c41e241`](https://github.com/ossiq/ossiq/commit/c41e2412c730fe1978e5d79d99bcd074e138ba21))
There's difference in behavior between NPM and
Python ecosystems when it comes to an engine
constraint. In NPM ecosystem it is normal to
accept the risk of pulling newer dependency than
current node version (e.g. node 20.x installed,
and dependency constrained to node 24.x could
be installed but with a warning). For python
ecosystem it should be strictly followed:
if there's lower bound python engine, then
only compatible dependencies should be taken,
otherwise it would be rejected by the package manager.

* fix: alias support was half-done in --override and the status table ([`d7ccd49`](https://github.com/ossiq/ossiq/commit/d7ccd4901785f0aa591ef16f6ccea367a664ce47))
Two gaps left by the alias-identity commit, both the kind where one half of a
command accepts something the other half cannot handle.
--override: build_update_plan learned to accept a manifest key, but
warn_unknown_override_versions still asked the registry for a package literally
called "uuid-v11" and raised "Unable to load package". Both now resolve through
one find_override_record, which tries the manifest key before the registry name.
A registry name shared by several aliases names two separately installed copies
and can only be forced for one, so it now reports the keys it found and forces
none, instead of picking arbitrarily.
status: the plan table and the acknowledgement prompt named aliases after the
previous commit while the status table still printed the canonical name, so the
same project read as two identical `uuid` rows in one view and two distinct ones
in another. Both now go through domain.common.display_package_name — one writer,
so the two surfaces cannot drift apart again.
Also drops pnpm and yarn from the engine dispatch. Neither has an adapter, so
nothing probes them: a floor evaluated on the declared path and skipped on the
detected one is worse than an unevaluated key, which at least fails open
consistently. They pass through as satisfied until pnpm support lands, which is
one entry plus a probe.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* fix(ui): --verbose no longer swallows the degraded-data warning ([`b9df900`](https://github.com/ossiq/ossiq/commit/b9df900d00cd4792b15dac894882d85b4905aaf4))
show_scan_progress returned early for --verbose and for a missing Rich, yielding
a no-op ScanProgress. warn_about_degraded_steps was the last statement of the
Rich branch, so neither path ever reached it — and a verbose CI log is exactly
where someone would go looking for the warning that a scan ran on incomplete
data.
The early-return path now keeps a real on_step_done that records outcomes
(only the animation is dropped), and the warning moved into a finally around
the whole contextmanager, so a scan that dies partway still reports what it got.
show_warning already had a plain-stderr fallback, so the no-Rich path needed
nothing further.
Verified against a genuinely unreachable OSV host: the warning is now present
with and without --verbose, where before it appeared only without.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* fix(info): mark the ladder rung holding the recommendation, not the rung it came from ([`7003e00`](https://github.com/ossiq/ossiq/commit/7003e004e2726fd272aa8ec4d66661d3dfac4395))
RecommendationRung.LATEST means "reachable only by widening past the installed
major", not "the newest release". For uuid@^7.0.0 the pick is 11.1.1 because
build_candidates gated 12-14 behind the ESM break, and the rung is still LATEST
— so the Policy Compliance block printed "Latest 14.0.2 ← recommended" next to
"Recommended 11.1.1", naming a version the reader was not being recommended.
In Range and In Major were mismarkable the same way, since the minimal-diff
tiers pick the nearest candidate rather than the rung's top.
The rung is correct upstream: apply_update_strategy writes the version and the
rung from one Candidate. Only the renderer's assumption was wrong, so the marker
is now keyed on version equality.
When the pick matches no rung — the case that motivates the change — the ladder
alone cannot say where it landed, so the block now also names rejected_candidates,
which held exactly those releases and had no reader anywhere in info.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* fix(status): a tier withholding a package is not the declared range capping it ([`e61959a`](https://github.com/ossiq/ossiq/commit/e61959ab6ea2103b01cb02412c3ab4f6bea86d01))
scikit-learn 1.8.0 declared <2.0.0 under --update-strategy security printed
"Constrained. Check newer version" with a sub-row reading
"<2.0.0 caps this below 1.9.1" — but <2.0.0 admits 1.9.1 perfectly well. The
tier admitted no motive; the range withheld nothing. The agent payload emitted
the same false reason alongside its own, correct strategy_withheld_reason, in
the same entry.
next_action_label gains a seventh label, Withheld by strategy, returned when
strategy_selection.withheld_reason is set — the branch select_target takes for
exactly this case, and which is None when the tier admitted a motive but nothing
was reachable. The label is 20 chars, so the measured What's Next width
thresholds do not move.
The surviving "caps this below" row now also has to be true: it is drawn only
when latest_in_range is absent or equals the installed version. Across
testdata/, three fixtures still draw it and each one earns it (npm/project1's
^0.9.1 really does cap i18n below 0.15.4).
Carried to all six contract surfaces: the export schema enum (both $defs), the
generated TS union, the report legend and style map, the MCP tool description,
SKILL.md and docs/reference.md. docs/recommendations.md lands tracked here with
its §3.2 warning box — which existed only to describe this defect — replaced by
the distinction between the two labels.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* fix(plan): npm aliases collapsed onto one registry name ([`0c17110`](https://github.com/ossiq/ossiq/commit/0c1711052e2bd62f59ebffd133ebe33f12542d06))
Two npm aliases of one package (uuid-v7: "npm:uuid@^7.0.0" and uuid-v11:
"npm:uuid@>11.0.0") share a package_name, and build_update_plan subtracted the
widening and cooldown partitions by that name. Holding one alias dropped its
sibling from the plan entirely: on testdata/npm/version-constrained that removed
uuid 13.0.0 -> ESM-only 14.0.2 from both the plan table and the acknowledgement
prompt, while the agent payload still flagged it carries_known_break.
The npm writer had the same collapse one layer down and worse: apply_direct_specs
iterates manifest keys but looked entries up by package_name, so no aliased
dependency ever matched and apply silently wrote nothing for it.
UpdateEntry now carries dependency_name, with `identity` (the manifest key) as
the plan's unit of identity and `display_name` for the console. package_name
stays the registry name — the solver, OSV and the registry clients key on it.
installed_versions stays keyed on package_name too: update_impact and
--strategy-override validation both want the canonical name.
--override accepts either spelling; the agent payload carries dependency_name
when it differs, since two entries otherwise share "package" with nothing to
tell them apart.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* fix(report): read next_action instead of re-deriving it; show the ladder ([`acb482b`](https://github.com/ossiq/ossiq/commit/acb482b2a8a016b761351a5af67b30b6df7b8b27))
useReportFilters.ts::computeWhatsNext was a hand-written copy of
next_action_label with no notion of ladder rungs, so a recommendation only
reachable by widening the declared range read "Update Immediately" in the
HTML report where the CLI says "Constrained. Check newer version" — naming a
target the reader cannot apply. Two of five direct dependencies on
testdata/pypi/version-constraint. The copy is deleted; the report reads the
exported field.
The ladder itself is now visible: an "in range"/"in major" line under Latest
when the rung sits below the registry's latest, a "widen" badge on the
recommendation, and a Version Ladder block in the detail panel mirroring the
info block. Threading the fields through the tree-view copy layers turned up
recommended_version being declared on the node but never populated, so that
panel had always shown a blank recommendation; fixed here too.

* fix(ui): abbreviate What's Next on terminals too narrow for the label ([`8ae6f81`](https://github.com/ossiq/ossiq/commit/8ae6f81f7e422de8a419711938834d976e3ea912))
"Constrained. Check newer version" is 32 chars, the widest label in the set,
and wrapped the compact status table onto two lines below 110 columns (157
with --full). The renderer now shortens it to "Constrained" below those
widths; the canonical label still goes to agent JSON, MCP, the export and the
HTML report, since it is a contract there rather than a column. The --full
sub-row naming the range and what it caps is never abbreviated.
Both thresholds are measured, not guessed, and pinned by tests that render a
worst-case row at the threshold and assert nothing wraps or ellipsizes.

* fix: package-manager adapter precedence and engine-range correctness ([`11ba033`](https://github.com/ossiq/ossiq/commit/11ba033c2a67287287ed7a512c9f9a656c4b8704))
- create_package_managers() now enforces first-match-per-registry precedence
  itself (PACKAGE_MANAGERS order), instead of yielding every match and
  leaving each adapter to break ties against its siblings (api_pep621 used
  to call PackageManagerPythonUv/Pip's has_package_manager directly). A
  project with a real lockfile still gets the fuller-featured adapter, and
  two adapters matching the same registry no longer spuriously trips the
  "multiple registry types" warning.
- inspected_manifests() exposes the manifest filenames adapters actually
  probe for, so UnknownProjectPackageManager's hint can name them instead of
  sources/ keeping a separate hardcoded copy that would go stale.
- extract_min_node_version: dropped ">" from NODE_FLOOR_COMPARATORS. An
  exclusive floor like ">18.0.0" was being returned as "18.0.0", a version
  the range explicitly excludes — now falls through to None, matching
  extract_min_python_version's existing >=/~=/==-only contract.

* fix: fixes console output and updated docs (GH-127) ([`a19cd7f`](https://github.com/ossiq/ossiq/commit/a19cd7faf91d4d2361c25ced4cd468ec10631b5a))

* fix: ossiq-produced overrides separated from user overrides (GH-127) ([`732755a`](https://github.com/ossiq/ossiq/commit/732755a038299c80949d199e4759a8c28d2aba05))
To "freeze" transitive tree for NPM the "overrides" mechanism
is used. The problem is that once tree is frozen, there's
no way to know which was written by the OSS IQ and which
was intentional by the user (missing knowledge), kind of
pooling equilibrium for the next OSS IQ run. Now it is
clearly separated via metadata section.

* fix: refactor back code repository abstraction (GH-127) ([`4dfafad`](https://github.com/ossiq/ossiq/commit/4dfafada9dc9240d109cb84c945b07139c628af6))

* fix(B8): warnings/progress/settings never reach stdout; agent format carries data_completeness inline; export supports '-' for stdout (GH-127) ([`633a8bf`](https://github.com/ossiq/ossiq/commit/633a8bfd4ead61466042ff0591ac4e39cd8ec7d5))
Point 1 (all diagnostics/progress/warnings to stderr): verified first, rather than
assumed, that Python's logging module already defaults to stderr with zero explicit
configuration - proved with an isolated subprocess test. That part of the report's
evidence doesn't reproduce as literally described; logging.basicConfig (only called
under --debug) also defaults to stderr when no stream is given. The real, still-live
gap was in ui/system.py's Rich console usage: show_settings and show_scan_progress's
Live progress bar (plus its trailing print("\n")) wrote to the plain stdout-bound
`console` object, not `error_console`. Harmless today only because every command that
calls them currently writes its actual payload to a file rather than stdout - but
that was about to stop being true the moment stdout-streaming existed (see below),
and violates the report's blanket rule regardless. Fixed both, plus
show_operation_progress for the same reason. Confirmed the human-facing payload
renderers (status/plan/html console tables) construct their own separate Console()
instances and were untouched by this.
Point 3 (object repr in the rate-limit warning) was already fixed in the B4 commit
(BatchStrategy.__str__); confirmed still in place, nothing further needed here.
Point 2 (warnings belong inside machine-readable documents): found a gap not covered
by the B4 work - agent format (status --format agent, both MCP tools) never carried
data_completeness at all. The B4 warning mechanism lives inside show_scan_progress,
which agent/MCP callers bypass entirely via the silent on_step callback - so a
degraded non-vulnerability source (GitHub rate-limited but OSV fine, say) vanished
with zero signal in agent output even though the export format already surfaced it.
Added data_completeness directly to build_update_decide's output
(service/agent.py). Deliberately scoped to build_update_decide only:
build_add_decide's PackageDetailResult carries no scan-level completeness at all,
which would need separate plumbing through build_installed_detail/
fetch_prospective_detail - noted as a follow-up rather than expanding scope here.
Related minor issue: export -o - now streams to stdout instead of attempting to
create a file literally named "-". Only safe to add after the point-1 fix, since
command_export unconditionally calls show_settings and show_scan_progress before
the renderer runs.
Also checked commands/plan.py and commands/html.py for the same risk class: neither
has a machine-readable stdout mode (plan is always UserInterfaceType.CONSOLE, html
always writes a file), so neither was in scope.
Tests: tests/commands/test_export.py (new) runs the real command_export function end
to end - scan/sources mocked, show_settings/show_scan_progress/the renderer all
real - with destination="-", in both verbose and non-verbose mode (they exercise
different diagnostic code paths), and with a degraded data source in play, asserting
captured stdout parses as exactly one JSON document. tests/ui/renderers/export/
test_json.py: two tests for the "-" destination. tests/service/test_agent_decision.py:
two tests for data_completeness in the agent format (clean and degraded). Updated two
existing ui/test_system.py mocks (console -> error_console) to match the redirect.
Full suite: 1506 passed, 1 skipped, zero regressions.
test_export.py's make_options had the same untyped-dict-unpacking issue
as test_status.py's fix on the previous branch in this stack - build via
dataclasses.replace on a real CommandExportOptions instance instead.

* fix(B7): agent format no longer omits direct dependencies with nothing to report ([`31caffa`](https://github.com/ossiq/ossiq/commit/31caffa744b0a09db10f605cd9a04c00a7b13eff))
Verified first that the report's literal reproduction (6 pinned deps, all outdated,
only pydantic had a CVE -> only pydantic listed) no longer reproduces on this branch:
build_update_entry's actionable gate already included diff_index in BEHIND_DIFFS,
which fires independent of solver/ladder state, so all 6 already appeared before this
commit. The codebase moved on from the report's literal evidence here the same way
it had for B1's "verdict": "block" schema and B3's old terminology - this report was
written against an earlier state of the tool.
The report's correct-behaviour text asks for something the diff_index check alone
doesn't cover, though: "every direct dependency... regardless of whether the solver
proposes a change... an agent cannot distinguish 'this package is fine' from 'this
package was not analysed'." A genuinely fine package - not outdated, no CVE, actively
maintained - still cleared none of build_update_entry's actionability checks and was
omitted outright. That ambiguity is exactly what this fixes.
- service/agent.py: build_update_entry now always returns an entry (dropped the
  `| None` return type). A non-actionable package gets an explicit minimal entry
  (next_action="no action needed", to==from, empty reasons/cves) instead of being
  dropped. build_update_decide no longer filters for None.
- Every entry - actionable or not - now also carries latest_version (the absolute
  newest, previously only implicit via "to" or the ladder fields and not always equal
  to either, e.g. a package pinned behind an API break where latest_in_major and
  latest_version differ). The report explicitly lists "latest overall" among the
  fields every entry should carry; it was missing before this commit regardless of
  the omission bug.
- agent_next_action is not called for the no-action path: it defaults label=None to
  UPDATE_IMMEDIATELY, which is correct for its existing (actionable-only) callers but
  would have mislabeled a genuinely fine package - that branch was never exercised
  before since build_update_entry returned None first. Setting next_action directly
  for the no-action case avoids the mismatch without touching agent_next_action.
Tests: updated the one existing test that asserted the old omission behaviour
(test_update_no_action_when_nothing_actionable) to assert the new explicit entry
instead. Added the report's own 6-package scenario verbatim as a regression test,
plus a focused test that a fine package alongside an outdated one gets its own
explicit no-action entry rather than being silently dropped from the list. Full
suite: 1500 passed, 1 skipped, zero regressions.
Ref: ossiq-defect-report.md, B7.

* fix(B4): explicit per-source data completeness, ported onto #128's ladder branch (GH-127) ([`1780211`](https://github.com/ossiq/ossiq/commit/1780211fe80f6a2732564395ccf99997e75b6035))
All five points from the defect report's B4 correct-behaviour list, ported from the
original independent B4 work onto this branch's version-ladder implementation.
Genuinely independent concern from the ladder work here - #128 doesn't touch any of
clients/batch.py, adapters/api_osv.py, adapters/api_github.py, ui/system.py,
commands/status.py, or mcp/server.py, so most of this ports as a clean copy. The
handful of files both branches touch (domain/common.py, service/project/models.py,
service/project/scan.py, ui/renderers/export/models.py + schema) are merged by hand
below, keeping both sets of additions.
Root cause (point 1/5): BatchClient.run_batch already tracked chunks_ok/chunks_failed
internally but only ever logged them at debug level - a caller had no way to tell
"checked, found nothing" apart from "couldn't check at all." Combined with scan.py's
step() progress markers firing before each fetch even starts (purely positional, not
a success signal), this produced the report's headline bug: a green checkmark for a
step that silently failed end to end.
- clients/batch.py: BatchRunSummary classifies a run as ok/partial/unreachable/
  rate_limited (domain.common.DataSourceStatus, added here alongside this branch's
  own RecommendationRung enum). BatchClient.last_summary holds it after every
  run_batch() call. BatchStrategy.__str__ fixes the rate-limit warning leaking a raw
  object repr (point 5/5).
- adapters/api_osv.py, adapters/api_github.py: CveApiOsv and
  SourceCodeProviderApiGithub expose self.last_summary. GitHub's 4 batch methods
  previously each opened a throwaway BatchClient with no way for a caller to inspect
  it afterward; prefetch.py's corresponding functions now take an already-constructed
  provider instead of `sources`, so one provider (and one session) is shared across
  all 4 fetches per scan.
- domain/common.py: DataCompleteness, a per-step status map with .overall (worst-of)
  and .degraded_steps. Threaded onto PrefetchedData and ScanResult alongside this
  branch's existing ladder fields on the same two dataclasses.
- service/project/scan.py: prefetch_scan_data reads provider.last_summary and
  sources.cve_database.last_summary right after each fetch. scan()'s step() wrapper
  and the on_step callback contract both broadened to optionally carry a completion
  status; this function turned out to be untouched by #128, so the port applied
  cleanly.
- ui/system.py: the CLI checkmark rendering (point 2/5) - the actual headline bug.
  render_scan_steps (extracted from an inline closure so it's directly testable)
  looks up each completed step's recorded status and picks a distinct icon/color/
  suffix per DataSourceStatus; ok stays a plain green checkmark, partial/unreachable/
  rate_limited never do. A summary warning lists any degraded steps by name after the
  progress bar finishes.
- ui/renderers/export/models.py + v1.5 schema: DataCompletenessExport in
  ExportMetadata (point 3/5), alongside this branch's own ladder export fields
  (latest_in_range/latest_in_major/recommended_from_rung) on PackageMetrics.
- commands/status.py, cli.py: --allow-partial flag (point 4/5). command_status checks
  data_completeness.status_for("vulnerabilities") after the scan and, by default,
  refuses to render at all - fails closed rather than ever producing what looks like
  a clean report. Deliberately not gated behind --security: CVE data is fetched for
  every status run regardless of that flag, so gating the exit code behind it would
  mean the identical degraded-OSV scenario exits 0 or 1 depending on an unrelated
  flag.
Bug caught while porting (found and already fixed once during the original B4 work,
reintroduced here purely by the porting process - a useful confirmation of how easy
this class of bug is to reintroduce during a merge): commands/info.py's agent-format
on_step callback still had the old one-argument lambda signature
(`on_step=lambda _: None`). Since scan.py's step() wrapper now always calls on_step
with two positional arguments once completeness-reporting fires, this would have
crashed `ossiq info --format agent` on every real invocation. Fixed the same way as
mcp/server.py's noop_step was fixed the first time around
(`lambda _key, _status=None: None`).
Note: apply_ladder_fallback's own latest_in_range computation (service/project/
ladder.py, this branch) calls version_satisfies_constraint - the same function the
companion B3 commit (bbde7a5) fixes. That commit lands first in this branch's
history for exactly that reason: an npm exact pin's latest_in_range was wrong before
it, independent of anything in this commit.
Tests: ported clients/test_batch.py, adapters/test_api_{osv,github}.py,
service/test_prefetch.py, ui/test_system.py, commands/test_status.py,
test_mcp_server.py wholesale (zero overlap with this branch's existing tests). Added
two data_completeness cases to this branch's existing (and much larger)
ui/renderers/export/test_json.py rather than reconciling the whole file. Full
combined suite - both this branch's original 1338 tests and everything from the
original independent B1-B4 work - passes together: 1497 passed, 1 skipped, zero
failures, zero regressions in either direction.
Rebase fixups after landing on the corrected PR128 trunk (which now
includes the update-strategy selector, TODO #2):
- scan.py: step() is typed Callable[[str, DataSourceStatus | None], None],
  which requires exactly two positional args - several call sites still
  called it with one, a latent type error unrelated to this rebase.
- test_status.py: CommandStatusOptions is now typed with UpdateStrategy /
  StrategyPlan fields rather than plain strings; build options via
  dataclasses.replace on a real instance instead of an untyped dict, and
  drop the now-removed security_only kwarg.
- test_cross_ecosystem_parity.py: apply_ladder_fallback was deleted when
  the strategy selector replaced it - ported the test onto
  apply_update_strategy under the STANDARD tier.
- ruff format reformatting picked up along the way.

* fix(B3): npm bare-version exact pins were silently widened to caret ranges ([`9b59a5f`](https://github.com/ossiq/ossiq/commit/9b59a5f7f3226d7303c56f255335d467ab013f09))
Ported onto #128's version-ladder branch: this bug is independent of, and was not
fixed by, the ladder work here. compute_version_ladder's latest_in_range calls the
same version_satisfies_constraint this fixes, so the ladder inherited the bug too -
confirmed directly: before this commit, compute_version_ladder(installed="4.17.1",
constraint="4.17.1") returned latest_in_range="4.22.2" instead of the actual pin.
Root cause: npm_version_satisfies_range() caret-expanded *any* bare numeric version
string, including full X.Y.Z versions like '4.17.1' - the normal way npm writes an
exact pin (npm install --save-exact). Per the node-semver spec ('no operator
specified = equality assumed') and confirmed against univers's own unmodified
behavior, only *partial* bare versions ('14', '14.2') are supposed to expand into a
range; a full bare version should mean exact equality. The old blanket regex meant a
declared exact pin such as "express": "4.17.1" was solved against effectively as
"^4.17.1" (anything below 5.0.0) - so npm's solver looked like it could move past a
pin that PyPI's "==4.17.1" correctly refused to cross.
Narrowed the caret-expansion regex to partial bare versions only
(solver/version_matchers.py: BARE_VERSION_RE -> PARTIAL_BARE_VERSION_RE). Verified
zero regressions: this branch's full test suite (1338 tests, including its own new
test_version_ladder.py) passes unchanged before and after - their own tests never
covered a bare/exact npm pin either (only caret ranges and alias specs), so this
gap existed independently on both sides until checked for directly.
Tests: ported test_cross_ecosystem_parity.py onto this branch's actual module
structure (service.project.ladder.compute_version_ladder,
service.project.recommendations.apply_ladder_fallback) - runs the real parser, real
solver, and real ladder end to end for both PyPI and npm on structurally equivalent
exact-pin scenarios. Confirmed the test actually catches the regression by reverting
the fix and rerunning: only the npm case fails, exactly as expected.
Ref: ossiq-defect-report.md, B3.

* fix: standard tier no longer strands drift-only packages with no target (GH-127) ([`3ef5ae0`](https://github.com/ossiq/ossiq/commit/3ef5ae06976d5b114143c4e8fd2c0d7aa73b7e07))
MAX_REACH[STANDARD] caps reach at IN_RANGE, and DRIFT isn't an escalating
motive, so a package held back only by version drift (an exact pin broken
by an API-incompatible major, e.g. pydantic==1.10.13) had no candidates
within reach at the default tier and select_target returned no target at
all. That's the exact TODO #1 scenario (0% vs 90% benchmark) the version
ladder exists to fix, reintroduced by the strategy selector replacing
apply_ladder_fallback.
Freshness tiers (standard/latest/cutting-edge) now widen one rung at a
time when drift alone leaves nothing in reach, same ascending walk
apply_ladder_fallback used, so a same-major patch is still preferred over
jumping straight to a breaking major when both exist. Minimal-diff tiers
(security/deprecation) are unaffected - drift alone was never their
motive to move.

* fix: fixed a undetermined behavior for pinned versions (GH-127) ([`0ac547e`](https://github.com/ossiq/ossiq/commit/0ac547ee6617a2794f9aced2c124314df6825ee4))
A project pinning `pydantic==1.10.13` gets `latest_version: 2.13.5`,
`recommended_version: None`. With correct refusal of the migration to 2.x,
OSS IQ left user with nowhere to go, so the dependency is never touched.
However, there is pydantic version `1.10.26` with a single PyPI query.
The fix is done through introduction of the versions "ladder" to clearly
determine latest version within a major release, so that recommendation
could be deduced from the ladder rather than just from the pure
solver output.

* fix: fixed encodings for windows, build without NPM and OSS IQ quality gate (GH-122) ([`9a84e11`](https://github.com/ossiq/ossiq/commit/9a84e11542f2979c7f62d8223f337cee14fbb46b))

* fix: fixed peerDependency issue for plan->apply sequence (GH-100) ([`2e03af2`](https://github.com/ossiq/ossiq/commit/2e03af267b9b8e7a412cfa2628746c402510df23))
During update of the dependencies, there was an issue
with the frontend caused by peerDependency settings
of transitive package and typescript.

* fix: fixed typos and small mistake (GH-50) ([`17daa81`](https://github.com/ossiq/ossiq/commit/17daa817c076c99c13c71ac757f85b071604726e))


### Refactor

* refactor(ui): render CompatibilityFacts fields; export schema mixins ([`97f3a1b`](https://github.com/ossiq/ossiq/commit/97f3a1b1c75b989e2cd98ac0ef994e2a9cf34ec8))
- status/plan/info console renderers and the export models read the new
  CompatibilityFacts cluster (record.compatibility.*) instead of the flat
  ScanRecord fields it replaced, and use the shared WIDENING_RUNGS /
  rung_scope_label instead of each defining its own {IN_MAJOR, LATEST} set
  and "new major"/"same major" string.
- export/models.py: LadderFields/CompatibilityFields mixins replace ~100
  lines of byte-identical Field(...) declarations duplicated between
  PackageMetrics and TransitivePackageMetrics (which had already drifted —
  one said "Absent when undeterminable", the copy still said "Null only").
  export_schema_v1.5.json amended in place to match (still unreleased, no
  version bump); frontend/src/types/report.ts regenerated from it.
- ui/system.py: reads DataCompleteness/ScanStep directly instead of
  duplicating its degraded-steps filter.

* refactor: move build_installed_detail/matches into service/package.py ([`aaf39d0`](https://github.com/ossiq/ossiq/commit/aaf39d09e0f8e7029f3b93cf8350369152c5efd9))
commands/info.py owned build_installed_detail (running the strategy selector
against a synthetic, unfiltered versions_since) and matches(), even though
nothing about either is specific to the `info` command — mcp/server.py was
already importing both from commands/info.py, a CLAUDE.md-documented
deviation (front doors should be thin; anything reachable from both CLI and
MCP belongs in service/). Moving them clears the way for a shared
update-context payload builder to use the same two functions instead of
picking a different one from a different place.

* refactor: consolidate ScanRecord's ladder/module-system/engine facts into CompatibilityFacts ([`6811afd`](https://github.com/ossiq/ossiq/commit/6811afda3a7a0e41cad82696f5df1b4463e95285))
ScanRecord had grown ~50 flat fields covering three different concerns
(version ladder, module-system/API breaks, engine compatibility) with
duplicated bucketing logic and multiple writers for the same derived field.
This collapses them into one CompatibilityFacts value (domain/compatibility,
added previously) with exactly two writers: service.project.records.scan_record
builds the ladder half at construction, and the new
service.project.target_facts.annotate_target_facts/clear_target_facts owns
the target half, called from both service.project.strategy.apply_update_strategy
(direct records) and service.project.recommendations.apply_recommendations
(transitive records) instead of each duplicating the annotation logic.
Also lands in this pass:
- classify_rung now classifies against version_constraint_declared (falling
  back to the last-writer-wins version_constraint only for transitives with
  no declaration of their own), so the value that gates whether `ossiq apply`
  may write matches the value shown to the user. Previously a record's rung
  could be computed against a constraint the root manifest never declared.
- service/project/runtime_context.py: engine-context detection gated on the
  project's own registry, so a pure-PyPI scan no longer spawns `node
  --version` / `npm --version` subprocesses for two answers nothing uses.
- ScanProgress splits the old single `on_step(key, status=None)` callback
  (disambiguated by `status is None`) into on_step_start/on_step_done, using
  the new ScanStep enum instead of magic strings duplicated across scan.py
  and the UI stepper.
- service/agent.py: build_update_entry/build_add_decide read the record's
  CompatibilityFacts instead of flat fields; engine-mismatch text now comes
  from one reason-returning function instead of three call sites building
  three different strings; a pick whose major line carries a known break is
  flagged with `carries_known_break` even when it sits inside the declared
  range (so it isn't missed just because requires_constraint_widening only
  fires on out-of-range picks).
- tests/test_import_boundaries.py: forbid ui/renderers/** from importing
  ossiq.strategy, closing the gap that let a pure package go unchecked.

* refactor: value-based diagnostics and shared version/compatibility primitives ([`f96fcce`](https://github.com/ossiq/ossiq/commit/f96fcce04ed5e1517a51bb459eed3c4afbeffa03))
Foundational additions used by the rest of this branch's cleanup pass:
- SourceFetch[T] + combine_statuses(): batch adapter methods (GitHub, EPSS,
  OSV, npm) now return their payload paired with a DataSourceStatus instead
  of leaving a mutable `last_summary` on the adapter for the caller to read
  back afterwards. Lower layers return diagnostics as values, per the house
  rule, instead of stashing them on adapter state.
- EngineContext, ScanStep, WIDENING_RUNGS/RUNG_ORDER/rung_scope_label: single
  definitions for facts and orderings that had drifted across call sites.
- normalize_dist_name / NameValueSpecError / parse_name_value_specs: moved
  into domain/ (pure) so `strategy/` no longer has to reach into
  adapters/package_managers/utils.py for a string-normalization helper, and
  so `--override` and `--strategy-override` parse and dedupe consistently.
- pad_npm_version: one npm version-padding implementation shared by
  major_key, npm_sort_key and library_scan instead of three copies.
- ApplicationError.render(): one title+hint formatter both CLI and MCP can
  use, rather than each re-deriving the same three-part message.
- domain/compatibility.py: CompatibilityFacts, the ladder + module-system +
  engine cluster lifted off ScanRecord (wired up in a later commit).
- solver/version_matchers.py: fixed npm_version_satisfies_range's handling
  of a `||` union of tilde ranges (e.g. "~5.5.8 || ~5.5.10"), which univers
  was flattening into an ungrouped constraint list and evaluating as if the
  branches were joined by AND — silently reclassifying an out-of-range
  version as satisfying the constraint.

* refactor: renamed binary ossiq-cli -> ossiq (GH-122) ([`193a8b5`](https://github.com/ossiq/ossiq/commit/193a8b5357f8a038fcc5780ffc65076fa4cb131a))
Renamed binary to align with the package name
and fixed some version identification.

* refactor: removed CSV export and older export versions (GH-121) ([`0f8c28d`](https://github.com/ossiq/ossiq/commit/0f8c28d2ee9deabfb61bdb0d78ee4ff7c9a6d352))
Removed totally CSV export cabaility: there's nothing
impossible to do with the JSON export. Also, sunset
older export versions.

* refactor: Health Score pivot, roll back logic and introduction of EPSSg (GH-60) ([`c56b784`](https://github.com/ossiq/ossiq/commit/c56b784d366632dfc38e4008a4fc54e42e08763c))
After long considerations, Health Score is not the right
direction. There are too many unbacked assumptions to make
it useful at this moment. Instead, implemented a prototype
of the Grouped EPSS, the concept introduced by
Stephen Shaffer in the article "Modeling Asset Risk Using EPSS".
Grouped Risk combines the individual probabilities
of every CVE into a single score that answers one question:
What are the overall odds that an attacker
exploits at least one of them over the next month?

* refactor: streamlined console renderers code (GH-65) ([`66549d3`](https://github.com/ossiq/ossiq/commit/66549d3418c2027c69e3647a8520b28a1b737a97))
`info` renderer needed to be changed, so I go
ahead and streamlined how different blocks rendered
as well as combined same blocks renderers for
info and status commands.


### Documentation

* docs: document the provenance chain and how to verify a release (GH-122) ([`68ae93c`](https://github.com/ossiq/ossiq/commit/68ae93c955a39c69b6b86ddff4fc16550b096622))
New SECURITY.md covers the vulnerability-reporting policy and the supply-
chain posture (Trusted Publishing, pinned/hashed deps, SLSA L3 provenance).
docs/how-to/verifying-a-release.md gives the exact gh attestation verify
commands per channel; RELEASE.md cross-references both and explains why the
release.yml/binaries.yml filenames and the reusable workflow names are fixed.

* docs: document export profiles and fixed_in (GH-143) ([`aa2f27e`](https://github.com/ossiq/ossiq/commit/aa2f27e5eb1ea60a9d3ca5f5bdd9ed6046bc215c))
The export README covers the two profiles, where a field's profile
is decided and the second schema a version bump now needs. SKILL.md
tells agents which export to hand over and how to read fixed_in.

* docs: document stated runtime, module-line policy, update verdict (GH-143) ([`3566501`](https://github.com/ossiq/ossiq/commit/35665010db546a3fe6348bec8d15cfeaa6f784ee))
Reference, recommendations, repository-stability and SKILL.md cover
the MCP runtime argument, --engine, tier-qualified ESM-only
recommendations, the comparison verdict and the dependency_health
rename.

* docs: reconcile recommendations.md with what the tool now does ([`4756a92`](https://github.com/ossiq/ossiq/commit/4756a92acf41cd12935ce6db6cc216e4f31e053d))
Sweep after the seven fixes. The §3.2 warning box, both §6 warning bullets and
the §6 HTML/exit-code rows described defects that no longer exist; §1's worked
example and §4's engine tables were re-run against actual output rather than
edited by hand.
Also fixes the links the file broke when it moved out of explanation/ — its
../reference.md and repository-stability.md targets resolved from the old
location — and wires it into the toctree, which still pointed at use-cases.
Sphinx goes from 9 warnings to a clean build.
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>

* docs: updated documentation and landing with new binary name (GH-122) ([`5464bb4`](https://github.com/ossiq/ossiq/commit/5464bb46df915f272ddd76e6819885262e0d49d3))

* docs: Updated README.md (GH-121) ([`fceed6e`](https://github.com/ossiq/ossiq/commit/fceed6e3209588371757061018fab6f86cc88af6))
Reflected lack of CSV/older versions of JSON export schema

* docs: updated docs to remove CSV/reference to the older export versions (GH-121) ([`e39b1a0`](https://github.com/ossiq/ossiq/commit/e39b1a0640b08f677a804ea6c608c7c6693cf9b4))

* docs: updated README, getting started, reference (GH-60) ([`3bf874c`](https://github.com/ossiq/ossiq/commit/3bf874c878365d1d1755a23fbeb52b8ea4c0d238))

* docs: added QA instruction how to calibrate CSI and updated the docs (GH-60) ([`37679a4`](https://github.com/ossiq/ossiq/commit/37679a4a9fd1d59f97ce6ba70288d4f425a23e5a))

* docs: updated documentation and added tests (GH-65) ([`97840e4`](https://github.com/ossiq/ossiq/commit/97840e4690b8006e508202bfdc32d5c0df1a74a0))

* docs: added comprehensive spec for the Health Score (GH-100) ([`8a22442`](https://github.com/ossiq/ossiq/commit/8a224420743466d29cafb109ff2527fb8b524838))
Added comprehensive spec for the Health Score for
the reference as well as Mermaid diagramming tool
to the Sphinx documentation.

* docs: updated docstring for compute_exposure_window (GH-99) ([`5cf7a24`](https://github.com/ossiq/ossiq/commit/5cf7a24e5e0788c36de8256227d8c82f333b3584))

* docs: updated SEO and changed hero section for the Poisoned Well ([`370e773`](https://github.com/ossiq/ossiq/commit/370e77350f940886a9bb3e0a8542c48e7f55e641))


### Test

* test(release): remove the testpypi rehearsal job (GH-122) ([`671360d`](https://github.com/ossiq/ossiq/commit/671360d438de539d00aed4ec0a9224241947f288))
TODO.md #3: the OIDC exchange against TestPyPI's pending publisher
was proven (run 36060445758, no invalid-publisher, both files
uploaded to test.pypi.org). release.yml is back to its pre-rehearsal
state.

* test(release): gate testpypi rehearsal on a tag, not a branch (GH-122) ([`703b4fa`](https://github.com/ossiq/ossiq/commit/703b4fa5dbc9c0e3b72a41a39cfac55507bbbe1b))
The release environment's deployment-branch-policy only admits refs
matching v*, so a branch-guarded if condition can never satisfy it.

* test(release): rehearse the TestPyPI trusted publisher (GH-122) ([`d445945`](https://github.com/ossiq/ossiq/commit/d445945186ff75fc9c41c88cfb1cf5f47ae8feb1))
Temporary: adds a branch-guarded publish-testpypi job so the OIDC
exchange against TestPyPI's pending publisher can be proven before a
real PyPI release is cut. Gates the real publish job to release
events so the new workflow_dispatch trigger can't reach it.
Remove once TODO.md #3 is checked off.

* test(ci): assert the supply-chain invariants across .github/workflows/ (GH-122) ([`f069777`](https://github.com/ossiq/ossiq/commit/f0697776c75cb1e1eaed5291bd2b2c9bfe59b110))
Encodes the SLSA L3 posture as tests rather than tribal knowledge: every
non-local action pinned to a full commit SHA, no workflow missing a
permissions block, secrets only reaching trusted action owners, and the
PyPI/npm trusted-publisher bindings (workflow filename, environment) left
intact. Needs pyyaml, added as a dev dependency, to parse the workflow files.

* test: measure both export profiles in export_size.py (GH-143) ([`df96951`](https://github.com/ossiq/ossiq/commit/df969519ef5ff30a41bce168d58bdd929d4e3db8))
export_size.py reports the standard and full export next to the
agent payload, and reads development_packages instead of
optional_packages.

* test: add MCP determinism and export-size repro scripts (GH-143) ([`516ce20`](https://github.com/ossiq/ossiq/commit/516ce201bca0e22c5850e763a9950beaa373a627))
mcp_determinism.py starts a fresh MCP server per run and varies one
input at a time, including the stated runtime. export_size.py
measures the export payload per field.

* test: add small CommonJS and PyPI fixture projects (GH-143) ([`7ba8158`](https://github.com/ossiq/ossiq/commit/7ba81581d85fa3ebbc06eb66eea26e2be5870e8f))
Add testdata/npm/small-cjs and testdata/pypi/small-py with exact
pins, lockfiles and a smoke test that require()s or imports every
dependency. Exclude testdata/ from ty, since the fixtures import
their own outdated dependencies.


### Chore

* chore: renormalize remaining CRLF files to LF ([`48ecdd4`](https://github.com/ossiq/ossiq/commit/48ecdd4c4231c15b4b8d4272ebd8b19551bf2fc1))
Four files were committed with CRLF before .gitattributes pinned
eol=lf, so Git kept reporting them as modified whenever it
re-checked them.

* chore(tests): store test_install.py with LF line endings (GH-122) ([`cbe8d76`](https://github.com/ossiq/ossiq/commit/cbe8d76f52e126a8742cd58e6f2d8d6e1fd103b8))
The file was committed with CRLF, which .gitattributes forbids for
*.py, so it showed as modified on every checkout. No content change.

* chore(ci): pin third-party GitHub Actions to commit SHAs (GH-122) ([`ea10482`](https://github.com/ossiq/ossiq/commit/ea10482a755e52a4142ab98f62e90345b6622b53))
Floating tags (@v6, @v7, ...) are mutable, so a workflow using one can build
against different code than what was reviewed; every third-party action now
pins a full commit SHA, kept current by the new Dependabot config. Two
workflows also gained an explicit permissions block where none previously
existed, and extractions/setup-just (which needed a PAT) is dropped in favor
of the now-locked rust-just dev dependency.

* chore(build): bound the build backend and freeze the lock's resolution cutoff (GH-122) ([`8faa51b`](https://github.com/ossiq/ossiq/commit/8faa51b609c5a7615c9649dcf134d6761d777858))
hatchling now resolves from a range (with an upper bound) instead of unpinned,
so a fresh PEP 517 resolve can't silently pull in a breaking major; the
release build still takes it from uv.lock via --no-build-isolation. exclude-
newer moved from a relative "5 days" to an absolute UTC timestamp so re-
locking to pick up a fix no longer depends on the day it happens to run.

* chore: ignore local TODO.md and PLAN.md (GH-122) ([`d9e3e0b`](https://github.com/ossiq/ossiq/commit/d9e3e0b0b014200865ae08cc160a09e1c5c1dfa2))
These are scratch planning files for in-progress work, not project docs.

* chore: newline in getting-started.md and ossiq deps update (GH-140) ([`df6f5ab`](https://github.com/ossiq/ossiq/commit/df6f5ab7fe39b8276f4568e421fe37844c7396e7))

* chore: simplified few unit tests (GH-127) ([`a7af49d`](https://github.com/ossiq/ossiq/commit/a7af49d1372db61ecae7015d43761d9e5733dd05))

* chore: normalize CRLF line endings and add .gitattributes ([`1e5e4e1`](https://github.com/ossiq/ossiq/commit/1e5e4e1b068fec7da051fd90d2f0709f005d6b14))
Four tracked files (docs/reference.md, ui/renderers/agent/console.py,
test_project_sources.py, test_json_schema_registry_v1_5.py) were stored with
CRLF endings and kept flipping to LF on edit, inflating review diffs by
thousands of phantom lines. Add .gitattributes (* text=auto eol=lf, with
per-extension pins) and normalize these four to LF so future edits produce
clean diffs.

* chore: remaining strategy artefacts (GH-127) ([`c9afc57`](https://github.com/ossiq/ossiq/commit/c9afc57094ed12bc4379feac4204132f7bfedf2e))

* chore: added LR as default line breaker (GH-122) ([`daa2fde`](https://github.com/ossiq/ossiq/commit/daa2fdefe2038b0b41752287d39f54678235b5d8))

* chore: updated QA test cases with the new binary name (GH-122) ([`1173d2f`](https://github.com/ossiq/ossiq/commit/1173d2f77edc793921d51092f0650b03501e27d9))

* chore(deps): Bump tornado in the uv group across 1 directory ([`6feea89`](https://github.com/ossiq/ossiq/commit/6feea89002cc991bde2af7c202aadbe623e884f3))
Bumps the uv group with 1 update in the / directory: [tornado](https://github.com/tornadoweb/tornado).
Updates `tornado` from 6.5.5 to 6.5.8
- [Changelog](https://github.com/tornadoweb/tornado/blob/master/docs/releases.rst)
- [Commits](https://github.com/tornadoweb/tornado/compare/v6.5.5...v6.5.8)
---
updated-dependencies:
- dependency-name: tornado
  dependency-version: 6.5.7
  dependency-type: indirect
...

* chore: Omitted json export format (GH-121) ([`cce3123`](https://github.com/ossiq/ossiq/commit/cce3123e0ae7cccec6dc4c6c0359691ba2864115))
Omitted JSON export format from the GA workflow
since there's only one option left.

* chore: updated QA documentation related to CSV and export versions (GH-121) ([`d8e1eb7`](https://github.com/ossiq/ossiq/commit/d8e1eb7940281bff246786314bb924798444dfd4))

* chore: fixed broken frontend build process due to argument passed to the npm 12 (GH-60) ([`75cac40`](https://github.com/ossiq/ossiq/commit/75cac40ebeb20c01c4923a19e1f4d10a98429820))

* chore: updated pyproject and reference doc (GH-60) ([`8a4299c`](https://github.com/ossiq/ossiq/commit/8a4299cc2fb2eb520481a22d29929803ab2074e2))

* chore: added QA scripts and classfier calibration guide (GH-60) ([`77f00c8`](https://github.com/ossiq/ossiq/commit/77f00c8b24c0f7a6bebb48d5e5fb3b11f6e3bdab))
Updated docs how to quality check LLM integratio and
calibrate Bayesian classifier.

* chore: removed CSI references from the HTML report (GH-60) ([`718fff5`](https://github.com/ossiq/ossiq/commit/718fff534c138dda6d8f7d54987e44a015362111))

* chore: clearned up CSI references (GH-60) ([`6e0ffde`](https://github.com/ossiq/ossiq/commit/6e0ffde38cf318b6a3c8fb737d0fb1dc377cc93b))
Cleanup after CSI implementation in favour of
Bayesian classifier: removed naming and
references in the docstrings.

* chore: updated FE and BE dependencies (GH-60) ([`689c297`](https://github.com/ossiq/ossiq/commit/689c2973c3b80bb783698f83be69f5f3545b69dc))

* chore: bumped transitive and direct dependencies with ossiq (GH-64) ([`4ab1e7b`](https://github.com/ossiq/ossiq/commit/4ab1e7bde577858d00394c2578c014cc5fee807f))

* chore: updated dependencies for ossiq python and frontend projects (GH-100) ([`c2444a7`](https://github.com/ossiq/ossiq/commit/c2444a7685e96e36020e1b16214b540702f1e904))


### Unknown

* unknown: docs+fix: manifest-inspection hint names actual adapters; doc sync ([`33e2558`](https://github.com/ossiq/ossiq/commit/33e25582fc6b5621f64a5f1000ac649cd9282cb1))
sources/project_sources.py's UnknownProjectPackageManager hint now calls
adapters.package_managers.api.inspected_manifests() to name the manifest
files that were actually probed, instead of a hardcoded
("pyproject.toml", "package.json", "requirements.txt") tuple that both
duplicated adapter knowledge and claimed Poetry support that doesn't exist.
docs/reference.md and data/SKILL.md updated to match this pass's behaviour
changes (ladder/compatibility fields, update-context, strategy options).

* unknown: fix(item 13): execute_update parses pyproject.toml once instead of per-package (GH-127) ([`9603a21`](https://github.com/ossiq/ossiq/commit/9603a21cc9755c14037bde7f6580356e57b4f597))
find_pyproject_direct_specifiers was called once per changed direct
dependency inside execute_update's rewrite loop, each call re-parsing
the whole document with tomllib.loads from scratch - an O(n) redundant
re-parse for n changed packages. Worse: a TOMLDecodeError there was
swallowed and returned [], so a parse failure on any iteration would
silently make every *remaining* package in the loop receive no rewrite
with no error raised - a new silent-partial-success mode in code whose
entire purpose was eliminating exactly that failure class.
execute_update now parses pyproject.toml once up front and buckets every
direct dependency string by normalised name before rewriting anything; a
parse failure now raises PackageManagerExecutionError for the whole
update instead of degrading package-by-package. Split
find_pyproject_direct_specifiers's parsing into a reusable
_direct_dependency_strings(data) helper so both call sites share one
parse-and-bucket path without re-parsing; find_pyproject_direct_specifiers
itself is unchanged for its existing callers/tests.

* unknown: fix(item 13): manifest writer silently destroyed packages sharing a name prefix (GH-127) ([`f4dd886`](https://github.com/ossiq/ossiq/commit/f4dd88660a3cb488e7dbaf0e0264f44febec1be7))
Confirmed, not just suspected. Reproduced the exact corruption the plan describes
(duplicate pydantic==X where pydantic-settings==Y belonged) through the real
execute_update function end to end, in a real temp project, with only subprocess.run
mocked:
  before: "pydantic==1.10.13", "pydantic-settings==2.15.0", "requests==2.28.1"
  updating pydantic to 1.10.26, old code produced:
  after:  "pydantic==1.10.26", "pydantic==1.10.26",          "requests==2.28.1"
pydantic-settings wasn't just left stale - it was gone, overwritten by a duplicate
pydantic line.
Root cause: execute_update's pyproject.toml rewrite matched
`"{package_name}[^"]*"` via regex - a bare prefix, not a package-name boundary.
"pydantic-settings==2.15.0" starts with "pydantic", so it matched too, and re.sub
replaces every match with the same new spec. This is an extremely common naming
pattern in the Python ecosystem (flask/flask-cors, pytest/pytest-cov,
click/click-plugins, numpy/numpydoc, ...), so the practical blast radius is large -
not a pydantic-specific edge case.
Checked the other two writers for the same pattern: api_pip_classic.py writes a
temp constraints file and never rewrites requirements.txt directly (unaffected);
api_npm.py parses package.json into a dict and does exact key lookups (unaffected).
The bug is isolated to api_uv.py.
Fix: find_pyproject_direct_specifiers (new) parses pyproject.toml with tomllib
(read-only, already used elsewhere in this file) and returns the exact, verbatim
dependency string(s) whose name normalises to the target package - reusing
Requirement/normalize_dist_name, both already established patterns in this exact
file (parse_pyproject_direct_specifiers uses the same combination for a different
purpose). execute_update now replaces those exact literal strings instead of
matching by prefix. Considered switching to tomlkit for fully structural editing,
but it's not currently a direct project dependency - adding one felt like a bigger,
separate decision than this fix warranted, so this stays consistent with the
file's existing text-based-edit-with-structural-lookup approach (see
upsert_uv_override_dependencies's docstring for the same rationale: keep the rest
of the file byte-identical).
Handles what the previous approach couldn't: name matching now goes through the
same PyPI normalisation used to parse the file in the first place (case,
-/_/. equivalence), and a package declared in more than one place (main list and
an optional-dependencies group) is correctly updated in every location rather than
only the first regex match.
Tests: tests/adapters/package_managers/test_api_uv.py - unit tests for
find_pyproject_direct_specifiers (prefix rejection, normalisation, multiple
sections, invalid TOML, unparseable requirement strings), and an
execute_update suite covering the exact reported corruption, the reverse
direction (updating the longer name must not touch the shorter one), four other
real-world prefix pairs (flask/flask-cors, pytest/pytest-cov, click/click-plugins,
numpy/numpydoc), the plan's own prescribed round-trip property (every dependency
present before a write is present after it, with only the intended specifier
changed), multi-section updates, and a no-op case. Confirmed these tests actually
catch the regression: temporarily restored the old regex, reran, and got exactly
the 6 failures touching the corruption scenario - the 3 unrelated cases (reverse
direction, multi-section, no-op) correctly still passed on the buggy code, since
they don't exercise the prefix collision. Full suite: 1522 passed, 1 skipped, zero
regressions.
ruff format reformatting after rebase, no semantic change.

* unknown: feature: added NPM release and updated Github Actions (GH-122) ([`c1fd08a`](https://github.com/ossiq/ossiq/commit/c1fd08ada0ef1143c9c3533a24f6d9ec3b215b73))
Added `binaries.yml` github actions to build NPM
binaries as well as updated other actions with
the new binary name.

* unknown: feature: html report new action "constrained" (GH-60) ([`b322d0f`](https://github.com/ossiq/ossiq/commit/b322d0fc69165dc2576e9550c1f7371a396cf0d1))

* unknown: feature: added "constrained" action (GH-60) ([`e401d1d`](https://github.com/ossiq/ossiq/commit/e401d1d4d83aecf96d72d40077244b0629275a5c))
For dependencies constrained by the ~ or ^
and offer what needs to be done next.

* unknown: added a new report overview to the index page, created a new report on supply chain attacks ([`ceb4760`](https://github.com/ossiq/ossiq/commit/ceb4760c3f8c765a4a1b9534fa4cf9bfa0fcdb70))

## v0.1.10 (2026-07-15)


### Feature

* feat: added mcp/skill MVP implementation (GH-94) ([`f676bb3`](https://github.com/ossiq/ossiq/commit/f676bb3e74497e095a470c4536d6fdbc9713a926))
Introduced MCP and SKILL.md initial implementations
via special formatting to minimize token usage and
maximize utility.

* feat: split status command HTML report into separate command and update UI (GH-96) ([`98f08ff`](https://github.com/ossiq/ossiq/commit/98f08ffd5891c7914b7fcb1610d713e1013819b5))
Split `status` command HTML report generation into separate `html` command
to streamline flows and simplify UX. Simplified `info` command for
a package representation. Updated user-facing documentation.

* feat: add command and respective implementations for different package managers (GH-96) ([`6dd542c`](https://github.com/ossiq/ossiq/commit/6dd542ca4cfeba7ca7c995314c8cd4f1e28baea6))
Added interface to install new dependencies as well as implementations
of it in all supported package managers.

* feat: introduced add command and package info (GH-96) ([`9b6c671`](https://github.com/ossiq/ossiq/commit/9b6c671f875c09aeb7e94819c6eb5cad4ac1fe88))
Introduced non-installed package details
option (for `info` command) and separate `add`
command boilerplate (WIP) to add new dependencies.

* feat: added comprehensive error handling mechanism (GH-95) ([`d8968ff`](https://github.com/ossiq/ossiq/commit/d8968ffc08ed2e024d0e82ce97a95c0018287494))


### Fix

* fix: secured github.com url detection in package path (GH-94) ([`3122f64`](https://github.com/ossiq/ossiq/commit/3122f64d235f29ac6950e280ad59b1566c53d2ac))

* fix: fixed --ignore behavior which makes it dissapear from the report (GH-94) ([`4165d01`](https://github.com/ossiq/ossiq/commit/4165d01fb4d07d7b2b875c9f643406298ef10b86))
With --ignore flag there'll be no recommendations generated, but
dependency still will be shown in the report.

* fix: fixed behavior for aliased package names in NPM (GH-94) ([`e5fbfb4`](https://github.com/ossiq/ossiq/commit/e5fbfb410532b4507eb4bacf803001379b422a98))
package.json aliases one real package under multiple names
(e.g. "ms-zero-caret": "npm:ms@^0.7.0", "ms-zero-tilde": "npm:ms@*")
wasn't correctly recommended by the solver.

* fix: Fix solver recommending unsatisfiable dependency constraints (GH-94) ([`2c41fc5`](https://github.com/ossiq/ossiq/commit/2c41fc5d94578137a83289fa8dc41e65ad034cdb))
Fixed unsatisfiable update for test case when
project direct dependency constraints contradiction when
version constraint is package>$version, but transitive
dependency contains version constraints with
the contradiction package<$version

* fix: fixed accidental exposure of github-token via --verbose flag (GH-94) ([`052a8bc`](https://github.com/ossiq/ossiq/commit/052a8bcb435f08baf78e3fc13183dcf9c2044aaa))

* fix: fixed install command naming for dev mode (GH-94) ([`788dc7b`](https://github.com/ossiq/ossiq/commit/788dc7bd660e04c22b1f09b71360c27c616f7df6))

* fix: fixed beta-ended versions handling for NPM (GH-94) ([`0f39085`](https://github.com/ossiq/ossiq/commit/0f39085cc08f1acf5ac5ed8e042c20d67f99a065))
If there are "beta" versions with endings like
9.0.0-rc2 comparison didn't work prpoerly and
were not able to check for version validity.

* fix: reverted status behavior to always show depenencies status (GH-95) ([`6e2752a`](https://github.com/ossiq/ossiq/commit/6e2752ab73f418769be654dc8106e5fd2838465b))


### Refactor

* refactor: broke down project service into smaller pieces (GH-94) ([`f925be5`](https://github.com/ossiq/ossiq/commit/f925be59031332a05a2fbcbf31b1d412de65cc49))
service/project.py became too large to comprehend with
the direct packages references from git gets ignored,
hence broke down it into smaller pieces.

* refactor: removed --script parameter of the plan command (GH-94) ([`763447a`](https://github.com/ossiq/ossiq/commit/763447aa4115b2d847d66b7a892b4cb3ca4b2dcb))
--script parameter was introduced in the previous release
to demonstrate what would be run on `apply`, but
there's no real need as for now.

* refactor: introduced pydantic-settings for the OSS IQ config file (GH-94) ([`9aedeb1`](https://github.com/ossiq/ossiq/commit/9aedeb199d030971c834e5fb8b416f542a168023))
Introduced pytdantic-settings to leverage as much as possible
standartized solution for configuration management as well
as modified install command to leverage dotenv package
(transitive to pydantic-setting) to write github token
for the SKILLS/MCP server.

* refactor: fixed generic Exception handlers across the codebase (GH-96) ([`d2fe26d`](https://github.com/ossiq/ossiq/commit/d2fe26d7767c098182c1747558a54d12571c27f5))

* refactor: streamlined package structure for commands and renderers (GH-96) ([`4cbb5b8`](https://github.com/ossiq/ossiq/commit/4cbb5b8e963575e4ef8129a2a4da081668896649))

* refactor: added vertical stepper to show what is going on (GH-95) ([`46f2e46`](https://github.com/ossiq/ossiq/commit/46f2e461f9d8b80fdd4ef08bc9b132b7c940e42e))

* refactor: refactored out Unit of work naming since it is not UoW (GH-95) ([`101fdc4`](https://github.com/ossiq/ossiq/commit/101fdc46bdb66e857de750ec5109b28eace18aa4))
Refactored remaining files/names mention Unit of work and split
unit_of_work module into solver and sources modules to reflect
what is inside in more precise manner.

* refactor: slashed unused abstract classes (GH-95) ([`f96fb2b`](https://github.com/ossiq/ossiq/commit/f96fb2b1b47abcd5f5f5c4b00d1ccfca39016347))
Removed API OSV abstract class and Github repository
abstract class.

* refactor: refactored Unit of Work to Sources and extracted VersionRules (GH-95) ([`60a7385`](https://github.com/ossiq/ossiq/commit/60a738590ef78308f56f03b50d3931cca12fecfb))
Renamed Unit Of Work to ProjectSources and abstracted out
VersionRules from package registries abstract class. Also,
fixed method names.


### Documentation

* docs: updated screenshots with the new UI of status and info commands (GH-94) ([`63dfcab`](https://github.com/ossiq/ossiq/commit/63dfcab27067a0a13b245e1e90e2642aa010df4b))

* docs: updated reference, getting started and readme (GH-94) ([`caa1f41`](https://github.com/ossiq/ossiq/commit/caa1f417e5f54e6b427452ea219ee26fa15687f0))
Updated References with more detailed description
of states as well as with the recovery paths.

* docs: update docs for the solver and other minor changes (GH-94) ([`8de00d8`](https://github.com/ossiq/ossiq/commit/8de00d8fc580509498b62938d759dd40dfc97031))
Updated landing.html, README.md and solver/README.md
to reflect respective changes in configuration and
support of SKILLS.md/MCP Server.

* docs: aligned domain README with the implementation (GH-95) ([`1b1a3c6`](https://github.com/ossiq/ossiq/commit/1b1a3c6ce6ae8fc91ce5438e09973ecda8854650))

* docs: updated public API MSR docs (GH-95) ([`2b9f7a9`](https://github.com/ossiq/ossiq/commit/2b9f7a9de48125608db588cea8d6ba03b6928773))


### Chore

* chore: fixed docs and small gaps in docker workflow (GH-94) ([`c5305b6`](https://github.com/ossiq/ossiq/commit/c5305b6f0ad9971cc70ac700a966e17c97add5d2))

* chore: aligned test cases with --script removal (GH-94) ([`0710561`](https://github.com/ossiq/ossiq/commit/0710561c03d7fe04617d17f3fea0e56e5c7bee7e))

* chore: removed not needed pyproject.toml file (GH-95) ([`8fb20f4`](https://github.com/ossiq/ossiq/commit/8fb20f4b5c9cb04d95cdab3fe821454077da65f7))

* chore: updated dependencies (GH-95) ([`8ce6564`](https://github.com/ossiq/ossiq/commit/8ce65641189f57550b87ce9443e09573093297de))

* chore: updated test cases to do the qa (GH-95) ([`94afc05`](https://github.com/ossiq/ossiq/commit/94afc053aaa5165ffc6fd1af7331589dfaceeef1))

## v0.1.9 (2026-06-23)


### Feature

* feat: separate MSR APIs from cli (GH-75) ([`314c828`](https://github.com/ossiq/ossiq/commit/314c8283ccb4b6d4f20e21a09f90a86e08bb2609))
There are two very different use cases provided by
the OSS IQ package: a CLI, the command line interface
to manage dependencies for NPM/PyPI and MSR APIs
(Mining Software Repositories) to enable other
projects leverage infrastructure to aggregate
information across different dependencies sources.
Also, updated Reference documentation to document
MSR APIs.

* feat: cooldown period, override package and security (GH-75) ([`9ca042c`](https://github.com/ossiq/ossiq/commit/9ca042c0ac783eec4dc7885b9b3134d30e5ff8e7))
Finished consistent UX for the plan/apply behavior to
cover use cases with cooldown period (7 days) with exception
of the new transitive dependencies (warning for now).
Added --override pkg==version option to force package
versions which in quarantine (outside of cooldown period).
Wrapped up --security option to just focus on security-related
updates.

* feat: added experimental implementation for lockfile-less projects (GH-75) ([`3d4ae22`](https://github.com/ossiq/ossiq/commit/3d4ae224bb5aa38254538e21f81d83f63a61f7cc))
Additional use case for packages without lockfile. The example
would be open source packages like React which are not final
product and must keep dependencies flexible instead of locked.

* feat: added cutoff date and update plan commands (GH-75) ([`1de85bc`](https://github.com/ossiq/ossiq/commit/1de85bcb152ad1c874a5b1c93a018a046a2fd795))
Adde cutoff date param to produce deterministic
update plans as well as execution of update plans
directly via ossiq-cli without intermediate shell script.

* feat: added concept of helper functions to simplify update process (GH-75) ([`f8ddb05`](https://github.com/ossiq/ossiq/commit/f8ddb05422274ba782cb5e47b3a1035d92ff4182))
For NPM there's complicated process to freeze/unfreeze
dependency tree which requires additional manipulations
with package.json - hence added helpers (semi) dynamic
interface to simplify update scripts.

* feat: added NPM override diff subcommand to recover update state (GH-75) ([`f15b712`](https://github.com/ossiq/ossiq/commit/f15b71267b19c962d586807b7b2431a5eadfdd7e))
After locking in package.json dependencies tree state leveraging
override configuration special command needed to get package.json
to the previous state, since everything is locked in now in package-lock.json

* feat: introduced --ignore/-i option for the oss-iq (GH-75) ([`7418d5a`](https://github.com/ossiq/ossiq/commit/7418d5ab186059e32858ce9e6c4ac7f88b425c62))
Introduced parameter to specify packages to ignore
during solver phase/recommendations generation. It would
allow to properly support overrides/internal knowledge
about compatibility beyond what is in pyproject.toml/package.json

* feat: Updated update command to accomodate new parameters (GH-75) ([`1e1ae16`](https://github.com/ossiq/ossiq/commit/1e1ae16d2eccc836ec61c019894d50f1b82d8c9d))
Added new parameters to update command, to accomodate
new user experience.

* feat: version specifier rewrite for pypi and npm (GH-75) ([`2442812`](https://github.com/ossiq/ossiq/commit/24428125e752c72d4e4eca4818d2295d5f8c9342))
First step of several to allow to modify version
specifier during update process.

* feat: added consideration of engine/python version (GH-75) ([`aa74569`](https://github.com/ossiq/ossiq/commit/aa74569360155e4bffa1fda4e3290ccd3ace00be))
Completed the infrastructure to consider node engine
and python version during update versions recommendations.

* feat: added update command to udpate transitive and direct dependencies (GH-75) ([`d7f8847`](https://github.com/ossiq/ossiq/commit/d7f884702b734a6f09b2e887aa8432a9fca7674a))
Added prototype of udpate command to generate commands (bash)
for the respective package manager (pip/uv/npm) to properly
update transitive and direct dependencies recommended by
the solver.

* feat: updated adapters to streamline work with versions (GH-75) ([`1758ae6`](https://github.com/ossiq/ossiq/commit/1758ae6083a7c6c790c1614c34221e6f53f2c338))
Updated registry adapters as well as package manager adapter
for UV to work with update command.

* feat: prototype of separate transitive dependencies recommendations (GH-75) ([`1fe5088`](https://github.com/ossiq/ossiq/commit/1fe5088d80ce4c392f06cb7e606634cf1c05342f))
Added --transitive command line (default: false) to show
transitive dependencies recommendations report.

* feat: update to solver to support dimond transitive dependency (GH-75) ([`28b31c6`](https://github.com/ossiq/ossiq/commit/28b31c6517c8801ad695c497afaa30ab9ef9eea1))
Added initial step to support dimont transitive dependencies
constraints as well as prepare for the transitive-aware
update recommendations/actionable update recommendations.

* feat: prototype of update command interface (GH-75) ([`c8edefd`](https://github.com/ossiq/ossiq/commit/c8edefdef21665a99e8561f1652df3a340a036dc))
Prototype of the update command to generate atomic
updates. In current implementation no transitive
dependencies supported.

* feat: refactored versions constraint parser to universe package (GH-76) ([`9c38772`](https://github.com/ossiq/ossiq/commit/9c3877287b0000790dd2128f69888e0f305d66ab))
Refactored from hand-made prototype level dependencies versions
constraint parser to `universe` package which is the most
popular package for this task. Also, refactored SAT encoder
to more readable version, so it is clear what variable/
constraints are encoded into what. Fixed some comments.

* feat: refactored solver prototype to consider transitive dependencies (GH-76) ([`9a40c60`](https://github.com/ossiq/ossiq/commit/9a40c604d9700ba4afc7ea4e8e1b2a4f81738562))
Initial version were too slow even for small projects
and disn't consider transitive dependencies. For larger
projects it is important, since there might be hard
constraints for what versions have to be used in
the transitive dependencies.

* feat: updated with transitive dependencies solver (GH-76) ([`44941bc`](https://github.com/ossiq/ossiq/commit/44941bce66910f93edcea69c5a6493ac1d5afbde))

* feat: added use_solver command temporarily for solver validation (GH-76) ([`dbfab89`](https://github.com/ossiq/ossiq/commit/dbfab8973011bc515a4f9dc0b443d856b592ed70))

* feat: added constraints encoder prototype (GH-76) ([`5667dc6`](https://github.com/ossiq/ossiq/commit/5667dc6dc5547be480d45b409b26c1cf90d88e53))

* feat: initial implementation of solvable pool (GH-76) ([`0d8de3d`](https://github.com/ossiq/ossiq/commit/0d8de3d68fec7c9ebbd0f37c67abdad98d6a8895))
Initial implementation of wiring dependencies
data into a solver problem.

* feat: initial steps for the dependency resolution solver (GH-76) ([`244d39a`](https://github.com/ossiq/ossiq/commit/244d39a17187a64856b5f5cb2f8ada0f4641bb0f))

* feat: added version age to the HTML report (GH-43) ([`c4e43c4`](https://github.com/ossiq/ossiq/commit/c4e43c42f6fd118030df136abeaaf3fd826264f8))
Added version age to the HTML report, also
removed datasets -> generated dataset items and
replaced with a UV script to generate datasets
from testdata.

* feat: added Version Age field to show age in absolute units (GH-43) ([`63d04cf`](https://github.com/ossiq/ossiq/commit/63d04cf855a72e820c265fc9a39a0a14ba610c4d))
Added absolute age (days, months, years) in relation to
the date of report generation to show how old package is.
Sometimes, package could be on the latest version and
Drift Status is Latest, but version age is 6 years.
For 6 years package either is extremely good, or
abandoned by the maintainer.

* feat: added deprecated flag to the html report (GH-43) ([`0b9f71c`](https://github.com/ossiq/ossiq/commit/0b9f71ca0fb319f03cf29df8fe9773837bd88ae4))

* feat: added console badge for deprecatred package (GH-43) ([`e619237`](https://github.com/ossiq/ossiq/commit/e61923742c14c58a8eaf4f47cbe5a5e3e5ffc9a7))

* feat: updated schema with deprecated and unpublished attributes (GH-43) ([`07db3f8`](https://github.com/ossiq/ossiq/commit/07db3f8d7f946a87fb01988bc969edc727842257))

* feat: added support of is_deprecated package and version for NPM (GH-43) ([`04fcbc8`](https://github.com/ossiq/ossiq/commit/04fcbc8a5c809625340f4efe0184599e0dd00d7e))

* feat: added yanked/prerelease labels to package details in console (GH-43) ([`70c5a8a`](https://github.com/ossiq/ossiq/commit/70c5a8a5df6f5c033382145c4170561ba8e8433f))

* feat: yanked and prerelease tags in the HTML report (GH-43) ([`afb8e97`](https://github.com/ossiq/ossiq/commit/afb8e97dd88e4745952b4a2edaf8e6699db6a06f))
Added visual indication that installed version is
yanked or pre-release in the HTML report:
 - for Table View there's label "yanked"
 - for Package Details there's label "yanked" next to
   the package version
 - for Dependency Tree Explorer it is new color (purple)
   coding for nodes which are yanked from the PyPI.

* feat: added export schema v1.4 for JSON and CSV (GH-43) ([`b62de5f`](https://github.com/ossiq/ossiq/commit/b62de5f6bdf2f0fa6d337886b3b2e9719e01d1bc))
Added new export schema version to expose
is_yanked and is_prerelease attributes.

* feat: added --allow-prerelease and --allow-prerelease-package commands (GH-43) ([`0a19211`](https://github.com/ossiq/ossiq/commit/0a19211de20268328e5c5e3764015bf4422c786d))
Added two command line parameters:
 - `--allow-prerelease` - allows to install the "latest and greatest"
   pre-release packages versions to risk it all.
 - `--allow-prerelease-package=package-name` - allow to install
   pre-release version of a specific package. Should be useful for
   OSS contributors or for urgent CVE fixes.

* feat: added package version attributes for yanked/prerelease versions (GH-43) ([`6050cac`](https://github.com/ossiq/ossiq/commit/6050cac250518dbb93301aac524fd69a4e67b851))
Added package version attributes to reflect yankdex pypy package,
or prerelease packages (e.g. 1.2.3rc1 and similar). Updated
respective tests.


### Fix

* fix: issue with NPM and transitive dependencies overrides (GH-45) ([`1dd5c13`](https://github.com/ossiq/ossiq/commit/1dd5c137403a4b9feaf3c4c20cc47b6352015b8f))
The issue is leftovers from GH-45 issue related to
the method used to apply and keep transitive dependencies
version. The original idea was to generate recommendations,
write to `overrides`, run `npm install` and then remove
overrides from the package.json. This approach doesn't work
with NPM, since it is mandatory to keep package.json and
package-lock.json in sync. But since specific (pinned)
versions of transitivity is security/deterministic
measure (we actually want to make sure recommended
version will be installed regardless of `npm ci` or
`npm install` methods to prevent "greedy" NPM behavior).

* fix: fixed markup and styling for Scan Report view in HTML report ([`b267f44`](https://github.com/ossiq/ossiq/commit/b267f44f69ce7ee62d3e9fbe037c08636bd6ba7b))
The Recommended Version column was missing and license wasn't
visible in the table. Fixed both.

* fix: fixed stale exact pin issue for NPM (GH-45) ([`8e954c0`](https://github.com/ossiq/ossiq/commit/8e954c0b1c425c23e2135cc84714d3e2c28821ea))
vite 8.0.7 pins rolldown to "==1.0.0rc1" exactly.
After vite bumps to 8.0.15, rolldown is pinned to
"==1.0.0rc3". The old exact constraint from vite 8.0.7
is in rolldown's all_constraints. Without the fix,
merged constraints ["==1.0.0rc1", "==1.0.0rc3"]
are impossible, hence is_actionable=False. Tagged
with the closed GH-45 issue, since it is related.

* fix: fixed various npm-related issues with transitive dependencies (GH-75) ([`8bc5297`](https://github.com/ossiq/ossiq/commit/8bc529716f880cb3ec04ea07b7da0c113067877f))
 - Simplified NPM_BARE_SEMVER regexp
 - Fixed optional dependencies traversal for transitive dependencies
 - Changed behavior of `apply` command for the NPM to keep
   overwritten versions inside package.json due to
   package.json/package-lock.json divergence.

* fix: fixed import for cli and recommended version for uv (GH-75) ([`60accda`](https://github.com/ossiq/ossiq/commit/60accdabbb90655732e0fe9a8d8cb0ce9741b023))
There was wrong version of package used during update
bash script generation.

* fix: fixed detection of installed packages for recommendations report (GH-75) ([`baffd7f`](https://github.com/ossiq/ossiq/commit/baffd7f19eab8547fc29ab6c3423aa571fa9f4ae))
Transitive dependencies from optional section were not considered
during scan, hence updates for the transitive dependencies
recommendations were considered as the "new" dependencies.

* fix: fixed issue with version age and updated console UI (GH-76) ([`5a774ac`](https://github.com/ossiq/ossiq/commit/5a774aceedef439f4f9ffc57b9c6698131cf40cb))
Fixed an issue with too large version age options,
added highlight to recommended version in the scan output
in case recommended doesn't match the latest and removed
duplicates in transitive dependencies recommendations.

* fix: fixed schema issues in 1.4 and version_age_days (GH-43) ([`f6e08ec`](https://github.com/ossiq/ossiq/commit/f6e08ec95647cf1e101acbe15712be6b3bccf5e6))
Fixed issue with the version_age_days field and
refactored tests to follow the same pattern as
JSON schema tests.

* fix: fixed package view in console to show unpublished and deprecated (GH-43) ([`0e7a6a4`](https://github.com/ossiq/ossiq/commit/0e7a6a4166e393533865392dc240b16f43043035))

* fix: fixed conflict with installed beta versions and allow prerelease flag (GH-43) ([`f7d68df`](https://github.com/ossiq/ossiq/commit/f7d68df180b3bcac03c6ec0f08abf38c0847a441))

* fix: fixed bug with legacy licenses in NPM and path expantion (GH-43) ([`ac8425a`](https://github.com/ossiq/ossiq/commit/ac8425a9a893fbb6e50de139f11fd06944212460))
Fixed use case with legacy licenses representation in NPM and
path expantion which haven't supported tilde ~ home folder.


### Refactor

* refactor: overhauled UX for the command line interface (GH-75) ([`c745276`](https://github.com/ossiq/ossiq/commit/c745276a9bf939cca21b4f17f8ecf15870fc2d8b))
Inspired by the article
https://www.loopwerk.io/articles/2026/uv-ux-mess/
and overhauled UX with the command line, since after
introduction of all the parameters it was confusing
and very non-intuitive how to use command line tool.

* refactor: changed solver to PySAT/Glucose (GH-75) ([`8f8c617`](https://github.com/ossiq/ossiq/commit/8f8c617f67c73d1a73a69592a0b21f8924c88937))
Changed RC2Stratified MaxSAT optimization solver
to Glucose to basically pick the newest version,
avoid deprecated preference without MaxSAT overhead.

* refactor: report peer dependencies violations status only in --full mode (GH-75) ([`8558feb`](https://github.com/ossiq/ossiq/commit/8558feb3c573df43d3f207aee981a894b720997b))
By default, only conflicting NPM Peers Dependencies
violations are reported, status of all violations,
even successfull ones reported onder --full scan mode.

* refactor: simplified console UX for scan and export commands (GH-75) ([`8f96896`](https://github.com/ossiq/ossiq/commit/8f968966f346e40fc36cc396eba44f7c185f6caf))
Removed --solver and --transitive modes and enable behavior
by default (we always want to recommend both) as well as
introduce --full flag and change default scan behavior: now
it reports only actionable updates and with --full it will
report state of the all dependencies on the project. The
intent is to reduce noise for the end user, since most
likely sequence of `scan`, then `update` would be used.

* refactor: refactored ladder_amo to be a bit more readable (GH-76) ([`cf80040`](https://github.com/ossiq/ossiq/commit/cf80040c941d72358693094da344996a2a4cbab5))
The original prototype has hard to read implementation of the
ladder encoding.


### Documentation

* docs: udpated READMEs, QA checklist ([`ad1c16c`](https://github.com/ossiq/ossiq/commit/ad1c16ce16b7a927d73093009a8122ff1db7119d))

* docs: fixed left padding for mobile view on landing ([`9b0c2b1`](https://github.com/ossiq/ossiq/commit/9b0c2b1dc99e311b4c22215cb23eeacd804c7c6e))

* docs: updated documentation, landing and screenshots ([`9d54afe`](https://github.com/ossiq/ossiq/commit/9d54afe59c2589ac5db6a5062d93d4f128440b02))

* docs: udpated reports, screenshots and getting started document ([`06a1c1a`](https://github.com/ossiq/ossiq/commit/06a1c1a7a6eaff1a32c543dbf71de12c10642b2d))

* docs: updated landing and fixed journal navigation ([`3b4a8ee`](https://github.com/ossiq/ossiq/commit/3b4a8eee3f59a3dfe9e7f9d3e5507143f51b582e))

* docs: udpated landing and fixed some mistakes in other docs ([`e95d0f5`](https://github.com/ossiq/ossiq/commit/e95d0f5a9ff62490382e9aeb16d52c426d7d2baa))

* docs: added Github Read-Only PAT section ([`0a99c79`](https://github.com/ossiq/ossiq/commit/0a99c7993c6544d3a2b1aaaf5904a07a518385fb))
Added section how ot expose Github Token
securely via Read-Only PAT.

* docs: updated reference and explanation (GH-75) ([`31f2289`](https://github.com/ossiq/ossiq/commit/31f2289792c53f0cba5652c0431b75c034bd50c0))
Added motivation and process description around
--security, --pin-all, plan/apply behavior and
--override.

* docs: fixed mistakes for the AI-generated code article ([`4e893d8`](https://github.com/ossiq/ossiq/commit/4e893d83d7332c02305aa4595521a0ed75c8fc9e))
 - added mobile version with hamburger menu
 - added "subscribe" option
 - fixed mistakes in layout and text
 - added "authors" and "designed by" sections
 - fixed mistakes in references and sources
docs: initial iteration for hamburger menu
docs: refactored chart to use same charting library
docs: finished chapters 4 and 5
docs: updated chapters up to 11
docs: finished main chapter content edits
docs: wrapped up article references
docs: added authors to the article
docs: cleaned up artifacts and some little details

* docs: added journal with initial iteration of the first article ([`dc2e501`](https://github.com/ossiq/ossiq/commit/dc2e5010e0d2ac918533b63908876a6319650321))

* docs: updated documentation and qa test cases (GH-75) ([`78e21da`](https://github.com/ossiq/ossiq/commit/78e21da9af23ba1ffe13a03952d2033b1a48a2f6))

* docs: added high level docs for the dependencies solver (GH-76) ([`a467e27`](https://github.com/ossiq/ossiq/commit/a467e27f9e4b8cecfa03c75e852426b75016e056))


### Chore

* chore: updated frontend build and transitive dependencies ([`63cb1b5`](https://github.com/ossiq/ossiq/commit/63cb1b5df36cfa4bf6056a30f9c129f013cda728))

* chore: bumped few packages with plan/apply commands ([`4bb49e2`](https://github.com/ossiq/ossiq/commit/4bb49e2c0c0b5eaac8bf185d314ab6f5f40ab0e2))

* chore: fixed some tests and minor api_github adapter refactoring (GH-75) ([`3f36360`](https://github.com/ossiq/ossiq/commit/3f36360ba53a42601cbc8330873fafc332576e8a))
Refactored back underscore methods names inside
api_github.py, since it makes it less readable.

* chore: updated packages for the html renderer (GH-75) ([`f2e77b7`](https://github.com/ossiq/ossiq/commit/f2e77b7e9ce02f34fa8054f473e0f80c1da610cd))

* chore: added automated tests script for QA at scale (GH-75) ([`50f2171`](https://github.com/ossiq/ossiq/commit/50f2171ba83bed6b47081c81353d856a1941f1b4))

* chore: added recommended version to export schema and fixed npm (GH-75) ([`af9fee1`](https://github.com/ossiq/ossiq/commit/af9fee1aad993354b294fe294387a22c3d79ee41))
The restore override state logic wasn't correct and fixed.

* chore: dogfooded own ossiq update command to update versions (GH-75) ([`4efafee`](https://github.com/ossiq/ossiq/commit/4efafee9462db78d441061b22bc377b9b5d8e2ba))
Used output of update command to introduce changes into lockfile
with the latest recommended versions. Didin't work well with
pyproject.toml, since it is a library and pinning could mess
up dependent projects.

* chore: updated readme, QA test cases and some minor fixes (GH-75) ([`388b12e`](https://github.com/ossiq/ossiq/commit/388b12ecde16f7d4fd1fd59bc8ae639bf7d9a5d6))

* chore: increased default solver timeout to 120 (GH-76) ([`c0ff58d`](https://github.com/ossiq/ossiq/commit/c0ff58d5feba45586c8158c98c4f20f2a7d15e86))
Increased solver timeout to 120 seconds by default
for larger projects. Later on should be moved to
a command line parameter.

* chore: added preliminary QA process to validate that release is good (GH-76) ([`14ccf46`](https://github.com/ossiq/ossiq/commit/14ccf46126e0cf8c5622a0d1ff4042ea5ac1ba04))
There are enough functionality now in the OSS IQ, so that QA
need to be structured. Added lightweight process to
QA new releases.

* chore: simplified schema versions tests (GH-43) ([`447a271`](https://github.com/ossiq/ossiq/commit/447a271a561c2350c915c7a557323b957e078d98))

* chore: bumped postcss version (GH-43) ([`81d7b4d`](https://github.com/ossiq/ossiq/commit/81d7b4d2a31c6939363f9745521996e9efdfc8d1))


### Unknown

* unknown: light edits on the text ([`a207967`](https://github.com/ossiq/ossiq/commit/a207967075993a5ffaf3b69a0eb067c4f2d9dc95))

* unknown: fixup! feat: prototype of update command interface ([`7090e09`](https://github.com/ossiq/ossiq/commit/7090e091b3e827fa4206c68263ca1c20089bd03b))

* unknown: fixup! feat: refactored versions constraint parser to universe package ([`0754494`](https://github.com/ossiq/ossiq/commit/07544948f04859c56c10cd95eea77a9d49d137ed))

## v0.1.8 (2026-04-29)


### Feature

* feat: Optimized dependency tree explorer (GH-78) ([`652466d`](https://github.com/ossiq/ossiq/commit/652466dee2531f03893dce68c998329c3847a9ed))
Updated UI and UX of the dependency tree representation
with overly deep transitive dependencies. Introduced
new concept of the "super", aggregated node and
separate subtree visualisation. Added CVE highlight
and aggregated duplicate dependencies links to
the grouped nodes.
Additionally, updated documentation, integration
test and UI description for the frontend.

* feat: updated frontend to support compressed schema v1.3 (GH-78) ([`4ed665c`](https://github.com/ossiq/ossiq/commit/4ed665c07c7951842dbfdc184f793b907ebf5768))

* feat: compressed json schema even more (GH-78) ([`a6beedc`](https://github.com/ossiq/ossiq/commit/a6beedc89d55c0cb763715f45ac0f01f23f98d06))
Compressed schema a bit over 10x (120mb to 9mb)
for larger transitive dependencies trees.

* feat: udpated frontend to support schema v1.3 (GH-78) ([`0d66185`](https://github.com/ossiq/ossiq/commit/0d6618557c337ed4775adf88b3558f12fc349bc0))
Added support of the new schema for the frontend.

* feat: introduced initial export schema optimization (GH-78) ([`a40735b`](https://github.com/ossiq/ossiq/commit/a40735bfd16531c33c49ac981dbf7c4947743d74))
Introduced export schema optimization to avoid
duplication of transitive dependency details.

* feat: added version constraints enrichment and tree parser for pip classic (GH-36) ([`ce5df44`](https://github.com/ossiq/ossiq/commit/ce5df44fe4ad13245a98403c444382e69f7afcc7))
Added fetching of version constraints from the PyPI for all python package
managers, since this information is not available in the lockfile unlike
in NPM. Additionally, extended PIP classic (requirements.txt) package
manager to traverse dependencies tree, so it is not flat in
the Transitive Dependencies Explorer.

* feat: updated color coding, filtering to support constraint types (GH-36) ([`ac5e733`](https://github.com/ossiq/ossiq/commit/ac5e7336b66dafeaa787be549e7e7fd14b12d121))
Changed color coding to communicate version constraints types.
Added same color coding to the table report as well. Updated
filters in Transitive Dependencies viewer.

* feat: extend v1.2 export schemas with NARROWED/PINNED constraint types and extras field (GH-36) ([`240fff7`](https://github.com/ossiq/ossiq/commit/240fff7b5b51bfa70fea6df3b2afcc4c10df6a9e))
Added NARROWED and PINNED to constraint_type enum in JSON and CSV v1.2 schemas,
and extras field (PyPI extras, e.g. requests[security,tests]) to
the export pipeline: DependencyDescriptor, ScanRecord, PackageMetrics, JSON schema,
CSV packages schema, and CSV renderer

* feat: add PINNED/NARROWED constraint types and PyPI extras parsing (GH-36) ([`64ae6f2`](https://github.com/ossiq/ossiq/commit/64ae6f220ce9483737617cfaa65120c73fbf253e))
Extend ConstraintType with PINNED (exact version) and NARROWED (explicit
range with bounds) to enable color-coding of dependency constraints in
the UI. Add structured extras storage for PyPI deps.
Classification rules:
- npm: ^/~ - DECLARED, bare x.y.z - PINNED, >=/<= ranges - NARROWED
- PyPI: single >= - DECLARED, ==x.y.z - PINNED, ~=/==x.*/compound - NARROWED
Also expands api_pip_classic to parse non-== specifiers (>=, ~=,
ranges) and stores PyPI extras (e.g. requests[security]) as a structured
list on Dependency.extras.

* feat: new export schema version v1.2 (GH-36) ([`be721b8`](https://github.com/ossiq/ossiq/commit/be721b8ef537f728e147893cb36069a1e6402edc))
Added new schema version v1.2 to make sure version constraints
exposed both to CSV and JSON formats. Additionally,
updated UIs to highlight versions difference with
exception of the HTML report part.

* feat: added support of global version constraint mechanisms in uv and pip (GH-36) ([`b0e03fa`](https://github.com/ossiq/ossiq/commit/b0e03facc0a63e6ce805749a3f0f5162e889aefb))
Added support of constraint-dependencies and override-dependencies for
UV and pip -c Constrain versions directive inside requirements.txt
The intent is to provide additional insights into project
direct and transitive dependencies versions constraints.

* feat: added constraints parsing to NPM lockfile parser (GH-36) ([`6d90b05`](https://github.com/ossiq/ossiq/commit/6d90b05d62d5ac9fd38f15cb9d6cf79ca5b3c2f1))
Added NPM to parse transitive dependencies constraints
extracted from the package-lock.json. Also, additionally
refactored parser to aggregate similar logic.

* feat: added domain schemas for dependency version constraint (GH-36) ([`c755c0f`](https://github.com/ossiq/ossiq/commit/c755c0f471be9b0e18b47c2a25b7aee0ab82c235))
Added initial ConstraintSource schema to represent type
of constraint override and its source. Possible options are
DECLARED, ADDITIVE or OVERRIDE. In this iteration the constraint
itself is not parsed.


### Fix

* fix: fixed some minor mismaatches with export schema and comments (GH-36) ([`20b3ecc`](https://github.com/ossiq/ossiq/commit/20b3ecc5e297beadb54111452c72b81efa94bb4a))

* fix: fixed batch status code processing (GH-36) ([`1207b4d`](https://github.com/ossiq/ossiq/commit/1207b4df02997ee8830cab168b4a720e67a4cbd3))
After some response from github optimizations,
there was a gap to process non-20x codes
and any non 429/403 or 404 code.

* fix: fixed gaps in uv, pip classic and npm implementations (GH-36) ([`f103265`](https://github.com/ossiq/ossiq/commit/f103265fe58ac5941b1f897e0d311067a18236be))
Fixed gaps in transitive dependnecy version constraint
classification in uv, pip classic and npm without lockfile.

* fix: fixed typos and inconsistencies in integration tests (GH-36) ([`92b4c3f`](https://github.com/ossiq/ossiq/commit/92b4c3f451bb9e6dee58da26b4cb2889e39178dd))

* fix: fixed tests for CSV export with frictionless (GH-36) ([`b366608`](https://github.com/ossiq/ossiq/commit/b366608a34481a2fb5e8f27ae15187ac5d0b0f2e))
Bumped frictionless version to 5.19.1 and fixed
tests.


### Chore

* chore: generated fresh version of spa_app.html (GH-36) ([`526fb96`](https://github.com/ossiq/ossiq/commit/526fb96b8441c7df70394576249c04f8d91e84fd))
Generated fresh version of the nuxt/vue-based SPA
html template with non-minified code.

* chore: fixed type scheme generation for FE (GH-36) ([`115309b`](https://github.com/ossiq/ossiq/commit/115309b9bc9388b7687896eb20705016b7d3865f))

* chore: updated frictionless and reduced cooldown  period to 5d (GH-36) ([`a36f3a1`](https://github.com/ossiq/ossiq/commit/a36f3a1133e1b04c0b4b92fb96a350608bfd9374))
This is something needed to be addressed later in future
versions of the OSS IQ: When target library released
before the max distance between versions, but new
version is within dependency cooldown period.

* chore: docs: lowered down min dependencies and update docs (GH-36) ([`47f036e`](https://github.com/ossiq/ossiq/commit/47f036e5568345ddbe0f78d73268f54c16e6d7b7))
There's no need to constraint min versions of packages,
since there's no hard dependencies on its particular
functionality. Also, updated documentation with very
description of why chasing latest version for
a package.

* chore: fixed issues with naming for PyPI and NPM package managers (GH-36) ([`fe713bb`](https://github.com/ossiq/ossiq/commit/fe713bb33f84c8a003634c66f7067ecf56be06ce))

## v0.1.7 (2026-04-08)


### Feature

* feat: added 403 graceful handling for github rate limits and updated FE deps (GH-70) ([`7e6af47`](https://github.com/ossiq/ossiq/commit/7e6af47aa8c33bb00dd36063688a178ecf5e4705))
Added separate  branch to handle combination of 403 and Retry-After header with
X-Ratelimit-Remaining header (see more in Github APIs documentation
"Checking the status of your rate limit") - hard stop for entire
strategy.

* feat: added caching versions comparison, fixed typing (GH-70) ([`0965a17`](https://github.com/ossiq/ossiq/commit/0965a17d90afcc907b662b5ce92acb1c842b591f))
For larger projects with a lot of interdependent transitive
dependencies (like @aws/* npm packages), there might be
large amount of transitive dependencies on the same packages
with the same version. There's a fix for this (via simple mapping)
as well as semver comparison caching with LRU cache.

* feat: refactored license source from clearlydefined to github (GH-70) ([`732b146`](https://github.com/ossiq/ossiq/commit/732b1465e56766307cf4d57e19c116f96e8cda49))
Prototype of refactoring of clearlydefined.io API to Github API.

* feat: batching request to the packages registries ([`795803f`](https://github.com/ossiq/ossiq/commit/795803f05e84299260febbe931e703324ae9f749))
Refactored API client to make requests to NPM and
PyPI using Batch API with batchSize=1, so that
there are 3 requests in parallel.
Identified serios performance issue with ClearlyDefined API.

* feat: batched requets, debug parameter, simple NPM cache, requests pool (GH-70) ([`e402048`](https://github.com/ossiq/ossiq/commit/e40204848d3b2d4b28daa9cbd8bf1961443a414d))
During debugging Batch fixed OSV strategy and ClearlyDefined strategy.
For sample project, there was 170K transitive packages (mostly, duplicates,
hello AWS) for around 40 dependencies. This led to fix for NPM (and local cache)
and requests pooling.
Removed requests-cache code, since semantically it wouldn't be useful for
batched (any change would lead to discard entire cache).

* feat: added integration test for the abstract batch client (GH-70) ([`7ee26eb`](https://github.com/ossiq/ossiq/commit/7ee26eb78d78342a88de1e06c97b424b7d80d397))
Added integration tests to test retry-after, 500 errors,
traffic light pattern and jitter to validate that
batching client applies respective strategies correctly.

* feat: added initial requests batching implementation (GH-70) ([`38c18bf`](https://github.com/ossiq/ossiq/commit/38c18bf9258bf8283be9199857e83fb0d6b0bc59))
Added initial implementation of BatchClient and
some tests to perform parallel requests to
I/O network bound APIs in more robust manner.


### Documentation

* docs: fixed dark theme logo for documentation ([`f2a692c`](https://github.com/ossiq/ossiq/commit/f2a692c84b00c72fd0fbf8b217120fd3d32c27a6))

* docs: fixed documentation search caused by sphinx-immaterial and sphinx 9.x ([`e0d2a30`](https://github.com/ossiq/ossiq/commit/e0d2a30d5b2c8cf50de8a966eb0f76788dfbb52e))

* docs: updated landing to work on mobile ([`0484168`](https://github.com/ossiq/ossiq/commit/0484168f575afbd9d3583c048fd84c09805597ea))
Updated landing so that hamburger menu works
and update some wording for social platform shares.


### Chore

* chore: fixed typos, removed unused dependencies (GH-70) ([`f9d6078`](https://github.com/ossiq/ossiq/commit/f9d607875d690861b35f4a261970f5bc7ed35f3a))

* chore: fixed dependency conflict between vite-plugin-vue-devtools and vite 8.x ([`7776062`](https://github.com/ossiq/ossiq/commit/77760629a6decd8304ac66457872e2f511ccddec))
vite-plugin-vue-devtools constrained vite dependency version to 6.x and 7.x,
so freshly released vite 8.x fail cannot be installed. This is exactly
why OSS IQ is developed - to provide visibility and clear plan how to
work this around.

* chore: fixed uv.lock (GH-70) ([`176824d`](https://github.com/ossiq/ossiq/commit/176824d072eee0ed2b7f49eeab8ca94ec6495747))

* chore: bumped requets due to CVE in the specified version ([`f8dfddb`](https://github.com/ossiq/ossiq/commit/f8dfddb4680f158d4d5b93f6b9576776bf7ca24b))

* chore(deps): bump requests in the uv group across 1 directory ([`0367a96`](https://github.com/ossiq/ossiq/commit/0367a961d6aad45d5bc7e6d3d487d731d09bc71b))
Bumps the uv group with 1 update in the / directory: [requests](https://github.com/psf/requests).
Updates `requests` from 2.32.5 to 2.33.0
- [Release notes](https://github.com/psf/requests/releases)
- [Changelog](https://github.com/psf/requests/blob/main/HISTORY.md)
- [Commits](https://github.com/psf/requests/compare/v2.32.5...v2.33.0)
---
updated-dependencies:
- dependency-name: requests
  dependency-version: 2.33.0
  dependency-type: direct:production
  dependency-group: uv
...

* chore(deps): bump simpleeval in the uv group across 1 directory ([`86ba4f0`](https://github.com/ossiq/ossiq/commit/86ba4f06a2934bb40478f7a1489cee5eaef0c3a9))
Bumps the uv group with 1 update in the / directory: [simpleeval](https://github.com/danthedeckie/simpleeval).
Updates `simpleeval` from 1.0.3 to 1.0.5
- [Release notes](https://github.com/danthedeckie/simpleeval/releases)
- [Commits](https://github.com/danthedeckie/simpleeval/compare/1.0.3...1.0.5)
---
updated-dependencies:
- dependency-name: simpleeval
  dependency-version: 1.0.5
  dependency-type: indirect
  dependency-group: uv
...

## v0.1.6 (2026-03-20)


### Feature

* feat: added package command to show package details in CLI (GH-18) ([`06191b3`](https://github.com/ossiq/ossiq/commit/06191b3e98e0120aa7efd8e7084163ae8be07453))
Added `package` command to show package details
in the console with transitive dependencies support
as well. Now, there's feature parity between HTML
and Terminal CLI.

* feat: added clearlydefined to main licenses information (GH-18) ([`e64ccb3`](https://github.com/ossiq/ossiq/commit/e64ccb3040b46ed0dae023b06264fa6022de543c))
ClearlyDefined.io is a project to collect and crowdsource
proper licensing information per package version. Now,
licensing information correctly provided in SPDX format.

* feat: simplified dependency panel design (GH-18) ([`c75b4e9`](https://github.com/ossiq/ossiq/commit/c75b4e9cd4f604c1d5964a1d713b4d37a7d8ffc5))
Simplified Dependencies Panel design to maximize
space and ergonomics.

* feat: licenses and transitive cves (GH-18) ([`e51f337`](https://github.com/ossiq/ossiq/commit/e51f337e98b57d1961845f312d6b22f8ba13a65c))
Dependencies licenses exposed for Dependency Detail panel
and in the report. Transitive CVEs also exposed next to
direct CVEs section.

* feat: added license from ClearlyDefined source (GH-18) ([`4849e70`](https://github.com/ossiq/ossiq/commit/4849e70f259d5811fe183894b568cbb8badb09df))
Added new source of information about Licenses in SPDX format
(ClearlyDefined) together with caching and updates to the
export model.

* feat: exposed license and purl fields (GH-18) ([`5b034e4`](https://github.com/ossiq/ossiq/commit/5b034e4b8d0cc1383441d24fe6af82431751e5bf))
Added license and purl fields to the export schema.
Note, that for PyPI license is a mess and needs to be
normalized in the future.

* feat: added OSV optimization with batch requests (GH-18) ([`d168bf7`](https://github.com/ossiq/ossiq/commit/d168bf78402830913bd9e780dbf7362b6ef1bd40))
Leveraged OSV API to perform batched requests instead
of per-package. Significantly improved performance.

* feat: added caching for Github and OSV (GH-18) ([`eb7d36b`](https://github.com/ossiq/ossiq/commit/eb7d36bcbda98d3976fea7af3f236c22a26fff4b))
Added requests-caching dependency to handle caching
for Github and OSV. Github is integrated, OSV is not.

* feat: updated dependency details dialogue and transitive explorer (GH-18) ([`5b51de5`](https://github.com/ossiq/ossiq/commit/5b51de530e93e754561e18cc6d15391d42bc4049))
Improved transitive dependency explorer with additional UX
when specific dependency is selected as well as designed
package details side panel. Refactored report to
open package details panel as well instead of direct
link to the registry.

* feat: added repo url/homepage url and package urls (GH-18) ([`a908788`](https://github.com/ossiq/ossiq/commit/a9087888f979d7cb00ec0432831201e80bebb2aa))
Extended schema with repo_url, homepage_url and
package_url of a package for more detailed information
about the package.

* feat: added version constraints, overwrites and aliases for NPM (GH-18) ([`f35143b`](https://github.com/ossiq/ossiq/commit/f35143b3fc359f518fe9680d68998efbe7bbfb31))
Added support of aliases in dependencies with multiple versions
of the same dependency support as well as overrides for NPM.
Aliases exposed via dependency_name property in export schema
and overrides just separately categorized as "overrides" category.
For PyPI added versions constraints, so it could be properly
highlighted in the frontend.

* feat: added new field version_constraint to PackageVersion (GH-18) ([`468be8d`](https://github.com/ossiq/ossiq/commit/468be8d87c401cdc4798fbaf3311d0dc00ef3838))
Added new field `version_constraint` to keep constraints of
a dependency. This is especially important for PyPI for explicit
upper bound version constraint which in combination with
version lag could indicate accumulated tech debt/risk exposure.
Added CSV schema version 1.1 to align with JSON schema version.
Added src/ossiq/domain/README.md with references to specs and
motivation behind certain features.

* feat: added filtering capability to explorer (GH-18) ([`02fdac7`](https://github.com/ossiq/ossiq/commit/02fdac706619589aaa1f7728a5681e268e07befc))
Added filtering by keyword (fuse.js), CVEs,
pinned and upper bound constrained versions.
Additionally, added legend and some UX help.

* feat: Mapping in dependency explorer (GH-18) ([`2a01db2`](https://github.com/ossiq/ossiq/commit/2a01db20ae946364d665c76ef3767b657323cad1))
Implemented exploration UI and UX for transitive dependencies,
handling of same dependencies by different packages as well
as CVEs highlight and pinned/upper version constrained dependencies.

* feat: transitive dependencies rendering code (GH-18) ([`4cce69b`](https://github.com/ossiq/ossiq/commit/4cce69bbca18ea59e90b43b621eb4e23f2a77008))
Initial iteration of transitive dependencies
rendering with D3.

* feat: introduced new export schema version 1.1 with transitive dependencies (GH-18) ([`dfa4492`](https://github.com/ossiq/ossiq/commit/dfa449284ee18c12c247f9766435bcc3f57edd75))
Introduced export schema 1.1 to cover use case with
transitive dependencies. Needed to render dependency
tree with D3 in frontend.

* feat: added support of transitive dependencies to the scan command (GH-18) ([`f2c027d`](https://github.com/ossiq/ossiq/commit/f2c027d5b1b7176229e1bbd53b3a8cf845072a6a))
Streamlined naming for ProjectVersion from generic dependencies to
declared_dependencies with aim to improve semantic meaning.
Added transitive dependencies traverse and extraction into
the scan command models. Additionally, renamed ProjectMetrics
to ScanResult to make it more semantically meaningful.
Added DESIGN.md file to track code-level gaps/improvements.

* feat: initial integration of Vue SPA and OSS IQ backend (GH-18) ([`50e7a2d`](https://github.com/ossiq/ossiq/commit/50e7a2df948492e8fbafb4b9f51254fb2849e179))
 - refactored Jinja2-based template to Vue-based SPA for scan command
 - removed Jinja2 templates and respective tags
 - reduced dependency on uow for scan-related commands to simplify
   project usage for MSR-specific research.

* feat: added initial frontend implementation for the OSS IQ report (GH-18) ([`cc4e62f`](https://github.com/ossiq/ossiq/commit/cc4e62fd323db00f7544832b48f53735f087c888))
Added two sections to the Vue-based app for the frontend:
 - Added Vue version of the current HTML-based report;
 - Added D3-based directed graph to represent transitive dependencies
Furthermore, created initial implementation to build frontend both
using hatch build hook and justfile command to maintain good
development experience.

* feat: strawmen reports for scan command and for transitive dependencies (GH-18) ([`113ef0c`](https://github.com/ossiq/ossiq/commit/113ef0c8ba427340f8e3e59e5b0448f2046d6ea6))
Added pretty much production-ready report for scan command and
strawmen implementation for transitive dependencies analysis
visualisation view with D3.

* feat: added frontend builder based on vue.js (GH-18) ([`fc6fded`](https://github.com/ossiq/ossiq/commit/fc6fdede22f03296f69cc936e7750fdea49cfa49))
Added VueJS application and build system to
build a self-contained SPA for HTML reports.
The ultimate goal is to generate SPA during
python package normal build process (facilitated
by Hatch) and distribute only built version.
Since there's attestation process happening,
distributed SPA would have same security
attributes as python package itself.
To provide best UX for the HTML report,
especially with introduction of Transitive
Dependencies, the tooling should have
enough capabilities to sustain development.

* feat: implemented dependency tree parsers for pylock and pip classic (GH-18) ([`4afa462`](https://github.com/ossiq/ossiq/commit/4afa462733c4ac12299edb778aaf49a667c97eb5))
 - Finilized implementaiton for pylock and pip classic requirements.txt
 - Modified tests respectively. Added test for dependency_tree.py interface

* feat: refactored tests and NPM package manager (GH-18) ([`620ed34`](https://github.com/ossiq/ossiq/commit/620ed3487b53c8aa3f076ac6020b16fadf240c13))
Refactored NPM package manager and tests to support
dependency tree structure.

* feat: refactored tests for uv and bug in dependency_tree parser (GH-18) ([`0ca1729`](https://github.com/ossiq/ossiq/commit/0ca1729e9a72d54f8ffe9dc6b9468ff461db301b))
Refactored/fixed tests for UV package manager dependencies parser
and small fix for categorization error in dependency tree.

* feat: introduced dependency tree parser (GH-18) ([`1c0b647`](https://github.com/ossiq/ossiq/commit/1c0b647d4d155917acc4f819bd41e868d594d556))
Implemented Dependency Tree abstract class and
implementations for UV and NPM (and NPM without lockfile).
Refactored Project service to work with new data structure.
Enhanced Depenency structure to work better with tree-like
structure.
WIP! Pylock is not finished as well as classic PIP is not
refactored yet.
Additionally, improved organization of pyproject.toml
in accordance with PEP735 and adjusted justfile respectively.


### Fix

* fix: fixed docs build workflow (GH-18) ([`72e5634`](https://github.com/ossiq/ossiq/commit/72e563455b5121df265d52d2201b270e9fd9a5a0))

* fix: fixed catalog: pnpm versioning in package.json (GH-18) ([`32e4a52`](https://github.com/ossiq/ossiq/commit/32e4a52a6b5dc25054a8d73fb5d0b0d1667f0584))
Fixed handling of pnpm artifacts (for an
example project @vue/core) to properly
handle `catalog:` version modifier.
Fixed request timeout for ClearlyDefined
due to large request size.

* fix: aligned behavior for transitive CVEs with Explorer view (GH-18) ([`0071804`](https://github.com/ossiq/ossiq/commit/007180453a8e88719966de31bcd804bbb4a76d7c))
Aligned transitive CVEs view in Dependency Details panel with
Explorer. Improved table layout slightly to fit license information.


### Refactor

* refactor: documentation migrated from mkdocs to sphinx (GH-18) ([`6ede725`](https://github.com/ossiq/ossiq/commit/6ede725b88d8292f2cf5ba89f2ff262c6c7c1912))
There's a mess with MkDocs support together with MkDocs-Material
folks who are hostages of the situation:
https://squidfunk.github.io/mkdocs-material/blog/2026/02/18/mkdocs-2.0/
Since this is just a beginning for OSS IQ, current
documentation is migrated to Sphinx with similar to
MkDocs-Material design.

* refactor: refactored scan function for better readibility (GH-18) ([`576e416`](https://github.com/ossiq/ossiq/commit/576e416addf58053c06eadb9241670775b18d003))
Refactored scan function for better readibility, fixed
tests for github/osv and project service.

* refactor: Refactored out dependency on pandas (GH-18) ([`932a174`](https://github.com/ossiq/ossiq/commit/932a174e04dd8f6ead9c710579e48d0a33331d30))
Removed the only piece of code dependend on pandas
to reduce dependencies from larger packages.

* refactor: refactored initial dependency tree parser (GH-18) ([`a5e6e1f`](https://github.com/ossiq/ossiq/commit/a5e6e1fb72d1d221e40119488203dea2e0929e4e))
Refactored initial implementation with packageName@version
keys and original unnecessary complexity.


### Documentation

* docs: updated README.md and fixed some mistakes in landing ([`b5baa3a`](https://github.com/ossiq/ossiq/commit/b5baa3aa078685868dd2d3253250a356f15ff875))

* docs: moved quality gates section next to try it out ([`c5abbf3`](https://github.com/ossiq/ossiq/commit/c5abbf3acfd0077e2b507949ffb16c92fbcdd92d))

* docs: added positioning to the landing page ([`a14595c`](https://github.com/ossiq/ossiq/commit/a14595cd8b0573ee4900b79c299c3fd768c693e1))

* docs: updated headline for the landing ([`00f3924`](https://github.com/ossiq/ossiq/commit/00f3924dc3a4d301d0e45d77f05e2ae50b01d189))

* docs: updated landing with better wording ([`9af3d58`](https://github.com/ossiq/ossiq/commit/9af3d5812a6daea8a5cdd37395126b9f88b3a902))
Improved some phrasing on the landing page,
simplified menu and removed redundant example.
Also, removed mentions of pnpm and poetry.

* docs: updated README to align with documentation (GH-18) ([`e49e683`](https://github.com/ossiq/ossiq/commit/e49e68364148a21aabbc6f56c98a28e5f3a9ac32))

* docs: finished documentation and updated landing (GH-18) ([`0f2cf65`](https://github.com/ossiq/ossiq/commit/0f2cf651a6de2c7f11e9825f17ba89ccb36cb544))
Finished documentation with the new tool Sphinx as well
as updated landing page for the tool. Aligned what is
currently implemented with what is on the landing. Removed
forward-looking references for now to clearly communicate
what value is already possible to unlock.

* docs: added reference documentation and updatd getting started (GH-18) ([`c8a2218`](https://github.com/ossiq/ossiq/commit/c8a2218cdefcbffc0b579a6143716ceb0c7ecee3))


### Chore

* chore: disabled docker image generation on publish and vscode setting ([`b80f8b0`](https://github.com/ossiq/ossiq/commit/b80f8b048e507b9391cdced98fb226d12b62d3cc))

* chore: updated frontend dependencies ([`d51dad9`](https://github.com/ossiq/ossiq/commit/d51dad9f822b138c90269d96f77ff6f71303386d))
Another demonstration why OSS IQ is needed -
around 10 dependencies were updated since
last week.

* chore(deps): bump undici ([`2c576f5`](https://github.com/ossiq/ossiq/commit/2c576f5fb2a9841c0d8a37446b5ac07ddadcfc1e))
Bumps the npm_and_yarn group with 1 update in the /frontend directory: [undici](https://github.com/nodejs/undici).
Updates `undici` from 7.22.0 to 7.24.4
- [Release notes](https://github.com/nodejs/undici/releases)
- [Commits](https://github.com/nodejs/undici/compare/v7.22.0...v7.24.4)
---
updated-dependencies:
- dependency-name: undici
  dependency-version: 7.24.4
  dependency-type: indirect
  dependency-group: npm_and_yarn
...

* chore: tests for clearlydefined and README updates (GH-18) ([`1f291f0`](https://github.com/ossiq/ossiq/commit/1f291f0d6334e9663e48fa0251f96a65454af6de))
Added sources used to README and added tests
for clearlydefined code.

* chore: updated frontend dependencies and some config to FE (GH-18) ([`38658e2`](https://github.com/ossiq/ossiq/commit/38658e2aae0ac80707d5d76cfe9ce87f867f6559))
 - updated all FE depndencies to the latest versions
 - changed green transitive descendant edges color to light blue
 - built frontend and placed as spa_app.html

* chore: Updated dependencies and fixed types (GH-18) ([`ad8bedd`](https://github.com/ossiq/ossiq/commit/ad8beddf2cb9bedc8c8f09f890af544380202360))
Updated packages using OSS IQ MCP server and
fixed typing (str, Enum -> StrEnum) as well as
fix frontend builder test.

* chore: simplified few places for future use (GH-18) ([`fe83c7b`](https://github.com/ossiq/ossiq/commit/fe83c7bbcbaa642c5ebc135496c81f80cd5d708a))
During development noticed that few places has
some type dependencies not needed for the use case.
Removed and added FIXME suggestion for gap in
implementation.

* chore(deps): bump cryptography in the uv group across 1 directory ([`de448fe`](https://github.com/ossiq/ossiq/commit/de448fee974b2afb9ea0ec3f8e869eb98b626c5a))
Bumps the uv group with 1 update in the / directory: [cryptography](https://github.com/pyca/cryptography).
Updates `cryptography` from 46.0.3 to 46.0.5
- [Changelog](https://github.com/pyca/cryptography/blob/main/CHANGELOG.rst)
- [Commits](https://github.com/pyca/cryptography/compare/46.0.3...46.0.5)
---
updated-dependencies:
- dependency-name: cryptography
  dependency-version: 46.0.5
  dependency-type: indirect
  dependency-group: uv
...

## v0.1.5 (2026-01-25)


### CI

* ci: fix duplicate assets record inside wheel archive (GH-5) ([`d29f4c8`](https://github.com/ossiq/ossiq/commit/d29f4c8ce3b909cf0cb6d485f8b8d19177795243))

## v0.1.4 (2026-01-25)


### Feature

* feat: initial Dockerfile implementation with documentation (GH-6) ([`e1068f9`](https://github.com/ossiq/ossiq/commit/e1068f97954731aca251a14b69eb7535046239c8))
Added initial Dockerfile implementation
and tested with colored and black-and-white output.
b/c of Rust dependency in common-expression-language
had to build two-phase (build, prod) Dockerfile.


### Fix

* fix: fixed test for csv schema validation and updated readme screenshot GH-5 ([`875a120`](https://github.com/ossiq/ossiq/commit/875a120269159870f2b09758293c9504eda81312))

* fix: aligned terminology with html report (GH-5) ([`7edf901`](https://github.com/ossiq/ossiq/commit/7edf90141c0b7821e3d6db4a6ebe60de155d449d))
Aligned terminology to be more sharp with each
metric collected for console report.

* fix: html templates in python package and template improvements (GH-5) ([`ce26cdd`](https://github.com/ossiq/ossiq/commit/ce26cdd2f5e94b581d03dbd72d69f348aaa8133b))
Fixed assets build for pypi package to include html report templates.
Additionally, improved wording and added date to HTML report for
better clarity.


### Documentation

* docs: updated docs with latest screenshots and console reports (GH-5) ([`e8f2733`](https://github.com/ossiq/ossiq/commit/e8f2733855bf82be18f51b9d77812ad58e8dc67a))
Updated all the screenshots, added sample report to the landing
and some other maintenance stuff.

* docs: finished first analysis and github actions tutorials (GH-5) ([`9c4bed5`](https://github.com/ossiq/ossiq/commit/9c4bed565d2e1e5bfd3ef22317b66385d1f9ebfd))
Updated Getting Started with slightly sharper framing and
finished two tutorials: First Analysis and Github Actions.
Added Google Analytics for the landing page.

* docs: updated getting started and landing (GH-6) ([`2c995a8`](https://github.com/ossiq/ossiq/commit/2c995a8311b34115d04079a829cec73d8725af17))

 - Updated Getting Started section with Export and Docker subsections
 - Updated Landing page with new HTML report screenshot

* docs(contribution): Updated CONTRIBUTING.md with latest changes (GH-11) ([`7a44238`](https://github.com/ossiq/ossiq/commit/7a44238093cca18cbccdd454383563feef6603e1))


### CI

* ci: added quality gate dogfood workflow (GH-5) ([`dfc7401`](https://github.com/ossiq/ossiq/commit/dfc74016cfe3359c44ee27e5e9ac9922bb071acc))
Created quality gate based on own tutorial
to threshould versions lag and fail on CVEs.

* ci: updated workflows for tests and release to docker hub (GH-6) ([`f1eba1b`](https://github.com/ossiq/ossiq/commit/f1eba1b794f8bb7fcfea1f61764d4c7091870619))

 - Added python 3.11-3.14 to test workflow
 - Added GA environment name to docker.yml


### Chore

* chore: removed python 3.10 from the list of supported versions (GH-6) ([`be2d64f`](https://github.com/ossiq/ossiq/commit/be2d64f533c45a32c8482bd32d78b9b833d32e52))
common-expression-language requires python 3.11+

* chore: Added RELEASE.md documentation (GH-11) ([`41ef530`](https://github.com/ossiq/ossiq/commit/41ef530e2f0605e2759797d8c0863f9a7c29b186))

* chore: fixed tip after the release (GH-11) ([`f57781b`](https://github.com/ossiq/ossiq/commit/f57781b2558e05b57d8d99a603ff6043a5d7eb28))


### Unknown

* unknown: Bump urllib3 from 2.5.0 to 2.6.3 in the uv group across 1 directory ([`e85bb3e`](https://github.com/ossiq/ossiq/commit/e85bb3e975f5015c6670aaa1369c4eef8ef60995))
Bumps the uv group with 1 update in the / directory: [urllib3](https://github.com/urllib3/urllib3).
Updates `urllib3` from 2.5.0 to 2.6.3
- [Release notes](https://github.com/urllib3/urllib3/releases)
- [Changelog](https://github.com/urllib3/urllib3/blob/main/CHANGES.rst)
- [Commits](https://github.com/urllib3/urllib3/compare/2.5.0...2.6.3)
---
updated-dependencies:
- dependency-name: urllib3
  dependency-version: 2.6.3
  dependency-type: indirect
  dependency-group: uv
...

* unknown: Bump virtualenv in the uv group across 1 directory ([`2cefc8b`](https://github.com/ossiq/ossiq/commit/2cefc8b6b75ae8633e71b9ab9061d9bca3e9d275))
Bumps the uv group with 1 update in the / directory: [virtualenv](https://github.com/pypa/virtualenv).
Updates `virtualenv` from 20.35.4 to 20.36.1
- [Release notes](https://github.com/pypa/virtualenv/releases)
- [Changelog](https://github.com/pypa/virtualenv/blob/main/docs/changelog.rst)
- [Commits](https://github.com/pypa/virtualenv/compare/20.35.4...20.36.1)
---
updated-dependencies:
- dependency-name: virtualenv
  dependency-version: 20.36.1
  dependency-type: indirect
  dependency-group: uv
...

## v0.1.3 (2026-01-15)


### Chore

* chore: fixed release.yml and added license to pyproject.toml (GH-11) ([`43e4bae`](https://github.com/ossiq/ossiq/commit/43e4bae0f603f0c71c7678db644589d3f909a083))

## v0.1.2 (2026-01-15)


### Feature

* feat: Added release.py script and release.yml GA workflow (GH-11) ([`ce6baeb`](https://github.com/ossiq/ossiq/commit/ce6baeb8b0f45628cb28467bd53e1752dfcffc03))
 - Added release.py script instead of python-semantic-release,
   which is confusing and doesn't work well with semi-manual
   release process I wanted to have initially.
 - Added release.yml Github Actions workflow with
   `release` GH Environment to work with PyPI
   Trusted Release with Release Attestation
 - Removed RELEASE.md in its current form, will
   add back newer version later.
 - Cleaned up pyproject.toml and justfile from
   python-semantic-release junk.


### Fix

* fix: added check for OSSIQ_GITHUB_TOKEN to release (GH-11) ([`2836b81`](https://github.com/ossiq/ossiq/commit/2836b81b505e9098c8b2decbcd1bc8ad8ee9e06a))
Added check to validate OSSIQ_GITHUB_TOKEN, otherwise
release.py fail on the last step (basically, broken state).

* fix: added explicit newline control to release notes (GH-11) ([`d2bfeef`](https://github.com/ossiq/ossiq/commit/d2bfeefd4f4db9c026cd7e8d860c1a6d7a16a515))
Added `**` character to explicitly control newline
character in git commit messages. This would be handy
to accurately generate changelog.

* fix: updated RELEASE.md to validate release process (GH-11) ([`68ae7c3`](https://github.com/ossiq/ossiq/commit/68ae7c36e3784ac13470299b4a2750c2669bae49))


### Chore

* chore: added twine to manually upload to pypi when needed (GH-11) ([`44a349e`](https://github.com/ossiq/ossiq/commit/44a349e06103fd7f8792b853a7f3efe97f75fe4b))

## v0.1.0 (2026-01-13)

### Feature

* feat: changed commit message for python-semantic-versioning

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`b4041e7`](https://github.com/ossiq/ossiq/commit/b4041e7e006ff35f44dbb921ae4f3e2ef8631573))

### Unknown

* Merge pull request #22 from ossiq/chore/GH-11--semantic-release-config

Chore/gh 11  semantic release config ([`fedaacd`](https://github.com/ossiq/ossiq/commit/fedaacd9ee78145a8960db53a925f431aa808ca1))


## v0.0.1 (2026-01-13)

### Chore

* chore: configure python-semantic-release for semi-manual release

Initial version of Release process. The idea is to keep it
as simple as possible and in semi-manual process, since
there&#39;s only one engineer to work on the project for now.

GH-11

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`e7e1167`](https://github.com/ossiq/ossiq/commit/e7e11678f6a376abc598a401a0684288f5d9a653))

### Unknown

* Merge pull request #20 from ossiq/GH-3--export-to-json-and-command-rebrand

GH-3  export to json and overview command rebrand ([`8b5ec76`](https://github.com/ossiq/ossiq/commit/8b5ec76470d0852974a96f0b0be11cec637b1d07))

* FIX: Fixed failing tests for CSV export

With help of Claude, refactored tests to
pass tests and be more precise with schema validation
tests. Requires additional review.

GH-3

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`d283d3c`](https://github.com/ossiq/ossiq/commit/d283d3cc0cd649629d0847dc0154c5cf088963c5))

* ADD: Added experimental CSV implementation with frictionless data standard

Added export to CSV with Tabular Data Package schema
https://specs.frictionlessdata.io/tabular-data-package/
to simplify data exchange when needed with OSS IQ.

There&#39;s schema validation functionality which is leveraged
just for testing and is not used during export operation.

Schemas are available alongside JSON schema in
`ui/renderers/export/schemas`.

Validation could be performed manually as well with
`uv run frictionless validate &lt;path_to_datapackage.json&gt;`

GH-3

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`2fb37d0`](https://github.com/ossiq/ossiq/commit/2fb37d0714516c5ce189358a851b123592ff9d39))

* MOD: Wrapped up JSON export functionality and prepared CSV export

Wrapped up implementation of JSON export as well as
added infrastructure to implement CSV export via tabular
package.

GH-3

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`aa7cf55`](https://github.com/ossiq/ossiq/commit/aa7cf55129012f7c800dff91714703109b8bdaf4))

* ADD: Added complete implementation of JSON exporter

 - Implemented export to JSON with JSONSchema and test
   to conform the schema and exported shape.
 - Refactored completely presentation layer and renamed it to
   `ui` as more straighforward way to comprehend. Simplified
   implementation of Console and HTML renderers.
 - Streamlined some argument naming and expected values,
   added usage of Literal instead of strings.
 - Added guideline for Claude to write tests using
   AAA Pattern (Arrange/Act/Assert) as well as
   other recommendations.

GH-3

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`97dee97`](https://github.com/ossiq/ossiq/commit/97dee9781c41293ca376b86f3e46fdd6cdc6c116))

* MOD: Refactored presentation to follow registry pattern

Refactored Presentation to follow pattern closer to
adapters/package_managers. The goal is to unify
patterns, so it is more manageable and easier
to comprehend. Additional goal is to lay groundwork
for the export command, so the implementation would
be a bit cleaner. Majority of the refactoring done
by Claude Code, but seems like it is pretty clean.

GH-3

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`e965250`](https://github.com/ossiq/ossiq/commit/e96525033258f226d79742ec31ea90347c6c1e09))

* MOD: Documented refactoring of overview to scan command

 - Fixed justfile, especially around integration tests
 - fixed documentation and README

GH-3

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`c4e63c1`](https://github.com/ossiq/ossiq/commit/c4e63c109d69dbdcb8402d7706ea618d924e3afd))

* MOD: Refactored overview command to scan

 - Refactored all the instances of overview command
   and renamed it to scan. Fixed wording.
 - Moved command parameters --presentation
   and --output to the scan command level.
 - Renamed output of project service to
   ProjectMetrics (ProjectOverviewSummary before).
   Fixed respective Jinja2 templates.

GH-3

Signed-off-by: Maksym Klymyshyn &lt;klymyshyn@gmail.com&gt; ([`c9c0843`](https://github.com/ossiq/ossiq/commit/c9c084359b2b9c87066de5385c3cf6f3c5a1752b))

* Merge pull request #15 from ossiq/GH-4-add-pypi-ecosystem

GH-4 add pypi ecosystem with uv, pylock.toml and plain requirements.txt ([`7eb5c0c`](https://github.com/ossiq/ossiq/commit/7eb5c0c0e929d1d6ff28fcd2a4c37722150ada37))

* FIX: fixed typos detected by copilot

GH-4 ([`0cb9e61`](https://github.com/ossiq/ossiq/commit/0cb9e6101c0b93f9f509a42c9f3b8cb14700faea))

* ADD: Added --registry-type option and changed behavior for --output option

Added --registry-type option to narrow down a specific registry for
case when two different ecosystem projects are in the same folder.

Changed --output option behavior, so that by default it would
generate overview_report_{project_name}.html in the current
directory, otherwise custom name would be used provided with
this option.

GH-4 ([`079a029`](https://github.com/ossiq/ossiq/commit/079a02930f60b7cf55923b9facca593f8d18b5cc))

* MOD: Updated test_api_github test

GH-4 ([`d45dcb1`](https://github.com/ossiq/ossiq/commit/d45dcb14d46573117f96e84f1bae45e06b4ac764))

* MOD: Reorganized pyproject dependencies and updated docs

Updated docs to clearly communicate what is possible and
what is not possible with the current implementation,
especially around PyPI ecosystem.

Reorganized dependencies in pyproject to have two
categories of optional dependencies: one is dev and
another one is docs to keep dependencies for documentation
and active development respectively.

GH-4 ([`ce87f41`](https://github.com/ossiq/ossiq/commit/ce87f41ca66da7e2d4deb2270cebe09fb471f344))

* MOD: Modified OSV database to align with types and generalized version sorting

Version sorting haven&#39;t worked properly due to two possible
inputs with the same properties. Refactored to use Generic Type
with respective possile inputs.

Refactored OSV CVEs list getter to return set of CVEs instead of
Iterator, since it would go to domain model and iterator
is not the best structure (at least from current understanding)
for this task. It will eventually end up in memory, so no point
streaming of it.

GH-4 ([`d5e20c3`](https://github.com/ossiq/ossiq/commit/d5e20c3733b55027fe51753f7ccbc971add3c6cb))

* MOD: Fixed linting issues with tests

GH-4 ([`edb2614`](https://github.com/ossiq/ossiq/commit/edb26143a408017304f47ca35e0485f38e23e4f1))

* MOD: Refactored requirements.txt parser

Initial implementation was overly verbose,
what claude offered was too granular Java-style
one condition/one method approach. Balanced out
to minimize if/continue branches.

GH-4 ([`a2ce15a`](https://github.com/ossiq/ossiq/commit/a2ce15a7629afa93544ab95bb6e340943d21d859))

* MOD: Fixed field name to align terminology

Changed field name from `package_manager` to
`package_manager_type` to align with other parts
as well as better represent its meaning, since
it contains not an instance of Package Manager, but
its type.

GH-4 ([`c00d076`](https://github.com/ossiq/ossiq/commit/c00d076f42e3f3c2a70f7ba659690f89ef0c43cf))

* MOD: Refactored Ecosystem term to Packages Manager

Ecosystem is not intuitive and doesn&#39;t reflect semantic
meaning of how it is  used throughout a project and rather
confusing.

GH-4 ([`99fbcfb`](https://github.com/ossiq/ossiq/commit/99fbcfbedfbba14ea057283752171fe08ae180e5))

* ADD: Added PIP classic tests and renamed pylock to pip

Added tests to cover PIP classic (claude generated) as well as
renamed pylock (since it&#39;s not a package manager) to pip.

Not there are two PIP implementations of adapters:
 - one for pylock PEP 751 modern standard
 - one for older requirements.txt files without pyproject.toml

GH-4 ([`b191b82`](https://github.com/ossiq/ossiq/commit/b191b8276bf9ac188b84b8427729ea2e368a907f))

* MOD: Removed black and added qa-integration command

Removed black since it conflicting with ruff. Ruff
is the way to format code for now for the project.

Added `qa-integration` command to justfile, so that
commands could be run against testdata/* sample projects.

GH-4 ([`cf008b6`](https://github.com/ossiq/ossiq/commit/cf008b688939f9ecc65d1f03c3e45bd7c31f1419))

* ADD: Added classic PIP requirements.txt support

requirements.txt is typically serves dual purpose:
intent (what was added by an engineer) and
a fact (result of pip freeze command). PIP classic
implementation assumes that input is result of
`pip freeze` command, so that it would reflect
what is installed currently in the python environment.

Intent use case could work also, but would be
more noisy, since there might be differences
introduced by resolved during pip install.

GH-4 ([`8cd21d9`](https://github.com/ossiq/ossiq/commit/8cd21d9006e8fc0efe3d77914eb1f1fec615397e))

* ADD: Added tests for domain version and adapters

Added tests, mostly generated with Claude for NPM, PyPI
and respective package managers. The idea behind is to
have some baseline with refactoring in the future.

GH-4 ([`8ba10da`](https://github.com/ossiq/ossiq/commit/8ba10dabc501bb42533f7695cf81761a281267d9))

* MOD: Adjusted presentation layer to accomodate PyPI

Adjusted presentation layer to support PyPI, especially
around categorizing difference significance between
versions (e.g. MINOR lag, MAJOR lag etc.)

Added CLAUDE.md context to help development with
Claude Code.

GH-4 ([`c9337ea`](https://github.com/ossiq/ossiq/commit/c9337ea20e6ddfc13be124c391e424da951ebdec))

* MOD: Modified versions and typing for some domain entities

Removed hardcoded semver dependency in versions: PyPI
infrastructure relying on PEP440 versioning standard which
is different from Semantic Versioning slightly.

Decision build-in to not support packages released before
2014 (when PEP440 was enforced).

Added support of pylock.toml (PEP751). The naming is PIP
as it is the most popular package manager and goes by
default with Python. There&#39;s no separation between
file format and package manager at the moment, so PIP
is good enough.

GH-4 ([`5df7068`](https://github.com/ossiq/ossiq/commit/5df706803f26b8f11ae8da84b3645a026dcb0ff8))

* MOD: Modified implementation of api_npm and api_uv

Simplified verbose implemenetation in api_npm.py and
fixed resource leaks in uv implementation.

GH-4 ([`70d6602`](https://github.com/ossiq/ossiq/commit/70d660212aedc83e70712a871868559404acab55))

* ADD: Added common-expression-language and pandas back to dependencies

Pandas needed to correctl parse human-readable data (potentially,
could be refactored out later).

Added common-expression-language (CEL) to constraint lockfile
schemas with human-readable rules, like:
  `&#34;version == 1 &amp;&amp; revision &gt;= 3&#34;`
So that there&#39;ll be some flexibility to cover more than
one version per handler for the future.

GH-4 ([`557dc77`](https://github.com/ossiq/ossiq/commit/557dc776ebc0159829728910d263541e3a018aec))

* MOD: Refactored UoW and Service to align with adapters

Refactored UoW and service to support new naming
and updated versions of initialization. Not much changes
needed, since most of it happened on the adapters level.

GH-4 ([`e2ab767`](https://github.com/ossiq/ossiq/commit/e2ab767e173e0df8384f8ded6980eb135ae098ca))

* MOD: Modified domain to support more complex Dependency representation

Added dataclass Dependency to keep both defined and installed versions
as well as support multiple categories of optional dependencies).

The idea is to use &#34;tags&#34; or &#34;labels&#34; UI elmeents to represent
categories inside report.

GH-4 ([`ce6f548`](https://github.com/ossiq/ossiq/commit/ce6f5484e64b5d22d9e9b80f33d20419dcaa3ecd))

* MOD: Finished refactoring of Registries

Moved out package management related functionality
out, only package registry communication left. Updated
interfaces to correctly follow naming.

GH-4 ([`82d2ce2`](https://github.com/ossiq/ossiq/commit/82d2ce2aadfbac64395a7445eb8af8ec478c753b))

* ADD: Added NPM package manager support with lockfiles

Added support for NPM package parser as well as
streamlined lockfile parsers and finished UV parser.

GHL-4 ([`79b826c`](https://github.com/ossiq/ossiq/commit/79b826ca6b4f116759b5df3a9270263392fe0b07))

* MOD: Fixed linting issues

This is result of `uv run just qa` command.
Need to streamline how to deal with it: probably
this command should be runned before each commit, since
it would produce useless diff (just linting).

GH-4 ([`85f9266`](https://github.com/ossiq/ossiq/commit/85f92661894f5a552a1af0a067185eba18429de6))

* MOD: Aligned some package versions for documentation

GH-4 ([`0c42ff4`](https://github.com/ossiq/ossiq/commit/0c42ff40b4f2d8c25dbb7302b0e7a486c9217dad))

* MOD: Refactored Project Unit of Work and respective service consumer

Refactored Project Unit Of Work (UoW) to reflect separation
between packages manager and packages registry. Now initialization
happening within UoW instance. Changed respective consumer
(project service).

Additionally, fixed some linting issues.

GH-4 ([`47f0fac`](https://github.com/ossiq/ossiq/commit/47f0fac6713090e2c1a2374aa9ee1cdf10ac9983))

* ADD/MOD: Introduced PyPi and UV package manager

Introduced adapters/package_managers to work with
different package managers (UV, NPM, Poetry in plans),
later on probably PNPM. The ultimate idea is that
there are much fewer registries in comparison to
package managers, hence should be treated differently.

Additionally, introduced new pattern of identifying
package manager base on project filename/lockfile
and pushed that logic into Package Manager implementation
itself. Supposedly, it would be easier to maintain/keep
localized.

GH-4 ([`7afe14e`](https://github.com/ossiq/ossiq/commit/7afe14ef952eb18b3b0c10ea05fbe0f13b833ae2))

* ADD: Added ecosystem domain entity

Added Ecosystem domain entity and adjusted
respectively other entities to split
Ecosystem (package registry) from Package
Manager (local tool). Currently,
Ecosystem term is not settled yet, might
be refactored to Package Manager to be more
intuitive.

GH-4 ([`17101be`](https://github.com/ossiq/ossiq/commit/17101beb41339f734e179234cd3c66ba131ff5bc))

* Merge pull request #14 from ossiq/GH-1-fixed-mkdocs-for-github-pages-custom-domain

MOD: Added custom domain name ossiq.dev ([`c22963d`](https://github.com/ossiq/ossiq/commit/c22963ddd2a5ae4c9de8094c4181b577b25f4ee6))

* MOD: Added custom domain name ossiq.dev

Added custom domain ossiq.dev instead of
github pages default domain which is a subfolder.

GH-1 ([`a1a991a`](https://github.com/ossiq/ossiq/commit/a1a991accfbb3a1518a4260281bf1a6cb028f08c))

* Merge pull request #13 from ossiq/GH-1-fixed-mkdocs-for-github-pages

MOD: Modified links to accomodate github pages ([`be12057`](https://github.com/ossiq/ossiq/commit/be12057e0d705194d269143c8d6018b48721762d))

* MOD: Modified links to accomodate github pages

The way github pages works is a bit different than
default configuration of MkDocs. Now fixed.

GH-1 ([`d1daaea`](https://github.com/ossiq/ossiq/commit/d1daaea0b1f0fb3c7202791140adb220aa4aeb43))

* Merge pull request #12 from ossiq/GH-1-documentation-workflow

Update checkout action and simplify workflow ([`505b6f7`](https://github.com/ossiq/ossiq/commit/505b6f76db69520bccc56b50e148c930f8a1462e))

* MOD: Modified github action to publish github pages

 - fixed material-mkdocs to align with the latest version
 - added recommended docs github action to publish docs
 - fixed mkdocs `info` plugin to not break mkdocs build

GH-1 ([`92a67a1`](https://github.com/ossiq/ossiq/commit/92a67a1ffa1d9d14598ff574e7d302b60d3ad282))

* Update checkout action and simplify workflow

Updated checkout action version and removed multi-line script. ([`a680d57`](https://github.com/ossiq/ossiq/commit/a680d570d7765b005388b900605afff4d8f5cc77))

* Merge pull request #2 from ossiq/GH-1--documentation

ADD: Added MkDoc and some initial configuration ([`6601bf2`](https://github.com/ossiq/ossiq/commit/6601bf2a428184538432320d8a3b7aa617a039d2))

* MOD: Cleaned Up PR Github Action

 - Cleaned up justfile to run proper commands
   as well as streamlined github action to leverage uv.
 - Added just to github actions
 - Added project uv sync
 - Fixed reference to just command inside just

GH-1 ([`38030b0`](https://github.com/ossiq/ossiq/commit/38030b0af73c3014cc0b601f62ae308e3123c439))

* MOD: Modified Readme to reflect landing content

Modified README.md to reflect what is in documentation
and landing.

GH-1 ([`0a29271`](https://github.com/ossiq/ossiq/commit/0a292710aba961fe36f07867635de632533f4808))

* MOD: Polished first iteration of Reference file

Polished first iteration of Refernce file:
removed full model descriptions, since there&#39;s
no way it would be possible to keep code
and documentation aligned without some
auto-generation tool. Additionally, described
version differences in version.py for further
reference

GH-1 ([`eab22d6`](https://github.com/ossiq/ossiq/commit/eab22d60528042fa8c841c8aeb6d4c38545d7485))

* MOD: Finalized initial draft of the documentation

 - finilized draft of documentation
 - finilized landing page and MkDocs configuration
 - aligned slogan everywhere

GH-1 ([`7d910cf`](https://github.com/ossiq/ossiq/commit/7d910cf709177168479655a53bbeabb5b1188021))

* ADD: Added first iteration of Getting Started

Added first iteration of Getting Started instruction.
Additionally, fixed use case for unpublished packages
as well as adjusted reports accordingly. Unpublished
packages now on the top of default priorities list.

GH-1 ([`262edad`](https://github.com/ossiq/ossiq/commit/262edadf289e3be8cdb5a3d400bec3ac0d17c3d9))

* fixup! MOD: Fixed unpublished package use case ([`165c81d`](https://github.com/ossiq/ossiq/commit/165c81daf0c1e7922b8d2b51ad19af264717f2db))

* MOD: Fixed unpublished package use case

Fixed some remaining accidental typing issues
and also added support for unpublished packages
from the NPM registry

GH-1 ([`219a61f`](https://github.com/ossiq/ossiq/commit/219a61f6f4f09e7246329061d85c4277b4133dc2))

* MOD: Fixed typing issues and redesigned settings access pattern

 - fixed remaning typing issues
 - refactored how to deal with Settings: leveraged
   Typer Context instead of &#34;global&#34; variable approach
   with wrong types

GH-1 ([`1ff4c69`](https://github.com/ossiq/ossiq/commit/1ff4c69eb44a186bbabb31e123b8ce3588240166))

* MOD: Reverted justfile commands and fixed some typign errors

 - with revert of `qa` command there are a lot of typing surprises.
   So far fixed 9 out of 35-ish.
 - reverted back Justfile command like test and qa which are actually
   useful and should be used.
 - removed unused/not needed AST-related code, would be needed
   later in the future.

GH-1 ([`ebbcf04`](https://github.com/ossiq/ossiq/commit/ebbcf04dc013a34ee983bcc2cc41db7ec5b49427))

* ADD: Added Landing and Explanation sections

 - Added Landing with more-or-less clear description, partially
generated with LLM.
 - Added Explanation section focused on audiences but with
   no links with the existing features (yet).
 - Setup for MkDocs

GH-1 ([`569d64f`](https://github.com/ossiq/ossiq/commit/569d64f5cfdde8db488d7e53d2269a735ba9d2bb))

* ADD: Added MkDoc and some initial configuration

Added MkDoc and few example files just to get a feeling.

GH-1 ([`62871bd`](https://github.com/ossiq/ossiq/commit/62871bd924672ea5a4a1cfa115dd51f9340e8158))

* ADD: Added AUTHORS and changed license to GNU AGPL v3 ([`5f97901`](https://github.com/ossiq/ossiq/commit/5f979019ab0b257477c392a3ef17c80d1343e965))

* ADD: Added CVE report to HTML

Added CVE report (count) with direct link to osv.org for now.

Next Steps:
 - Separate issue to abstract out OSV.dev
 - Refactor back CVE severity score instead of converstion to categories
   since there&#39;s apparently standard, so likely other source will be compatible
   or has clear conversion.
 - Add larger scores highlights above the table with report data (separate issue) ([`98e9a57`](https://github.com/ossiq/ossiq/commit/98e9a57380097967f61ea6d09a3e3185803c4c95))

* ADD: Added CVE from OSV.dev and integrated into Console report

Added CVE database and adapter for osv.dev, so that
quantity of CVEs could be displayed in the report. No
transitive dependencies reporting yet.

Next Steps:
 - Make sure theme is good in Light mode
 - Integrate CVEs into HTML report
 - Solidify CSV export, currently prototype implementation
 - Start adding tests ([`d800dc6`](https://github.com/ossiq/ossiq/commit/d800dc6ebe38d94ca57ec25ab53e573e11232cad))

* MOD: Major refactoring/rebranding from udpate_burden to ossiq

Python module renamed to ossiq for simplicity and
package/project renamed to ossiq-cli for nicer
naming and clarity. Requirements migrated to UV package
manager, so now there&#39;s uv.lock file.

Next Step:
 - add CVE repository from osv.dev ([`8cb55c5`](https://github.com/ossiq/ossiq/commit/8cb55c5fbefea7f525248609b19c90dcc75a2f8d))

* MOD: Added sorting by columns and export as CSV

Added sorting by any column (three modes: asc, desc and no sorting)
and download report data as a CSV file.

Next Steps:
 - Integrate CSV reports from Github
 - Make sure theme is good in Light mode ([`7bba605`](https://github.com/ossiq/ossiq/commit/7bba605f68fa898324793a0420e4d6300cae31c8))

* MOD: Added value filtering and initial sorting implementation

- Added filtering by all available columns as well as
  filters reset and search by substring
- Added initial implmenetation of sorting (naive)
- Hide report description by default;

Next steps:
 - Finish sorting by available columns
 - Implement CSV export
 - Make sure styling is consistent for Light and Dark modes ([`91e5d31`](https://github.com/ossiq/ossiq/commit/91e5d312f291e246a15cb5c777712271470cc1b0))

* MOD: Added basic filtering capability by range to the HTML report

Added basic filter capability (imperfect for now) with Vue and
some raw javascript. MVP implementation for Time Lag metric.

Next step:
 - Add by value filtering (Major/Minor etc.)
 - Add checkbox filtering (Production/Development) packages
 - Fix mobile (Tablet) markup and check Light Theme
 - Hide Legend by default ([`f12e06b`](https://github.com/ossiq/ossiq/commit/f12e06b7af5c78b057f5fabc52ab05bcef740f84))

* MOD: Added Releases Lag metric

Finished data-wise first iteration of the Overview command.
Added initial HTML markup and Vue app integration (via CDN)
for the HTML report.

Next Steps:
 - Implement filters for HTML report
 - Add filter for Dev/Non-dev dependencies ([`32a2571`](https://github.com/ossiq/ossiq/commit/32a257107c713607cb53acb8a319569ce2239a52))

* MOD: Refactored Project Overview records

Integrated versions diff instance into ProjectOverviewSummary
and sorted records by versions difference index first,
then by by Time Lag

Next Step:
 - Calculate difference in versions (Versions Lag)
 - Integrate Development Dependencies into HTML template ([`fe418cb`](https://github.com/ossiq/ossiq/commit/fe418cbbc3de3cc89538ed473695f8088ddc1409))

* MOD: Refactored highlight logic into filters and tags

Refactored logic into filters and tags, unified logic
to format &#34;human readable&#34; delta in days, so that
HTML and Console version produce same results.

Enhanced HTML template, added Material design icons experiment and
some boilerplate legend.

Next Steps:
 - Add lag in number of releases
 - Produce ProjectOverviewSummary with already sorted dependencies
   according to the sorting rules (Major releases first, then
   time lag threshold, then minor releases and the rest ([`3f2816e`](https://github.com/ossiq/ossiq/commit/3f2816eac03b3c7c12f00d4482a1d4c3e8f3cdf2))

* MOD: Added Jinja-rendered HTML report design

- Refactored HTML design for the Dependencies
  Lag report, added some fonts and meaningful header.
- Added Time Lag highlight (currently, red font) for
  dependencies over the specified threshold.
- Added `output_destination` setting, but not
  impelmented yet the function. The purpose would
  be to store HTML report to the specified location.
- Renamed config.py to settings.py to align with the
  classname/easier to remmeber during development to which
  file switch for the configuration.
- Moved all help messages to messages.py to cleanup
  cli.py a bit.

Next steps:
 - Finish HTML report with the project info and
   short aggregated summary on the top.
 - Add intelligent versions lag description
   to the table, for example &#34;2 patch, 2 minor, 1 major&#34;
 - Add highlight to the table rows for the lagging
   dependencies. ([`148e905`](https://github.com/ossiq/ossiq/commit/148e905c6a08cf6de5d1d1ce78b6fbb0f882c30b))

* MOD: Finished segregation by prod/dev packages and non-zero exit code

Added segregation in console table between prod/dev packages
as two separate tables as well as added --production flag to
focus only on production packages.

Additional nice feature is to exit with non-zero exit code in
case there are packages older than specified threshold, so that
overview could be build into CI/CD pipeline under a PR and
drive behaviors to keep packages updated.

Next Steps:
 - Add HTML view of the same info
 - Add JSON view of the same info ([`755d68d`](https://github.com/ossiq/ossiq/commit/755d68dd8f4712c969fa847b15e9dc5a8290b3cd))

* MOD: Added lag theshold to highlight packages outside lag

Added basic implementation of the lag highlight code, parameters
to the command and formatting.

Refactored factories to be simple function, no need to maintain
class.

Added a function to parse vague time delta (e.g. 3m ), but
there&#39;s clear idea how to convert it to exact number.

Next steps:
 - refactor vague parsing time delta function to calculate precisely;
 - control exit code depends on the lag threshold and production flag
 - write better help functions
 - renamte package to the new name, write good readme. ([`9ea75f3`](https://github.com/ossiq/ossiq/commit/9ea75f3421dd14947d0b2c383c1133c6933ccef2))

* MOD: Finished overview command with time lag

Finished overview command with versions overview
and Time Lag formatted.

Next Step:
 - Add threshould in days when to return non-zero exit code, so that
   this information could be included into CI/CD pipeline. ([`4494fe2`](https://github.com/ossiq/ossiq/commit/4494fe2ba0f65e3be2a66a2b5d2579ea9d9828be))

* MOD: Finished initial implementaiton of aggregated changes

Finished initial implementation of changes aggregation logic
in Service Layer (service/common/package_versions), stuck
a bit with Version date. By default there&#39;s no date provided
from the NPM API response related to Package Info, so
probably woudl need to requrest versions separately.

Next Steps:
 - Figure out how exactly versions works from NPM perspective.
   Seems like there&#39;s direct connection with the repository
   unlike PyPi infrastructure where published version at least
   used to be completely independent.

 - Finish versions aggregation, so that Overview command
   could be finished. ([`dc930ee`](https://github.com/ossiq/ossiq/commit/dc930ee4255a136fb1bb01e1ab10fd7c8acb6875))

* MOD: Added presentation layer and initial implementation of overview

Added presentation layer and ability to support multiple
presentation methods. At least HTML should be added later.

Also, initial implementation of UoW for the Project Overview
alongside some additional details.

Next step: Finish Project Overview command with
respective high level minimal metrics like version lag. ([`b7d9aac`](https://github.com/ossiq/ossiq/commit/b7d9aac469d457cad115025b34a1cbff704f0d22))

* MOD: Finished initial implementation of DDD-like architecture

Finished DDD-like (or clean architecture like) architeceture
with complete implementation of NPM and Github as well
as redesigned Project Unit of Work and service.

Next step: generate Project Overview service response
and show it in a nicely formatted table/complete
project overview command. ([`1b6fcbc`](https://github.com/ossiq/ossiq/commit/1b6fcbcc93c12008f3eff8476b5d9f8693109cff))

* ADD: Added UoW project and respective infrastructure

Few architectural decisions:
 - unit of work for packages doesn&#39;t make sence by itself
   without project. And UoW purpose is atomicity
   which is not needed for now at all. Keeping UoW
   for a project just for the future convenience if
   caching layer would ever needed (to prevent from
   partial caching).
 - project adapter is not needed either b/c it would
   always go hand to hand with Package Registry
   API/implementation, so it makes sense to keep them
   together. For now there&#39;s not much sophistication
   expected from the Project reader itself.
 - repository provider abstraction doesn&#39;t make
   sense to initialize at UoW level, since it&#39;s
   specific to a particular package, hence
   would need to be instanticated for each.

Next step:
 - Design full service to pull installed packages info
   and return some useful metrics about its current state. ([`ea7cdf3`](https://github.com/ossiq/ossiq/commit/ea7cdf3b35ba2b8799dd9276949e57f023acf1f4))

* ADD: Added NPM registry abstraction and extended UoW

Added NPM registry abstraction with factory similarly
to the Github repository and extended UoW to
initialize.

Next step would be to abstract out local project,
seems like the packages situation with Python
became a bit more complex with uv/PEP 621. ([`eb7b3d9`](https://github.com/ossiq/ossiq/commit/eb7b3d96473fa62cbdb28ef81d0fd49ecac79610))

* MOD: MVP of Unit Of Work with Service Layer

Attempt to follow Cosmic Python approach with
kind of Clean Architecture abstractions using
Factory to abstract Github Client (and NPM eventually)
and Unit of Work pattern to isolate clients initialization.

No tests yet, but feels like it&#39;s coming.

Next step is to abstract out NPM and repeat
same MVP as without redesign. ([`27470d6`](https://github.com/ossiq/ossiq/commit/27470d606f64f629eb5ff3e0e4a3cff063ea6455))

* MOD: Chores related to models design

Initial implementaion of the interaction (MVP) is
working but barely maintainable. Especially
potential to add PyPi. Refactored to something
similar to Service Layer architecture for now,
at least models are in the dedicated space and
API clients interaction now have own interface
to follow. ([`9d6b69e`](https://github.com/ossiq/ossiq/commit/9d6b69e70e3d9e5acb472f81943b203f247b85a2))

* MOD: Added doc how to run overview

Added documentation how to run the tool with hatch
in development mode. ([`bf874d0`](https://github.com/ossiq/ossiq/commit/bf874d027c60873d78951ea8698cb47f43c59222))

* MOD: Simplified implementation in versions difference

Simplified implementation of identifying difference
between versions and fixed some __repr__ leftovers
after attribute rename. ([`eff09c2`](https://github.com/ossiq/ossiq/commit/eff09c24167011544fb12c47af3ba603cc63a7fb))

* MOD: Finished with package and source code changes aggregation

Finished implementation of the pulling meta information about
versions as well as detecting difference (in commits) between
installed and consequtive versions for a NPM package and Github
repository.

Next stop is to create an overview of what is currently
goint on version-wise as well as code age and summary of
the newer changes. ([`a2a7d88`](https://github.com/ossiq/ossiq/commit/a2a7d88c4d8300180131664398afeb458d3bb23c))

* MOD: Added settings to the tool and some more github logic

Added settings to set github_token globally when needed
and some additional logic about pulling versions caused
mismatch between what was released and what was
published. Example is i18n-node, where
there is 0.15.0 release and the next one is 0.15.2, while
NPM contains 0.15.1. We would need to resolve divergence
somehow later. ([`93dcf4f`](https://github.com/ossiq/ossiq/commit/93dcf4f182a251ab55ddb478c946cf68dab46ea1))

* MOD: Finished source code versions and package versions loading

As per idea in the previous commit, limited loaded version
just fot the ones needed to calculate difference between
what is installed and the latest package release. Added
support for Github pagination and both Github releases
and Github tags based on Github API. ([`b3b7c6e`](https://github.com/ossiq/ossiq/commit/b3b7c6ee37d1a1ee02ed080d5553d640adb53a9f))

* MOD: Added github versions and npm versions pulling logic

Added NPM versions pulling logic and respective data structures
as well as pulling releases (completed) and tags. Current blocker
is combination between pagination and page limits. As an example,
luxon library has pretty large amount of tags and default
quantity returned is 30 tags. This is not enough to correcly
match versions registered at NPM and tags loaded from Github.

Additionally, designed structures to define Version
from this tool perspective which is combination between
data from the registry (like NPM) and low-level
data available in source code repository provider (github).

NOTE: as an idea to try is to actually load no more than
difference between what is installed and what is available,
hence likely one-two pages loaded would be more than enough. ([`0918b80`](https://github.com/ossiq/ossiq/commit/0918b809889ef3927343bd45b5594ee2561bd53a))

* MOD: Factored in public package info

Factored in public package info (currently, for NPM),
added some useful abstractions and organized code
around possibility to perform analysis both on
PyPi and NPM. Implemented NPM only for now.

Moved AST code changes analysis into code subfolder. ([`f4b501e`](https://github.com/ossiq/ossiq/commit/f4b501ea426ff4336482d6e137c715aa9e3a5095))

* ADD: Initial commit with pypi package tools

Initial commit with pypi package infrastructure
and some experiments around AST parsing. ([`15b27df`](https://github.com/ossiq/ossiq/commit/15b27df3c7491c341656b07981f48da25175e7b0))

* Initial commit ([`659ccd4`](https://github.com/ossiq/ossiq/commit/659ccd4a54c7490eb621c4c68ada331c1c487ed1))

* Initial commit ([`b1ac852`](https://github.com/ossiq/ossiq/commit/b1ac8524f4cb8e2e57b4fdc09753c952b39747db))
