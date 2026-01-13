# CHANGELOG



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
