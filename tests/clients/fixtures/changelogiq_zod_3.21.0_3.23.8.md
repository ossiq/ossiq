---
package: "zod"
ecosystem: "npm"
from_version: "3.21.0"
to_version: "3.23.8"
release_date: "2024-05-08"
risk_level: "HIGH"
breaking_change: true
security_fix: true
cve_references: []
---

# Migration guides

- 3.22.1: [MIGRATION.md](https://github.com/colinhacks/zod/blob/v3.22.1/MIGRATION.md)
- 3.23.0: [MIGRATION.md](https://github.com/colinhacks/zod/blob/v3.23.0/MIGRATION.md)

# Changelog

## [3.23.8] - 2024-05-08

_Adds Bronze sponsor logos, tweaks tier definitions and changes RefinementCtx to an interface._

### Added

- Add Bronze sponsor logos ([#3470](https://github.com/colinhacks/zod/issues/3470))

### Changed

- Tweak sponsor tier definitions ([#3471](https://github.com/colinhacks/zod/issues/3471))
- Change RefinementCtx to an interface

## [3.23.7] - 2024-05-07

_Adds new copper and social crow content and fixes JSDoc property documentation being erased by extendShape._

### Added

- Add copper content
- Add social crow content

### Fixed

- Fix extendShape erasing JSDoc property documentation ([#3437](https://github.com/colinhacks/zod/issues/3437), [#3463](https://github.com/colinhacks/zod/issues/3463))

## [3.23.6] - 2024-05-03

_Fixes freezing of async ZodReadonly results and adds documentation for protecting against cyclical objects._

### Fixed

- Fix freezing of async ZodReadonly results ([#3457](https://github.com/colinhacks/zod/issues/3457))

## [3.23.5] - 2024-04-29

_Allows ZodEnum to accept readonly string arrays._

### Changed

- Allow ZodEnum to accept a readonly string array ([#3444](https://github.com/colinhacks/zod/issues/3444))

## [3.23.4] - 2024-04-23

_Reverts the change to the default Input and adds the 3.23 announcement._

### Added

- Add the 3.23 announcement

### Changed

- Restore the previous default Input behavior

## [3.23.3] - 2024-04-22

_Release version 3.23.3._

## [3.23.2] - 2024-04-22

_Updates the protocol and fixes t3env in version 3.23.2._

### Changed

- Update the protocol

### Fixed

- Fix t3env

## [3.23.1] - 2024-04-22

_Restores any as the default generic type for ZodType to avoid breakages with common packagers._

### Changed

- Change the default generic types of ZodType back to any

## [3.23.0] - 2024-04-21

_Adds new string validators for ISO date, time, duration and base64 formats, improves datetime and discriminated unions, and fixes several validation bugs._

### Added

- Add z.string().date() to validate ISO 8601 date strings ([#1766](https://github.com/colinhacks/zod/issues/1766))
- Add z.string().time() to validate ISO 8601 time strings with an optional sub-second precision setting ([#1766](https://github.com/colinhacks/zod/issues/1766))
- Add z.string().duration() to validate ISO 8601 duration strings ([#3265](https://github.com/colinhacks/zod/issues/3265))
- Add z.string().base64() to validate base64 strings ([#3047](https://github.com/colinhacks/zod/issues/3047))
- Allow optional, nullable, readonly, branded and catch-wrapped literals as discriminator keys in discriminated unions
- Allow falsy values as custom error messages ([#3178](https://github.com/colinhacks/zod/issues/3178))
- Add a message attribute to enum validation errors ([#3169](https://github.com/colinhacks/zod/issues/3169))

### Changed

- **Breaking:** Add ZodPipeline, ZodReadonly and ZodSymbol to the ZodFirstPartySchemaTypes union ([#3247](https://github.com/colinhacks/zod/issues/3247))
- **Breaking:** Restrict .pick() and .omit() masks to known object keys, so unknown keys now cause compiler errors ([#3255](https://github.com/colinhacks/zod/issues/3255))
- Allow timezone-less datetimes in z.string().datetime() via a local option ([#2522](https://github.com/colinhacks/zod/issues/2522))
- Make the input of .required() readonly ([#3301](https://github.com/colinhacks/zod/issues/3301))
- Add never properties to safe parse return types ([#3295](https://github.com/colinhacks/zod/issues/3295))
- Make EnumValues generic ([#2338](https://github.com/colinhacks/zod/issues/2338))

### Fixed

- Reject invalid day-of-month values such as February 30th in datetime validation ([#3391](https://github.com/colinhacks/zod/issues/3391))
- Preserve error mappings when using Enum.extract and Enum.exclude ([#3240](https://github.com/colinhacks/zod/issues/3240))
- Report errors from preprocess schemas nested as the second property of an object ([#2912](https://github.com/colinhacks/zod/issues/2912))
- Fix addQuestionMarks so optional object properties are typed correctly ([#3352](https://github.com/colinhacks/zod/issues/3352))
- Stop z.record().parse() from filtering out undefined values ([#3251](https://github.com/colinhacks/zod/issues/3251))
- Fix email validation rejecting addresses containing single quotes ([#2889](https://github.com/colinhacks/zod/issues/2889))
- Stop allowing commas in email addresses ([#3286](https://github.com/colinhacks/zod/issues/3286))
- Align the cuid2 validation regex with the cuid2 library ([#2961](https://github.com/colinhacks/zod/issues/2961))
- Speed up enum comparison by using Set.has instead of Array.indexOf ([#2659](https://github.com/colinhacks/zod/issues/2659))
- Speed up IPv4 parsing ([#3413](https://github.com/colinhacks/zod/issues/3413))
- Avoid unnecessary error maps for better performance ([#2532](https://github.com/colinhacks/zod/issues/2532))

## [3.22.5] - 2024-04-18

_No changelog found: no release notes, changelog entry or git tag._

## [3.22.4] - 2023-10-04

_Adds deprecation notices to built type declarations and fixes the ULID regex._

### Changed

- Include deprecated JSDoc annotations in built type declarations ([#2717](https://github.com/colinhacks/zod/issues/2717))
- Load the emoji regex lazily

### Fixed

- Fix the ULID validation regex ([#2225](https://github.com/colinhacks/zod/issues/2225))
- Fix broken links in the ecosystem documentation ([#2840](https://github.com/colinhacks/zod/issues/2840))

## [3.22.3] - 2023-10-03

_Fixes a ReDoS vulnerability in the email regex and updates documentation._

### Changed

- Clarify ISO 8601 datetime documentation ([#2673](https://github.com/colinhacks/zod/issues/2673))
- Update custom schemas documentation example to use type narrowing ([#2778](https://github.com/colinhacks/zod/issues/2778))
- Update reference to discriminated unions documentation ([#2485](https://github.com/colinhacks/zod/issues/2485))

### Removed

- Remove obsolete documentation text about readonly types ([#2676](https://github.com/colinhacks/zod/issues/2676))

### Fixed

- Fix ReDoS vulnerability in the email regex ([#2824](https://github.com/colinhacks/zod/issues/2824))

## [3.22.2] - 2023-08-19

_Adds documentation entries for ecosystem tools and fixes type inference for superRefine._

### Fixed

- Fix type inference for superRefine

## [3.22.1] - 2023-08-15

_Fixes handling of `this` in ZodFunction schemas, which now requires the Reflect API._

### Changed

- **Breaking:** Require the Reflect API for parsing function schemas ([#2652](https://github.com/colinhacks/zod/issues/2652))

### Fixed

- Fix `this` binding in ZodFunction schemas so methods receive the correct context ([#2651](https://github.com/colinhacks/zod/issues/2651), [#2652](https://github.com/colinhacks/zod/issues/2652))

## [3.22.0] - 2023-08-14

_Adds a readonly schema wrapper and method, broadens email validation, and fixes a prototype pollution vulnerability._

### Added

- Add ZodReadonly schema and a readonly() method on all schemas that freezes parsed output and infers readonly types ([#2634](https://github.com/colinhacks/zod/issues/2634))
- Add getters for map keys and values ([#2356](https://github.com/colinhacks/zod/issues/2356))
- Pass context to preprocess callbacks ([#2426](https://github.com/colinhacks/zod/issues/2426))

### Changed

- Allow subdomains and hyphens in email string validation ([#2274](https://github.com/colinhacks/zod/issues/2274), [#2157](https://github.com/colinhacks/zod/issues/2157))
- Generalize the UUID regular expression
- Remove unnecessary type casts when creating enums ([#2332](https://github.com/colinhacks/zod/issues/2332))

### Fixed

- Fix prototype pollution vulnerability ([#2239](https://github.com/colinhacks/zod/issues/2239))
- Fix super refinement function types ([#2420](https://github.com/colinhacks/zod/issues/2420))

### Security

- Fix a prototype pollution vulnerability ([#2239](https://github.com/colinhacks/zod/issues/2239))

## [3.21.4] - 2023-03-07

_Release version 3.21.4 with no user-facing changes._

## [3.21.3] - 2023-03-06

_Reverts a previous change and fixes the npm canary action path pattern._

### Fixed

- Fix the npm canary action path pattern ([#2148](https://github.com/colinhacks/zod/issues/2148))

## [3.21.2] - 2023-03-06

_Improves generic type inference and typings and passes input into catchValue._

### Changed

- Improve type inference and typings inside generic functions
- Pass the input value into catchValue

## [3.21.1] - 2023-03-06

_Adds ULID validation and string includes checks, and improves parsing performance._

### Added

- Add ULID validation via z.string().ulid() ([#2049](https://github.com/colinhacks/zod/issues/2049))
- Add includes check with options to string schemas ([#1887](https://github.com/colinhacks/zod/issues/1887))

### Changed

- Make safeParse().error a getter
- Cache lazy path evaluation for a moderate performance improvement ([#2137](https://github.com/colinhacks/zod/issues/2137))

### Fixed

- Restore toLowerCase and toUpperCase string methods

[3.23.8]: https://github.com/colinhacks/zod/compare/v3.23.7...v3.23.8
[3.23.7]: https://github.com/colinhacks/zod/compare/v3.23.6...v3.23.7
[3.23.6]: https://github.com/colinhacks/zod/compare/v3.23.5...v3.23.6
[3.23.5]: https://github.com/colinhacks/zod/compare/v3.23.4...v3.23.5
[3.23.4]: https://github.com/colinhacks/zod/compare/v3.23.3...v3.23.4
[3.23.3]: https://github.com/colinhacks/zod/compare/v3.23.2...v3.23.3
[3.23.2]: https://github.com/colinhacks/zod/compare/v3.23.1...v3.23.2
[3.23.1]: https://github.com/colinhacks/zod/compare/v3.23.0...v3.23.1
[3.23.0]: https://github.com/colinhacks/zod/releases/tag/v3.23.0
[3.22.4]: https://github.com/colinhacks/zod/compare/v3.22.3...v3.22.4
[3.22.3]: https://github.com/colinhacks/zod/compare/v3.22.2...v3.22.3
[3.22.2]: https://github.com/colinhacks/zod/compare/v3.22.1...v3.22.2
[3.22.1]: https://github.com/colinhacks/zod/compare/v3.22.0...v3.22.1
[3.22.0]: https://github.com/colinhacks/zod/compare/v3.21.4...v3.22.0
[3.21.4]: https://github.com/colinhacks/zod/compare/v3.21.3...v3.21.4
[3.21.3]: https://github.com/colinhacks/zod/compare/v3.21.2...v3.21.3
[3.21.2]: https://github.com/colinhacks/zod/compare/v3.21.1...v3.21.2
[3.21.1]: https://github.com/colinhacks/zod/compare/v3.21.0...v3.21.1
