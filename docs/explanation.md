# Explanation

## OSS IQ: The Case for Engineering Fitness

OSS IQ introduces a paradigm shift in software supply chain management: **moving from reactive vulnerability patching to proactive sustainability modeling.**

While traditional tools focus on the current state of a dependency (is it secure today?),

**OSS IQ focuses on its trajectory** (will it be viable in two years?). This section explores the architectural rationale behind this "Layer 3" approach.

## The Three-Layer Maturity Model

To understand where OSS IQ fits, we must view dependency management as an evolving stack of capabilities. Most organizations are currently stuck at Layer 2.


| **Layer**                    | **Focus**           | **Key Question**                     | **Primary Artifacts**               |
| ---------------------------- | ------------------- | ------------------------------------ | ----------------------------------- |
| **3: Engineering Fitness**   | **Sustainability**  | Is this a sound long-term bet?       | Longitudinal signals, Decay metrics |
| **2: Security & Compliance** | **Risk Mitigation** | Is this safe/legal to use right now? | CVEs, License policies              |
| **1: Inventory**             | **Visibility**      | What are we actually using?          | SBOMs (CycloneDX/SPDX)              |


## Audience Perspectives

If you're just starting out, it's easy to think that if the code "works" and the security scanner shows green, you're safe. Scanners are looking for fires that are happening right now, not risks that are slowly growing. You could be using a library that has no known security holes today but hasn't had a commit in two years. That's what "Maintenance Decay" means. Or maybe the library is changing so quickly that every small change breaks your build. This is called "Release Volatility." OSS IQ makes these hidden signals clear, which helps you understand that risk builds up long before a failure happens.


### Quantifying Technical Debt

You've seen this movie before: you know a specific library is becoming a liability, but it's hard to justify a refactor to stakeholders when you can't point to a specific CVE. This is why we need to move toward "Architecture Fitness Functions" for the supply chain. Instead of arguing based on vibes, we look at longitudinal signals. We can actually compare two libraries by their **"Maintenance Velocity"** or identify **"Structural Fragility"**-those single points of failure where a project is being held together by one tired contributor. It turns an intuitive judgment into shared evidence.

By tracking longitudinal signals, architects can:

  - Evidence-Based Selection: Compare two libraries not just by features, but by their "Maintenance Velocity."
  - Identify Structural Fragility: Spot dependencies that are becoming "single points of failure" due to dwindling community support.
  - Standardize Evaluation: Move from subjective "vibes" to a structured rubric for dependency on-boarding.

### Cooldown as Supply-Chain Quarantine

A growing share of supply-chain attacks ride on *freshly published* releases: a maintainer account
is compromised, a malicious version is pushed, and automated update tooling distributes it before
anyone notices. The cooldown period (`--cooldown-period`, default 7 days) treats version age as a
quarantine: very fresh releases are penalized in the solver and withheld from the update plan until
they have survived in the wild for a while.

Quarantine creates one deliberate tension: what if the quarantined version fixes a CVE? OSS IQ
resolves it in favour of the *known* risk — a package whose installed version carries a CVE bypasses
the cooldown hold, because a concrete vulnerability outweighs the statistical freshness risk. The
bypass is always visible in the plan (a `CVE` tag and a "cooldown bypassed" note), and teams that
want manual control can scope runs with `--security` or force a vetted version with
`--override pkg==version`. Brand-new transitive dependencies sit outside the quarantine — they are
resolved by the native package manager — so the plan surfaces their age and flags fresh ones with
`⚠` instead of silently admitting them.

### Governance at Scale

When it's not about micro-managing individual package choices, but about managing a portfolio of risk you want to ensure your teams aren't just "fixing bugs" but building on sustainable foundations.

 - From Reactive to Proactive: Instead of responding to a "Zero Day," you are alerted when a critical dependency's health score dips below a defined threshold.
 - Policy as Code: Define organizational "Fitness Gates" that prevent high-risk, low-activity dependencies from entering the codebase in the first place.
 - Resource Allocation: Gain visibility into which teams are carrying the most "Dependency Debt," allowing for better-informed architectural investments.


<!-- ## Key Differentiators: Point-in-Time vs. Longitudinal

The core innovation of OSS IQ is the move from Snapshot Analysis to Trend Analysis.

Traditional scanners provide a "Pass/Fail" grade based on known vulnerabilities. OSS IQ intent is to evaluates the health of the producer, not just the state of the product. This allows organizations to anticipate a failure before it manifests as a security vulnerability or a production outage. -->
