---
title: Upgrade one package at a time
description: Step through your updates with ossiq upgrade. Preview each one, install it, run your tests, then keep, roll back or skip it. A coding agent can drive the same steps.
---

# Upgrade one package at a time

Run `ossiq upgrade start`, and OSS IQ queues the updates `plan` lists as steps. Each step shows what
changes, installs it and runs your tests. You then keep it, roll it back or skip it before the next
step begins. A failing step stops one package, not the whole batch.

`ossiq upgrade` works with npm, pnpm and uv projects. It does not commit anything, so commit between
steps if you want a commit per package.

The session lives in a `.ossiq/` directory in the project. It holds `update-progress.json` and a copy
of the manifest and lockfile from before each step, and it ignores itself, so `git add -A` skips it.
Every command reads the session from there, so you can close the terminal and come back.

## Start a session

1. Start the session with the command that tests your project:

   ```bash
   ossiq upgrade start --test-command "npm test"
   ```

   OSS IQ runs the test command once before it changes anything. If that run fails, no session
   starts, so a failure after a step always points at that step.

2. Read the queue it prints:

   ```text
   ──────────────────────── OSS IQ — Upgrade: step 1 of 7 ─────────────────────────
     ▶    1  lodash 4.17.15 → 4.18.1  PENDING
          2  qs 6.10.1 → 6.17.1  PENDING
          3  semver 7.3.5 → 7.8.6  PENDING
          4  uuid 8.3.2 → 14.0.3  PENDING
          5  dayjs 1.10.0 → 1.11.23  PENDING
          6  chalk 4.0.0 → 6.0.1  PENDING
          7  get-intrinsic 1.3.0 → 1.3.1  PENDING
   ```

A step is one direct dependency plus the packages that must move with it. Those are the transitive
copies it pulls in and the peers that only work together, such as `react` and `react-dom`. The
transitive updates that no direct dependency pulls in share the last step.

OSS IQ orders the steps by:

1. Install pass (see [Install passes](../reference/commands.md#install-passes)).
2. Packages with a CVE before the rest, highest EPSS (exploit probability) score first.
3. Smaller version bumps before larger ones.
4. Name.

`start` accepts the options of [`plan`](../reference/commands.md#plan-and-apply), such as
`--update-strategy latest`, and three of its own:

| Option | Effect |
|---|---|
| `--test-command CMD` | Run `CMD` before the first step and after every install |
| `--limit N` | Queue only the first `N` steps |
| `--package NAME` | Queue only the step of one direct dependency |

## Read a step

`start` also shows everything OSS IQ knows about the first update:

- the row `status --full` prints for the package
- the `info` report for the target version
- the module-system and engine breaks
- a summary of the changelog

A package that moves with it gets its row too.

To read the changelog of every version in the step, run:

```bash
ossiq upgrade changelog
```

Add `--web` to open the same range on [changelogiq.dev](https://changelogiq.dev) in your browser.

The changelogs come from changelog IQ. OSS IQ sends it the ecosystem, the package name and the two
versions. The first request for a range can take a while, because the service writes the changelog then.
OSS IQ waits and reports progress on stderr. When the service is unreachable, the step shows "Not
available" with the web link, and nothing else changes.

## Apply a step and test it

1. Install the step and run the test command:

   ```bash
   ossiq upgrade apply
   ```

   OSS IQ plans again first. If a newer release appeared since the preview, it shows the new
   versions and exits with status 3. It never installs versions you haven't seen.

2. Check the result:

   ```text
     ▶ ●  1  lodash 4.17.15 → 4.18.1  AWAITING_REVIEW

     Installed. The tests passed.

     Next
       ossiq upgrade test
       ossiq upgrade rollback
       ossiq upgrade continue
       ossiq upgrade skip
       ossiq upgrade finish
       ossiq upgrade abort
   ```

3. Keep the step and move to the next one:

   ```bash
   ossiq upgrade continue
   ```

Without a test command, `apply` stops at "Installed. No test command is set, so nothing was checked."

## Fix a step whose tests fail

A failing step exits with status 3 and waits in `AWAITING_REFACTOR`:

```text
  ▶ ✗  6  chalk 4.0.0 → 6.0.1  AWAITING_REFACTOR

  Installed, but the tests failed (exit 1).

  Test command exited with 1. Last output:
      banner: (text) => chalk.bold(text),
                              ^

    TypeError: chalk.bold is not a function
  ...
```

`continue` and `finish` refuse until the tests pass. You have three choices:

- **Fix the code, then run the tests again.** Repeat as often as you need, by hand or with a
  coding agent:

  ```bash
  ossiq upgrade test
  ```

  Once they pass, run `ossiq upgrade continue`.

- **Roll the step back** to its preview, and decide again:

  ```bash
  ossiq upgrade rollback
  ```

- **Skip the step** with a reason, which rolls it back first:

  ```bash
  ossiq upgrade skip --reason "chalk 6 needs ESM"
  ```

A rollback puts the manifest and lockfile back and reinstalls from them. It does not touch your
code. Code you changed to fit the new version stays in your working tree, so revert it with git.

## Stop early or start over

| Command | Effect |
|---|---|
| `ossiq upgrade finish` | Ends the session and keeps what is installed. An applied step whose tests pass counts as kept. It refuses while the tests fail |
| `ossiq upgrade abort` | Puts the manifest and lockfile back as they were at `start`, reinstalls, and ends the session |

The session also ends by itself when you keep or skip the last step.

## Work from a menu

Add `--interactive` to `start` or `status`, and OSS IQ asks which action to take after each step,
offering only the actions the step allows:

```text
  a apply   c changelog   w web   s skip   f finish   x abort   q quit
Choose:
```

Each key runs the subcommand with the same name, `n` runs `continue`, and `w` opens the changelog on
the web. `q` leaves the session as it is. Run `ossiq upgrade status --interactive` to pick it up again.

## Let a coding agent drive

Every subcommand takes `--format agent` and prints one JSON document on stdout. Output from npm,
uv and your test command goes to stderr, so stdout stays valid JSON.

| Exit status | Meaning |
|---|---|
| `0` | The command did what you asked |
| `1` | An error stopped it. See [Troubleshoot a session](#troubleshoot-a-session) |
| `3` | The step needs attention: the tests failed, the install was refused, or the versions to install changed |

The loop for an agent:

1. `ossiq upgrade start --format agent --test-command "npm test"`, then read `step.packages`. Each
   direct package carries `update` (the entry `status --format agent` prints), `update_context` and
   `changelog` with its `breaking` items and `migration_guides`.
2. `ossiq upgrade apply --format agent`.
3. On exit status 3, read `step.last_test.output_tail`, fix the code, and run
   `ossiq upgrade test --format agent` until it exits 0.
4. `ossiq upgrade continue --format agent`.
5. `rollback` or `skip` when the fix isn't worth it. The `commands` field lists the subcommands
   that make sense next.

`outcome` is `IN_PROGRESS` until the session ends as `COMPLETED`, `FINISHED` or `ABORTED`, or
`NOTHING_TO_DO` when the plan is empty. `ossiq upgrade changelog --format agent` adds the whole
changelog as `changelogs[].markdown`. [`ossiq install skills`](../reference/commands.md#install-skills)
teaches Claude Code, Codex and Copilot this loop.

## Set defaults for the project

Put the test command and a step limit in the project's `.ossiq.yaml`, and `start` uses them unless
a flag says otherwise:

```yaml
# .ossiq.yaml
version: 1
upgrade:
  limit: 3
  test-command: "npm test"
```

The command runs in your shell, from the project directory, so commit it only if everyone who
runs `ossiq upgrade` should run it. See [Project policy file](../reference/configuration.md#project-policy-file).

(troubleshoot-a-session)=
## Troubleshoot a session

### "An upgrade session is already in progress here."

A session already exists for this project. Run `ossiq upgrade status` to resume it, or
`ossiq upgrade abort` to discard it.

### "The test command already fails before any upgrade"

The test command failed on the untouched project, and the message ends with its last output. Fix
those tests first, or start without `--test-command`.

### "`ossiq upgrade` does not support ... projects yet."

Only npm, pnpm and uv projects can step through updates. `ossiq apply` still applies the whole plan.

### "The versions to install changed since the preview."

A newer release appeared between the preview and `apply`, and the step now shows the new versions.
Read them, then run `ossiq upgrade apply` again.

### "No upgrade session in this project."

`.ossiq/` holds no session here. Run `ossiq upgrade start`, or run the command from the project
directory you started in.

### "The session file is unreadable"

Someone edited the file in `.ossiq/`, or another OSS IQ version wrote it. Run `ossiq upgrade abort` with
the version that started the session, or delete `.ossiq/` to forget it. Deleting it leaves the project
files as they are now.
