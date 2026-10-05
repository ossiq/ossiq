# 11 — GitHub Login: `auth` commands, the scan prompt and the secret store

Covers the device-flow login: `ossiq auth login | status | logout`, the login a scan starts when no
token resolves, the opt-outs, and machines without a secret store.

Run from repo root on a desktop machine (macOS, Windows, or Linux with GNOME Keyring or KWallet).
Every case needs network access and a GitHub account.

**Warning:** these cases log in with your real GitHub account and write to your real secret store
(service `dev.ossiq.github`). Run TC-O08 at the end to remove the login.

**Precondition:** no token may reach the process, or the login never starts. In every shell you use:

```bash
unset CI OSSIQ_GITHUB_TOKEN GITHUB_TOKEN OSSIQ_GITHUB_AUTH
uv run ossiq auth logout
uv run ossiq auth status
```

- [ ] `auth status` says `Not logged in` and names the platform's store under `Storage:`
      (`macOS Keychain`, `Windows Credential Manager` or `Secret Service (the desktop keyring)`)
- [ ] `~/.config/ossiq/config` (if present) has no `OSSIQ_GITHUB_TOKEN` or `OSSIQ_GITHUB_AUTH` line

---

## TC-O01: `auth` help

```bash
uv run ossiq --help
uv run ossiq auth --help
uv run ossiq auth login --help
```

- [ ] `--help` lists the `auth` command
- [ ] `auth --help` lists `login`, `status` and `logout`
- [ ] `auth login --help` lists `--no-wait` and `--resume`, and says it exits with status 75 while
      the code waits for approval

---

## TC-O02: Log in from a terminal

```bash
uv run ossiq auth login
echo "exit: $?"
uv run ossiq auth login
```

- [ ] The first run prints `Open:  https://github.com/login/device`, a code like `ABCD-1234`,
      `The code expires in 15 minutes.` and `Waiting for approval...`
- [ ] After you approve on GitHub, it prints `✓ Logged in as @<you>. The token is stored in the
      system keyring (<store>).` and exits 0
- [ ] The second run prints `Already logged in to GitHub as @<you>` and requests no new code

---

## TC-O03: `auth status` after login

```bash
uv run ossiq auth status
echo "exit: $?"
```

- [ ] `Source:   GitHub login (system keyring)`, `Login:    @<you>`, `Scope:    none (public data only)`
- [ ] `Expires:` is about 8 hours from now, in UTC
- [ ] `Storage:` names the platform's store; exit 0
- [ ] The output contains no token (no `gho_` string)

---

## TC-O04: Log in without a terminal, then resume

```bash
uv run ossiq auth logout
uv run ossiq auth login --no-wait; echo "exit: $?"
uv run ossiq auth login --resume --no-wait; echo "exit: $?"   # before approving
# approve the code on GitHub
uv run ossiq auth login --resume; echo "exit: $?"
uv run ossiq auth login --resume; echo "exit: $?"     # nothing pending any more
```

- [ ] `--no-wait` prints the URL and code, says to run the command again or `--resume`, and exits 75
- [ ] `--resume --no-wait` before approval exits 75 with the **same** code (in a terminal, `--resume`
      alone waits for the approval instead)
- [ ] `--resume` after approval prints `✓ Logged in as @<you>` and exits 0
- [ ] `--resume` with nothing pending prints `Nothing To Resume` and exits 1, with no traceback

---

## TC-O05: A scan starts the login

```bash
uv run ossiq auth logout
uv run ossiq status testdata/pypi/uv > out.txt 2> err.txt; echo "exit: $?"
cat err.txt
# approve the code on GitHub
uv run ossiq status testdata/pypi/uv
rm out.txt err.txt
```

- [ ] With stderr redirected (no terminal), the scan writes the code to `err.txt` and exits 75;
      `out.txt` is empty
- [ ] After approval, the second scan runs authenticated: no `The API quota may not cover this
      scan` warning about a 60-request limit
- [ ] `uv run ossiq auth status` shows the login

---

## TC-O06: Opt-outs skip the login

```bash
uv run ossiq auth logout
OSSIQ_GITHUB_AUTH=off uv run ossiq status testdata/pypi/uv; echo "exit: $?"
CI=true uv run ossiq status testdata/pypi/uv; echo "exit: $?"
```

- [ ] Neither run shows a login code; both exit 0
- [ ] Both run unauthenticated; if the quota looks short, the warning names `OSSIQ_GITHUB_TOKEN`
      and `ossiq auth login`
- [ ] With `OSSIQ_GITHUB_AUTH=off` in `~/.config/ossiq/config` instead of the environment, the
      result is the same (remove the line afterwards)

---

## TC-O07: An environment token outranks the login

Log in first (TC-O02), then:

```bash
OSSIQ_GITHUB_TOKEN=$(gh auth token) uv run ossiq auth status
GITHUB_TOKEN=$(gh auth token) uv run ossiq auth status
```

- [ ] The first run shows `Source:   OSSIQ_GITHUB_TOKEN environment variable`
- [ ] The second run shows `Source:   GITHUB_TOKEN environment variable`
- [ ] Neither run prints the token

---

## TC-O08: Log out

```bash
uv run ossiq auth logout; echo "exit: $?"
uv run ossiq auth status
uv run ossiq auth logout; echo "exit: $?"
```

- [ ] The first logout prints `Logged out: the stored GitHub login was removed from this machine.`
      and the `https://github.com/settings/applications` revoke hint; exit 0
- [ ] `auth status` says `Not logged in`
- [ ] The second logout prints `Nothing to remove` and exits 0

---

## TC-O09: Revoking on GitHub leads to a new login

Log in (TC-O02), then remove **OSS IQ** at <https://github.com/settings/applications>.

```bash
uv run ossiq status testdata/pypi/uv
```

- [ ] The scan says the stored login was discarded, then shows a new login code
- [ ] No traceback; after approving, `auth status` shows the new login

---

## TC-O10: No secret store (container)

```bash
uv build --wheel
docker run --rm -v "$(pwd)/dist":/dist:ro python:3.13-slim sh -c \
  'pip install -q /dist/ossiq-*.whl && ossiq auth status; ossiq auth login; echo "exit: $?"'
```

- [ ] `auth status` finishes in about a second, shows `Storage:  none available` and names
      `OSSIQ_GITHUB_TOKEN`; exit 0
- [ ] `auth login` fails at once with `Credential Store Unavailable` naming `OSSIQ_GITHUB_TOKEN`;
      exit 1; no hang

---

## TC-O11: macOS — Keychain access after an upgrade (optional)

A Keychain item belongs to the program that created it, so a rebuilt binary counts as a new
program. Build one with:

```bash
uv run pyinstaller packaging/pyinstaller/ossiq.spec --noconfirm   # binary: dist/ossiq/ossiq
```

1. Log in with that binary (A): `dist/ossiq/ossiq auth login`.
2. Change any source file, rebuild at the same path (B), then run `dist/ossiq/ossiq auth status`.

- [ ] One Keychain dialog appears; after about 2 s the terminal shows `Waiting for the system
      keyring...`
- [ ] **Always Allow**: the command finishes, and later runs are silent
- [ ] **Deny** (repeat with a fresh binary): a scan warns and runs without a token; no retry loop
