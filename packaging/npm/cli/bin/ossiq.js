#!/usr/bin/env node
"use strict";

// Thin launcher for the platform-specific `ossiq` binary.
//
// The real executables ship in optional, platform-gated packages (the model used
// by esbuild and friends), so npm installs exactly one of them for the current
// host. There is deliberately no postinstall script: nothing here needs to run at
// install time, so `npm ci --ignore-scripts` and pnpm's default settings work.

const { spawnSync } = require("child_process");
const path = require("path");

const PLATFORM_PACKAGES = {
  "darwin arm64": "@ossiq/cli-darwin-arm64",
  "darwin x64": "@ossiq/cli-darwin-x64",
  "linux arm64": "@ossiq/cli-linux-arm64",
  "linux x64": "@ossiq/cli-linux-x64",
  "win32 x64": "@ossiq/cli-win32-x64",
};

const FALLBACK_HINT = [
  "",
  "OSS IQ is also published to PyPI and can be installed without Node:",
  "",
  "    uv tool install ossiq      # or: pipx install ossiq",
  "    ossiq status",
  "",
  "See https://github.com/ossiq/ossiq for details.",
].join("\n");

function resolveBinary() {
  const key = `${process.platform} ${process.arch}`;
  const packageName = PLATFORM_PACKAGES[key];

  if (!packageName) {
    return {
      error:
        `ossiq does not ship a prebuilt binary for ${key}.` +
        `\nSupported: ${Object.keys(PLATFORM_PACKAGES).join(", ")}.`,
    };
  }

  let packageJsonPath;
  try {
    packageJsonPath = require.resolve(`${packageName}/package.json`);
  } catch (err) {
    return {
      error:
        `The platform package ${packageName} is not installed.` +
        "\n\nThis usually means npm skipped optional dependencies (--no-optional / --omit=optional)," +
        "\nor the platform is unsupported (musl-based Linux such as Alpine is not covered by the" +
        "\nprebuilt binaries, which are linked against glibc).",
    };
  }

  const executable = process.platform === "win32" ? "ossiq.exe" : "ossiq";
  return { binary: path.join(path.dirname(packageJsonPath), "bin", "ossiq", executable) };
}

function main() {
  const { binary, error } = resolveBinary();

  if (error) {
    process.stderr.write(`${error}\n${FALLBACK_HINT}\n`);
    process.exit(1);
  }

  const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });

  if (result.error) {
    process.stderr.write(`Failed to run ${binary}: ${result.error.message}\n${FALLBACK_HINT}\n`);
    process.exit(1);
  }

  // Propagate a fatal signal as the conventional 128+n exit code so callers and
  // CI see the real cause instead of a bare success.
  if (result.signal) {
    process.stderr.write(`ossiq terminated by signal ${result.signal}\n`);
    process.exit(1);
  }

  process.exit(result.status === null ? 1 : result.status);
}

main();
