# ADR-0008: Even/odd minor versions, build identity from git

Status: accepted · Date: 2026-11-16 · Supersedes the "bump on every change" rule

## Context
Until now every change bumped the version of each affected deliverable (a library fix bumped
lib, CLI and app; the app also bumped `versionCode` by hand). That caused churn and still did
not identify a build: local builds of uncommitted work, forgotten bumps and branches all
produce equal versions with different content. With several test phones running development
builds, it must be possible to tell exactly which change each one runs.

## Decision
- **Even/odd minor**: releases have an even minor (0.4.0, 0.4.1, 0.6.0, 1.0.0), development
  rounds an odd minor with patch 0 (0.5.0). A minor bump resets patch, a major bump resets minor
  and patch; versions only increase. Versions are set only at a release and at the start of the
  next development round – not per change.
- **Build identity from git** (`tools/git_version.py`, run at every build by CMake and Gradle):
  `X.Y.Z` exactly at tag `<component>-vX.Y.Z` with a clean work tree, otherwise
  `X.Y.Z-dev.N+gHASH` (N commits after the newest tag of that component), `X.Y.Z-dev+gHASH` (no
  tag yet), `.dirty` appended for uncommitted changes, `X.Y.Z+nogit` outside git. The commit
  hash identifies the build; `git bisect` between two phones' commits finds a regression.
- **Android `versionCode` = git commit count** (`git rev-list --count HEAD`): increases with
  every commit on `main`, so nightlies and releases install over each other. `main` is never
  rewritten; CI checks out with full history.
- **CHANGELOG**: each change adds its entry under `### X.Y.Z (unreleased)` of its deliverable;
  a version counts as released once its tag exists.
- **`tools/android_release.py`** performs an app release: asks for the release version
  (default: current if even minor, else next even minor) and the next development version
  (default: release minor + 1), checks the rules, commits the release (version + CHANGELOG
  heading with date), creates the annotated tag, commits the start of the next round. It does
  not push.

## Consequences
- The version in the build files is the version of the round, not of a build; the exact
  build is only known from the artifact (`versionName`, `--version`, `version()`) or
  `git describe`.
- Builds need git and the `.git` directory for the full identity; source trees without it
  build as `X.Y.Z+nogit` (versionCode 1).
- The Android `versionCode` jumped from 5 (hand-set) to the commit count (> 28), so existing
  installs upgrade.
- Library and CLI releases follow the same rules by hand (no script yet).
