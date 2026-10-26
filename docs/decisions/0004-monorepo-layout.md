# ADR-0004: Monorepo with `libs/`, `apps/`, shared `testdata/`

Status: proposed · Date: 2026-10-26

## Decision
One repository; layout as in `docs/architecture.md`. CMake is the primary build at the
root; `apps/android` is a self-contained Gradle project that compiles the decoder from
source via `add_subdirectory`. Real-world captures in `testdata/` are shared by C++,
CLI and Android tests.

Linux data acquisition (wpa_supplicant ctrl socket / D-Bus, nl80211) is **postponed**; when it
comes it becomes a separate library `libs/wifi-scan-linux` so the future Qt app can reuse it.

## Consequences
- A decoder change is immediately visible in all frontends; one PR can update all.
- Android Studio must open `apps/android` (not the repo root).
