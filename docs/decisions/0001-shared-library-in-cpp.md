# ADR-0001: Shared library `libwifianalyze` in C++23

Status: accepted · Date: 2026-10-26

## Context
IE decoding is needed by the CLI, the Android app and a future Qt app. The previous
prototypes had two independent implementations (C++ and Kotlin) that drifted apart.
Besides IE decoding, all frontends also need the same BSS summary, channel/frequency math,
OUI lookup and wording of decoded data.

## Options (language)
1. **C++23 library**, consumed natively (CLI, later Qt) and via NDK/JNI (Android).
2. Kotlin Multiplatform; CLI via Kotlin/Native; Qt would need a C interop layer.
3. Rust with C ABI / UniFFI bindings.
4. Separate implementations per platform.

## Options (scope / name)
a. `wifi-ie-decode` – IE decoding only; summary/channel/OUI/i18n elsewhere or squeezed in.
b. **`libwifianalyze`** – one library with modules `ie`, `summary`, `channel`, `oui`,
   `i18n`, `json`, `capture`.

## Decision
Option 1 + b. C++ is native on Linux and for Qt, fully supported by the NDK, and matches
existing know-how. Language level: the newest standard that works on all target toolchains
(Fedora 45 GCC/Clang and the current NDK Clang for Android 16) – currently C++23, raised
when both support the next one.
IE decoding is the bulk, but the other shared parts are real and would otherwise be
duplicated; one library with clear internal modules is simpler than several tiny ones and
avoids a rename later. Name is consistent with `wifi-analyze-cli`.

## Consequences
- Memory safety must be earned: bounds-checked reader, sanitizers and fuzzing are mandatory.
- Android needs a JNI bridge and an NDK build (ADR-0003).
- The library stays I/O-free; downloads, files and caches are frontend concerns.
