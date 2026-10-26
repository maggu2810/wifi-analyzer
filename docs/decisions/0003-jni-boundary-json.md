# ADR-0003: JNI boundary passes bytes in, versioned JSON out

Status: proposed · Date: 2026-10-26

## Options
1. **JSON string** (same output as CLI `--format json`), parsed by kotlinx.serialization.
2. Construct Kotlin objects directly from C++ via JNI calls.
3. Binary format (FlatBuffers / protobuf).

## Decision
Option 1. One code path for all consumers, trivially debuggable, testable against the
same golden files. Data volume (≈ 100 BSS × < 2 KB IEs per scan) makes the cost negligible.
Calls are batched per scan and run off the main thread.

## Consequences
- The JSON schema is a real contract (versioned, schema file, golden tests).
- If profiling ever shows a problem, option 3 can be added behind the same Kotlin API.
