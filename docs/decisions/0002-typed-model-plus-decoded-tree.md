# ADR-0002: Typed model plus generic decoded tree

Status: accepted (refined during M1) · Date: 2026-10-26

## Context
In the old prototype every element needed a parser, a printer overload and a JSON
overload; the Android app would have needed a fourth (Compose) rendering per element.

## Decision
Each element decoder produces
1. a **typed struct** (source of truth, used for `BssSummary` logic and tests), and
2. via one `describe()` function, a **generic tree** of labelled fields with values, units,
   byte/bit ranges and significance.

All frontends (CLI text, JSON, Android, Qt) render the tree generically. Frontends may
special-case a `type_key` for richer widgets, but never need to.

## Consequences
- Adding an element touches one source file + registry line + tests.
- Labels live in the library (English); frontends agree automatically.
- Byte ranges enable hex highlighting on every platform for free.

## Refinement (M1)
Instead of a separate `describe(const T&)` per element, each decoder is a single function that
reads the fields and builds the tree in the same pass (via the `Decoder` helpers), so every node
gets its exact byte/bit range for free. Typed values exist only where the summary or frontends
need them. The library also renders node values to text (`format_value`) so all frontends show
identical strings.
