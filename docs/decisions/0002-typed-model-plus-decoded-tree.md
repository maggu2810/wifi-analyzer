# ADR-0002: Typed model plus generic decoded tree

Status: proposed · Date: 2026-10-26

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
