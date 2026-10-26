# wifi-analyzer

Tools to inspect WiFi networks and fully decode IEEE 802.11 Information Elements (IEs).

- **libwifianalyze** – portable C++23 library: decodes raw IE byte streams into a typed
  model and a presentation-neutral "decoded tree", derives a per-BSS summary, provides
  channel/frequency math, OUI vendor lookup and translated labels.
- **wifi-analyze-cli** (Linux) – decodes IE hex strings, pasted `wpa_cli BSS` output or
  capture files and prints them readable (text) or as JSON.
- **Android app** – scans with the Android WiFi APIs, decodes all IEs through the same
  library (JNI), and presents networks sortable/filterable with rich detail views.
- Postponed: Linux scan acquisition library, Qt desktop app.

Status: **planning**. See [`docs/`](docs/README.md) and [`AGENTS.md`](AGENTS.md).
