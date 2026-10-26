# wpa_cli BSS dumps

`bss-dump.txt`: four `wpa_cli BSS <id>` blocks concatenated (format as printed by
wpa_supplicant's control interface: `key=value` lines). The `ie=` values are the synthetic
captures from `../synthetic/`; the other fields are plausible values. Block 0 also has a
`beacon_ie=` line.
