# Synthetic captures

Hand-built IE streams following the formats of IEEE 802.11-2020/ax/be and real hostapd beacons.
They are not recordings; each file documents what it is meant to exercise.

| File | Content |
|---|---|
| `wpa2-wpa3-5ghz-ax.hex` | 5 GHz ch 36 (80 MHz, center 5210), WPA2/WPA3-Personal transition (PSK+SAE, PMF capable, SAE-H2E), HT/VHT/HE 2x2, WMM, BSS Load, Country DE, 802.11k/v |
| `wpa3-6ghz-be-mlo.hex` | 6 GHz Wi-Fi 7: SAE + SAE-EXT-KEY, PMF required, GCMP-256, HE 6 GHz operation (ch 5), EHT 320 MHz (center 6105) with one punctured subchannel, Multi-Link (MLD MAC, link 1, 2 links), RNR with a co-located 5 GHz AP, TPE |
| `wpa-wpa2-tkip-2ghz-wps.hex` | 2.4 GHz ch 6, WPA + WPA2 mixed with TKIP group cipher, 802.11b/g/n 1x1 20 MHz, WPS 2.0 with device information (ACME Inc / Router1) |
| `open-hotspot-owe-mbssid.hex` | 2.4 GHz ch 11 open hotspot: Interworking (free public, internet), ANQP, Roaming Consortium, Hotspot 2.0 Release 3, OWE transition element, Multiple BSSID with one nontransmitted profile (WPA2 "Guest2") |
