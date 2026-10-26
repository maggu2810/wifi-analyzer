# Android captures

| File | Source | Notes |
|---|---|---|
| `emulator-androidwifi.hex` | Android 17 emulator (API 37, google_apis x86_64), AP "AndroidWifi" (hostapd of the emulator), 2437 MHz, read from the app's Raw tab | Real (non-synthetic) IEs. Non-conformant: Supported Rates carries 12 rates (max. 8), Country string lacks the environment octet (`55 53` + triplet `01 0d 14`). Open network, WMM, Extended Capabilities (bit 70 FTM responder). |
