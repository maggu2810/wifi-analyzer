# ADR-0007: Signed APKs built and published by GitHub Actions

Status: accepted · Date: 2026-11-16

## Context
The Android app is self-distributed (open questions: "Android distribution"). Users need a
signed APK; building it on a developer machine is not reproducible and needs the key there.
Testers also want builds of the current `main` without waiting for a release.

## Decision
- Workflow `.github/workflows/android.yml` (the first CI job of the project; the other jobs
  of `docs/build-and-tooling.md` "CI" remain planned):
  - push to `main` → GitHub **pre-release** `android-nightly`, deleted and recreated on every
    push (tag moves to the new commit), APK `wifi-analyzer-<versionName>-nightly-<sha>.apk`.
  - tag `android-vX.Y.Z` → GitHub **release** marked "latest", APK
    `wifi-analyzer-X.Y.Z.apk`, notes from the matching `CHANGELOG.md` section. The workflow
    fails if the tag does not match `versionName`.
  - Each release carries `SHA256SUMS`; the signature is verified with `apksigner` before
    publishing.
- One app signing key (RSA 4096, PKCS12, alias in the secret) for nightly and release
  builds, so users can switch between both channels (Android only refuses a lower
  `versionCode`). The key is stored as repository secrets `ANDROID_KEYSTORE_BASE64`,
  `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`; the master copy and its password are kept
  offline by the maintainer.
- Gradle reads the key from the environment variables `ANDROID_KEYSTORE_FILE`,
  `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`; without them `assembleRelease` produces an
  unsigned APK as before. The signed build runs without configuration cache (it would store
  the passwords on disk).

## Consequences
- Anyone with write access to the workflows can use the key; a compromised GitHub account
  compromises the key. Restricting the secrets to a GitHub Environment limited to `main` and
  `android-v*` tags is possible later.
- A Play Store listing (if ever) uses Play App Signing with a separate upload key; whether
  Play uses this key or a Google-generated one decides whether Play and GitHub installs can
  update each other.
- Losing the key means updates under the same applicationId are impossible.
- No version bump for workflow or signing changes (they do not change the app).
