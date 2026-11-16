#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Release the Android app (AGENTS.md "Versioning", docs/decisions/0008-versioning-from-git.md).

1. asks for the release version (default: current version if its minor is even, otherwise
   the next even minor) and the next development version (default: release minor + 1),
2. checks the version rules (release: even minor, development: odd minor; a minor bump
   resets patch, a major bump resets minor and patch; versions only increase),
3. commits "android: release X" (appVersion + CHANGELOG heading "### X – <date>") and creates
   the annotated tag android-vX,
4. commits "android: start development of Y" (appVersion + CHANGELOG heading
   "### Y (unreleased)").

Nothing is pushed; the push command is printed at the end.
"""

import datetime
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
GRADLE = REPO / "apps/android/app/build.gradle.kts"
CHANGELOG = REPO / "CHANGELOG.md"
TAG_PREFIX = "android-v"
CHANGELOG_SECTION = "## Android app"
VERSION_LINE = re.compile(r'^(val appVersion = ")(\d+\.\d+\.\d+)(")$', re.MULTILINE)

Version = tuple[int, int, int]


class ReleaseError(Exception):
    pass


def fmt(v: Version) -> str:
    return ".".join(map(str, v))


def parse(text: str) -> Version:
    m = re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", text.strip())
    if not m:
        raise ReleaseError(f"'{text}' is not a version X.Y.Z")
    return int(m[1]), int(m[2]), int(m[3])


def git(*args: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise ReleaseError(f"git {' '.join(args)} failed:\n{result.stderr.strip()}")
    return result.stdout.strip()


def check_step(old: Version, new: Version, what: str) -> None:
    """new must be greater (or equal, allow_equal) and reset lower parts on a bump."""
    if new[0] > old[0]:
        if new[1:] != (0, 0):
            raise ReleaseError(f"{what} {fmt(new)}: major bump from {fmt(old)} requires "
                               f"{new[0]}.0.0")
    elif new[0] == old[0] and new[1] > old[1]:
        if new[2] != 0:
            raise ReleaseError(f"{what} {fmt(new)}: minor bump from {fmt(old)} requires "
                               f"{new[0]}.{new[1]}.0")


def check_release(current: Version, release: Version) -> None:
    if release < current:
        raise ReleaseError(f"release {fmt(release)} is lower than current {fmt(current)}")
    if release[1] % 2 != 0:
        raise ReleaseError(f"release {fmt(release)}: minor must be even (odd = development)")
    check_step(current, release, "release")
    if git("tag", "--list", TAG_PREFIX + fmt(release)):
        raise ReleaseError(f"tag {TAG_PREFIX}{fmt(release)} exists already")


def check_next(release: Version, nxt: Version) -> None:
    if nxt <= release:
        raise ReleaseError(f"development {fmt(nxt)} must be higher than release {fmt(release)}")
    if nxt[1] % 2 != 1:
        raise ReleaseError(f"development {fmt(nxt)}: minor must be odd (even = release)")
    check_step(release, nxt, "development")


def default_release(current: Version) -> Version:
    major, minor, _ = current
    return current if minor % 2 == 0 else (major, minor + 1, 0)


def ask(prompt: str, default: Version) -> Version:
    answer = input(f"{prompt} [{fmt(default)}]: ").strip()
    return parse(answer) if answer else default


def read_app_version() -> Version:
    matches = VERSION_LINE.findall(GRADLE.read_text(encoding="utf-8"))
    if len(matches) != 1:
        raise ReleaseError(f"expected one 'val appVersion = \"X.Y.Z\"' line in {GRADLE}")
    return parse(matches[0][1])


def write_app_version(v: Version) -> None:
    text = GRADLE.read_text(encoding="utf-8")
    GRADLE.write_text(VERSION_LINE.sub(rf"\g<1>{fmt(v)}\g<3>", text), encoding="utf-8")


def changelog_unreleased(lines: list[str], current: Version) -> tuple[int, int]:
    """Index of the '### <current> (unreleased)' heading of the Android section and the
    number of entry lines below it."""
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith(CHANGELOG_SECTION))
    except StopIteration:
        raise ReleaseError(f"CHANGELOG.md has no '{CHANGELOG_SECTION}' section") from None
    heading = next((i for i in range(start + 1, len(lines))
                    if lines[i].startswith("## ") or lines[i].startswith("### ")), None)
    expected = f"### {fmt(current)} (unreleased)"
    if heading is None or lines[heading] != expected:
        found = lines[heading] if heading is not None and lines[heading].startswith("### ") \
            else "nothing"
        raise ReleaseError(f"CHANGELOG.md: expected '{expected}' as first heading of the "
                           f"Android section, found {found!r}")
    end = next((i for i in range(heading + 1, len(lines))
                if lines[i].startswith("#")), len(lines))
    entries = sum(1 for l in lines[heading + 1:end] if l.strip())
    return heading, entries


def release_changelog(current: Version, release: Version) -> None:
    lines = CHANGELOG.read_text(encoding="utf-8").splitlines()
    heading, _ = changelog_unreleased(lines, current)
    lines[heading] = f"### {fmt(release)} – {datetime.date.today().isoformat()}"
    CHANGELOG.write_text("\n".join(lines) + "\n", encoding="utf-8")


def start_changelog(release: Version, nxt: Version) -> None:
    lines = CHANGELOG.read_text(encoding="utf-8").splitlines()
    heading = next(i for i, l in enumerate(lines) if l.startswith(f"### {fmt(release)} – "))
    lines[heading:heading] = [f"### {fmt(nxt)} (unreleased)", ""]
    CHANGELOG.write_text("\n".join(lines) + "\n", encoding="utf-8")


def confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N]: ").strip().lower() in ("y", "yes")


def run() -> int:
    if git("status", "--porcelain"):
        raise ReleaseError("work tree is not clean; commit or stash first")
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if branch != "main" and not confirm(f"You are on '{branch}', not 'main'. Continue?"):
        return 1

    current = read_app_version()
    print(f"Current app version: {fmt(current)}")
    _, entries = changelog_unreleased(CHANGELOG.read_text(encoding="utf-8").splitlines(),
                                      current)

    release = ask("Release version", default_release(current))
    check_release(current, release)
    nxt = ask("Next development version", (release[0], release[1] + 1, 0))
    check_next(release, nxt)

    print(f"\n  release      {fmt(release)}  (tag {TAG_PREFIX}{fmt(release)})"
          f"\n  development  {fmt(nxt)}\n")
    if entries == 0:
        print(f"Warning: CHANGELOG.md has no entries for {fmt(current)} (unreleased).")
    if not confirm("Create the two commits and the tag?"):
        return 1

    write_app_version(release)
    release_changelog(current, release)
    git("add", str(GRADLE), str(CHANGELOG))
    git("commit", "-q", "-m", f"android: release {fmt(release)}")
    git("tag", "-a", TAG_PREFIX + fmt(release), "-m",
        f"Wi-Fi Analyzer {fmt(release)} (Android)")

    write_app_version(nxt)
    start_changelog(release, nxt)
    git("add", str(GRADLE), str(CHANGELOG))
    git("commit", "-q", "-m", f"android: start development of {fmt(nxt)}")

    print(git("log", "--oneline", "--decorate", "-3"))
    print(f"\nPublish with:\n  git push --atomic origin {branch} {TAG_PREFIX}{fmt(release)}")
    return 0


def main() -> int:
    try:
        return run()
    except ReleaseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\naborted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
