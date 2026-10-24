# DeadWeight

## TL;DR

DeadWeight finds what is installed on a Windows PC but never used —
and shows its evidence for every claim. It inventories installed
apps, optional features, and capabilities, cross-checks them
against the usage records Windows itself keeps (Prefetch,
UserAssist, BAM), and writes a tiered report: what looks safe to
remove, what must never be touched, and — the honest middle —
everything it cannot make a recommendation about. **v1 is entirely
read-only: it recommends, it never removes, disables, or changes
anything.** Local-only, no telemetry, MIT.

## Why

Every PC accumulates software: trials never opened again, helper
apps from old hardware, optional Windows features enabled years ago.
The usual advice is suspicion-driven ("this looks useless"). That is
how seasonal software gets deleted in March and missed in April.

DeadWeight's rule is the opposite: **nothing is recommended on
suspicion.** Every item in the report carries its evidence — the
size Windows reports, when it was installed, whether any usage
source saw it run, when, how often, and what executable matched.
When the evidence is too thin, the report says so instead of
guessing.

## The tiers

- **Safe to remove** — recommendations only in v1. For apps, this
  requires *no* usage evidence across a window of at least 90 days
  *and* an install date older than the whole window. For features,
  it requires the feature to be on the curated review list in the
  tiering rules (`rules.rs`, versioned — see below) and currently
  enabled. Removal of features goes through Windows' own reversible
  path (a feature can be re-enabled the same way).
- **Disable and watch** — the tier for services and helper programs
  that can be disabled, watched, and re-enabled before any removal
  decision. Slice 1 does not inventory services, so this section is
  empty by design; it arrives with the disable tier in a later slice.
- **Never touch** — security components (Defender, Security Health,
  the Windows security stack, …) are listed explicitly, so you can
  see they were considered and excluded — never silently skipped,
  never recommended against.
- **No recommendation** — everything else, each with its reason:
  usage evidence found, installed too recently to judge, evidence
  window too short, not covered by the current rules.

## How the evidence works

Windows records program execution in three places, and DeadWeight
reads all three, each fault-tolerant (one failing source means less
evidence, never a failed audit):

- **Prefetch** (`C:\Windows\Prefetch`) — file names and times.
- **UserAssist** (Explorer's records) — run counts and last-run
  times per program.
- **BAM** (Background Activity Moderator) — last-execution time per
  program, per user.

Evidence is matched to apps by executable name: a match when the
normalized executable name equals the app's normalized display
name, or one contains the other (with a minimum length, so short
names cannot match eagerly). The report prints the executable that
matched, so the heuristic is never hidden. Features and
capabilities get no usage evidence — nothing records "running" a
feature — which is why their tiering relies on the curated list
instead.

**Absence of evidence is not proof of non-use.** All three sources
can be cleared, capped, or never recorded. The report says this,
every time, in the header.

**Seasonal warning.** When the evidence on a PC spans less than
365 days, the report warns prominently: software used once a year
looks exactly like dead weight in a shorter window. The tiering
rules are conservative for the same reason — under a 90-day
window, no app is called safe at all.

## Privacy

Usage evidence is forensic data about how a PC is used. DeadWeight
treats it that way:

- Everything is read and processed **on the machine**. Nothing is
  uploaded, phoned home, or telemetered — there is no network code.
- Stored audits live only under `%LOCALAPPDATA%\DeadWeight\audits`.
- `deadweight purge` deletes the whole audit store in one action
  and reports what it removed.

## Usage

```
deadweight audit [--out <path>]   collect an audit, save it, print the report (Windows)
deadweight report <audit.json>    print the report for a saved audit (any platform)
deadweight purge                  delete the local audit store
```

Try the report renderer without a Windows machine:

```
cargo run -p deadweight -- report examples/example-audit.json
```

The tiering lists (never-touch patterns, the feature review list)
live in `crates/dw-core/src/rules.rs` as source data with a
`RULES_VERSION` constant that is printed in every report, so a
change to what DeadWeight recommends is a reviewable diff.

## Limitations (v1)

- **Read-only.** No removal, no disabling, no UI yet. Any tool that
  claims this version changes your PC is not this version.
- **DISM needs elevation.** Feature and capability inventory runs
  `dism.exe /Online …`, which most Windows builds only allow from
  an elevated process. Without it, the audit continues with a
  warning and no features.
- **DISM parsing is English-locale.** The parser keys on DISM's
  English field labels; on other locales the feature inventory
  comes back empty (with a warning), never fabricated.
- **BAM and Prefetch may need elevation** and may simply be absent
  — both are handled as "less evidence", with warnings.
- **Evidence matching is a heuristic** (see above). The field test
  in the brief is what validates it against reality.
- **Sizes are what Windows reports** (the Uninstall key's
  `EstimatedSize`, written by each installer). When Windows does
  not report a size, the report says "size not reported" — sizes
  are never estimated by DeadWeight.
- Out of scope, permanently for this product line: registry
  cleaning, driver deletion, in-place DLL stripping.

## Status

Honest status, in the project's Verified / Partially Verified /
Unverified terms:

- **Verified:** the pure core — audit model, evidence parsing
  (ROT13, UserAssist layout, FILETIME, Prefetch names), DISM
  parsing, tiering rules, report rendering — and the evidence
  matching/store logic, all unit-tested on the host gate
  (`cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`
  on host and Windows targets, full `cargo test`).
- **Unverified:** everything that touches a real Windows machine —
  the collector's runtime output, evidence-matching quality against
  real Prefetch/UserAssist/BAM data, DISM behavior across builds.
  The planted-PC validation plan in `docs/BRIEF.md` is the verdict;
  until it runs, treat the collector as unproven.
- **Not built:** the disable tier (slice 2), any UI, and any form
  of removal. v1 cannot change a PC.

## Layout

- `crates/dw-core` — pure model, parsing, tiering rules, report.
- `crates/dw-win` — the Windows collector and local audit store.
- `crates/deadweight` — the CLI.

## License

MIT — see `LICENSE`.
