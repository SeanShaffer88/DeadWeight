# DeadWeight

## TL;DR

DeadWeight finds what is installed on a Windows PC but never used —
and shows its evidence for every claim. It inventories installed
apps, optional features and capabilities, services, and startup
items, cross-checks them against the usage records Windows itself
keeps (Prefetch, UserAssist, BAM), and writes a tiered report: what
looks safe to remove, what could be disabled and watched, what must
never be touched, and — the honest middle — everything it cannot
make a recommendation about. **The audit is read-only; the one
thing DeadWeight can change is narrow and reversible: a service's
start type or a startup item's enabled state, only through an
explicit `disable` command that attempts a restore point first,
journals the action before it happens, and can be undone.**
Nothing is ever removed. Local-only, no telemetry, MIT.

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
- **Disable and watch** — services and startup items that start on
  their own, live outside the Windows folder, and have no usage
  evidence for themselves or the app they belong to. These are the
  only items DeadWeight can act on: `deadweight disable` sets a
  service's start type to Disabled (a running service is never
  stopped) or marks a startup item disabled through the same
  StartupApproved mechanism Task Manager uses. The item then sits
  on a 30-day watch (`deadweight disabled`); re-enable it any time
  with `deadweight enable`. Protected Windows, security, and update
  services are never candidates — they are never-touch, in the
  rules and in the disable command itself.
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
- Stored audits and the action journal live only under
  `%LOCALAPPDATA%\DeadWeight` (`audits` and `journal` folders).
- `deadweight purge` deletes the whole audit store in one action
  and reports what it removed.
- `deadweight export <dir>` is the one way data leaves the store,
  and only when you run it: it copies the journal and the latest
  audit into a folder you choose, with a manifest.

## Usage

```
deadweight audit [--out <path>]     collect an audit, save it, print the report (Windows)
deadweight report <audit.json>      print the report for a saved audit (any platform)
deadweight disable service <name> [--no-restore-point] [--yes]
deadweight disable startup <name> [--source <token>] [--no-restore-point] [--yes]
                                    disable a service or startup item (Windows);
                                    dry-run by default — without --yes, the plan
                                    and current state print and nothing changes
deadweight enable [--id <id>]       undo a disable (Windows; default: newest)
deadweight journal                  list journal entries (any platform)
deadweight disabled                 the watch list: what is still disabled,
                                    since when, and whether its watch is due
deadweight export <dir>             copy journal + latest audit to a folder
deadweight purge                    delete the local audit store
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

- **No removal, ever, in v1.** The audit is read-only and there is
  no UI yet. The only changes DeadWeight makes are the two
  disable-tier operations above — a service start type, a startup
  item's StartupApproved state — each explicit, journaled, and
  undoable. Optional features, capabilities, and apps are never
  changed; their tiers are recommendations for you to act on (or
  not) through Windows' own tools.
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
  parsing, tiering rules (version 2, including the protected-
  services denylist and the service/startup candidacy rules),
  report rendering — the evidence matching/store logic, and the
  disable tier's plan/journal/engine/export state machine, all
  unit-tested on the host gate (`cargo fmt --all`,
  `cargo clippy --all-targets -- -D warnings` on host and Windows
  targets, full `cargo test`).
- **Partially Verified:** the collector (now including services
  and startup items) and the startup disable/enable path run
  against a live Windows system in CI on every push — collection
  succeeds and a planted startup item round-trips through disable
  and undo. A CI runner is not a real PC, so this is evidence, not
  proof.
- **Unverified:** everything else that touches a real Windows
  machine — the collector's runtime output quality,
  evidence-matching quality against real Prefetch/UserAssist/BAM
  data, DISM behavior across builds, **service start-type
  mutation, and restore-point creation**. The planted-PC
  validation plan in `docs/BRIEF.md` is the verdict; until it runs,
  treat those paths as unproven.
- **Not built:** any UI, and any form of removal. Features,
  capabilities, and apps remain report-only in v1 — plainly:
  DeadWeight will never be the tool that uninstalls them in this
  version.

## Layout

- `crates/dw-core` — pure model, parsing, tiering rules, report.
- `crates/dw-win` — the Windows collector, the disable tier
  (plan/journal/engine/export plus the Windows platform and
  restore-point implementations), and the local store.
- `crates/deadweight` — the CLI.

## License

MIT — see `LICENSE`.
