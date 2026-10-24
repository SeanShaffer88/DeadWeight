# Roadmap

## Slice 1 — Read-only audit (built)

- Inventory: installed apps (Uninstall keys), optional features and
  capabilities (DISM), each with the state/size/date Windows reports.
- Usage evidence from Prefetch, UserAssist, and BAM — fault-tolerant
  per source, fused, and matched to apps by executable name with the
  matched executable printed in the report.
- Tiered plain-language report (rules version 1): Safe to remove /
  Disable and watch / Never touch / No recommendation, with the
  seasonal warning under a 365-day evidence window and the
  absence-of-evidence caveat in every report.
- Local audit store under `%LOCALAPPDATA%\DeadWeight` with
  one-action `purge`.
- **No actions of any kind in this slice.** Nothing in slice 1
  mutates the system.

## Slice 2 — The disable tier (built)

- Inventory grew: services (SCM — name, start type including
  delayed automatic, state, normalized program path) and startup
  items (Run/RunOnce keys and both Startup folders) join the audit,
  with exact-executable evidence and a recorded parent app. Rules
  version 2 tiers them: protected services and Windows-folder
  services are never candidates; a service or startup item is a
  disable-and-watch candidate only with no usage evidence for
  itself or its parent app.
- Disable-only actions for services and startup items, following
  the family safety contract: plan validated first (protected
  services refused in code, RunOnce refused), prior state captured,
  restore point attempted before any mutation (abort unless the
  user explicitly proceeds without one), every action journaled
  *before* it happens, verified by re-reading, undoable after a
  crash. Dry-run by default in the CLI.
- Watch period support: `deadweight disabled` lists what is still
  disabled, since when, and flags items past their 30-day watch;
  undo is `deadweight enable`. `deadweight export` copies the
  journal and latest audit out with a manifest. Nothing is removed
  in this slice either.
- Verification status: engine/journal/plan are unit-tested; the
  startup path is exercised against a live system in CI; service
  mutation and restore-point creation stay **Unverified** until
  the field test.
- App/feature *removal* stays out — features and apps are
  report-only for all of v1.

## Slice 3 — Seasonal and safety UX

- First-run guidance that explains the evidence window and why a
  short window means fewer recommendations (never more).
- "Watched and fine" outcomes feeding back into tiering confidence.
- Report history: compare audits over time; an item that survives
  two audits a season apart is a stronger candidate than one audit's
  guess.

## Validation

Per the brief: a planted-PC (or VM) test — install a set of known
apps, run some, leave others untouched, enable a review-list
feature, and confirm the report tiers each correctly, names the
matched executable, excludes the security stack explicitly, and
warns when the planted evidence window is short. Collector runtime
stays **Unverified** until that runs on a real Windows machine.

## Explicitly out of scope

- Registry cleaning.
- Driver deletion.
- In-place DLL stripping / "slimming" installed binaries.
- Any automatic or scheduled action: DeadWeight never acts on its
  own, in any slice.
