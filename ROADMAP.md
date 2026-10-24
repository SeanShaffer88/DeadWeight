# Roadmap

## Slice 1 — Read-only audit (this version)

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
- **No actions of any kind.** Nothing in v1 mutates the system; the
  only write outside DeadWeight's own store is nothing at all.

## Slice 2 — The disable tier

- Inventory services and helper programs (the "Disable and watch"
  tier becomes real).
- Disable-only quarantine for that tier, following the family
  safety contract: capture prior state first, restore point
  attempted before any mutation, every action journaled *before* it
  happens and undoable after a crash, user confirmation in
  proportion to risk, never-touch rules enforced in code.
- Watch period support: a disabled item is listed with its disable
  date and one-click undo; nothing is removed in this slice either.
- App/feature *removal* stays out until the watch data says the
  disable tier is safe to stand on.

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
