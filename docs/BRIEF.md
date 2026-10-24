# DeadWeight — condensed project brief

Brief 3 of the Buildable Windows Optimization pack. This is the
condensed in-repo form; the full pack is the source document.

## Pitch

Finds what is installed but never used. Core promise: **nothing is
recommended on suspicion** — every item carries evidence (size,
last-use, why it was tiered).

## v1 MVP (slice 1)

READ-ONLY audit + tiered report only. No actions of any kind. The
report and README must never imply removal capability in v1.

- **Inventory:** installed apps (Uninstall registry keys), Windows
  optional features and capabilities (DISM).
- **Usage evidence:** Prefetch (file names + times), UserAssist
  (ROT13 names, run counts + last-run), BAM (per-executable
  last-execution FILETIME). Each source fault-tolerant and labelled.
- **Tiers:**
  - *Safe to remove* — caches and clearly unused optional features
    with a supported reversible path; in v1 these are
    recommendations.
  - *Disable and watch* — services/helpers; slice 1 reports
    candidates only (services are inventoried with slice 2).
  - *Never touch* — security components, drivers for present
    hardware; listed explicitly so the user sees they were
    considered and excluded.
  - Plus the honest *No recommendation* remainder.
- **Tiering lists** are versioned in-repo as source data with a
  `RULES_VERSION` printed in every report.

## Defining risks

- **Seasonal false positives.** Software used yearly looks unused in
  a short window. Mitigations: the report warns prominently when
  the evidence window spans < 365 days; tiering is conservative
  (no app is "safe" under a 90-day window or when installed inside
  the window).
- **Absence of evidence ≠ non-use.** All three evidence sources can
  be cleared, capped, or never recorded. The report states this.
- **Evidence is forensic.** It never leaves the machine; the audit
  store lives under `%LOCALAPPDATA%\DeadWeight`; `deadweight purge`
  deletes it in one action. Stated in README and the report footer.

## Architecture (as built)

- `dw-core` — pure: model, evidence parsing (ROT13, UserAssist
  72-byte layout, FILETIME, Prefetch names), DISM output parsing,
  tiering rules, report. `#![forbid(unsafe_code)]`.
- `dw-win` — collector (registry + DISM + Prefetch + SCM +
  StartupApproved reads), evidence matching/fusion, atomic local
  store + purge, and the disable tier (`action/`: plan, journal,
  engine, export; `win`: the platform and restore-point
  implementations). `unsafe` only in the `win` module. Collection
  is read-only; the only writes to the system are the disable
  tier's two operations — a service's start type and a startup
  item's StartupApproved value — both through the journaled
  engine.
- `deadweight` — CLI: `audit`, `report`, `disable`, `enable`,
  `journal`, `disabled`, `export`, `purge`.

## Slice 2 (built): the disable tier

Services and startup items are inventoried (SCM; Run/RunOnce keys;
Startup folders), tiered under rules version 2 (protected-services
denylist shared by tiering and the disable command), and can be
disabled and re-enabled through the family safety contract:
restore point attempted first, journal written before mutation,
verify by re-read, 30-day watch list. Optional features,
capabilities, and apps are never mutated — for them the report
remains the whole product, in every v1 slice.

## Later slices

- Slice 3: seasonal/safety UX, audit-over-audit comparison.

## Out of scope

Registry cleaning, driver deletion, in-place DLL stripping —
permanently. Auto-revert or any unprompted action — permanently.

## Validation

Planted-PC/VM test per the pack: install known apps, run some,
leave others, enable a review-list feature, keep the security
stack present. The report must tier each correctly, name matched
executables, exclude the security stack explicitly, and warn on a
short evidence window. Until it runs, Windows runtime is
**Unverified**.
