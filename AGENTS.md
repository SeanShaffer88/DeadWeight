# AGENTS.md — working agreements for DeadWeight

This file records how work is done in this repository. It applies to human
and automated contributors alike.

## The contract

- The condensed project brief is `docs/BRIEF.md` and the slice plan is
  `ROADMAP.md`. Read both before substantial work. If implementation
  reveals the brief is wrong, change the brief in the same change and
  say why.
- Small, reviewable steps. Each step does one thing and leaves the gate
  green: `cargo fmt --all`,
  `cargo clippy --all-targets -- -D warnings`, and the full
  `cargo test` (never a filtered subset — a filtered gate can hide a
  failure in another module).

## Engineering standards

- Safe Rust. `dw-core` and the CLI carry `#![forbid(unsafe_code)]`.
  The collector's `unsafe` FFI lives only in `dw-win`'s `win` module,
  each block commented with its invariants, and the core stays `forbid`.
- Small, reputable dependency set; stdlib first. `serde` (derive) and
  `serde_json` are justified because the audit format is JSON.
  Slice 1 adds `windows` 0.61 to `dw-win` only (target-gated to
  Windows), justified because it provides the supported registry
  bindings the collector and evidence readers use — hand-declaring
  those `extern` signatures would be strictly worse. DISM is driven
  through `std::process` and Prefetch through `std::fs`, so no
  further bindings are needed. (`windows-sys` was evaluated and is
  not needed.) A new dependency requires a written justification in
  the change that adds it.
- Pure logic (model, parsing, rules, report, evidence matching) stays
  pure and unit-tested. Anything that touches a live system belongs
  in the collector layer, never in the core.
- Local data only, offline-first. No networking, no telemetry, no
  accounts — not behind a flag, not "for diagnostics", not ever.
  Audit files describe a real PC and its usage history; they are
  never committed to this repo (see `.gitignore`).

## Safety rules (product-specific, non-negotiable)

- **v1 is read-only — no mutation code paths at all.** Slice 1 has no
  remove, disable, or modify functionality, and no code path that
  could grow one by accident: the registry wrapper exposes read
  operations only. The single deletion the product performs is
  `purge`, which deletes DeadWeight's *own* audit store at the
  user's explicit request.
- **Nothing is recommended on suspicion.** Every recommendation must
  cite its evidence in the report (size as reported, install date,
  evidence sources, matched executable, rule matched). If the
  evidence cannot be cited, the tier is No recommendation.
- **Absence of evidence is not proof of non-use.** Copy, comments,
  and rules must never blur this. Under a 90-day evidence window no
  app may be tiered Safe to remove; under 365 days every report
  carries the seasonal warning.
- **Never-touch always wins.** The never-touch rules run first in
  tiering and override every other rule. Security settings and
  components are never a recommendation target.
- **Evidence is sensitive local data.** Prefetch/UserAssist/BAM data
  and the audits derived from it never leave the machine, are never
  logged beyond the report the user asked for, and are deleted by
  `purge` in one action.
- **Tiering lists are versioned source data.** The never-touch and
  feature-review lists live in `dw-core/src/rules.rs` with
  `RULES_VERSION`, printed in every report. Changing a list bumps
  the version in the same commit.
- **No registry cleaning, no driver deletion, no DLL stripping.**
  Out of scope by design; do not add them in any slice.
- Impact and size figures are what Windows reports. Code and copy
  must never present an installer-reported size as a measured size.

## Documentation and reporting

- Documentation names no third-party products. Refer to capabilities and
  Windows platform components, not other software.
- Report exactly what ran: which checks, on which Windows
  editions/builds, with what result. Never claim a scenario passed that
  did not run. Windows runtime behaviour is **Unverified** until it has
  been field-tested on a real machine.
- User-facing copy: plain language, no absolutes, no fear words, and
  the evidence caveats wherever a recommendation appears.

---

## Development standard

This project follows SEAN's **Universal Windows Desktop Master Prompt** —
the standing development standard for all of SEAN's Windows desktop
projects, current and future. The full text is maintained by SEAN (ask
him for the current version); this section is the in-repo summary, and
the project's own instructions add project-specific requirements on top
of it.

Core standards:

- Production quality only: no rough demos or placeholder features
  presented as finished; safe defaults for beginners, explained advanced
  controls for professionals.
- Accessibility is a requirement: keyboard navigation, accessible names,
  visible focus, sufficient contrast, no meaning by color alone,
  specific error messages with a fix path.
- Every consequential action explains its risks, limitations, and
  recovery options; destructive or irreversible actions are confirmed,
  previewed where feasible, and backed up or undoable where feasible.
- Data safety: local-first storage, offline-capable core features,
  versioned data formats, atomic writes, tested migrations, and no
  silent data loss.
- Verification honesty: compatibility and readiness claims are labeled
  Verified, Partially verified, or Unverified; never claim a check that
  did not run.

Standing defaults (a project brief may override a specific default):

- Product-family look: the black/red aesthetic matching InstallScope is
  preferred, not mandatory.
- Rust is the default for new projects and for new components where it
  fits; existing stacks are preserved — this is not a rewrite mandate.
- Support as many Windows versions as makes sense for the project;
  consider Windows 10 support when feasible without materially extending
  development time. Never claim support that has not been verified.
- Status and task reports include a Progress % and an ETA whenever they
  can be estimated responsibly.
- Public documentation avoids competitor comparisons by default
  (internal research may name competitors; license attributions for
  bundled components are kept).
- License: MIT for SEAN-owned projects; forks retain their upstream
  license.
