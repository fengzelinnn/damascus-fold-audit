# Damascus Fold A Implementation Plan

> For agentic workers: execute independent tasks in isolated file scopes and run the tests before claiming completion. User explicitly authorized independent work while protocol decisions remain pending.

**Goal:** Produce a reviewable feasibility and correctness workbench plus A-group experiment tooling, without silently choosing unresolved protocol options.

**Architecture:** Pure Python arbitrary-precision arithmetic provides independent correctness checks. Parameters, algebra, file codec, canonical wire, transcript challenges, external evidence, protocol orchestration, logging, aggregation and plotting have separate boundaries. The complete protocol extension is specified in `full-protocol-plan.md` and implemented as documented in `full-protocol.md`; secure deployment retains the explicit external/parameter gates in `design.md`.

**Tech stack:** Python 3.12 standard library for core/tests, pinned optional Matplotlib and python-pptx for plotting. No legacy Rust code imported.

**Spec:** `docs/design.md`.

## Global constraints

Only frozen current paper; no discarded graphs or B-group data. No formal performance runs. No source repository edits. Do not adopt candidate proof bounds or chunking. Never label a parameter set secure merely because q>2beta. User confirmed public publication after creating the target. Verify owner, public visibility, write permission and existing baseline before writing.

## Review focus

- Terminal degree-one ring multiplication by its variable must equal negation.
- Integer terminal lift must not be reduced before the norm check.
- Malformed lengths/integers and noncanonical field values must reject before allocation.
- CPU/GPU requested versus actual backend and fallback must be distinguishable.
- Fixture, published, simulation and local-measured data must never be pooled.

## Tasks

- [x] Inspect workspace, preserve existing BPoSt state, freeze paper bytes and provenance.
- [x] Implement `validate_current_parameters(d,T,k,q)` in `damascus_a/parameters.py`; test exact q boundary, invalid T, huge d and obvious SIS attacks.
- [x] Implement typed ring and fold operations in `damascus_a/algebra.py`, `damascus_a/fold.py`; randomized small differential tests plus all review focus arithmetic cases.
- [x] Implement canonical integer/framing primitives and bounded decoder in `damascus_a/encoding.py`; test collisions, negative zero, nonminimal encodings, truncation and resource limits. The initial stage left the file/protocol profile unselected; the authorized extension implements both.
- [x] Implement explicit backend and reproducible correctness-run JSON/CSV in `damascus_a/backend.py`, `telemetry.py`, `cli.py`; preserve real elapsed ns with data_kind correctness_test.
- [x] Add independent aggregation and A1–A5 blank/fixture plotting, editable PPTX and vector PDF; reject invalid provenance and label any font fallback.
- [x] Independently audit legacy commit and source-ground ADJ21/ePoSt baseline definitions, without treating their software or published timing as local measurements.
- [x] Add deployment preflight, locked dependencies, source-integrity checks, upload allowlist and credential scan.
- [x] Run all tests and smoke commands; independent review; archive source package and record exact remaining gates. See `validation.md` for the tested scope.

The authorized extension implements legal byte-file registration, canonical full-prefix Fiat–Shamir proving and complete verification with required external evidence interfaces and persistent admission. The approved32-byte ternary codec is implemented. Actual certification/receipt providers and their environment, approved concrete security parameters, optimized backends and formal local data collection remain outstanding. Tests cannot substitute for those conditions or a security proof.
