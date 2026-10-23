# Low-security full-protocol experiments

This entry measures the actual implementation using explicitly experimental
parameters. It executes Setup, file registration, fresh epoch context creation,
Prove and complete Verify. It retains the ternary codec, complete transcript
prefix, odd checks, integer norm, final opening, canonical serialization and
SQLite admission. Strict production policy and formal publication admission
remain unchanged. Passing these experiments establishes correctness for the
tested inputs, not production PoSt security.

The named `toy-ternary32-full-v1` family defaults to `T=4`, `k=2`,
`q=2147483647`; depth is recorded per case. These values are experimental inputs,
not a newly proposed security parameter set. The existing parameter audit is
retained verbatim in every run and row. A modulus bit length is not a number of
security bits. External epoch/publication providers remain `TEST_ONLY`; their
execution time is not external authentication or publication latency.

## Run from the source directory

Use Python 3.12. The protocol and collectors need no third-party dependency.
Only figure rendering needs the existing optional Matplotlib dependency.

```sh
python -m unittest discover -s tests -v
python -m damascus_a experiment --experimental-only --output ../my-experiment --depths 2,3,4,5,6 --epochs 3 --repetitions 2 --backend cpu-fused --environment-label my-actual-machine
python -m damascus_a plot-experiment --matrix ../my-experiment/matrix.json --output ../my-experiment-figures
```

The same commands work in PowerShell when Python 3.12 is on PATH. Use distinct
output directories on each machine and retain their actual hardware metadata.
The delivered cloud results do not measure the user's i5 or i9 platforms.

To use a real local input file and an explicit arithmetic profile:

```sh
python -m damascus_a protocol-experiment --experimental-only --output ../single-run --d 6 --T 4 --k 2 --q 2147483647 --epochs 3 --input-file sample.bin --context-mode decode --backend cpu-reference --test-seed 20261023
```

`--test-seed` selects a reproducible **test** PRNG for setup/epochs; omitting it
from the single-run command uses system secrets, without creating authenticated
external evidence. Matrix runs generate actual deterministic input bytes, encode
them and compute real proofs. No timing is synthesized. Input bytes and wire
artifacts are saved locally to permit exact reproduction; keep them private.

For the unchanged Ternary32 codec, full byte capacities are:

| d | ring degree / witness polynomial count | witness coefficients | max file bytes |
|---:|---:|---:|---:|
| 2 | 4 | 16 | 3 |
| 3 | 8 | 64 | 12 |
| 4 | 16 | 256 | 50 |
| 5 | 32 | 1024 | 202 |
| 6 | 64 | 4096 | 809 |
| 7 | 128 | 16384 | 3236 |

Small capacities are a consequence of the preserved representation. This work
does not solve the original large-parameter or large-file bottleneck.

## Resource limits and failure records

Before file loading, setup or output creation, preflight checks the original wire
limits, exact codec capacity, coefficient counts and configured budgets. The
memory/work models are versioned estimates, not measured memory or guaranteed
upper bounds. `--memory-mib` can tighten the default 512 MiB estimate budget;
it does not install an operating-system memory limit. `--work-budget` defaults to
100,000,000 modeled operations and can be explicitly raised up to 1,000,000,000.
The absolute collector limits include depth 7, input 4096 bytes and 32 epochs;
independent wire/memory/work limits can reject a case below those limits.

The matrix driver starts a separate process for each depth/context/repetition
and enforces `--timeout-seconds` (default 120, maximum 600). Timeouts and child
failures have explicit status and no accepted timing report. Partial runs retain
`RUN_INCOMPLETE.json`; never rename them as successful observations. Individual
`protocol-experiment` calls have preflight only; use the matrix driver for an
enforced timeout. RSS is the child process lifetime high-water mark, including
setup, Prove, Verify and diagnostic replay. VRAM is unmeasured (`null`).

## Exact execution and timing boundaries

`cpu-reference` retains the original arithmetic path. `cpu-fused` uses Python
integers to accumulate a module inner product before its final modular reduction,
consuming one polynomial pair at a time. It does not create a complete converted
witness/generator tensor. Original signed witnesses remain unchanged. This is an
optional CPU optimization, not a compiled native or GPU implementation. The
`ExactArithmeticBackend` protocol defines an exact native interface for later
implementations. A GPU request fails unless explicit CPU fallback is requested;
the actual backend is always logged.

The Verify comparison concerns immutable decoded public registration only:

- `decode`: decode the complete canonical context for every new epoch.
- `retained`: decode the canonical registration for the first epoch, then reuse
  that immutable public object when constructing subsequent epoch contexts.
  The first decode is marked separately from subsequent reuse.

Neither mode clears OS/hardware caches or caches generator replay results. Every
sample performs the complete `protocol.verify` call and claims a different epoch.
Replay rejection and historical verification are diagnostics outside the primary
measurement. This is not a comparison of system-wide cold/warm cache states.

`verify_ns = verifier_init_ns + verify_call_ns`, with nine exclusive stages:
initialization, parsing/context, challenges, generator replay, commitment/parity,
integer norm, opening, SQLite admission, and remaining work. Their integer sum
must equal the recorded total. TEST_ONLY provider checks are inside the Verify
call. Canonical context encoding and provider construction are separately timed
preparation, outside Verify. Initial ledger creation is separately recorded;
every admission claim is inside Verify.

Setup time includes Setup, file registration and canonical pp/registration
serialization. Fresh-epoch amortization includes setup once and each new Prove
plus complete Verify; a second curve excludes setup. Neither includes artifact
disk writes, ledger creation, provider preparation or diagnostic replay. Figure
captions retain these exclusions. Process wall time is separately available.

## Figures and remaining evidence

The separate experimental renderer validates artifact sizes/hashes and the
timing partition before drawing. It does not relax the formal aggregator.

- A1: actual complete proof, registration and individual round record bytes.
- A2: complete Verify partition, separating decode, first retained decode and
  later retained registration reuse where data exist.
- A3: amortized costs of different new epochs, with and without setup.
- A4 supplement: actual measured cloud/process RSS only. The requested i5/i9
  pair, VRAM sampling and platform failure ceilings still require local runs.
- A5: missing baseline/source/semantics material remains pending; no invented
  baseline measurements or heterogeneous performance rankings.

All figures remain marked low-security and TEST_ONLY evidence. Their use in the
paper requires the user's review of this experimental scope; no manuscript is
modified by this change.

## Source and delivery identity

The work starts from a verified 83-file engineering snapshot of upstream
`21fd6ad6c7a2781157c7e776b3d3a5e9ed9e4b74`. The local Git root commit records
that import and is not a recovered upstream history. The delivery manifest lists
the original Git blob hashes and local file hashes. Local code changes reside on
`engineering/stage3-preserve-semantics` in an isolated worktree. No shell network
clone or Library transfer is needed to run the delivered source.

Deliver only reviewed source/tests/instructions and derived experimental figures.
Raw input files, configurations, logs, evidence artifacts, ledgers, private
manuscripts, private reports and credentials are excluded from the delivery ZIP.
Remote publication remains separate from this local verified delivery.
