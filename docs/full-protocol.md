# Frozen-paper protocol implementation

Version 0.2.0 implements the complete mathematical protocol and its canonical byte path in Python 3.12. The frozen source hashes are in `sources/paper/manifest.json`. No manuscript file, folding equation, extraction bound or legal ternary coefficient bound was changed. This document distinguishes executable checks from external assumptions; a passing correctness run establishes neither SIS hardness nor storage-time security.

## File encoding and legal registration

Active `main.tex` lines 405–406 require a public injective ternary codec with recorded length and specified padding. The whole-file radix example at line 407 is commented out. The approved implementation convention, including zero padding, is `Ternary32Codec` in `file_codec.py`:

1. Partition bytes in file order into blocks of at most 32 bytes. Interpret each block of actual length `r` as an unsigned big-endian integer `X`; leading zero bytes remain part of that length.
2. Let `c(r)` be the smallest integer with `3^c(r) >= 2^(8r)`, computed exactly without floating point. Emit exactly `c(r)` base-three digits, least significant first, mapping `0,1,2` to `0,1,-1`. In particular `c(0)=0`, `c(1)=6`, `c(31)=157`, `c(32)=162`.
3. The final partial block uses its actual byte count, without byte padding. High unused ternary digits are zero. Flatten block coefficients in file order, with index `t` placed at polynomial `t//n`, degree `t%n`, where `n=2^d`. Pad the remaining positions to `M=4^d` with zero coefficients.
4. The full fixed version descriptor is part of public parameters; the exact original byte length is part of registration. Both are included in the authenticated epoch context and every Fiat–Shamir input.
5. Decoding reconstructs exactly `r` big-endian bytes per block and rejects a block integer `X >= 2^(8r)`, nonzero global padding, wrong shape, non-integer/bool/nonternary coefficients, impossible length or insufficient capacity. The checked registration interface also verifies whole-witness `encode(decode(witness)) == witness`.

At fixed registered length each block conversion is one-to-one, so concatenation and fixed zero padding are injective. Every initial coefficient has absolute value at most one. Different lengths of all-zero files can share a padded witness: length binding is required, not inferred from the commitment. The legal registered object includes that length and codec. This matches the extraction decoder's use of the registered length at line 1193.

Capacity is exactly `C(ell)=162*(ell//32)+c(ell%32) <= M`. Do not use the whole-file information bound `2^(8ell)<=3^M` as this codec's capacity test. For example `M=4096` fits 809 bytes, whereas a single whole-file radix conversion could fit 811. This small block-rounding cost changes the size-to-parameter mapping, not the folding/security formulas. Empty files have an all-zero witness and registered length zero.

`iterencode(reader, ell, parameters)` handles short binary reads, requests at most 32 bytes, validates exact EOF and yields flat coefficients lazily. Conversion never creates a whole-file integer. `encode` still materializes the witness; `decode` materializes the output. The reference arithmetic is also materialized. None of these interfaces promises bounded-memory gigabyte proving.

## Setup, epochs and proofs

`ProtocolParameters` binds `(d,T,k,q)`, codec descriptor and suite `DF-SHAKE256-v1`. `setup` samples each of `k*M` generator coefficients independently using `secrets.randbelow(q)`. An injected sampler is explicit test instrumentation, logged as such. Resource checks precede allocation. No caller flag marks an unreviewed setup secure.

`register_bytes`/`register_encoded` enforce the selected codec image, ternary norm, original opening, length and resource limits. `EpochContext` binds the entire registration plus opaque epoch ID, seed and authenticated deadline bytes. Deadline units, authority and boundary semantics are supplied by the configured evidence provider, not assumed by the protocol.

`epoch_init` and `prove_epoch` start from the original registered witness/generators at level zero for every epoch. The prover computes vector cross terms, hashes the full context and prefix to obtain `x`, performs the vector fold, computes polynomial cross terms, checks `odd(C)=L+R` before deriving `y`, then performs the polynomial fold. It returns exactly `d` ordered records and the signed integer terminal opening. No previous epoch's terminal state is reused.

The two domains `vec` and `poly`, the round index, all preceding round records and the current relevant cross terms are framed unambiguously. SHAKE256 consumes the **full canonical context and prefix**, not a digest substitution for the paper oracle input. For `T=2^b`, the first `b` output bits, most significant first, give an integer in `0..T-1`; add one for the exact challenge range `1..T`. The suite supports `b>256` and rejects unknown suites. This is a concrete random-oracle instantiation, not a proof that SHAKE256 is an ideal oracle.

## Canonical wire and complete Verify

`wire.py` encodes public parameters, registration, context, indexed round records and full proof. Frames bind version/type; lengths use four-byte unsigned big endian, integer magnitudes use minimal big endian, signed integers use a one-byte sign and reject negative zero. Residues use the exact width implied by `q` and reject values outside `[0,q)`. Decoders reject trailing bytes, redundant integer encodings, inconsistent dimensions/record counts, wrong context and oversized inputs before expensive allocation. `WireLimits` are explicit application resource budgets, carried through hashing and evidence binding without changing canonical bytes.

The proof contains a context digest, exactly `d` ordered records and the integer opening. Registration and full context are separate artifacts; context embeds registration. `protocol_artifacts.serialization_evidence` validates canonical decoding and partitions every proof byte, including frame/count/length prefixes and the last opening. It separately counts registration, full context and opaque evidence. These counts are not a measurement of network transfer or deduplicated storage.

`verify_published` performs canonical parsing, strict parameter policy, both configured external evidence checks, full-prefix challenge reconstruction, public generator replay, commitment updates, odd checks before polynomial oracle queries, the **integer** terminal norm before any modular reduction, and opening equality in **all k coordinates**. It is repeatable for historical audit. `verify` adds atomic persistent SQLite admission only after every check succeeds. Its key binds registration and epoch, excluding seed/deadline, so changing either cannot create another admission slot for that registration/epoch. Invalid proofs do not consume a slot.

Verify timing partitions are exclusive: parsing/context (including evidence adapters), challenges, generator replay, commitment/parity, norm, opening, and residual other. The total includes all work through successful/failed admission. The runner also records actual admission time separately within that partition, and caller-return overhead; disk artifact export is outside the Verify interval. Per-round proving durations and actual serialized sizes are retained.

## External authentication and time boundary

`EpochContextValidator` and `PublicationEvidenceValidator` are required configured trust interfaces. There is no permissive default or hard-coded certificate scheme. Missing, mismatched or exception-raising providers reject. Independent wrapper checks bind returned assertions to exact context, registration, epoch, deadline, provider/time-domain IDs, evidence digest, complete proof including opening, and the already validated epoch assertion.

The epoch adapter must validate real authentication/finality evidence for the full context and that registration/identifier/deadline were fixed before seed release. The publication adapter must validate actual complete-proof publication, ordering and receipt within the authenticated deadline in its configured clock domain. Historical verification cannot replace authenticated receipt with the verifier's current wall clock or a prover timestamp. Exact ordered records are checked by the proof decoder and replay.

Frozen lines 1216–1237 additionally assume a conditional-uniform seed independent of unqueried oracle values and a cutoff boundary fixing the prover/program/advice/private/cooperating/file-history state before seed release; later inputs must not add file-dependent information beyond the permitted simulation model. A certificate or local test signature does not establish these assumptions. The certification layer's eventual synchrony/Byzantine assumptions and external-time limitations remain those of the paper (including lines 439 and 1028–1032). Deployment requires a real provider and an operational environment satisfying them; the library cannot infer those facts from opaque bytes.

The correctness runner's private `TEST_ONLY` adapters validate deterministic mock bindings and tick rules to exercise failure paths. They deliberately do not implement a real certifier, cutoff or trusted clock, and logs explicitly deny those guarantees. They are not default providers in `protocol.py`.

## Parameter policy and reproducible correctness

All main APIs default to `policy='strict'`, which currently rejects because there is **no approved concrete security profile**. Explicit `policy='correctness'` executes the unchanged equations and returns the full parameter audit, including failed sufficient conditions and attack flags; `secure_profile` stays false. No parameter is silently reduced, no candidate extraction recurrence is substituted, and no fixed-depth whole-block protocol is adopted.

The shipped runner fixes `d=2,T=4,k=2,q=2^521-1` for tiny correctness cases. These are not deployment security parameters; any listed terminal SIS attack findings remain visible. It performs setup once, legal registration, at least two fresh test epochs from the original witness, actual complete verification/admission, historical verification and replay rejection. JSON retains the full parameter audit, source map, artifact-part manifest, provenance, backend and timer partitions; CSV is a flattened subset with primary sizes/hashes/paths and times. `cache='uncontrolled'` is not a cold/cached experiment. Diagnostic re-verifications and initial ledger database creation are outside the recorded primary audit-cost sum; each actual admission operation is inside its complete Verify interval.

```bash
python -m damascus_a protocol-correctness --correctness-only --epochs 2 --output runs/full-protocol
# Explicit reproducible TEST setup; never a cryptographic setup claim:
python -m damascus_a protocol-correctness --correctness-only --test-seed 17 --output runs/full-protocol-seed17
```

CPU reference execution, serialization and deployment scripts are available now. Approved security parameters, real certification/receipt adapters and their external conditions, optimized CPU/GPU arithmetic, actual platform validation and authorized formal data collection remain separate work. A1–A5 layouts and validation scripts are available; no correctness telemetry is promoted to paper data.
