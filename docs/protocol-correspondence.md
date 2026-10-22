# Frozen-paper protocol correspondence

This document maps the implemented execution path to the frozen `main.tex` with SHA-256 `481a41f1bb3c7dd0f971d6cee87151242910214fda3315887778b48dc9da9bd0`. Line references identify that exact source. The original manuscript is not included in the publication package. Tests establish implementation behavior; they do not establish the paper's hardness or authenticated-environment assumptions.

## Source-to-code map

| Requirement | Frozen TeX lines | Implemented path | Scope |
|---|---|---|---|
| Public injective ternary byte encoding, registered length, `beta0=1` | 405–406; legal extracted coefficients decoded at 1193 | [file_codec.py](../damascus_a/file_codec.py): `Ternary32Codec`; [codecs.py](../damascus_a/codecs.py): `checked_encode`, `checked_decode` | Approved fixed-block implementation; exact mapping and capacity below. |
| Challenge set `1..T`, `T` a power of two at least four | 403–405 | [fold.py](../damascus_a/fold.py): `FoldParameters`, stage challenge validation; [transcript.py](../damascus_a/transcript.py): `_sample` | Exact first `log2(T)` XOF bits plus one; each arithmetic inverse is checked. |
| Uniform setup generators and public parameter tuple | 440; 444–445; 450 | [protocol.py](../damascus_a/protocol.py): `setup`; [protocol_types.py](../damascus_a/protocol_types.py): `ProtocolParameters` | Default sampler is `secrets.randbelow(q)` for every generator coefficient. Injected samplers are labeled test instrumentation. Supplied parameters are audited; no reviewed security profile is synthesized. |
| Ring tower, dimensions, registered commitment | 480–500 | [algebra.py](../damascus_a/algebra.py): `Ring`, `RingElement`, `module_inner`; [fold.py](../damascus_a/fold.py): `initialize`; [protocol.py](../damascus_a/protocol.py): `register_bytes`, `register_encoded` | `N_j=n_j=2^(d-j)`; immutable signed witness coefficients, canonical public residues; whole initial commitment retained. |
| Registered statement and certified public context | 444–448; 475–490 | [protocol_types.py](../damascus_a/protocol_types.py): `Registration`, `EpochContext`; [wire.py](../damascus_a/wire.py): context and registration encoding | Bind parameters, codec, file identifier, byte length, initial commitment, entire generator family, epoch, seed, and opaque deadline. Object construction alone is not certification. |
| Each epoch begins from the original registration | 537–547; 608–612 | [protocol.py](../damascus_a/protocol.py): `_initial_state`, `epoch_init`, `prove_epoch` | Recompute from original generators and compare the full initial public state; a preceding terminal witness is not reused as the next registration. |
| Original vector cross terms and folds | 551–558 | [fold.py](../damascus_a/fold.py): `vector_cross_terms`, `vector_prove`, `vector_update`, generator/commitment helpers | Preserve `L=<fL,gR>`, `R=<fR,gL>`, integer witness `fL+x*fR`, and generator `gL+x^-1*gR`. |
| Original polynomial terms, parity and folds | 559–571; 594–601 | [fold.py](../damascus_a/fold.py): `polynomial_cross_terms`, `parity_validate`, `polynomial_prove`, `polynomial_update` | `L=<fe,go>` contains no `Y`; `R=<fo,ge>`; check `odd(Ctilde)=L+R`; generator `ge+(Y/y)*go`; terminal `Y=-1`. |
| Complete-prefix, domain-separated Fiat–Shamir challenges | 438; 448; 518–530; 589–600 | [transcript.py](../damascus_a/transcript.py): `vector_oracle_input`, `polynomial_oracle_input`, challenge functions; [protocol.py](../damascus_a/protocol.py): `prove_epoch`, `_verify` | `DF-SHAKE256-v1` consumes canonical full context, exact indexed prefix and current terms. Neither full context nor prefix is replaced by a short digest in the oracle input. Parity precedes the polynomial challenge. |
| Canonical records, exactly `d` ordered rounds, full public replay | 583–610; 612 | [wire.py](../damascus_a/wire.py): bounded encoders/decoders; [protocol.py](../damascus_a/protocol.py): `_verify` | Each record carries its index and four typed modules. Missing/extra/reordered records, noncanonical integers/residues, truncation and trailing bytes reject. Generator and commitment paths both replay. |
| Transmitted integer norm and all-coordinate terminal opening | 611–621; 643–650 | [fold.py](../damascus_a/fold.py): `final_open`, `check_terminal`, exact norm comparator; [protocol.py](../damascus_a/protocol.py): terminal checks | Compare the unreduced signed integer against `B=(1+T)^(2d)` before the modular equation; check all `k` coordinates. Intermediate witness bound is `(1+T)^(2j+1)`. |
| Certified epoch, authenticated complete-proof publication, deadline and replay rejection | 448; 612; 1028–1032; 1213–1217 | [environment.py](../damascus_a/environment.py): configured validator interfaces, binding checks, `AdmissionLedger`; [protocol.py](../damascus_a/protocol.py): `verify`, `verify_published` | External adapters supply actual certification/receipt validation. Persistent atomic admission happens only after successful evidence and algebra checks. Historical verification is repeatable and does not consume a new admission slot. |
| Current honest/extraction bounds and level-indexed hardness conditions | 651–659; indexed assumption at 396 | [parameters.py](../damascus_a/parameters.py): `validate_current_parameters`, terminal attack screening; [protocol.py](../damascus_a/protocol.py): policy gate | Retain the four-child source bound and adverse audit results. Arithmetic inequalities and successful tests do not establish hardness. Strict policy rejects an unapproved profile. |

The low-level fold APIs also remain usable with explicit mathematical test challenges. Their input/output contract is documented in [core-api.md](core-api.md); they do not replace the protocol's context, wire, challenge, evidence, or admission checks.

## Approved Ternary32 codec

The complete versioned descriptor is `TERNARY32_DESCRIPTOR` in [file_codec.py](../damascus_a/file_codec.py). It is bound in `ProtocolParameters.codec`, and the original byte length is bound in the registration. The codec is supplied explicitly to the generic registration API.

For each consecutive block of `r <= 32` bytes:

1. Interpret the actual bytes as an unsigned big-endian integer `X`; a partial final block is not padded with extra bytes.
2. Let `c(r)` be the least nonnegative integer satisfying `3^c(r) >= 2^(8r)`. In particular, `c(0)=0` and `c(32)=162`.
3. Emit exactly `c(r)` base-three digits, least significant first, mapping `0 -> 0`, `1 -> 1`, `2 -> -1`. Missing high digits are zero.
4. Concatenate blocks in file order. Flat coefficient `t` goes to polynomial `floor(t/n)` at degree `t mod n`, with `n=2^d`. Pad the rest of the `M=4^d` coefficient slots with zero.

The exact capacity test is

```text
required_coefficients(ell) = 162 * floor(ell/32) + c(ell mod 32)
required_coefficients(ell) <= 4^d
```

This block-specific test must be used; a whole-file information-capacity inequality is not sufficient to account for the per-block rounding. For example, `d=2` gives 16 slots and holds exactly three bytes; four bytes require 21 slots and reject.

Decoding validates the entire immutable `n`-by-`n` ternary shape, rejects each block integer `X >= 2^(8r)`, requires every global padding coefficient to be zero, and emits exactly `r` big-endian bytes per block. The registered length preserves leading zero bytes and determines every block boundary. Thus decoding reverses encoding at fixed length. Across different lengths, injectivity is of the registered pair `(ell, witness)`; the length must not be discarded. `checked_encode`/`checked_decode` additionally enforce complete-vector re-encoding equality.

This supplies the legal public byte mapping required at lines 405–406 and the final deterministic file-decoding step described at line 1193. It leaves `beta0=1`, every fold equation, the honest norm, four-child extraction bounds, and security assumptions unchanged. It does not introduce independently audited chunks or change the whole registered object into multiple protocol instances.

`iterencode(reader, ell, parameters)` streams the full flat coefficient sequence using at most one 32-byte conversion integer at a time. It supports short reads and rejects truncated or extra data; EOF is checked before emitting the final data block or global padding. Partial iterator output must not be registered. Generic `encode` still materializes the full witness, and `decode` materializes the original bytes. A streaming codec does not establish gigabyte-scale protocol feasibility. Practical wire/engine resource limits remain separate from mathematical and security parameters.

## Engineering choices and external conditions

The versioned binary wire and SHAKE256 suite instantiate the source's abstract injective encoding and random-oracle calls. The framing, hash suite, evidence identifiers, parser budgets, and local persistent ledger are concrete engineering choices; their tests do not prove cryptographic security. Public residues and signed opening encodings are canonical. Resource budgets are applied before nested allocations and do not become security parameters.

The evidence interfaces require configured providers, matching context/registration/epoch/deadline bindings, provider and time-domain identities, and a digest of the complete proof including its opening. Deadline units and boundary rules belong to the authenticated provider. No default accepting provider, prover timestamp, present wall clock, or caller boolean stands in for authenticated historical receipt. Matching digests cannot make an untrusted provider into a trusted authority.

Conditional seed uniformity, the pre-seed information boundary, actual publication order and timely receipt, and the relevant consensus assumptions remain external conditions. Parameter security also remains unapproved. The protocol's default strict path therefore fails closed. Explicit `policy='correctness'` executes the actual equations and wire path while retaining the parameter audit and `secure_profile=False`; it is not a certified deployment or formal performance run.

## Verification evidence

The corresponding test modules are [test_algebra.py](../tests/test_algebra.py), [test_fold.py](../tests/test_fold.py), [test_file_codec.py](../tests/test_file_codec.py), [test_codec_interface.py](../tests/test_codec_interface.py), [test_wire.py](../tests/test_wire.py), [test_transcript.py](../tests/test_transcript.py), [test_environment.py](../tests/test_environment.py), and [test_protocol.py](../tests/test_protocol.py).

Coverage includes independent multiplication and byte/base-three oracles, both fold stages and generator paths, exact norm boundaries and wrong final coordinates, complete context/prefix binding, malformed canonical encodings, wrong/late receipt bindings, full-proof opening substitution, and concurrent epoch admission. Codec tests include 303 seeded length-0-through-100 comparisons, exact capacity cases, 31/32/33-byte boundaries, surplus codewords, global padding and streaming length enforcement. Provider fixtures explicitly carry `TEST_ONLY` identities. Tests and correctness timing do not reproduce or validate the manuscript's published deployment measurements.
