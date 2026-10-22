# Frozen-paper complete execution path: implementation plan and status

The user authorized faithful full prover/verifier engineering on 2026-10-22 and approved Ternary32Codec subject to preserving the frozen equations, extraction bound, and claims. The complete CPU reference path is implemented: Setup, byte/encoded Register, EpochInit, Prove, canonical wire, Fiat–Shamir replay, full Verify, and persistent atomic admission. Root manages integration validation and publication. No approved concrete security profile exists: strict rejects; only explicit correctness mode executes. A new extraction bound or independently proved file chunking has not been adopted.

Original manuscripts, legacy snapshots, B-group material and private deployment data stay excluded from publication. No formal performance collection or production readiness is asserted.

## Source gaps and approved engineering choices

Active TeX 405–406 requires a public injective ternary codec, padding and byte length. The example at 407 is commented out. The approved Ternary32Codec now instantiates that public parameter:

- Consecutive blocks of at most 32 bytes are unsigned big-endian integers.
- An actual r-byte block uses exactly c(r)=min{c:3^c≥2^(8r)} trits; c(32)=162 and c(0)=0.
- Trit order is least significant first; digits 0/1/2 map to coefficients 0/1/−1. Unused high trits are zero.
- The tail uses its actual length. Blocks follow file order, flatten as polynomial_index*n+degree, and receive global zero padding to M=4^d.
- Required coefficients are 162*floor(ell/32)+c(ell mod 32). Capacity overflow, surplus block codewords and nonzero global padding reject.
- The full TERNARY32_DESCRIPTOR and registered ell are bound through pp/registration/context. Injectivity includes that length: distinct-length all-zero inputs may share a padded witness.
- The 32-byte conversion block is not a separately registered/proved chunk. Streaming avoids a whole-file conversion integer; materialized encode/decode and the reference protocol still store the full witness/file.

Register requires an explicit FileCodec whose descriptor equals pp.codec, validates ternary shape/bounds and the canonical codec image, and checks its roundtrip. Ternary32Codec is an approved implemented option. Sample roundtrips do not prove global injectivity of arbitrary external codec implementations.

TeX 448, 511–530,582–619 requires full context/prefix binding and all fold/terminal checks. Implemented DF-wire-v1 and DF-SHAKE256-v1 instantiate canonical serialization and unbiased 1…T challenges without altering those equations. Every challenge consumes the full context and indexed prefix; an intermediate digest replaces neither.

Certificate/time algorithms remain external (TeX 612, 1028–1032,1216). Missing configured validators reject. The external provider defines deadline's opaque value, time/order domain and boundary semantics. Publication evidence binds the entire proof including the integer opening. Prover clocks, caller booleans and test issuers are not authenticated timely receipt. Cutoff information boundaries, conditional seed distribution and production consensus remain external assumptions.

## Implemented shared types and wire

protocol_types.py provides immutable validated types:

- ProtocolParameters(arithmetic: FoldParameters, codec: bytes, suite: bytes=b'DF-SHAKE256-v1').
- Registration(pp, file_id: bytes, file_length: int, initial: PublicState), with matching arithmetic and level zero.
- EpochContext(registration, epoch: bytes, seed: bytes, deadline: bytes).
- EpochProof(context_digest: bytes, records: tuple[RoundRecord,...], opening: int); evidence is separate and explicitly bound by validators.
- WireLimits, finite resource budgets independent of security parameters.

wire.py implements encode/decode_pp, encode/decode_registration, encode/decode_context, encode_round_record(record,j,pp)/decode_round_record(raw,j,pp), encode_proof(proof,context)/decode_proof(raw,context), standalone encode_module and context_binding. Encoders and decoders accept limits. Parsers reject trailing/noncanonical bytes, bad dimensions/index/context, malformed record counts and missing openings; dimension/byte checks precede nested allocation.

Registration carries pp and the full g0. Proof carries its 32-byte context identifier, exactly d indexed records and signed integer opening, without repeating g0. Complete context and external evidence are separate actual artifacts; identifier hashes never replace full Fiat–Shamir inputs.

## Workstream status

| Workstream | Implemented | Remaining boundary |
|---|---|---|
| fold.py | Separate cross-term, witness-fold, generator, commitment and parity stages; original math API retained | CPU reference, not optimized NTT/CUDA |
| protocol_types.py / wire.py | Public types, all canonical formats, bounded decoding | Resource budgets do not approve security |
| codecs.py / file_codec.py | Checked codec interface and approved Ternary32Codec | No proof-system chunking; full witness still materialized |
| transcript.py | Complete-context/prefix SHAKE256 and distinct identifier domains | Hashes do not certify randomness/deadlines |
| environment.py | Abstract validators, exact result bindings, full-proof receipt binding, SQLite atomic ledger | Real certification/receipt providers unconfigured |
| protocol.py | Uniform default generator sampling, legal Register, original-state reset, staged Prove, full Verify and post-validation admission | strict rejects; correctness explicitly retains unresolved/adverse parameter audit |
| protocol_artifacts.py | Actual proof-byte partition and separate registration/context/evidence | Not network measurement or proof acceptance |
| Root integration | API/CLI documentation, correctness reporting, exclusive full-verification timing and A-group contracts | Root records integrated validation/publication; no formal performance collection |

The verifier parses canonical bytes and checks external evidence before replay, reconstructs every generator/commitment, checks odd components before the polynomial challenge, checks the transmitted integer norm before modular use, and checks all k terminal coordinates. Historical verify_published is repeatable. Stateful verify requires a persistent ledger and claims the registration/epoch key only after all checks succeed.

Correctness results retain the parameter audit. q>2 beta_ext, a small-prime screen or successful tests do not approve a deployment profile or alter the manuscript security theorem.

## Verification and publication contract

Focused tests cover stage identities, codec image/length/padding/stream boundaries, canonical vectors and malformed input, full transcript/receipt substitution, integer alias/norm rejection, all-coordinate opening and persistent replay races. Root performs full-suite/integration review after parallel scopes stabilize; this document does not invent test results.

Only reviewed allowed files may be published through normal fast-forward GitHub commits after checking the remote baseline. Raw manuscripts, legacy sources, real logs, private locators/keys and server configuration remain excluded. GPU is not implemented for this profile. Diagnostic timers and fixture charts are not formal performance evidence or proof of storage-time security.
