# Verified stage: 2026-10-22

This stage implements the complete frozen-paper CPU protocol path, approved Ternary32 file codec, canonical wire, full-prefix Fiat–Shamir, external evidence interfaces and persistent admission. It remains correctness-only: no concrete security profile or real external certifier/receipt provider has been approved. Tests are not a security proof.

## Executed checks

- `python -m unittest discover -s tests -v`: **169 tests passed** under CPython 3.12.14. Tests include independent convolution/fold recomputation, staged parity-before-challenge behavior, full context/prefix binding, strict canonical decoding, exact integer norms and all-k opening, external result binding, concurrent/reopened admission, file-codec image checks, true artifact-byte accounting, reproducible fresh epochs, plotting and release isolation.
- `python -m compileall -q damascus_a scripts`: passed.
- `python scripts/verify_sources.py`: both frozen original SHA-256 values matched the public source manifest. Raw originals are deliberately absent from the public package.
- `bash scripts/run_local.sh`: Linux preflight plus four small d=2 algebra cases and two complete fresh protocol epochs accepted; replay was rejected. Original JSON/CSV and binary artifacts stay local and are explicitly not performance evidence. The full-protocol profile retains `rejected_known_attack` / `terminal_lll_bit_bound`, never a deployment-safe label.
- Core wheel 0.2.0 built with existing setuptools using `pip wheel --no-deps --no-build-isolation --no-index --no-cache-dir`. The final wheel SHA-256 is `17102e34660192946c7798e96b1073a49aca58d7eac53bc4411ec8eba6ae9c61`. A fresh isolated target installation, run outside the source tree, accepted two complete epochs using the installed CLI, actual codec and mock-evidence path. This does not verify a clean plotting dependency install.
- Empty and NON-PAPER fixture A1–A5 decks rendered as native editable PowerPoint objects. Both were exported through `scripts/export_ppt_preview.py`; both PDFs have five pages and zero raster image objects. Publication typography is not verified.
- Independent arithmetic and artifact reviews completed. Regressions cover integer-bound comparison, symlinked release ancestors, private-locator exclusion, fixture relabeling, retained run/backend/source evidence, incompatible builds/methods, A4 run separation, parameter schedules, TeX literal escaping and PowerPoint theme shadows.

## Codec and full-protocol review evidence

- Eleven codec tests cover 303 independent randomized radix-oracle cases, empty/leading-zero files, block boundaries, exact809-byte capacity at M=4096, surplus codewords, nonzero padding, typed shape and short/truncated/overlong streams. An independent exhaustive one-byte review found256 distinct legal encodings and rejected all473 surplus six-trit codewords. This supplies engineering evidence for the approved convention, not a substitute for the mathematical injectivity argument.
- Independent protocol, codec, wire/transcript, external-binding and artifact/runner reviews found no Important/Critical defects in their reviewed scope. A discovered custom-WireLimits propagation issue was fixed, with a5000-byte identifier regression through proving, evidence validation and admission.
- The actual three-byte correctness fixture generated2609-byte proofs,3229-byte registration and round-record parts of1667 and876 bytes. These are counts of this exact small serialized case, not scaling or performance results. Context and external mock evidence are counted separately. All Verify timing partitions summed exactly; same-epoch replay and previous-epoch proof substitution rejected.
- The final runner metadata explicitly excludes initial ledger creation and diagnostic re-verifications from primary audit costs; admission itself is inside complete Verify. Its five focused tests were rerun after this metadata clarification.

## Limits

The complete protocol, codec, wire, challenge suite and external-validation interfaces are implemented. Current tests do not establish cryptographic security, authenticate real epochs or receipt times, implement GPU arithmetic, measure formal performance, or validate the two user platforms. Remaining conditions are listed in `design.md` and `full-protocol.md`. The test providers are explicitly simulated; strict protocol entry points reject without an approved security profile.

The exact plotting versions are pinned, but clean dependency installation and wheel hash locking were blocked by the cloud package-index proxy. Libertine/newtx packages are absent; marked previews use fallback fonts and publication rendering rejects. Windows deployment scripts have not been executed here. ePoSt full-text/author-code details remain unresolved as described in `baselines.md`.

No discarded figure, B-group data, raw server log, or user-machine performance measurement enters these results.
