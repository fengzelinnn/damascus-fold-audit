# Verified stage: 2026-10-22

This is a feasibility, arithmetic-correctness and experiment-tooling stage. It is not a complete authenticated PoSt implementation or security certification.

## Executed checks

- `python -m unittest discover -s tests -v`: **81 tests passed** under CPython 3.12.14. Tests include independent convolution and folded-commitment recomputation, exact integer bounds, malformed inputs, provenance isolation, actual artifact-byte accounting, plotting and release isolation.
- `python -m compileall -q damascus_a scripts`: passed.
- `python scripts/verify_sources.py`: both frozen original SHA-256 values matched the public source manifest. Raw originals are deliberately absent from the public package.
- `bash scripts/run_local.sh`: Linux preflight plus four small d=2 correctness cases accepted; original JSON/CSV stay local and are explicitly not performance evidence.
- Core wheel built with existing setuptools using `pip wheel --no-deps --no-build-isolation --no-index --no-cache-dir`; independently installed core accepted two d=1 correctness cases.
- Empty and NON-PAPER fixture A1–A5 decks rendered as native editable PowerPoint objects. Both were exported through `scripts/export_ppt_preview.py`; both PDFs have five pages and zero raster image objects. Publication typography is not verified.
- Independent arithmetic and artifact reviews completed. Regressions cover integer-bound comparison, symlinked release ancestors, private-locator exclusion, fixture relabeling, retained run/backend/source evidence, incompatible builds/methods, A4 run separation, parameter schedules, TeX literal escaping and PowerPoint theme shadows.

## Limits

The current tests do not establish cryptographic security, choose a file codec/wire/Fiat–Shamir suite, authenticate epochs or receipt times, implement GPU arithmetic, measure formal performance, or validate the two user platforms. D1–D6 remain open in `design.md`.

The exact plotting versions are pinned, but clean dependency installation and wheel hash locking were blocked by the cloud package-index proxy. Libertine/newtx packages are absent; marked previews use fallback fonts and publication rendering rejects. Windows deployment scripts have not been executed here. ePoSt full-text/author-code details remain unresolved as described in `baselines.md`.

No discarded figure, B-group data, raw server log, or user-machine performance measurement enters these results.
