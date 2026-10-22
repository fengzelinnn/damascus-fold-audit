# NON-PAPER synthetic test fixtures

Every value in `NON_PAPER_fixture.jsonl` is a hand-authored synthetic test constant. The described files, proofs, epochs, clocks, platforms and failures do not exist. This is not correctness evidence, benchmark output, simulation evidence, or a paper result. In particular, `certified_new=true` here is deliberately a fake assertion used to test the validation path.

Regenerate only with `python fixtures/make_fixture.py`. Render only with explicit `--fixture`; every slide, PDF and SVG carries a prominent NON-PAPER label. Publication aggregation rejects this file, including when the selected figure has no fixture rows.

The fixture payload is ASCII text and is not an approved wire format or a cryptographically valid proof. The A1 test exercises actual byte counting and artifact hash checks only.
