# A1–A5 tooling: evidence contract and current deliverables

This tooling produces **empty layouts**, or clearly marked **NON-PAPER synthetic fixture previews**, from independently validated logs. It has collected no performance measurements. The Python reference kernel is correctness work; it is not the final protocol, a complete benchmark implementation, or a proxy for Rust/CUDA results. D1–D6 in `design.md` remain prerequisites for formal local data collection. No old figure or B-group data is used.

## Run the authorized empty and fixture paths

From the project root, using the installed plotting dependencies:

```bash
python -m unittest tests.test_aggregate tests.test_plotting -v
python -m damascus_a.plotting --output outputs/a-group-empty
python fixtures/make_fixture.py
python -m damascus_a.plotting --input fixtures/NON_PAPER_fixture.jsonl --fixture --output outputs/a-group-NON-PAPER-fixture
python -m damascus_a.aggregate fixtures/NON_PAPER_fixture.jsonl --experiment A3
```

The following commands **must reject**, with exit status 2:

```bash
python -m damascus_a.aggregate fixtures/NON_PAPER_fixture.jsonl --experiment A1 --publication
python -m damascus_a.plotting --input fixtures/NON_PAPER_fixture.jsonl --output /tmp/must-not-export-fixture
python -m damascus_a.plotting --output /tmp/must-not-export-publication --publication
```

The last rejection is specific to the current environment: exact desktop `Linux Libertine O`, `libertine.sty` and `newtxmath.sty` are missing. TeX executables alone do not satisfy the font requirement. Preview exports visibly state **PREVIEW FONT FALLBACK: DejaVu Serif / DejaVu math**; no silent substitution is allowed in publication mode.

Each successful export directory contains `A1.svg` … `A5.svg`, `A1.pdf` … `A5.pdf`, a five-slide `A-group-editable.pptx`, and an aggregation/provenance `manifest.json`. Blank slides use native editable axes/text/table objects with no numeric data. Fixture slides use native editable PowerPoint scatter/stacked charts with embedded workbook data and native tables, with no image media. SVG/PDF use vector graphics. Font embedding in PowerPoint is not implemented. Plot labels are editable plain text; **PowerPoint TeX/newtx equation objects are not implemented**, so the current PPTX is a layout/figure-editing artifact, not a claim of completed final equation typography.

The current blank and fixture PPTX files were also converted through local LibreOffice to five-page PDFs and checked with `pdfimages -list`: **zero image objects in both exports**. Native shape/chart effects are explicitly cleared (`a:effectLst`, theme `effectRef=0`) because inherited connector shadows otherwise rasterize during export. The check is specific to this exporter/version, not a guarantee about every PowerPoint/LibreOffice version. A screenshot-free PPTX alone does not prove that its PDF export is vector.

The checked preview exporter below uses an isolated LibreOffice profile, requires the adjacent EMPTY LAYOUT/NON-PAPER manifest, and refuses rasterized or unrecognized PDF inventories and existing destinations. It does not approve publication typography.

```bash
python scripts/export_ppt_preview.py outputs/a-group-empty/A-group-editable.pptx --output outputs/a-group-empty/A-group-from-ppt-vector.pdf
python scripts/export_ppt_preview.py outputs/a-group-NON-PAPER-fixture/A-group-editable.pptx --output outputs/a-group-NON-PAPER-fixture/A-group-from-ppt-vector.pdf
```

```bash
soffice -env:UserInstallation=file:///tmp/damascus-a-vector-profile-empty --headless --convert-to pdf --outdir /tmp/damascus-a-vector-check-empty outputs/a-group-empty/A-group-editable.pptx
pdfimages -list /tmp/damascus-a-vector-check-empty/A-group-editable.pdf
soffice -env:UserInstallation=file:///tmp/damascus-a-vector-profile-fixture --headless --convert-to pdf --outdir /tmp/damascus-a-vector-check-fixture outputs/a-group-NON-PAPER-fixture/A-group-editable.pptx
pdfimages -list /tmp/damascus-a-vector-check-fixture/A-group-editable.pdf
```

## Record schema and API

`schemas/experiment.schema.json` defines a single JSONL record; JSON arrays are also accepted. The standard-library validator in `damascus_a/aggregate.py` independently checks numeric types, provenance, artifact contents, exact Verify partitions and cross-record consistency. JSON Schema alone cannot validate those semantic invariants.

```python
from damascus_a.aggregate import load_records, validate_record, aggregate

records = load_records("path/to/observations.jsonl")
validate_record(records[0])
result = aggregate(records, "A2", publication=False)
```

Required identity fields are `schema_version=1`, `data_kind`, `experiment`, `scheme`, `scheme_version`, `profile`, `protocol_hash`, `parameter_id`, `hardware_id`, `backend`, `cache`, `run_id`, `repetition`, `status`, `file_bytes` and `provenance`. `backend` preserves requested/actual implementation and fallback reason. Provenance records source, measurement method, hardware description and UTC time, with optional source hash, build and command. Repeated runs retain a run ID and repetition index; repeated epoch audits also retain a sequence index, unique audit/proof IDs, registration ID and certified-context source.

The only accepted data kinds are `fixture`, `correctness_test`, `local_measured`, and `published`. Simulation is deliberately unsupported. Fixture records must explicitly set `provenance.non_paper=true`. Correctness logs are not figure inputs. A `protocol_hash="unresolved"` is accepted only for fixtures/correctness; local/published records require a lowercase SHA-256 source hash. The schema does not invent a finalized protocol hash or an approved parameter profile.

`provenance.non_paper=true` independently excludes publication use. Relabeling such evidence `local_measured` or `published` is inconsistent and rejected; the marker cannot disappear during aggregation. Every result row includes `observation_ids` linking to `metadata.observations`, which retains original run/repetition IDs, requested/actual backend and fallback reason, complete provenance (including varying source IDs and timestamps), and the individual measured quantities. Artifact contents are represented there by their checked byte counts/hashes and ordered part manifest, without duplicating large inline payloads. Each observation ID is the SHA-256 of its validated normalized input record.

Aggregation rejects incompatible `source_sha256` values. Within each hardware ID it also rejects incompatible `build_description`, `measurement_method` or `hardware_description`, including absent-versus-present source/build metadata. A4 can retain platform-specific build and method descriptions in separate panels; it never pools their timings. A4 resource curves distinguish **both run ID and repetition**, so separate runs with repetition zero do not merge into a single series.

Missing metrics are absent or `null`; they are never silently converted to zero. Measured durations are integer nanoseconds, byte counts are integer bytes, and plot unit conversions are explicit: `MiB = 2^20 bytes`, `ms = ns / 10^6`. Floating-point and boolean durations/counts reject. No unit inference from labels is performed.

`publication=True` rejects fixture/correctness records **anywhere in the supplied input**, even if the selected figure would otherwise filter them out. A1–A4 never ingest published timings. A5 retains separate semantic/source/hardware rows and does not expose pooled timing columns. A1–A3 reject mixed profiles, source protocol hashes, schemes/versions, hardware IDs and actual backends. A4 permits exactly two distinct hardware IDs while keeping the other identities fixed.

File scaling may require size-dependent parameters under one approved profile. Mixed `parameter_id` values therefore require an explicit, common, nonempty `parameter_schedule_id`; each file size must still map to exactly **one** parameter ID across repetitions, cache modes and platforms. The complete `parameters_by_file_bytes` mapping is preserved in aggregation metadata and each A1/A2/A4 result row retains its parameter ID. Differing parameter schedules cannot be pooled. A3 uses one file size and consequently one parameter ID. This is provenance support, not parameter selection or security approval.

## Figure contracts

| Figure | Aggregation and displayed quantity | Rejection / limit |
|---|---|---|
| A1 | File size versus actual full proof, registration and **each individual round record** bytes. Repetitions are arithmetic means with counts retained. | Requires artifact bytes and SHA-256; exhaustive contiguous part manifest must match the full proof and include round records and terminal opening. Supplied header/context/challenge/framing bytes are included; this tool does not decide which of those fields a future wire profile serializes. No element-count formula substitutes for serialization. |
| A2 | At every file size, cold/cached stacked bars cover the **entire Verify** interval: parsing/context, challenges, generator replay, commitment/parity, norm, opening, explicit residual Other. | All seven nonoverlapping integer-ns stages must sum exactly to `verify_ns`; both cold and cached observations are required. Inclusive/nested spans cannot be added as exclusive stages. |
| A3 | Across successive **NEW epochs** on one registered file: `(setup + sum(Prove + Verify)) / audit_count`, with a separate setup-excluded companion. | Setup occurs once at the sequence start, followed by explicit zeroes. Sequence starts at 1 with no gaps; audit/proof IDs cannot repeat, even across repetitions. Every epoch declares its certified context source. |
| A4 | Two local-platform panels: per-repetition peak process RSS and sampled VRAM maximum; failed tested sizes are explicitly labeled. | Exactly two hardware IDs; successful RSS required. Missing VRAM stays unavailable. Timeout/OOM/parameter rejection/error retain reasons. Failure points are observed limits, not interpolated capacity claims. |
| A5 | ADJ21 **public low-storage PoR**, ePoSt **storage-time**, and Damascus remain separate rows by semantics, guarantee, security/parameters, source/evidence kind, hardware/backend. | No heterogeneous-hardware seconds ranking. Primary-source findings and unresolved ePoSt full-text details are in `baselines.md`; no numerical published results were imported into these layouts. |

A2 cache labels are assertions by the collector; future collector logs must define the cache policy, cold-start reset, scope of parsing/opening and timer nesting. A3 uniqueness checks prevent accidental same-proof benchmark reuse but do not authenticate an epoch. The `certified_new` flag and a context source string are **not substitutes for externally authenticated context or trusted receipt times**. These remain unresolved protocol-level gates, not validation guarantees of this package.

A4 currently draws successful resource observations and annotates failed tested sizes. Raw failed-run resource values remain in the exported manifest when supplied; they are not joined to the successful resource curve. VRAM sample intervals are retained in nanoseconds, and a reported sampled maximum is never called an exact device peak. Process RSS, process tree RSS, allocator use and device-wide use are different quantities; collectors must identify the actual method in provenance.

## Actual-byte evidence

`serialization` contains `wire_profile`, `codec`, `full_proof`, `registration`, and an ordered `parts` list. Every artifact contains `bytes`, `sha256`, and exactly one of canonical lowercase `hex` or a relative `path`. A part additionally contains `kind` and byte `offset`. All parts must match the corresponding bytes in the full proof with no gaps or overlaps. Exactly one terminal opening is required. The registration artifact is separately counted.

Sidecars are resolved relative to the input log and cannot escape that directory, including through symlinks. `load_records` verifies size/hash and normalizes sidecars into the loaded representation. Current loading reads artifacts into memory; it is suitable for reviewable logs, not yet a streaming multi-gigabyte artifact pipeline.

These checks establish **actual byte accounting and declared part coverage**. They do not establish that arbitrary supplied bytes are a valid or complete proof under an approved wire profile. A complete protocol decoder and independent recomputation are still required after D1–D6. The fixture's ASCII payload is deliberately not a proof.

## Tested scope and remaining gates

Unit coverage includes mixed-profile/hardware/backend rejection, exact byte/hash/offset checks, omission of opening, malformed Verify partitions, missing cold/cached pairs, reused epoch/proof IDs, setup double counting, missing VRAM, two-platform separation and A5 source separation. Rendering checks inspect the PPTX zip structure for native charts/embedded workbooks, native editable blank objects, visible NON-PAPER/font labels and absence of screenshot media; SVG is checked for absence of image elements.

Review regressions also cover independent run IDs, incompatible source/build/method/hardware metadata, retained observation evidence, a relabeled fixture retaining `non_paper=true`, and TeX-special characters in literal labels. The TeX route escapes all titles, axis/legend/category labels, annotations, table cells and footnotes. Escaping is tested with rendering I/O mocked; a complete Libertine/newtx publication render cannot be tested until the required fonts/packages are installed.

The numeric fixture path tests layout and arithmetic only. It does not benchmark the machine, run two local platforms, validate baseline security, approve protocol decisions, certify new epochs, implement a GPU backend, or supply paper-ready evidence. Final typography, real logs, full-protocol implementation, approved parameters and local collection authorization remain outstanding.
