"""Independent, fail-closed A-group log validation and aggregation.

This module does not collect measurements or decide the protocol wire format.
Byte counts are checked against supplied artifacts; cryptographic completeness
of an approved protocol profile remains a separate prerequisite.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from statistics import mean
from typing import Any

KINDS = {"fixture", "correctness_test", "local_measured", "published"}
EXPERIMENTS = {"A1", "A2", "A3", "A4", "A5", "correctness"}
STAGES = ("parsing_context", "challenges", "generator_replay", "commitment_parity", "norm", "opening", "other")
STATUSES = {"ok", "timeout", "oom", "parameter_rejected", "error"}
CONTEXT = ("data_kind", "scheme", "scheme_version", "profile", "protocol_hash", "parameter_id", "hardware_id")


class ValidationError(ValueError):
    """A record cannot support the requested figure."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _integer(value: Any, name: str, *, minimum: int = 0) -> None:
    _need(type(value) is int and value >= minimum, f"{name} must be an integer >= {minimum}")


def _text(value: Any, name: str) -> None:
    _need(isinstance(value, str) and bool(value.strip()), f"{name} must be a nonempty string")


def _choice(value: Any, choices: set[str], name: str) -> None:
    _need(isinstance(value, str) and value in choices, f"unknown {name}")


def _digest(value: Any, name: str) -> None:
    _need(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value), f"{name} must be lowercase SHA-256 hex")


def _artifact(blob: Any, base_dir: Path | None) -> bytes:
    _need(isinstance(blob, dict), "serialized artifact must be an object")
    _integer(blob.get("bytes"), "artifact.bytes")
    _digest(blob.get("sha256"), "artifact.sha256")
    _need(("hex" in blob) != ("path" in blob), "artifact requires exactly one of hex or path")
    if "hex" in blob:
        _need(isinstance(blob["hex"], str), "artifact.hex must be text")
        try:
            data = bytes.fromhex(blob["hex"])
        except ValueError as exc:
            raise ValidationError("invalid artifact hex") from exc
        _need(data.hex() == blob["hex"], "artifact hex must be canonical lowercase without whitespace")
    else:
        _need(base_dir is not None, "artifact.path requires a log base directory")
        _text(blob["path"], "artifact.path")
        root = Path(base_dir).resolve()
        path = (root / blob["path"]).resolve()
        _need(path.is_relative_to(root), "artifact path escapes the log directory")
        _need(path.is_file(), f"artifact is unavailable: {blob['path']}")
        _need(path.stat().st_size == blob["bytes"], "artifact file size disagrees with byte count")
        data = path.read_bytes()
    _need(len(data) == blob["bytes"], "serialized byte count disagrees with actual artifact")
    _need(hashlib.sha256(data).hexdigest() == blob["sha256"], "artifact SHA-256 mismatch")
    return data


def _serialization(value: Any, base_dir: Path | None) -> None:
    _need(isinstance(value, dict), "serialization must be an object")
    for name in ("wire_profile", "codec"):
        _text(value.get(name), f"serialization.{name}")
    full = _artifact(value.get("full_proof"), base_dir)
    _artifact(value.get("registration"), base_dir)
    parts = value.get("parts")
    _need(isinstance(parts, list) and bool(parts), "full proof requires an exhaustive ordered part manifest")
    offset = 0
    kinds = []
    for part in parts:
        _need(isinstance(part, dict), "proof part must be an object")
        _choice(part.get("kind"), {"header", "context", "challenge", "round_record", "terminal_opening", "other"}, "proof part kind")
        _integer(part.get("offset"), "part.offset")
        _need(part["offset"] == offset, "proof part manifest has gaps, overlap or wrong ordering")
        data = _artifact(part.get("artifact"), base_dir)
        _need(bool(data), "proof parts must not be empty")
        _need(full[offset:offset + len(data)] == data, "proof part disagrees with serialized full proof")
        offset += len(data)
        kinds.append(part["kind"])
    _need(offset == len(full), "proof part manifest does not cover the entire proof")
    # Header/context/challenge encodings are not decided here. If supplied,
    # they remain counted and covered by the exhaustive artifact manifest.
    for kind in ("round_record", "terminal_opening"):
        _need(kind in kinds, f"full proof manifest omits {kind}")
    _need(kinds.count("terminal_opening") == 1, "full proof requires exactly one terminal opening")


def validate_record(record: dict, base_dir: Path | None = None) -> dict:
    """Validate one record without relying on collection code or JSON Schema."""
    _need(isinstance(record, dict), "record must be an object")
    _need(type(record.get("schema_version")) is int and record["schema_version"] == 1, "unsupported schema_version")
    _choice(record.get("data_kind"), KINDS, "data_kind")
    _choice(record.get("experiment"), EXPERIMENTS, "experiment")
    for name in (*CONTEXT[1:], "run_id"):
        _text(record.get(name), name)
    if "parameter_schedule_id" in record:
        _text(record["parameter_schedule_id"], "parameter_schedule_id")
    if record["protocol_hash"] != "unresolved":
        _digest(record["protocol_hash"], "protocol_hash")
    else:
        _need(record["data_kind"] in {"fixture", "correctness_test"}, "real/published records require a protocol source hash")
    _integer(record.get("file_bytes"), "file_bytes")
    _integer(record.get("repetition"), "repetition")
    _choice(record.get("cache"), {"cold", "warm", "none"}, "cache state")
    _choice(record.get("status"), STATUSES, "status")
    backend = record.get("backend")
    _need(isinstance(backend, dict), "backend must describe requested and actual implementations")
    for key in ("requested", "actual"):
        _text(backend.get(key), f"backend.{key}")
    _need("fallback_reason" in backend and (backend["fallback_reason"] is None or isinstance(backend["fallback_reason"], str)), "backend.fallback_reason must be text or null")
    if backend["requested"] != backend["actual"]:
        _text(backend["fallback_reason"], "backend.fallback_reason")
    provenance = record.get("provenance")
    _need(isinstance(provenance, dict), "provenance is required")
    for key in ("source_id", "measurement_method", "hardware_description", "timestamp_utc"):
        _text(provenance.get(key), f"provenance.{key}")
    if "source_sha256" in provenance:
        _digest(provenance["source_sha256"], "provenance.source_sha256")
    if "build_description" in provenance:
        _text(provenance["build_description"], "provenance.build_description")
    if "non_paper" in provenance:
        _need(type(provenance["non_paper"]) is bool, "provenance.non_paper must be boolean")
    if record["data_kind"] in {"local_measured", "published"}:
        _need(provenance.get("non_paper") is not True, "non_paper evidence cannot be relabelled as local_measured/published")
    if record["data_kind"] == "fixture":
        _need(provenance.get("non_paper") is True, "fixture provenance must explicitly set non_paper=true")
    for name in ("setup_ns", "prove_ns", "verify_ns"):
        if record.get(name) is not None:
            _integer(record[name], name)
    stages = record.get("stages_ns")
    if stages is not None:
        _need(isinstance(stages, dict) and set(stages) == set(STAGES), "Verify stages must include parsing_context, challenges, generator_replay, commitment_parity, norm, opening and other exactly")
        for name, duration in stages.items():
            _integer(duration, f"stages_ns.{name}")
        _need(record.get("verify_ns") is not None and sum(stages.values()) == record["verify_ns"], "Verify total must equal all nonoverlapping stages including opening and explicit other")
    if record.get("epoch") is not None:
        epoch = record["epoch"]
        _need(isinstance(epoch, dict), "epoch must be an object")
        _integer(epoch.get("sequence_index"), "epoch.sequence_index", minimum=1)
        for key in ("audit_id", "proof_id", "registration_id", "context_source"):
            _text(epoch.get(key), f"epoch.{key}")
        _need(type(epoch.get("certified_new")) is bool, "epoch.certified_new must be boolean")
    if record.get("serialization") is not None:
        _serialization(record["serialization"], base_dir)
    resources = record.get("resources")
    if resources is not None:
        _need(isinstance(resources, dict), "resources must be an object")
        for name in ("peak_rss_bytes", "sampled_peak_vram_bytes", "vram_sampling_interval_ns"):
            if resources.get(name) is not None:
                _integer(resources[name], f"resources.{name}")
        if resources.get("sampled_peak_vram_bytes") is not None:
            _integer(resources.get("vram_sampling_interval_ns"), "resources.vram_sampling_interval_ns", minimum=1)
    if record["status"] != "ok":
        _text(record.get("failure_reason"), "failure_reason")
    if record.get("comparison") is not None:
        comp = record["comparison"]
        _need(isinstance(comp, dict), "comparison must be an object")
        _choice(comp.get("protocol_family"), {"public_low_storage_por", "epost", "damascus"}, "baseline semantics")
        for name in ("guarantee", "security_model", "source", "cost_scope", "parameter_notes"):
            _text(comp.get(name), f"comparison.{name}")
    return record


def load_records(path: str | Path) -> list[dict]:
    """Load a JSON list or JSONL; artifacts are resolved beside the input log."""
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    try:
        records = json.loads(text) if text.lstrip().startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValidationError(f"malformed log: {exc}") from exc
    _need(isinstance(records, list), "log must be a JSON list or JSONL")
    for row in records:
        validate_record(row, source.parent)
        # Normalize sidecar artifacts into verified inline bytes so that later
        # independent aggregation does not depend on a mutable working directory.
        serial = row.get("serialization")
        if serial is not None:
            blobs = [serial["full_proof"], serial["registration"], *[p["artifact"] for p in serial["parts"]]]
            for blob in blobs:
                if "path" in blob:
                    blob["hex"] = _artifact(blob, source.parent).hex()
                    del blob["path"]
    return records


def _context(records: list[dict], *, allow_hardware: bool = False) -> dict:
    varying_parameters = len({r["parameter_id"] for r in records}) > 1
    schedules = {r.get("parameter_schedule_id") for r in records}
    if varying_parameters:
        _need(len(schedules) == 1 and None not in schedules, "cannot pool mixed parameter_id without one explicit shared parameter_schedule_id")
    elif schedules != {None}:
        _need(len(schedules) == 1 and None not in schedules, "cannot pool inconsistent parameter schedule declarations")
    parameter_mapping = {}
    for row in records:
        size, parameter = str(row["file_bytes"]), row["parameter_id"]
        _need(size not in parameter_mapping or parameter_mapping[size] == parameter, "parameter_id mismatch at the same file size, including across cache modes and platforms")
        parameter_mapping[size] = parameter
    keys = [key for key in CONTEXT if not (allow_hardware and key == "hardware_id") and not (varying_parameters and key == "parameter_id")]
    for key in keys:
        _need(len({row[key] for row in records}) == 1, f"cannot pool mixed {key}")
    _need(len({row["backend"]["actual"] for row in records}) == 1, "cannot pool mixed actual backends")
    _need(len({row["provenance"].get("source_sha256") for row in records}) == 1, "incompatible provenance source_sha256")
    # A4 panels never average across platforms. Platform-specific build and
    # measurement descriptions may differ, but a reused hardware ID cannot
    # conceal incompatible source/build/method/identity descriptions.
    for group in _groups(records, lambda row: row["hardware_id"]).values():
        for key in ("build_description", "measurement_method", "hardware_description"):
            _need(len({row["provenance"].get(key) for row in group}) == 1, f"incompatible provenance {key} within hardware_id")
    for key in ("codec", "wire_profile"):
        values = {row["serialization"][key] for row in records if row.get("serialization") is not None}
        _need(len(values) <= 1, f"cannot pool mixed serialization {key}")
    result = {key: records[0][key] for key in keys} | {"backend": records[0]["backend"]["actual"], "parameters_by_file_bytes": parameter_mapping}
    if schedules != {None}:
        result["parameter_schedule_id"] = records[0]["parameter_schedule_id"]
    return result


def _groups(records: list[dict], key) -> dict:
    groups: dict[Any, list[dict]] = {}
    for row in records:
        groups.setdefault(key(row), []).append(row)
    return groups


def _observation_id(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _evidence(records: list[dict]) -> list[dict]:
    """Retain input facts and per-record links without duplicating artifact bytes."""
    observations = []
    for row in records:
        item = deepcopy(row)
        item["observation_id"] = _observation_id(row)
        serial = item.get("serialization")
        if serial is not None:
            for artifact in [serial["full_proof"], serial["registration"], *[part["artifact"] for part in serial["parts"]]]:
                artifact.pop("hex", None)
        observations.append(item)
    return observations


def _observation_ids(records: list[dict]) -> list[str]:
    return [_observation_id(row) for row in records]


def aggregate(records: list[dict], experiment: str, *, publication: bool = False) -> dict:
    """Aggregate one figure, retaining units, identity, sample counts and statuses.

    Publication aggregation rejects fixtures and correctness tests anywhere in
    the supplied input, even when they belong to a different figure.
    """
    _need(experiment in EXPERIMENTS - {"correctness"}, "expected A1 through A5")
    for record in records:
        validate_record(record)
        if publication:
            _need(record["data_kind"] in {"local_measured", "published"}, "publication aggregation rejects fixture/correctness_test input")
            _need(record["provenance"].get("non_paper") is not True, "publication aggregation rejects provenance.non_paper evidence")
    rows = [r for r in records if r["experiment"] == experiment]
    result = {"experiment": experiment, "empty": not rows, "publication": publication, "rows": [], "metadata": {}}
    if not rows:
        return result
    _need(all(r["data_kind"] != "correctness_test" for r in rows), "correctness tests are not performance or paper data")
    _need(len({(r["run_id"], r["repetition"], r["hardware_id"], r["file_bytes"], r["cache"], (r.get("epoch") or {}).get("sequence_index")) for r in rows}) == len(rows), "duplicate observations")
    if experiment == "A5":
        for row in rows:
            _need(row.get("comparison") is not None, "A5 requires semantics, security model and source")
            result["rows"].append({key: row[key] for key in (*CONTEXT, "run_id", "repetition", "backend", "provenance", "comparison", "status", "file_bytes")} | {"observation_ids": [_observation_id(row)]})
        result["metadata"] = {"timing_comparison": "none: each source and hardware remains a separate row", "data_kinds": sorted({r["data_kind"] for r in rows}), "observations": _evidence(rows)}
        return result
    result["metadata"] = _context(rows, allow_hardware=experiment == "A4")
    result["metadata"]["observations"] = _evidence(rows)
    _need(all(r["data_kind"] != "published" for r in rows), "A1-A4 require artifact-backed local logs; published results belong in A5")
    if experiment != "A4":
        _need(all(r["status"] == "ok" for r in rows), "failed observations cannot be averaged into successful timing/byte curves")
    if experiment == "A1":
        _need(len({r["cache"] for r in rows}) == 1, "A1 cannot pool mixed cache modes")
        for file_bytes, group in sorted(_groups(rows, lambda r: r["file_bytes"]).items()):
            _need(all(r.get("serialization") is not None for r in group), "A1 requires actual full-proof, registration and round artifacts")
            serials = [r["serialization"] for r in group]
            rounds = [[p["artifact"]["bytes"] for p in s["parts"] if p["kind"] == "round_record"] for s in serials]
            _need(len({len(x) for x in rounds}) == 1, "round count varies within one A1 file size")
            result["rows"].append({"file_bytes": file_bytes, "parameter_id": group[0]["parameter_id"], "full_proof_bytes": mean(s["full_proof"]["bytes"] for s in serials), "registration_bytes": mean(s["registration"]["bytes"] for s in serials), "round_bytes": [mean(x[i] for x in rounds) for i in range(len(rounds[0]))], "n": len(group), "observation_ids": _observation_ids(group)})
        result["metadata"]["byte_scope"] = "Actual artifacts; exhaustive full-proof part manifest includes terminal opening. Wire semantic approval remains external."
    elif experiment == "A2":
        _need(all(r.get("stages_ns") is not None for r in rows), "A2 requires the entire partitioned Verify phase")
        _need(all(r["cache"] in {"cold", "warm"} for r in rows), "A2 requires explicit cold/warm cache state")
        for (size, cache), group in sorted(_groups(rows, lambda r: (r["file_bytes"], r["cache"])).items()):
            result["rows"].append({"file_bytes": size, "parameter_id": group[0]["parameter_id"], "cache": cache, "verify_ns": mean(r["verify_ns"] for r in group), "stages_ns": {s: mean(r["stages_ns"][s] for r in group) for s in STAGES}, "n": len(group), "observation_ids": _observation_ids(group)})
        for size in {r["file_bytes"] for r in rows}:
            _need({r["cache"] for r in rows if r["file_bytes"] == size} == {"cold", "warm"}, "A2 requires both cold and warm observations at every file size")
    elif experiment == "A3":
        _need(len({r["file_bytes"] for r in rows}) == 1, "A3 requires one file size")
        _need(len({r["cache"] for r in rows}) == 1, "A3 cannot pool mixed cache modes")
        curves = []
        all_audits: set[str] = set()
        all_proofs: set[str] = set()
        for (run, repetition), group in sorted(_groups(rows, lambda r: (r["run_id"], r["repetition"])).items()):
            _need(all(r.get("epoch") is not None for r in group), "A3 requires an epoch sequence")
            group.sort(key=lambda r: r["epoch"]["sequence_index"])
            _need([r["epoch"]["sequence_index"] for r in group] == list(range(1, len(group) + 1)), "A3 requires contiguous NEW epoch sequence starting at one")
            _need(len({r["epoch"]["registration_id"] for r in group}) == 1, "A3 sequence must refer to the same registered file")
            _need(all(r["epoch"]["certified_new"] for r in group), "A3 rejects cached same-proof repetitions: every audit must be a certified NEW epoch")
            _need(group[0].get("setup_ns") is not None, "A3 setup cost must be measured at the sequence start")
            _need(all(r.get("setup_ns") == 0 for r in group[1:]), "A3 setup must occur exactly once, followed by explicit zeroes")
            setup = group[0]["setup_ns"]
            cumulative = 0
            curve = []
            for index, row in enumerate(group, 1):
                audit, proof = row["epoch"]["audit_id"], row["epoch"]["proof_id"]
                _need(audit not in all_audits and proof not in all_proofs, "A3 audit/proof identifier reused; cached same proof is not a new epoch")
                all_audits.add(audit)
                all_proofs.add(proof)
                _need(row.get("prove_ns") is not None and row.get("verify_ns") is not None, "A3 needs actual prove and entire Verify cost for every epoch")
                cumulative += row["prove_ns"] + row["verify_ns"]
                curve.append({"audit_count": index, "with_setup_ns": (setup + cumulative) / index, "without_setup_ns": cumulative / index, "observation_ids": _observation_ids(group[:index])})
            curves.append(curve)
        _need(len({len(c) for c in curves}) == 1, "A3 repetitions must have equal epoch sequence lengths")
        for index in range(len(curves[0])):
            result["rows"].append({"audit_count": index + 1, "with_setup_ns": mean(c[index]["with_setup_ns"] for c in curves), "without_setup_ns": mean(c[index]["without_setup_ns"] for c in curves), "n": len(curves), "observation_ids": [identifier for curve in curves for identifier in curve[index]["observation_ids"]]})
        result["metadata"]["audit_semantics"] = "Successive certified NEW epochs on one registered file; unique audit/proof IDs; setup once per sequence. IDs and certification provenance are assertions requiring external review."
        result["metadata"]["formula"] = "(setup_ns + sum(prove_ns + verify_ns)) / audit_count; companion excludes setup"
    elif experiment == "A4":
        _need(len({r["hardware_id"] for r in rows}) == 2, "A4 requires exactly two separately identified local platforms")
        _need(len({r["cache"] for r in rows}) == 1, "A4 cannot pool mixed cache modes")
        for row in sorted(rows, key=lambda r: (r["hardware_id"], r["file_bytes"], r["repetition"])):
            resources = row.get("resources")
            _need(resources is not None, "A4 requires a resource observation object, including nulls if unavailable")
            if row["status"] == "ok":
                _integer(resources.get("peak_rss_bytes"), "successful A4 peak_rss_bytes")
            result["rows"].append({key: row[key] for key in ("hardware_id", "file_bytes", "parameter_id", "status", "run_id", "repetition", "backend", "resources", "provenance")} | {"failure_reason": row.get("failure_reason"), "observation_ids": [_observation_id(row)]})
        result["metadata"]["resource_semantics"] = "RSS is the reported process peak; VRAM is a sampled observed maximum, not an exact device peak. Failures mark tested points, not interpolated limits."
    return result


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--experiment", choices=sorted(EXPERIMENTS - {"correctness"}), required=True)
    parser.add_argument("--publication", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(aggregate(load_records(args.input), args.experiment, publication=args.publication), indent=2, allow_nan=False))
    except (ValidationError, OSError) as exc:
        parser.exit(2, f"aggregation rejected: {exc}\n")


if __name__ == "__main__":
    main()
