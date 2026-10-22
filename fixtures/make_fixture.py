"""Generate hand-authored SYNTHETIC NON-PAPER test inputs; never measurements.

The fake files, clocks, proofs, certifications and platforms exist solely to
exercise validation and rendering. Nothing here implements any real protocol.
"""
import hashlib
import json
from pathlib import Path

STAGES = ("parsing_context", "challenges", "generator_replay", "commitment_parity", "norm", "opening", "other")
MIB = 2 ** 20


def blob(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "hex": data.hex()}


def base(name, **updates):
    row = {
        "schema_version": 1, "data_kind": "fixture", "experiment": name,
        "scheme": "NON-PAPER synthetic fixture", "scheme_version": "fixture-v1",
        "profile": "NON-PAPER fixture profile", "protocol_hash": "unresolved",
        "parameter_id": "fixture-only", "hardware_id": "FICTIONAL-platform-1",
        "backend": {"requested": "fixture", "actual": "fixture", "fallback_reason": None},
        "cache": "cold", "run_id": "NON-PAPER-" + name, "repetition": 0,
        "status": "ok", "file_bytes": MIB, "setup_ns": 100_000_000,
        "prove_ns": 20_000_000, "verify_ns": 28_000_000,
        "stages_ns": {name: i * 1_000_000 for i, name in enumerate(STAGES, 1)},
        "provenance": {
            "source_id": "fixtures/make_fixture.py — NON-PAPER",
            "measurement_method": "Hand-authored synthetic constants; no measurements",
            "hardware_description": "FICTIONAL platform; does not describe any actual machine",
            "timestamp_utc": "2000-01-01T00:00:00Z", "non_paper": True,
        },
    }
    row.update(updates)
    return row


def fake_serialization(scale):
    parts = [("header", b"NON-PAPER HEADER"), ("context", b"FAKE CONTEXT"), ("challenge", b"FAKE CHALLENGE"), ("round_record", b"FAKE ROUND" * scale), ("round_record", b"FAKE ROUND TWO" * scale), ("terminal_opening", b"FAKE OPENING")]
    manifest, offset = [], 0
    for kind, data in parts:
        manifest.append({"kind": kind, "offset": offset, "artifact": blob(data)})
        offset += len(data)
    return {"wire_profile": "NON-PAPER-not-a-protocol", "codec": "NON-PAPER-ASCII", "full_proof": blob(b"".join(data for _, data in parts)), "registration": blob(b"FAKE REGISTRATION"), "parts": manifest}


def make_records():
    rows = []
    for scale, size in enumerate((MIB, 4 * MIB, 16 * MIB), 1):
        rows.append(base("A1", file_bytes=size, serialization=fake_serialization(scale)))
        for cache, factor in (("cold", 2), ("warm", 1)):
            stages = {name: i * factor * scale * 1_000_000 for i, name in enumerate(STAGES, 1)}
            rows.append(base("A2", file_bytes=size, cache=cache, verify_ns=sum(stages.values()), stages_ns=stages))
    for index in range(1, 6):
        rows.append(base("A3", setup_ns=100_000_000 if index == 1 else 0, epoch={"sequence_index": index, "audit_id": f"FAKE-EPOCH-{index}", "proof_id": f"FAKE-PROOF-{index}", "registration_id": "FAKE-REGISTRATION", "context_source": "SYNTHETIC fixture assertion; not a certified context", "certified_new": True}))
    for platform in (1, 2):
        for scale, size in enumerate((MIB, 4 * MIB, 16 * MIB), 1):
            resources = {"peak_rss_bytes": (70 + scale * 25 * platform) * MIB, "sampled_peak_vram_bytes": (40 + scale * 20) * MIB if platform == 2 else None, "vram_sampling_interval_ns": 10_000_000 if platform == 2 else None}
            rows.append(base("A4", hardware_id=f"FICTIONAL-platform-{platform}", file_bytes=size, resources=resources))
        rows.append(base("A4", hardware_id=f"FICTIONAL-platform-{platform}", file_bytes=64 * MIB, status="oom" if platform == 1 else "timeout", failure_reason="SYNTHETIC fixture status, no run occurred", resources={"peak_rss_bytes": None, "sampled_peak_vram_bytes": None, "vram_sampling_interval_ns": None}))
    for index, family in enumerate(("public_low_storage_por", "epost", "damascus")):
        rows.append(base("A5", run_id=f"NON-PAPER-A5-{index}", scheme=f"SYNTHETIC {family}", comparison={"protocol_family": family, "guarantee": "NON-PAPER placeholder; no real guarantee claimed", "security_model": "NON-PAPER; no reviewed model", "parameter_notes": "NON-PAPER toy parameters", "source": "Hand-authored fixture; no cited paper results", "cost_scope": "Rendering test only; no measured cost"}))
    return rows


if __name__ == "__main__":
    destination = Path(__file__).with_name("NON_PAPER_fixture.jsonl")
    destination.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in make_records()), encoding="utf-8")
    print(f"NON-PAPER synthetic fixture written: {destination}")
