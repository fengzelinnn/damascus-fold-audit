"""Independent rejection and arithmetic checks; all records are NON-PAPER fixtures."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from damascus_a.aggregate import STAGES, ValidationError, aggregate, load_records, validate_record


def blob(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "hex": data.hex()}


def record(experiment="A2", **updates):
    row = {
        "schema_version": 1, "data_kind": "fixture", "experiment": experiment,
        "scheme": "NON-PAPER toy fixture", "scheme_version": "fixture-v1", "profile": "fixture-only",
        "protocol_hash": "unresolved", "parameter_id": "fixture-parameters", "hardware_id": "fixture-host-a",
        "backend": {"requested": "fixture", "actual": "fixture", "fallback_reason": None},
        "cache": "cold", "run_id": "fixture-run", "repetition": 0, "status": "ok", "file_bytes": 1024,
        "setup_ns": 100, "prove_ns": 20, "verify_ns": 28,
        "stages_ns": dict(zip(STAGES, range(1, 8))),
        "provenance": {"source_id": "test-only", "measurement_method": "hand-authored synthetic fixture, NON-PAPER", "hardware_description": "FICTIONAL fixture platform A", "timestamp_utc": "2000-01-01T00:00:00Z", "non_paper": True},
    }
    row.update(updates)
    return row


def serialization():
    parts = [("header", b"HEAD"), ("context", b"ctx"), ("challenge", b"ch"), ("round_record", b"round"), ("terminal_opening", b"opening")]
    offset = 0
    manifest = []
    for kind, data in parts:
        manifest.append({"kind": kind, "offset": offset, "artifact": blob(data)})
        offset += len(data)
    return {"wire_profile": "fixture-only", "codec": "fixture-bytes", "full_proof": blob(b"".join(data for _, data in parts)), "registration": blob(b"reg"), "parts": manifest}


class AggregationTests(unittest.TestCase):
    def rejects(self, rows, experiment, text):
        with self.assertRaisesRegex(ValidationError, text):
            aggregate(rows, experiment)

    def test_empty_does_not_fabricate_rows(self):
        for name in ("A1", "A2", "A3", "A4", "A5"):
            self.assertTrue(aggregate([], name)["empty"])

    def test_publication_rejects_fixture_even_in_other_experiment(self):
        with self.assertRaisesRegex(ValidationError, "publication aggregation rejects"):
            aggregate([record()], "A1", publication=True)

    def test_relabelled_fixture_non_paper_marker_still_rejects(self):
        row = record("A1", data_kind="local_measured", protocol_hash="a" * 64, serialization=serialization())
        with self.assertRaisesRegex(ValidationError, "non_paper"):
            aggregate([row], "A1", publication=True)

    def test_incompatible_build_source_method_or_hardware_description_rejects(self):
        for field, first, second in (("source_sha256", "a" * 64, "b" * 64), ("build_description", "build-one", "build-two"), ("measurement_method", "exclusive spans v1", "different spans v2"), ("hardware_description", "actual machine 1", "different machine 2")):
            rows = [record(), record(cache="warm")]
            rows[0]["provenance"][field] = first
            rows[1]["provenance"][field] = second
            with self.subTest(field=field):
                self.rejects(rows, "A2", "incompatible provenance")

    def test_aggregate_retains_auditable_run_backend_and_source_evidence(self):
        rows = [record(), record(cache="warm", run_id="another-run")]
        rows[0]["backend"] = {"requested": "gpu", "actual": "fixture", "fallback_reason": "GPU unavailable"}
        rows[0]["provenance"]["source_id"] = "first-source"
        rows[1]["provenance"]["source_id"] = "second-source"
        result = aggregate(rows, "A2")
        observations = result["metadata"]["observations"]
        self.assertEqual({o["run_id"] for o in observations}, {"fixture-run", "another-run"})
        self.assertEqual(observations[0]["backend"], rows[0]["backend"])
        self.assertEqual(observations[0]["provenance"], rows[0]["provenance"])
        self.assertEqual(result["rows"][0]["observation_ids"], [observations[0]["observation_id"]])

    def test_correctness_is_not_performance(self):
        self.rejects([record(data_kind="correctness_test")], "A2", "correctness tests")

    def test_mixed_profile_hardware_and_backend_rejected(self):
        for field, new in (("profile", "other"), ("hardware_id", "other"), ("parameter_id", "other")):
            other = record(cache="warm", **{field: new})
            self.rejects([record(), other], "A2", "cannot pool mixed")
        other = record(cache="warm", backend={"requested": "other", "actual": "other", "fallback_reason": None})
        self.rejects([record(), other], "A2", "actual backends")

    def test_a2_whole_verify_and_other_are_preserved(self):
        result = aggregate([record(), record(cache="warm")], "A2")
        self.assertEqual(result["rows"][0]["verify_ns"], 28)
        self.assertEqual(result["rows"][0]["stages_ns"]["opening"], 6)
        self.assertEqual(result["rows"][0]["stages_ns"]["other"], 7)

    def test_malformed_stages_reject(self):
        mutations = [lambda r: r["stages_ns"].pop("opening"), lambda r: r.update(verify_ns=29), lambda r: r["stages_ns"].update(norm=-1), lambda r: r["stages_ns"].update(norm=True), lambda r: r["stages_ns"].update(norm=1.0), lambda r: r["stages_ns"].update(unknown=0)]
        for mutate in mutations:
            row = record()
            mutate(row)
            with self.subTest(row=row), self.assertRaises(ValidationError):
                validate_record(row)

    def test_bad_identity_types_reject_cleanly(self):
        for key in ("data_kind", "experiment", "cache", "status"):
            for value in ([], {}, None):
                with self.subTest(key=key, value=value), self.assertRaises(ValidationError):
                    validate_record(record(**{key: value}))

    def test_a2_missing_cache_pair_rejects(self):
        self.rejects([record()], "A2", "both cold and warm")

    def test_a1_uses_actual_bytes_including_opening(self):
        result = aggregate([record("A1", serialization=serialization())], "A1")
        self.assertEqual(result["rows"][0]["full_proof_bytes"], 21)
        self.assertEqual(result["rows"][0]["round_bytes"], [5])
        self.assertEqual(result["rows"][0]["registration_bytes"], 3)

    def test_a1_does_not_choose_unresolved_header_or_challenge_encoding(self):
        serial = serialization()
        serial["parts"] = [p for p in serial["parts"] if p["kind"] in {"round_record", "terminal_opening"}]
        offset, payload = 0, b""
        for part in serial["parts"]:
            part["offset"] = offset
            payload += bytes.fromhex(part["artifact"]["hex"])
            offset += part["artifact"]["bytes"]
        serial["full_proof"] = blob(payload)
        result = aggregate([record("A1", serialization=serial)], "A1")
        self.assertEqual(result["rows"][0]["full_proof_bytes"], 12)

    def test_size_dependent_parameters_require_declared_schedule(self):
        rows = [record("A1", file_bytes=1024, parameter_id="size-small", serialization=serialization()), record("A1", file_bytes=4096, parameter_id="size-large", serialization=serialization())]
        self.rejects(rows, "A1", "explicit shared parameter_schedule_id")
        for row in rows:
            row["parameter_schedule_id"] = "reviewed-size-dependent-schedule"
        result = aggregate(rows, "A1")
        self.assertEqual(result["metadata"]["parameters_by_file_bytes"], {"1024": "size-small", "4096": "size-large"})
        self.assertEqual([r["parameter_id"] for r in result["rows"]], ["size-small", "size-large"])
        rows[1]["parameter_schedule_id"] = "other-schedule"
        self.rejects(rows, "A1", "explicit shared parameter_schedule_id")

    def test_schedule_cannot_hide_mismatched_parameters_at_same_size(self):
        rows = [record("A2", parameter_id="parameter-a", parameter_schedule_id="schedule"), record("A2", cache="warm", parameter_id="parameter-b", parameter_schedule_id="schedule")]
        self.rejects(rows, "A2", "parameter_id mismatch at the same file size")

    def test_false_byte_counts_hashes_offsets_omitted_opening_reject(self):
        mutations = [lambda s: s["full_proof"].update(bytes=999), lambda s: s["full_proof"].update(sha256="0" * 64), lambda s: s["parts"][1].update(offset=0), lambda s: s["parts"].pop(), lambda s: s["parts"][-1].update(kind="other"), lambda s: s["parts"][0].update(artifact=blob(b"FAIL"))]
        for mutate in mutations:
            serial = serialization()
            mutate(serial)
            with self.subTest(serial=serial), self.assertRaises(ValidationError):
                validate_record(record("A1", serialization=serial))

    def test_sidecars_are_verified_and_confined(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = record("A1", serialization=serialization())
            artifact = row["serialization"]["registration"]
            (root / "reg.bin").write_bytes(b"reg")
            del artifact["hex"]
            artifact["path"] = "reg.bin"
            (root / "log.jsonl").write_text(json.dumps(row) + "\n")
            loaded = load_records(root / "log.jsonl")
            self.assertEqual(aggregate(loaded, "A1")["rows"][0]["registration_bytes"], 3)
            artifact["path"] = "../outside.bin"
            with self.assertRaisesRegex(ValidationError, "escapes"):
                validate_record(row, root)

    def epochs(self):
        return [record("A3", setup_ns=100 if i == 1 else 0, epoch={"sequence_index": i, "audit_id": f"epoch-{i}", "proof_id": f"proof-{i}", "registration_id": "reg-1", "context_source": "NON-PAPER fixture context", "certified_new": True}) for i in range(1, 4)]

    def test_a3_cumulative_formula_includes_setup_prove_and_all_verify(self):
        result = aggregate(self.epochs(), "A3")
        self.assertEqual([r["without_setup_ns"] for r in result["rows"]], [48, 48, 48])
        self.assertEqual(result["rows"][1]["with_setup_ns"], 98)
        self.assertAlmostEqual(result["rows"][2]["with_setup_ns"], 244 / 3)

    def test_a3_reused_proof_or_audit_is_not_new_epoch(self):
        for key in ("audit_id", "proof_id"):
            rows = self.epochs()
            rows[1]["epoch"][key] = rows[0]["epoch"][key]
            self.rejects(rows, "A3", "reused")
        rows = self.epochs()
        rows[1]["epoch"]["certified_new"] = False
        self.rejects(rows, "A3", "certified NEW epoch")

    def test_a3_gaps_or_repeated_setup_reject(self):
        rows = self.epochs()
        rows[1]["epoch"]["sequence_index"] = 4
        self.rejects(rows, "A3", "contiguous")
        rows = self.epochs()
        rows[1]["setup_ns"] = 100
        self.rejects(rows, "A3", "exactly once")

    def test_a4_preserves_two_platform_failures_and_missing_vram(self):
        resources = {"peak_rss_bytes": 1000, "sampled_peak_vram_bytes": None, "vram_sampling_interval_ns": None}
        rows = [record("A4", resources=resources), record("A4", hardware_id="fixture-host-b", status="oom", failure_reason="synthetic fixture boundary", resources={})]
        result = aggregate(rows, "A4")
        self.assertEqual(result["rows"][1]["status"], "oom")
        self.assertIsNone(result["rows"][0]["resources"]["sampled_peak_vram_bytes"])
        self.rejects(rows[:1], "A4", "exactly two")

    def test_a4_retains_distinct_runs_with_same_repetition(self):
        resources = {"peak_rss_bytes": 1000, "sampled_peak_vram_bytes": None, "vram_sampling_interval_ns": None}
        rows = [record("A4", resources=resources, run_id="run-one"), record("A4", resources=resources, run_id="run-two"), record("A4", resources=resources, hardware_id="fixture-host-b")]
        result = aggregate(rows, "A4")
        self.assertEqual([r["run_id"] for r in result["rows"][:2]], ["run-one", "run-two"])

    def test_a5_keeps_sources_semantics_and_hardware_separate_without_seconds(self):
        comparison = {"protocol_family": "public_low_storage_por", "guarantee": "fixture only", "security_model": "fixture only", "source": "fixture only", "cost_scope": "fixture only", "parameter_notes": "fixture only"}
        first = record("A5", comparison=comparison)
        second = record("A5", run_id="other", hardware_id="fixture-host-b", profile="different", comparison={**comparison, "protocol_family": "epost"})
        result = aggregate([first, second], "A5")
        self.assertEqual(len(result["rows"]), 2)
        self.assertNotIn("verify_ns", result["rows"][0])


if __name__ == "__main__":
    unittest.main()
