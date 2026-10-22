"""Bounded full-protocol correctness runs with explicit TEST_ONLY evidence.

This module is a local demonstration runner, not an external authority. Its
providers compare exact objects and simulated ticks; they establish no real
authentication, seed distribution, cutoff boundary, or timely publication.
Actual timings and wire bytes are retained as correctness telemetry only.
"""
from __future__ import annotations

import csv
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import random
import secrets
from time import perf_counter_ns
from uuid import uuid4

from . import protocol, transcript, wire
from .backend import select_backend
from .encoding import Reader, encode_bytes, encode_uint, frame, read_frame
from .environment import (AdmissionLedger, EnvironmentValidationError,
    EpochContextValidator, EpochValidation, PublicationEvidenceValidator,
    PublicationValidation, evidence_digest)
from .file_codec import Ternary32Codec
from .fold import FoldParameters
from .protocol_artifacts import serialization_evidence
from .protocol_types import EpochContext, ProtocolParameters
from .telemetry import machine_info, peak_rss_bytes

VERIFY_STAGES = ('parsing_context', 'challenges', 'generator_replay',
                 'commitment_parity', 'norm', 'opening', 'admission', 'other')
_TIME_DOMAIN = b'TEST_ONLY/simulated-ticks/v1'
_PAPER_SHA256 = '481a41f1bb3c7dd0f971d6cee87151242910214fda3315887778b48dc9da9bd0'
_DISCLAIMER = ('NON-PAPER correctness telemetry. TEST_ONLY simulated evidence; '
               'real certification, time, seed distribution and cutoff conditions '
               'are not established. The retained parameter audit is adverse.')


def simulated_deadline(tick: int = 100) -> bytes:
    """An opaque protocol field interpreted ONLY by this local test provider."""
    return frame(b'TEST_ONLY/deadline/v1', encode_uint(tick))


def _deadline_tick(raw: bytes) -> int:
    try:
        tag, payload = read_frame(raw)
        if tag != b'TEST_ONLY/deadline/v1':
            raise ValueError('unexpected simulated deadline tag')
        reader = Reader(payload)
        tick = reader.uint()
        reader.finish()
        return tick
    except (ValueError, TypeError) as error:
        raise EnvironmentValidationError('invalid TEST_ONLY deadline') from error


def _context_fields(ctx: EpochContext) -> dict:
    return dict(context_digest=transcript.context_digest(ctx),
                registration_digest=transcript.registration_digest(ctx.registration),
                epoch=ctx.epoch, deadline=ctx.deadline)


class TestOnlyEpochValidator(EpochContextValidator):
    """Exact-byte fixture comparison; no certificate or real authority exists."""
    __test__ = False

    def __init__(self, context: EpochContext):
        super().__init__(b'TEST_ONLY/epoch/v1', _TIME_DOMAIN)
        self._context = wire.encode_context(context)
        self.evidence = frame(b'TEST_ONLY/epoch-evidence/v1', self._context)

    def validate(self, context: EpochContext, evidence: bytes) -> EpochValidation:
        if wire.encode_context(context) != self._context or evidence != self.evidence:
            raise EnvironmentValidationError('TEST_ONLY epoch exact-byte mismatch')
        if type(evidence) is not bytes:
            raise EnvironmentValidationError('TEST_ONLY evidence must be bytes')
        _deadline_tick(context.deadline)
        return EpochValidation(**_context_fields(context), provider_id=self.provider_id,
            time_domain=self.time_domain, evidence_digest=evidence_digest(evidence))


class TestOnlyPublicationValidator(PublicationEvidenceValidator):
    """Exact proof/context and simulated inclusive tick cutoff, without signing."""
    __test__ = False

    def __init__(self, context: EpochContext, proof_bytes: bytes, *, receipt_tick: int = 90):
        super().__init__(b'TEST_ONLY/publication/v1', _TIME_DOMAIN)
        self._context = wire.encode_context(context)
        if type(proof_bytes) is not bytes:
            raise TypeError('proof_bytes must be bytes')
        self._proof = proof_bytes
        self._tick = receipt_tick
        self.evidence = frame(b'TEST_ONLY/publication/v1',
            encode_bytes(self._context) + encode_bytes(proof_bytes) + encode_uint(receipt_tick))

    def validate(self, context: EpochContext, proof_bytes: bytes, evidence: bytes,
                 epoch_validation: EpochValidation) -> PublicationValidation:
        if (wire.encode_context(context) != self._context or type(proof_bytes) is not bytes
                or proof_bytes != self._proof or type(evidence) is not bytes
                or evidence != self.evidence):
            raise EnvironmentValidationError('TEST_ONLY publication exact-byte mismatch')
        epoch_provider = TestOnlyEpochValidator(context)
        expected = epoch_provider.validate(context, epoch_provider.evidence)
        if epoch_validation != expected:
            raise EnvironmentValidationError('TEST_ONLY publication epoch assertion mismatch')
        if self._tick > _deadline_tick(context.deadline):
            raise EnvironmentValidationError('TEST_ONLY simulated receipt after deadline')
        return PublicationValidation(**_context_fields(context), provider_id=self.provider_id,
            time_domain=self.time_domain, evidence_digest=evidence_digest(evidence),
            proof_digest=transcript.proof_digest(proof_bytes), epoch_validation=epoch_validation)


class _TimedAdmissionLedger(AdmissionLedger):
    """Measure the actual SQLite claim interval already inside Verify.other."""
    claim_ns = 0

    def claim(self, key: bytes, proof_digest: bytes) -> bool:
        started = perf_counter_ns()
        try:
            return super().claim(key, proof_digest)
        finally:
            self.claim_ns += perf_counter_ns() - started


def _json_safe(value):
    if isinstance(value, bytes):
        return value.hex()
    if type(value) is int and value.bit_length() > 256:
        return hex(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_safe(v) for v in value]
    return value


def _save(out: Path, relative: str, raw: bytes) -> dict:
    target = out / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(raw)
    return dict(path=relative, bytes=len(raw), sha256=sha256(raw).hexdigest())


def _save_evidence(out: Path, index: int, ctx: EpochContext, raw: bytes,
                   epoch_evidence: bytes, publication_evidence: bytes,
                   registration: dict) -> dict:
    evidence = serialization_evidence(ctx, raw, epoch_evidence=epoch_evidence,
                                      publication_evidence=publication_evidence)
    directory = f'epochs/{index:04d}'
    serialization = evidence['serialization']
    serialization['full_proof'] = _save(out, f'{directory}/proof.bin', raw)
    serialization['registration'] = registration
    for i, part in enumerate(serialization['parts']):
        part['artifact'] = _save(out, f'{directory}/parts/{i:02d}-{part["kind"]}.bin',
                                 bytes.fromhex(part['artifact']['hex']))
    for key, artifact in evidence['auxiliary_artifacts'].items():
        evidence['auxiliary_artifacts'][key] = _save(
            out, f'{directory}/{key.replace("_", "-")}.bin', bytes.fromhex(artifact['hex']))
    return evidence


def _verify_summary(result: protocol.VerifyResult) -> dict:
    return dict(accepted=result.accepted, admitted=result.admitted, reason=result.reason,
                timings_ns=result.timings_ns, protocol_assurance=result.assurance,
                interpreted_assurance='TEST_ONLY_SIMULATED_PROVIDER',
                certify_real_time=False, external_conditions_not_established=True)


def _measured_verify(raw: bytes, ctx: EpochContext, ledger: _TimedAdmissionLedger,
                     evidence: dict) -> tuple[protocol.VerifyResult, int, dict]:
    ledger.claim_ns = 0
    started = perf_counter_ns()
    result = protocol.verify(raw, ctx, ledger=ledger, policy='correctness', **evidence)
    elapsed = perf_counter_ns() - started
    measured = result.timings_ns
    if measured['total'] != sum(v for k, v in measured.items() if k != 'total'):
        raise RuntimeError('internal Verify stages do not partition its total')
    if not 0 <= ledger.claim_ns <= measured['other'] or elapsed < measured['total']:
        raise RuntimeError('Verify measurement intervals are inconsistent')
    stages = {name: measured[name] for name in VERIFY_STAGES if name not in ('other', 'admission')}
    stages['admission'] = ledger.claim_ns
    stages['other'] = measured['other'] - ledger.claim_ns + elapsed - measured['total']
    if sum(stages.values()) != elapsed:
        raise RuntimeError('whole-call Verify stages do not partition elapsed time')
    return result, elapsed, stages


def _sources() -> dict:
    names = ('algebra', 'backend', 'codecs', 'encoding', 'environment', 'file_codec',
             'fold', 'parameters', 'protocol', 'protocol_artifacts', 'protocol_run',
             'protocol_types', 'telemetry', 'transcript', 'wire')
    root = Path(__file__).resolve().parent
    files = {f'damascus_a/{name}.py': sha256((root / f'{name}.py').read_bytes()).hexdigest()
             for name in names}
    digest = sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return dict(source_sha256=digest, source_files_sha256=files)


def _write_csv(out: Path, rows: list[dict]) -> None:
    fields = ['record_id', 'run_id', 'data_kind', 'non_paper', 'publication_eligible',
              'certify_real_time', 'external_conditions_not_established', 'cache',
              'epoch_sequence', 'epoch_id', 'seed_hex', 'file_bytes', 'status', 'accepted',
              'admitted', 'setup_ns', 'prove_ns', 'verify_ns', 'backend_requested',
              'backend_actual', 'backend_fallback', 'backend_reason', 'protocol_hash',
              'parameter_id', 'hardware_id', 'source_sha256', 'rounds_json']
    fields += [name + '_ns' for name in VERIFY_STAGES]
    artifact_names = ('full_proof', 'registration', 'context', 'epoch_evidence', 'publication_evidence')
    fields += [name + suffix for name in artifact_names for suffix in ('_bytes', '_sha256', '_path')]
    with (out / 'protocol-correctness.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            flat = {key: row[key] for key in fields if key in row}
            flat.update({'backend_' + k: v for k, v in row['backend'].items()})
            flat['source_sha256'] = row['provenance']['source_sha256']
            flat['rounds_json'] = json.dumps(row['rounds'], separators=(',', ':'))
            flat.update({name + '_ns': value for name, value in row['stages_ns'].items()})
            artifacts = dict(row['auxiliary_artifacts'],
                             full_proof=row['serialization']['full_proof'],
                             registration=row['serialization']['registration'])
            for name, artifact in artifacts.items():
                flat.update({name + '_' + k: artifact[k] for k in ('bytes', 'sha256', 'path')})
            writer.writerow(flat)


def run_protocol_correctness(output: Path, *, data: bytes = b'\x00\x7f\xff',
        epochs: int = 2, test_seed: int | None = None, backend: str = 'cpu-reference',
        allow_cpu_fallback: bool = False, correctness_only: bool = False) -> dict:
    """Execute 2–4 fresh tiny epochs, save actual artifacts, and test replay.

    The fixed arithmetic profile is deliberately only a correctness case; its
    full adverse audit is retained. An existing output directory is never used.
    Explicit test_seed reproducibly selects test setup/epoch bytes; otherwise
    setup uses the protocol's secrets default and epoch seeds use secrets.
    Saved registration contains the actual public setup needed for replay.
    """
    if correctness_only is not True:
        raise ValueError('explicit correctness_only=True / --correctness-only is required')
    if type(data) is not bytes or len(data) > 3:
        raise ValueError('this correctness runner accepts only 0–3 actual input bytes')
    if type(epochs) is not int or not 2 <= epochs <= 4:
        raise ValueError('this correctness runner accepts only 2–4 fresh epochs')
    if test_seed is not None and type(test_seed) is not int:
        raise TypeError('test_seed must be an explicit integer or None')
    selection = select_backend(backend, allow_cpu_fallback=allow_cpu_fallback)
    out = Path(output)
    out.mkdir(parents=True, exist_ok=False)
    incomplete = out / 'RUN_INCOMPLETE.json'
    incomplete.write_text(json.dumps({'status': 'incomplete', 'disclaimer': _DISCLAIMER}) + '\n')
    run_id = str(uuid4())
    created = datetime.now(timezone.utc).isoformat()
    machine = machine_info(include_gpu=False)
    hardware_id = sha256(json.dumps(machine, sort_keys=True).encode()).hexdigest()
    source = _sources()
    provenance = dict(source, source_id=run_id, captured_at=created, non_paper=True,
        build_description='Python CPU reference source; no compiled accelerator',
        measurement_method='perf_counter_ns whole calls; sequential exclusive Verify intervals',
        hardware_description=json.dumps(machine, sort_keys=True))
    codec = Ternary32Codec()
    pp = ProtocolParameters(FoldParameters(2, 4, 2, (1 << 521) - 1), codec.descriptor)
    rng = None if test_seed is None else random.Random(test_seed)
    setup_started = perf_counter_ns()
    setup = protocol.setup(pp, policy='correctness', randbelow=None if rng is None else rng.randrange)
    registered = protocol.register_bytes(setup, b'TEST_ONLY/file/' + sha256(data).digest(),
                                         data, codec=codec, policy='correctness')
    pp_raw = wire.encode_pp(pp)
    registration_raw = wire.encode_registration(registered.registration)
    setup_once_ns = perf_counter_ns() - setup_started
    setup_artifacts = dict(public_parameters=_save(out, 'public-parameters.bin', pp_raw),
                           registration=_save(out, 'registration.bin', registration_raw))
    input_artifact = _save(out, 'input.bin', data)
    parameter_id = sha256(pp_raw).hexdigest()
    ledger = _TimedAdmissionLedger(out / 'admission.sqlite3')
    rows, seeds, previous_raw = [], set(), None
    for index in range(1, epochs + 1):
        seed = secrets.token_bytes(32) if rng is None else rng.getrandbits(256).to_bytes(32, 'big')
        if seed in seeds:
            raise RuntimeError('unexpected duplicate epoch seed; run is incomplete')
        seeds.add(seed)
        ctx = EpochContext(registered.registration, b'TEST_ONLY/epoch/' + index.to_bytes(4, 'big'),
                           seed, simulated_deadline())
        prove_started = perf_counter_ns()
        produced = protocol.prove_epoch(ctx, registered.witness, policy='correctness')
        prove_ns = perf_counter_ns() - prove_started
        raw = produced.proof_bytes
        epoch_provider = TestOnlyEpochValidator(ctx)
        publication_provider = TestOnlyPublicationValidator(ctx, raw)
        evidence = dict(epoch_validator=epoch_provider, publication_validator=publication_provider,
                        epoch_evidence=epoch_provider.evidence, publication_evidence=publication_provider.evidence)
        verified, verify_ns, stages = _measured_verify(raw, ctx, ledger, evidence)
        if not verified.accepted or not verified.admitted:
            raise RuntimeError('primary correctness verification failed: ' + verified.reason)
        historical = protocol.verify_published(raw, ctx, policy='correctness', **evidence)
        replay = protocol.verify(raw, ctx, ledger=ledger, policy='correctness', **evidence)
        diagnostics = dict(historical_verification=_verify_summary(historical),
                           same_epoch_replay=_verify_summary(replay))
        if not historical.accepted or replay.accepted or replay.reason != 'replayed_epoch':
            raise RuntimeError('historical verification / replay correctness check failed')
        if previous_raw is not None:
            previous = protocol.verify(previous_raw, ctx, ledger=ledger, policy='correctness', **evidence)
            diagnostics['previous_epoch_proof'] = _verify_summary(previous)
            if previous.accepted or previous.reason != 'malformed_or_wrong_context_proof':
                raise RuntimeError('old proof was not rejected under the fresh epoch context')
        artifacts = _save_evidence(out, index, ctx, raw, epoch_provider.evidence,
                                    publication_provider.evidence, setup_artifacts['registration'])
        rows.append(dict(schema='DF-protocol-correctness-epoch-v1', record_id=f'{run_id}/{index}',
            run_id=run_id, data_kind='correctness_test', non_paper=True, publication_eligible=False,
            certify_real_time=False, external_conditions_not_established=True,
            scheme='DamascusFold', scheme_version='DF-wire-v1', profile='correctness-only-unsafe',
            protocol_hash=_PAPER_SHA256, parameter_id=parameter_id, hardware_id=hardware_id,
            backend=asdict(selection), cache='uncontrolled', epoch_sequence=index,
            epoch_id=ctx.epoch.hex(), seed_hex=seed.hex(), deadline_hex=ctx.deadline.hex(),
            registration_id=transcript.registration_digest(registered.registration).hex(),
            context_id=transcript.context_digest(ctx).hex(), proof_id=transcript.proof_digest(raw).hex(),
            repetition=0, status='ok', file_bytes=len(data), accepted=True, admitted=True,
            setup_ns=setup_once_ns if index == 1 else 0, prove_ns=prove_ns, verify_ns=verify_ns,
            internal_prove_ns=produced.total_ns, internal_verify_total_ns=verified.timings_ns['total'],
            stages_ns=stages, rounds=[asdict(r) for r in produced.rounds],
            verification=_verify_summary(verified), diagnostics=diagnostics,
            provenance=provenance, **artifacts))
        previous_raw = raw
    total = setup_once_ns + sum(r['prove_ns'] + r['verify_ns'] for r in rows)
    report = _json_safe(dict(schema='DF-protocol-correctness-run-v1', run_id=run_id,
        created_at=created, disclaimer=_DISCLAIMER, data_kind='correctness_test', non_paper=True,
        formal_measurement=False, publication_eligible=False, production_ready=False,
        security_established=False, certify_real_time=False, external_conditions_not_established=True,
        cache='uncontrolled', backend=asdict(selection), hardware=machine, hardware_id=hardware_id,
        provenance=provenance, parameter_id=parameter_id, parameters=asdict(pp.arithmetic),
        parameter_audit=asdict(setup.parameter_report), protocol_hash=_PAPER_SHA256,
        codec_descriptor_hex=codec.descriptor.hex(), suite_hex=pp.suite.hex(), file_bytes=len(data),
        randomness=dict(setup_source=setup.randomness_source, test_seed=test_seed,
            epoch_seed_source='system_secrets' if rng is None else 'explicit_test_seed_PRNG',
            external_seed_distribution_established=False),
        evidence_provider=dict(kind='TEST_ONLY_SIMULATED_PROVIDER',
            epoch_provider_id=epoch_provider.provider_id.hex(),
            publication_provider_id=publication_provider.provider_id.hex(),
            time_domain_hex=_TIME_DOMAIN.hex(), receipt_tick=90, deadline_tick=100,
            deadline_boundary='inclusive simulated ticks only', real_authority=False),
        input=input_artifact, setup_artifacts=setup_artifacts, setup_once_ns=setup_once_ns,
        timing_scope=dict(setup='setup + original file registration + canonical pp/registration serialization; excludes disk I/O',
            prove='entire prove_epoch call; each epoch starts from the original registered witness',
            verify='entire verify call including evidence validation, final opening and SQLite admission',
            admission='actual SQLite claim duration split from internal other; key/digest work remains in other',
            other='remaining exclusive Verify work plus call/return overhead',
            diagnostics='historical verification and replay checks are separate; excluded from fresh epoch cost',
            infrastructure='initial ledger database creation is outside setup_once and fresh epoch cost; individual claims are inside Verify',
            collection='uncontrolled cache, one primary observation per new epoch, no performance inference'),
        fresh_epoch_cost=dict(total_ns=total, count=epochs, average_ns=total / epochs,
            formula='(setup_once_ns + sum(prove_ns + verify_ns for each NEW epoch)) / count',
            includes=['setup and registration once', 'fresh prove', 'complete verify and admission'],
            excludes=['disk artifact writes', 'initial ledger database creation',
                      'test evidence construction', 'historical/replay diagnostics'],
            meaning='correctness-run accounting only; not A3 paper data'),
        resources=dict(peak_rss_bytes=peak_rss_bytes(),
            rss_scope='entire Python process lifetime high-water mark, not isolated per operation',
            peak_vram_bytes=None, vram_status='not_measured_cpu_reference'),
        replay=dict(input='input.bin', context='epochs/NNNN/context.bin', proof='epochs/NNNN/proof.bin',
            public_setup='registration.bin contains the actual sampled public generators',
            instruction='decode context; encode input with Ternary32Codec; prove_epoch(policy=correctness); compare exact saved proof bytes',
            admission='existing admission.sqlite3 must reject re-admission; historical verification is repeatable'),
        epochs=rows))
    with (out / 'protocol-correctness.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    with (out / 'epochs.jsonl').open('x') as stream:
        for row in report['epochs']:
            stream.write(json.dumps(row, sort_keys=True) + '\n')
    _write_csv(out, report['epochs'])
    incomplete.unlink()
    return report


def protocol_correctness(args) -> dict:
    """CLI adapter; parser ownership stays with damascus_a.cli."""
    data = bytes.fromhex(getattr(args, 'input_hex', '007fff'))
    report = run_protocol_correctness(Path(args.output), data=data, epochs=args.epochs,
        test_seed=args.test_seed, backend=args.backend, allow_cpu_fallback=args.allow_cpu_fallback,
        correctness_only=args.correctness_only)
    print(json.dumps(dict(output=str(args.output), accepted_epochs=len(report['epochs']),
        data_kind='correctness_test', cache='uncontrolled', non_paper=True,
        certify_real_time=False, external_conditions_not_established=True,
        parameter_status=report['parameter_audit']['status'])))
    return report
