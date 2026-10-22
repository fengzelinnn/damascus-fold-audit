"""Complete frozen-paper execution with explicit codecs and external evidence.

All entry points default to strict policy, which currently fails closed: there
is no approved concrete security profile. Explicit ``policy='correctness'``
executes the unchanged equations and retains the full adverse parameter audit.
It never certifies security or produces formal performance evidence.

The raw-byte codec is explicit; authenticated epoch/publication authorities are
mandatory external dependencies. Historical verification is repeatable; admission is a
separate operation requiring an atomic persistent ledger.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import secrets
from time import perf_counter_ns
from typing import Callable

from . import fold, transcript, wire
from .algebra import Generators, Ring, Witness, require_integer
from .codecs import FileCodec, checked_decode, checked_encode
from .environment import (AdmissionLedger, EpochContextValidator, EpochValidation,
    EnvironmentValidationError, PublicationEvidenceValidator, PublicationValidation,
    checked_epoch_validation, checked_publication_validation)
from .parameters import ParameterValidation, validate_current_parameters
from .protocol_types import (EpochContext, EpochProof, ProtocolParameters, Registration,
                             WireLimits)

DEFAULT_LIMITS = WireLimits()
_STAGES = ('parsing_context', 'challenges', 'generator_replay',
           'commitment_parity', 'norm', 'opening')


class ParameterPolicyError(ValueError):
    def __init__(self, report: ParameterValidation):
        super().__init__('no approved parameter security profile; strict policy rejects')
        self.parameter_report = report


@dataclass(frozen=True, slots=True)
class SetupResult:
    pp: ProtocolParameters
    generators: Generators
    parameter_report: ParameterValidation
    policy: str
    randomness_source: str
    secure_profile: bool = False


@dataclass(frozen=True, slots=True)
class RegisteredFile:
    registration: Registration
    witness: Witness
    parameter_report: ParameterValidation
    policy: str
    secure_profile: bool = False


@dataclass(frozen=True, slots=True)
class RoundTrace:
    index: int
    x: int
    y: int
    duration_ns: int


@dataclass(frozen=True, slots=True)
class ProveResult:
    proof: EpochProof
    proof_bytes: bytes
    parameter_report: ParameterValidation
    rounds: tuple[RoundTrace, ...]
    total_ns: int
    policy: str
    secure_profile: bool = False


@dataclass(frozen=True, slots=True)
class VerifyResult:
    accepted: bool
    reason: str
    timings_ns: dict[str, int]
    parameter_report: ParameterValidation | None
    policy: str
    assurance: str
    epoch_validation: EpochValidation | None = None
    publication_validation: PublicationValidation | None = None
    admitted: bool = False
    secure_profile: bool = False


def _audit(pp: ProtocolParameters, limits: WireLimits) -> ParameterValidation:
    # This performs finite dimension/byte checks BEFORE any setup allocation.
    wire.encode_pp(pp, limits=limits)
    if pp.suite != transcript.SUPPORTED_SUITE:
        raise ValueError('unsupported Fiat--Shamir suite')
    p = pp.arithmetic
    return validate_current_parameters(d=p.d, T=p.T, k=p.k, q=p.q)


def _policy(policy: str, report: ParameterValidation) -> None:
    if policy not in ('strict', 'correctness'):
        raise ValueError("policy must be 'strict' or explicit 'correctness'")
    if policy == 'strict':
        # There is deliberately no caller boolean or pretend approval registry.
        raise ParameterPolicyError(report)


def setup(pp: ProtocolParameters, *, policy: str = 'strict',
          limits: WireLimits = DEFAULT_LIMITS,
          randbelow: Callable[[int], int] | None = None) -> SetupResult:
    """Sample each of k*M generator coefficients independently using randbelow.

    The default uses secrets.randbelow(q). Injecting a sampler is explicit test
    instrumentation and cannot establish the required distribution.
    """
    report = _audit(pp, limits)
    _policy(policy, report)
    sampler = secrets.randbelow if randbelow is None else randbelow
    if not callable(sampler):
        raise TypeError('randbelow must be callable')
    p = pp.arithmetic
    ring = Ring(p.q, 1 << p.d)  # _audit bounded d, n, k*M and coefficient bytes.
    def coefficient():
        value = sampler(p.q)
        require_integer(value, 'sampled generator coefficient')
        if not 0 <= value < p.q:
            raise ValueError('sampled generator coefficient outside [0,q)')
        return value
    generators = tuple(tuple(ring.element(tuple(coefficient() for _ in range(ring.n)))
                             for _ in range(p.k)) for _ in range(ring.n))
    return SetupResult(pp, generators, report, policy,
                       'system_secrets' if randbelow is None else 'injected_test_sampler')


def _registration_preflight(setup_result: SetupResult, file_id: bytes,
                            file_length: int, policy: str,
                            limits: WireLimits) -> ParameterValidation:
    if not isinstance(setup_result, SetupResult):
        raise TypeError('setup_result must be SetupResult')
    report = _audit(setup_result.pp, limits)
    _policy(policy, report)
    if type(file_id) is not bytes or not file_id or len(file_id) > limits.max_metadata_bytes:
        raise ValueError('file_id must be nonempty bytes within metadata limit')
    require_integer(file_length, 'file_length')
    if not 0 <= file_length <= limits.max_file_length:
        raise ValueError('file_length outside configured resource limit')
    return report


def register_encoded(setup_result: SetupResult, file_id: bytes, file_length: int,
                     witness: Witness, *, codec: FileCodec, policy: str = 'strict',
                     limits: WireLimits = DEFAULT_LIMITS) -> RegisteredFile:
    """Register only a canonical encoded file under the explicit matching codec."""
    report = _registration_preflight(setup_result, file_id, file_length, policy, limits)
    pp = setup_result.pp
    checked_decode(codec, pp.codec, witness, file_length, pp.arithmetic)
    state = fold.initialize(pp.arithmetic, witness, setup_result.generators)
    registration = Registration(pp, file_id, file_length, state.public)
    wire.encode_registration(registration, limits=limits)
    return RegisteredFile(registration, witness, report, policy)


def register_bytes(setup_result: SetupResult, file_id: bytes, data: bytes, *,
                   codec: FileCodec, policy: str = 'strict',
                   limits: WireLimits = DEFAULT_LIMITS) -> RegisteredFile:
    if type(data) is not bytes:
        raise TypeError('file data must be bytes')
    _registration_preflight(setup_result, file_id, len(data), policy, limits)
    witness = checked_encode(codec, setup_result.pp.codec, data, setup_result.pp.arithmetic)
    return register_encoded(setup_result, file_id, len(data), witness, codec=codec,
                            policy=policy, limits=limits)


def _initial_state(context: EpochContext, witness: Witness,
                   limits: WireLimits) -> fold.WitnessState:
    wire.encode_context(context, limits=limits)
    reg = context.registration
    state = fold.initialize(reg.pp.arithmetic, witness, reg.initial.generators)
    if state.public != reg.initial:
        raise ValueError('original witness does not open the registered initial commitment')
    return state


def epoch_init(context: EpochContext, witness: Witness, *, policy: str = 'strict',
               limits: WireLimits = DEFAULT_LIMITS) -> fold.WitnessState:
    """Reset to the ORIGINAL registration, never a preceding terminal state."""
    if not isinstance(context, EpochContext):
        raise TypeError('context must be EpochContext')
    report = _audit(context.registration.pp, limits)
    _policy(policy, report)
    return _initial_state(context, witness, limits)


def prove_epoch(context: EpochContext, witness: Witness, *, policy: str = 'strict',
                limits: WireLimits = DEFAULT_LIMITS) -> ProveResult:
    """Derive each challenge after its specified cross-terms and full prefix."""
    start = perf_counter_ns()
    if not isinstance(context, EpochContext):
        raise TypeError('context must be EpochContext')
    report = _audit(context.registration.pp, limits)
    _policy(policy, report)
    state = _initial_state(context, witness, limits)
    prefix, rounds = (), []
    for j in range(context.registration.pp.arithmetic.d):
        round_start = perf_counter_ns()
        L_vec, R_vec = fold.vector_cross_terms(state)
        x = transcript.vector_challenge(context, prefix, j, L_vec, R_vec, limits=limits)
        vector = fold.vector_prove(state, x, L_vec, R_vec)
        L_poly, R_poly = fold.polynomial_cross_terms(vector)
        fold.parity_validate(vector.public, L_poly, R_poly)
        record = fold.RoundRecord(L_vec, R_vec, L_poly, R_poly)
        y = transcript.polynomial_challenge(context, prefix, j, record, limits=limits)
        state = fold.polynomial_prove(vector, y, L_poly, R_poly)
        prefix = prefix + (record,)
        rounds.append(RoundTrace(j, x, y, perf_counter_ns() - round_start))
    opening = fold.final_open(state)
    proof = EpochProof(transcript.context_digest(context, limits=limits), prefix, opening)
    proof_bytes = wire.encode_proof(proof, context, limits=limits)
    return ProveResult(proof, proof_bytes, report, tuple(rounds),
                       perf_counter_ns() - start, policy)


class _Rejected(Exception):
    pass


class _Timings:
    def __init__(self):
        self.started = perf_counter_ns()
        self.stages = {name: 0 for name in _STAGES}

    @contextmanager
    def measure(self, name):
        start = perf_counter_ns()
        try:
            yield
        finally:
            self.stages[name] += perf_counter_ns() - start

    def finish(self):
        total = perf_counter_ns() - self.started
        # Measurements are sequential, exclusive intervals, never nested.
        return dict(self.stages, other=total - sum(self.stages.values()), total=total)


def _verify(raw: bytes, context: EpochContext, *, policy: str,
            limits: WireLimits, epoch_validator, publication_validator,
            epoch_evidence, publication_evidence, ledger, admission: bool) -> VerifyResult:
    timings = _Timings()
    report = epoch_validation = publication_validation = None
    accepted = admitted = False
    reason = 'invalid_input'
    try:
        with timings.measure('parsing_context'):
            if not isinstance(context, EpochContext):
                raise _Rejected('invalid_context')
            report = _audit(context.registration.pp, limits)
            _policy(policy, report)
            if admission and not isinstance(ledger, AdmissionLedger):
                raise _Rejected('admission_ledger_required')
            try:
                proof = wire.decode_proof(raw, context, limits=limits)
            except (TypeError, ValueError) as error:
                raise _Rejected('malformed_or_wrong_context_proof') from error
            try:
                epoch_validation = checked_epoch_validation(epoch_validator, context, epoch_evidence,
                                                            limits=limits)
                publication_validation = checked_publication_validation(
                    publication_validator, context, raw, publication_evidence, epoch_validation,
                    limits=limits)
            except (EnvironmentValidationError, TypeError, ValueError) as error:
                raise _Rejected('external_evidence_rejected') from error
        state = context.registration.initial
        prefix = ()
        for j, record in enumerate(proof.records):
            with timings.measure('challenges'):
                x = transcript.vector_challenge(context, prefix, j, record.L_vec, record.R_vec,
                                                limits=limits)
            with timings.measure('generator_replay'):
                generators = fold.vector_generators(state, x)
            with timings.measure('commitment_parity'):
                commitment = fold.vector_commitment(state, record.L_vec, record.R_vec, x)
            vector = fold.VectorPublicState(state.parameters, state.level, generators, commitment)
            with timings.measure('commitment_parity'):
                try:
                    fold.parity_validate(vector, record.L_poly, record.R_poly)
                except ValueError as error:
                    raise _Rejected('parity_failed') from error
            # The odd-component check must precede the polynomial oracle query.
            with timings.measure('challenges'):
                y = transcript.polynomial_challenge(context, prefix, j, record, limits=limits)
            with timings.measure('generator_replay'):
                generators = fold.polynomial_generators(vector, y)
            with timings.measure('commitment_parity'):
                commitment = fold.polynomial_commitment(vector, record.L_poly, record.R_poly, y)
            state = fold.PublicState(state.parameters, state.level + 1, generators, commitment)
            prefix = prefix + (record,)
        with timings.measure('norm'):
            # Use the transmitted signed integer, before ANY modular operation.
            # Core's exact bit-bound comparator avoids enormous honest powers.
            if not fold._within_honest_bound(proof.opening, state.parameters, state.parameters.d):
                raise _Rejected('opening_norm_failed')
        with timings.measure('opening'):
            if state.level != state.parameters.d or len(state.generators) != 1 or state.ring.n != 1:
                raise _Rejected('not_terminal')
            if any(c != g.scale(proof.opening)
                   for c, g in zip(state.commitment, state.generators[0])):
                raise _Rejected('opening_relation_failed')
        if admission:
            # This commit is AFTER every proof and external-evidence check.
            # Its full duration belongs to other and the enclosing actual total.
            if not ledger.claim(transcript.admission_key(context, limits=limits), transcript.proof_digest(raw)):
                raise _Rejected('replayed_epoch')
            admitted = True
        accepted = True
        reason = 'accepted_correctness_only'
    except ParameterPolicyError:
        reason = 'parameter_policy_not_approved'
    except _Rejected as error:
        reason = str(error)
    except Exception as error:
        # Unexpected provider/storage/type failures fail closed, never admit.
        reason = 'verification_error:' + type(error).__name__
    assurance = ('externally_validated_unreviewed' if publication_validation is not None
                 else 'not_established')
    return VerifyResult(accepted, reason, timings.finish(), report, policy, assurance,
                        epoch_validation, publication_validation, admitted)


def verify_published(raw: bytes, context: EpochContext, *,
                     epoch_validator: EpochContextValidator | None = None,
                     publication_validator: PublicationEvidenceValidator | None = None,
                     epoch_evidence: bytes | None = None,
                     publication_evidence: bytes | None = None,
                     policy: str = 'strict', limits: WireLimits = DEFAULT_LIMITS) -> VerifyResult:
    """Repeatable historical verification; does not consume an admission slot."""
    return _verify(raw, context, policy=policy, limits=limits,
                   epoch_validator=epoch_validator, publication_validator=publication_validator,
                   epoch_evidence=epoch_evidence, publication_evidence=publication_evidence,
                   ledger=None, admission=False)


def verify(raw: bytes, context: EpochContext, *, ledger: AdmissionLedger,
           epoch_validator: EpochContextValidator | None = None,
           publication_validator: PublicationEvidenceValidator | None = None,
           epoch_evidence: bytes | None = None, publication_evidence: bytes | None = None,
           policy: str = 'strict', limits: WireLimits = DEFAULT_LIMITS) -> VerifyResult:
    """Validate and atomically admit once; a persistent ledger is mandatory."""
    return _verify(raw, context, policy=policy, limits=limits,
                   epoch_validator=epoch_validator, publication_validator=publication_validator,
                   epoch_evidence=epoch_evidence, publication_evidence=publication_evidence,
                   ledger=ledger, admission=True)
