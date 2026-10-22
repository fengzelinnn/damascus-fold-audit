"""External certification interfaces and persistent epoch admission.

Frozen main.tex lines 448, 612 and 1216 require authenticated context, ordering
and deadlines. Their certificate/evidence formats and time domains are external.
Configured adapters must validate those real artifacts; this module supplies no
issuer, clock, permissive adapter, or evidence that signing establishes freshness.
The cutoff information boundary and conditional seed distribution remain external
assumptions (lines 1216-1237), even when every binding check succeeds.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from abc import ABC, abstractmethod
from contextlib import closing
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .protocol_types import WireLimits

if TYPE_CHECKING:
    from .protocol_types import EpochContext


class EnvironmentValidationError(ValueError):
    """External evidence was rejected or did not bind the requested objects."""


def _bytes(value: bytes, name: str, *, digest: bool = False) -> None:
    if type(value) is not bytes:
        raise TypeError(f'{name} must be immutable bytes')
    if not value or (digest and len(value) != 32):
        raise EnvironmentValidationError(f'{name} must be ' +
                                         ('32 bytes' if digest else 'nonempty'))


def evidence_digest(raw: bytes) -> bytes:
    """Identify exact opaque evidence; hashing it does not authenticate it."""
    if type(raw) is not bytes:
        raise TypeError('evidence must be immutable bytes')
    return hashlib.sha256(b'DF/evidence-id/v1\0' + len(raw).to_bytes(8, 'big') + raw).digest()


@dataclass(frozen=True, slots=True)
class EpochValidation:
    """Adapter assertion bound to exact context/evidence, not a security proof.

    Provider and time-domain identifiers must come from configured trust policy.
    Deadline bytes have no built-in units or comparison convention.
    """
    context_digest: bytes
    registration_digest: bytes
    epoch: bytes
    deadline: bytes
    provider_id: bytes
    time_domain: bytes
    evidence_digest: bytes

    def __post_init__(self) -> None:
        for name in ('context_digest', 'registration_digest', 'evidence_digest'):
            _bytes(getattr(self, name), name, digest=True)
        for name in ('epoch', 'deadline', 'provider_id', 'time_domain'):
            _bytes(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class PublicationValidation(EpochValidation):
    """Complete-proof receipt assertion with the exact epoch assertion attached."""
    proof_digest: bytes
    epoch_validation: EpochValidation

    def __post_init__(self) -> None:
        EpochValidation.__post_init__(self)
        _bytes(self.proof_digest, 'proof_digest', digest=True)
        if type(self.epoch_validation) is not EpochValidation:
            raise EnvironmentValidationError('publication requires an EpochValidation')
        EpochValidation.__post_init__(self.epoch_validation)
        for name in ('context_digest', 'registration_digest', 'epoch', 'deadline', 'time_domain'):
            if getattr(self, name) != getattr(self.epoch_validation, name):
                raise EnvironmentValidationError(f'publication/epoch mismatch: {name}')


class _ConfiguredValidator(ABC):
    def __init__(self, provider_id: bytes, time_domain: bytes) -> None:
        _bytes(provider_id, 'provider_id')
        _bytes(time_domain, 'time_domain')
        self._provider_id = provider_id
        self._time_domain = time_domain

    @property
    def provider_id(self) -> bytes:
        return self._provider_id

    @property
    def time_domain(self) -> bytes:
        return self._time_domain


class EpochContextValidator(_ConfiguredValidator):
    """Configured external authority; no accepting implementation is provided.

    Implementations authenticate the complete context, registration and epoch,
    and evidence that registration/identifier/deadline were fixed before seed
    release. They enforce their trust/finality policy. Certificate validity alone
    cannot establish conditional-uniform randomness or the cutoff information
    boundary. Reject unusable evidence with EnvironmentValidationError.
    """
    @abstractmethod
    def validate(self, context: EpochContext, evidence: bytes) -> EpochValidation:
        raise NotImplementedError


class PublicationEvidenceValidator(_ConfiguredValidator):
    """Authenticate complete-proof publication/order and timely receipt.

    Implementations bind the exact serialized proof INCLUDING its integer final
    opening, enforce ordering and the authenticated deadline in their declared
    domain/boundary semantics, and bind the supplied epoch validation. They may
    have a different provider identifier from the epoch certifier, but must use
    the same time domain. Prover timestamps and the verifier's present wall clock
    cannot substitute for authenticated historical receipt.
    """
    @abstractmethod
    def validate(self, context: EpochContext, proof_bytes: bytes, evidence: bytes,
                 epoch_validation: EpochValidation) -> PublicationValidation:
        raise NotImplementedError


def _context_bindings(context: EpochContext, *,
                      limits: WireLimits = WireLimits()) -> dict[str, bytes]:
    from .transcript import context_digest, registration_digest
    return dict(context_digest=context_digest(context, limits=limits),
                registration_digest=registration_digest(context.registration, limits=limits),
                epoch=context.epoch, deadline=context.deadline)


def _provider_bindings(validator: _ConfiguredValidator, required: type) -> dict[str, bytes]:
    if not isinstance(validator, required):
        raise EnvironmentValidationError(f'a configured {required.__name__} is required')
    provider_id, time_domain = validator.provider_id, validator.time_domain
    _bytes(provider_id, 'provider_id')
    _bytes(time_domain, 'time_domain')
    return dict(provider_id=provider_id, time_domain=time_domain)


def _check_fields(result: EpochValidation, expected: dict[str, bytes]) -> None:
    for name, value in expected.items():
        if getattr(result, name) != value:
            raise EnvironmentValidationError(f'adapter result binding mismatch: {name}')


def checked_epoch_validation(validator: EpochContextValidator, context: EpochContext,
                             evidence: bytes, *,
                             limits: WireLimits = WireLimits()) -> EpochValidation:
    """Invoke the configured adapter and independently check all return bindings.

    The adapter is the external trust boundary, not an untrusted callback chosen
    by the prover. Exact binding checks prevent accidental result substitution;
    they cannot make a dishonest accepting adapter into an authentic certifier.
    The caller supplies the same limits used to validate its context. Configured
    providers retain their own evidence/context limits; these do not change the
    canonical bytes, digest domains, or the abstract adapter signature.
    """
    _bytes(evidence, 'epoch evidence')
    expected = _context_bindings(context, limits=limits)
    expected.update(_provider_bindings(validator, EpochContextValidator))
    expected['evidence_digest'] = evidence_digest(evidence)
    result = validator.validate(context, evidence)
    if type(result) is not EpochValidation:
        raise EnvironmentValidationError('epoch adapter must return EpochValidation')
    EpochValidation.__post_init__(result)
    _check_fields(result, expected)
    return result


def checked_publication_validation(validator: PublicationEvidenceValidator,
                                   context: EpochContext, proof_bytes: bytes,
                                   evidence: bytes,
                                   epoch_validation: EpochValidation, *,
                                   limits: WireLimits = WireLimits()) -> PublicationValidation:
    """Check receipt bindings after checked_epoch_validation has succeeded.

    The protocol must pass that already-validated result, not a prover-supplied
    EpochValidation object. This function does not claim an epoch or parse a proof;
    full algebra/wire verification and atomic admission belong to the caller.
    Pass the same limits used for context validation and checked_epoch_validation;
    the configured provider independently applies its declared resource policy.
    """
    from .transcript import proof_digest
    _bytes(proof_bytes, 'proof_bytes')
    _bytes(evidence, 'publication evidence')
    expected = _context_bindings(context, limits=limits)
    if type(epoch_validation) is not EpochValidation:
        raise EnvironmentValidationError('a checked EpochValidation is required')
    EpochValidation.__post_init__(epoch_validation)
    _check_fields(epoch_validation, expected)
    expected.update(_provider_bindings(validator, PublicationEvidenceValidator))
    if expected['time_domain'] != epoch_validation.time_domain:
        raise EnvironmentValidationError('epoch and publication time domains differ')
    expected['evidence_digest'] = evidence_digest(evidence)
    expected['proof_digest'] = proof_digest(proof_bytes)
    result = validator.validate(context, proof_bytes, evidence, epoch_validation)
    if type(result) is not PublicationValidation:
        raise EnvironmentValidationError('publication adapter must return PublicationValidation')
    PublicationValidation.__post_init__(result)
    _check_fields(result, expected)
    if result.epoch_validation != epoch_validation:
        raise EnvironmentValidationError('publication binds different epoch evidence')
    return result


class AdmissionLedger:
    """SQLite uniqueness ledger, separate from repeatable public verification.

    Call claim ONLY after complete successful protocol/evidence verification.
    This storage primitive cannot determine whether a digest names a valid proof.
    Failed verification must never call claim. One unique key binds registration
    and epoch; changing seed/deadline/proof does not create another admission.
    Each operation has its own SQLite connection and commits atomically, allowing
    independent processes/instances to share one persistent database.
    """
    def __init__(self, path: str | os.PathLike[str]) -> None:
        supplied_path = os.fspath(path)
        if not isinstance(supplied_path, str):
            raise TypeError('ledger path must be text')
        if not supplied_path or supplied_path == ':memory:':
            raise ValueError('ledger requires a persistent filesystem path')
        self._path = os.path.abspath(supplied_path)
        with closing(sqlite3.connect(self._path, timeout=30)) as connection:
            with connection:
                connection.execute('''CREATE TABLE IF NOT EXISTS damascus_admissions_v1 (
                    epoch_key BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(epoch_key) = 'blob' AND length(epoch_key) > 0),
                    proof_digest BLOB NOT NULL
                        CHECK(typeof(proof_digest) = 'blob' AND length(proof_digest) = 32)
                    ) WITHOUT ROWID''')

    def claim(self, key: bytes, proof_digest: bytes) -> bool:
        """Commit first admission; return False for every subsequent claim.

        This is not idempotent success: retrying even the same proof returns False.
        SQLite/storage failures propagate instead of being treated as admission.
        """
        _bytes(key, 'admission key')
        _bytes(proof_digest, 'proof_digest', digest=True)
        with closing(sqlite3.connect(self._path, timeout=30)) as connection:
            with connection:
                cursor = connection.execute(
                    'INSERT INTO damascus_admissions_v1 (epoch_key, proof_digest) '
                    'VALUES (?, ?) ON CONFLICT(epoch_key) DO NOTHING', (key, proof_digest))
                return cursor.rowcount == 1
