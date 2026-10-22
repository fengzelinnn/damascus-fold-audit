"""Canonical full-transcript Fiat--Shamir inputs for the frozen-paper protocol.

The SHAKE256 input is a versioned frame containing, in this exact order: the
complete canonical context, ``vec``/``poly`` domain, round index, complete
indexed preceding records, and the current vector pair (plus the polynomial
pair in the polynomial domain). Neither context nor prefix is replaced by a
digest. The suite identifier is bound inside the context's public parameters.

Identifier hashes are separate SHA-256 domains. They identify bytes; they do
not certify an epoch, enforce a deadline, or establish parameter security.
"""
from __future__ import annotations

import hashlib

from .algebra import Module, Ring, require_integer, require_tuple, validate_module
from .encoding import encode_bytes, encode_uint
from .fold import RoundRecord
from .protocol_types import EpochContext, Registration, WireLimits
from .wire import (DEFAULT_LIMITS, context_binding, encode_context, encode_module,
                   encode_registration, encode_round_record)


SUPPORTED_SUITE = b"DF-SHAKE256-v1"
_FS_DOMAIN = b"DF/FS/v1"
_REGISTRATION_DOMAIN = b"DF/registration-id/v1"
_PROOF_DOMAIN = b"DF/proof-id/v1"
_ADMISSION_DOMAIN = b"DF/admission-id/v1"
_UINT32_MAX = 0xffffffff


def _blob(raw: bytes) -> bytes:
    # Individual wire objects already obey finite WireLimits. Their complete
    # concatenation must not inherit encoding.frame's smaller 8-MiB default.
    return encode_bytes(raw, max_bytes=_UINT32_MAX)


def _frame(domain: bytes, payload: bytes) -> bytes:
    return encode_bytes(domain, max_bytes=32) + _blob(payload)


def _prefix_input(ctx: EpochContext, prefix: tuple[RoundRecord, ...], j: int,
                  limits: WireLimits) -> tuple[bytes, bytes, Ring]:
    if not isinstance(ctx, EpochContext):
        raise TypeError("context must be an EpochContext")
    require_integer(j, "round index")
    require_tuple(prefix, "record prefix")
    # The canonical context encoder validates pp, the complete registration,
    # metadata and the initial state's dimensions before their use below.
    context_raw = encode_context(ctx, limits=limits)
    pp = ctx.registration.pp
    if pp.suite != SUPPORTED_SUITE:
        raise ValueError("unsupported Fiat--Shamir suite")
    if not 0 <= j < pp.arithmetic.d:
        raise ValueError("round index must be in 0..d-1")
    if len(prefix) != j:
        raise ValueError("record prefix length must equal the round index")
    # Each wire record includes its original index and is validated against
    # that level's full modulus, polynomial degrees and module rank.
    prefix_raw = encode_uint(len(prefix)) + b"".join(
        _blob(encode_round_record(previous, index, pp, limits=limits))
        for index, previous in enumerate(prefix)
    )
    ring = Ring(pp.arithmetic.q, ctx.registration.initial.ring.n >> j)
    return context_raw, prefix_raw, ring


def _oracle_input(context_raw: bytes, prefix_raw: bytes, j: int, domain: bytes,
                  modules: tuple[Module, ...], limits: WireLimits) -> bytes:
    payload = _blob(context_raw) + _blob(domain) + encode_uint(j) + prefix_raw
    payload += b"".join(_blob(encode_module(module, limits=limits)) for module in modules)
    return _frame(_FS_DOMAIN, payload)


def vector_oracle_input(ctx: EpochContext, prefix: tuple[RoundRecord, ...], j: int,
                        L: Module, R: Module, *, limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    """Expose the actual canonical vector-oracle preimage for independent tests."""
    context_raw, prefix_raw, ring = _prefix_input(ctx, prefix, j, limits)
    rank = ctx.registration.pp.arithmetic.k
    validate_module(L, ring, rank, "L_vec")
    validate_module(R, ring, rank, "R_vec")
    return _oracle_input(context_raw, prefix_raw, j, b"vec", (L, R), limits)


def polynomial_oracle_input(ctx: EpochContext, prefix: tuple[RoundRecord, ...],
                            j: int, record: RoundRecord, *,
                            limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    """Expose the polynomial preimage, including both current cross-term pairs."""
    context_raw, prefix_raw, _ = _prefix_input(ctx, prefix, j, limits)
    # Validate all four current modules at exactly this indexed level before
    # accessing them; the current index is already carried by the FS input.
    encode_round_record(record, j, ctx.registration.pp, limits=limits)
    return _oracle_input(context_raw, prefix_raw, j, b"poly",
                         (record.L_vec, record.R_vec, record.L_poly, record.R_poly), limits)


def _sample(preimage: bytes, T: int) -> int:
    """Map the first log2(T) SHAKE bits bijectively to 1..T, without bias."""
    require_integer(T, "challenge-set size")
    if T < 4 or T & (T - 1):
        raise ValueError("challenge-set size must be a power of two >= 4")
    bits = T.bit_length() - 1
    width = (bits + 7) // 8
    stream = hashlib.shake_256(preimage).digest(width)
    # Bytes use network bit order. Discard only trailing padding bits, never
    # truncate to a fixed 256-bit digest when a legal T requires more bits.
    return (int.from_bytes(stream, "big") >> (width * 8 - bits)) + 1


def vector_challenge(ctx: EpochContext, prefix: tuple[RoundRecord, ...], j: int,
                     L: Module, R: Module, *, limits: WireLimits = DEFAULT_LIMITS) -> int:
    return _sample(vector_oracle_input(ctx, prefix, j, L, R, limits=limits),
                   ctx.registration.pp.arithmetic.T)


def polynomial_challenge(ctx: EpochContext, prefix: tuple[RoundRecord, ...],
                         j: int, record: RoundRecord, *,
                         limits: WireLimits = DEFAULT_LIMITS) -> int:
    return _sample(polynomial_oracle_input(ctx, prefix, j, record, limits=limits),
                   ctx.registration.pp.arithmetic.T)


def context_digest(ctx: EpochContext, *, limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    """Return the single authoritative wire context binding (32 bytes)."""
    return context_binding(ctx, limits=limits)


def registration_digest(reg: Registration, *, limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    """Identify the complete canonical registration, including pp and generators."""
    return hashlib.sha256(_frame(_REGISTRATION_DOMAIN, encode_registration(reg, limits=limits))).digest()


def proof_digest(raw: bytes) -> bytes:
    """Identify all supplied proof bytes, including the transmitted opening.

    This does not parse or accept a proof; the verifier separately checks the
    canonical proof against its external context before consuming admission.
    """
    if type(raw) is not bytes:
        raise TypeError("proof bytes must be immutable bytes")
    return hashlib.sha256(_frame(_PROOF_DOMAIN, raw)).digest()


def admission_key(ctx: EpochContext, *, limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    """One registration/epoch key, invariant under seed/deadline substitutions.

    Substitutions must still fail context certification; they cannot manufacture
    a fresh admission slot for an already consumed registration and epoch.
    """
    encode_context(ctx, limits=limits)  # validate the complete structured context
    payload = _blob(encode_registration(ctx.registration, limits=limits)) + _blob(ctx.epoch)
    return hashlib.sha256(_frame(_ADMISSION_DOMAIN, payload)).digest()
