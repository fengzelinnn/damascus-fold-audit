"""Version-one bounded canonical protocol wire.

All frames are encode_bytes(tag) || encode_bytes(payload), using the existing
big-endian canonical primitives. The exact payload orders are:
  pp: q, k, d, T (uint), codec, suite (blob);
  registration: pp(blob), file_id(blob), file_length(uint), level=0(uint),
                generator_count(uint), each generator(blob), commitment(blob);
  context: registration(blob), epoch(blob), seed(blob), deadline(blob);
  round: index(uint), L_vec(blob), R_vec(blob), L_poly(blob), R_poly(blob);
  proof: context_digest(blob,32 bytes), exact d(uint), indexed rounds(blob),
         opening(sint).
Internal modules are k(uint), n(uint), then all coefficients in coordinate-major
order at exactly ceil(bit_length(q)/8) bytes each. Their q is supplied by pp.
Standalone module frames (for current cross terms in Fiat--Shamir) contain
q(uint), n(uint), k(uint), then the same coefficient layout.

Signed openings retain their integer lift; semantic norm/algebra/certification
checks belong to the verifier. No wire field selects a raw-byte file codec.
"""

from functools import wraps
from hashlib import sha256

from .algebra import Module, Ring, RingElement, require_integer, validate_module
from .encoding import (DecodeError, Reader, decode_field, encode_bytes,
                       encode_field, encode_sint, encode_uint)
from .fold import FoldParameters, PublicState, RoundRecord
from .protocol_types import (EpochContext, EpochProof, ProtocolParameters,
                             Registration, WireLimits)

DEFAULT_LIMITS = WireLimits()
_TAG_PP = b'DF/pp/v1'
_TAG_REGISTRATION = b'DF/registration/v1'
_TAG_CONTEXT = b'DF/context/v1'
_TAG_ROUND = b'DF/round/v1'
_TAG_PROOF = b'DF/proof/v1'
_TAG_MODULE = b'DF/module/v1'
_TAG_CONTEXT_ID = b'DF/context-id/v1'


def _decoder(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except DecodeError:
            raise
        except (ValueError, TypeError, OverflowError) as error:
            raise DecodeError(str(error)) from error
    return wrapped


def _limits(limits: WireLimits) -> None:
    if not isinstance(limits, WireLimits):
        raise TypeError('limits must be WireLimits')


def _blob(value: bytes, limits: WireLimits) -> bytes:
    return encode_bytes(value, max_bytes=limits.max_blob_bytes)


def _uint(value: int) -> bytes:
    return encode_uint(value, max_bytes=8)


def _metadata(value: bytes, limits: WireLimits) -> bytes:
    if type(value) is not bytes or not value:
        raise ValueError('metadata must be nonempty immutable bytes')
    return encode_bytes(value, max_bytes=min(limits.max_metadata_bytes, limits.max_blob_bytes))


def _frame(tag: bytes, payload: bytes, limits: WireLimits) -> bytes:
    _limits(limits)
    size = 8 + len(tag) + len(payload)
    if size > limits.max_total_bytes:
        raise ValueError('total-size limit exceeded')
    return encode_bytes(tag, max_bytes=32) + _blob(payload, limits)


def _unframe(raw: bytes, tag: bytes, limits: WireLimits) -> Reader:
    _limits(limits)
    outer = Reader(raw, max_total=limits.max_total_bytes)
    if outer.blob(max_bytes=32) != tag:
        raise DecodeError('wrong wire domain or version')
    payload = outer.blob(max_bytes=limits.max_blob_bytes)
    outer.finish()
    return Reader(payload, max_total=limits.max_blob_bytes)


def _join(parts, limits: WireLimits) -> bytes:
    """Enforce aggregate size before extending the payload buffer."""
    output = bytearray()
    for part in parts:
        if len(part) > min(limits.max_blob_bytes, limits.max_total_bytes) - len(output):
            raise ValueError('aggregate payload limit exceeded')
        output.extend(part)
    return bytes(output)


def _parameter_shape(pp: ProtocolParameters, limits: WireLimits) -> tuple[int, int]:
    _limits(limits)
    if not isinstance(pp, ProtocolParameters):
        raise TypeError('pp must be ProtocolParameters')
    p = pp.arithmetic
    width = (p.q.bit_length() + 7) // 8
    if width > limits.max_q_bytes:
        raise ValueError('modulus byte limit exceeded')
    if (p.T.bit_length() + 7) // 8 > limits.max_integer_bytes:
        raise ValueError('challenge integer limit exceeded')
    if p.d > limits.max_depth or p.d > limits.max_records:
        raise ValueError('depth or record limit exceeded')
    # Compare bit lengths BEFORE computing 2**d.
    if limits.max_ring_degree < 1 or p.d >= limits.max_ring_degree.bit_length():
        raise ValueError('ring degree limit exceeded')
    n = 1 << p.d
    if p.k > limits.max_module_rank:
        raise ValueError('module rank limit exceeded')
    coefficient_count = n * p.k * (n + 1)
    if coefficient_count > limits.max_coefficients:
        raise ValueError('registered coefficient count limit exceeded')
    if coefficient_count * width > min(limits.max_blob_bytes, limits.max_total_bytes):
        raise ValueError('registered coefficient byte limit exceeded')
    _metadata(pp.codec, limits)
    _metadata(pp.suite, limits)
    return n, width


def encode_pp(pp: ProtocolParameters, *, limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    _parameter_shape(pp, limits)
    p = pp.arithmetic
    payload = _join((encode_uint(p.q, max_bytes=limits.max_q_bytes), _uint(p.k),
                     _uint(p.d), encode_uint(p.T, max_bytes=limits.max_integer_bytes),
                     _metadata(pp.codec, limits), _metadata(pp.suite, limits)), limits)
    return _frame(_TAG_PP, payload, limits)


@_decoder
def decode_pp(raw: bytes, *, limits: WireLimits = DEFAULT_LIMITS) -> ProtocolParameters:
    r = _unframe(raw, _TAG_PP, limits)
    q = r.uint(max_bytes=limits.max_q_bytes)
    k, d = r.uint(max_bytes=8), r.uint(max_bytes=8)
    T = r.uint(max_bytes=limits.max_integer_bytes)
    codec = r.blob(max_bytes=min(limits.max_metadata_bytes, limits.max_blob_bytes))
    suite = r.blob(max_bytes=min(limits.max_metadata_bytes, limits.max_blob_bytes))
    r.finish()
    pp = ProtocolParameters(FoldParameters(d=d, T=T, k=k, q=q), codec, suite)
    _parameter_shape(pp, limits)
    return pp


def _module_bytes(module: Module, ring: Ring, k: int, limits: WireLimits) -> bytes:
    validate_module(module, ring, k)
    width = (ring.q.bit_length() + 7) // 8
    if k > limits.max_module_rank or ring.n > limits.max_ring_degree:
        raise ValueError('module dimensions exceed limits')
    if width > limits.max_q_bytes or k * ring.n > limits.max_coefficients:
        raise ValueError('module coefficient limit exceeded')
    if k * ring.n * width > min(limits.max_blob_bytes, limits.max_total_bytes):
        raise ValueError('module byte limit exceeded')
    parts = (encode_field(value, ring.q) for element in module for value in element.coefficients)
    return _join((_uint(k), _uint(ring.n), _join(parts, limits)), limits)


def _read_module(raw: bytes, ring: Ring, k: int, limits: WireLimits) -> Module:
    r = Reader(raw, max_total=limits.max_blob_bytes)
    actual_k, actual_n = r.uint(max_bytes=8), r.uint(max_bytes=8)
    if (actual_k, actual_n) != (k, ring.n):
        raise DecodeError('module dimensions do not match parameters and level')
    width = (ring.q.bit_length() + 7) // 8
    count = k * ring.n
    if count > limits.max_coefficients or width > limits.max_q_bytes:
        raise DecodeError('module coefficient limit exceeded')
    size = count * width
    # Validate complete byte count before constructing tuples or ring elements.
    if size != len(raw) - r.offset:
        raise DecodeError('incorrect module coefficient byte count')
    coefficients = r.take(size)
    r.finish()
    return tuple(RingElement(ring, tuple(
        decode_field(coefficients[(coordinate*ring.n+i)*width:
                                  (coordinate*ring.n+i+1)*width], ring.q)
        for i in range(ring.n))) for coordinate in range(k))


def encode_module(module: Module, *, limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    """Canonical standalone typed module for full transcript cross-term inputs."""
    _limits(limits)
    if type(module) is not tuple or not module or not isinstance(module[0], RingElement):
        raise TypeError('module must be a nonempty immutable RingElement tuple')
    ring, k = module[0].ring, len(module)
    body = _module_bytes(module, ring, k, limits)
    reader = Reader(body, max_total=limits.max_blob_bytes)
    reader.uint(max_bytes=8)
    reader.uint(max_bytes=8)
    payload = _join((encode_uint(ring.q, max_bytes=limits.max_q_bytes),
                     _uint(ring.n), _uint(k), body[reader.offset:]), limits)
    return _frame(_TAG_MODULE, payload, limits)


def encode_registration(registration: Registration, *,
                        limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    if not isinstance(registration, Registration):
        raise TypeError('registration must be Registration')
    n, _ = _parameter_shape(registration.pp, limits)
    if registration.file_length > limits.max_file_length:
        raise ValueError('file length limit exceeded')
    initial = registration.initial
    k, ring = registration.pp.arithmetic.k, initial.ring
    def parts():
        yield _blob(encode_pp(registration.pp, limits=limits), limits)
        yield _metadata(registration.file_id, limits)
        yield _uint(registration.file_length)
        yield _uint(initial.level)
        yield _uint(n)
        for generator in initial.generators:
            yield _blob(_module_bytes(generator, ring, k, limits), limits)
        yield _blob(_module_bytes(initial.commitment, ring, k, limits), limits)
    return _frame(_TAG_REGISTRATION, _join(parts(), limits), limits)


@_decoder
def decode_registration(raw: bytes, *, limits: WireLimits = DEFAULT_LIMITS) -> Registration:
    r = _unframe(raw, _TAG_REGISTRATION, limits)
    pp = decode_pp(r.blob(max_bytes=limits.max_blob_bytes), limits=limits)
    n, width = _parameter_shape(pp, limits)
    file_id = r.blob(max_bytes=min(limits.max_metadata_bytes, limits.max_blob_bytes))
    file_length = r.uint(max_bytes=8)
    if file_length > limits.max_file_length:
        raise DecodeError('file length limit exceeded')
    if r.uint(max_bytes=8) != 0:
        raise DecodeError('registration initial level must be zero')
    if r.uint(max_bytes=8) != n:
        raise DecodeError('registered generator count must equal 2**d')
    k = pp.arithmetic.k
    if n * k * (n + 1) * width > len(r.raw) - r.offset:
        raise DecodeError('truncated registered coefficient data')
    ring = Ring(pp.arithmetic.q, n)
    generators = tuple(_read_module(r.blob(max_bytes=limits.max_blob_bytes), ring, k, limits)
                       for _ in range(n))
    commitment = _read_module(r.blob(max_bytes=limits.max_blob_bytes), ring, k, limits)
    r.finish()
    return Registration(pp, file_id, file_length, PublicState(pp.arithmetic, 0, generators, commitment))


def encode_context(context: EpochContext, *, limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    if not isinstance(context, EpochContext):
        raise TypeError('context must be EpochContext')
    payload = _join((_blob(encode_registration(context.registration, limits=limits), limits),
                     _metadata(context.epoch, limits), _metadata(context.seed, limits),
                     _metadata(context.deadline, limits)), limits)
    return _frame(_TAG_CONTEXT, payload, limits)


@_decoder
def decode_context(raw: bytes, *, limits: WireLimits = DEFAULT_LIMITS) -> EpochContext:
    r = _unframe(raw, _TAG_CONTEXT, limits)
    registration = decode_registration(r.blob(max_bytes=limits.max_blob_bytes), limits=limits)
    budget = min(limits.max_metadata_bytes, limits.max_blob_bytes)
    epoch, seed, deadline = r.blob(max_bytes=budget), r.blob(max_bytes=budget), r.blob(max_bytes=budget)
    r.finish()
    return EpochContext(registration, epoch, seed, deadline)


def context_binding(context: EpochContext, *, limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    """The unique public context ID; Fiat--Shamir still consumes the full context."""
    encoded = encode_context(context, limits=limits)
    return sha256(_frame(_TAG_CONTEXT_ID, encoded, limits)).digest()


def _round_rings(j: int, pp: ProtocolParameters, limits: WireLimits) -> tuple[Ring, Ring]:
    n, _ = _parameter_shape(pp, limits)
    require_integer(j, 'round index')
    if not 0 <= j < pp.arithmetic.d:
        raise ValueError('round index outside 0..d-1')
    ring = Ring(pp.arithmetic.q, n >> j)
    return ring, Ring(ring.q, ring.n // 2)


def encode_round_record(record: RoundRecord, j: int, pp: ProtocolParameters, *,
                        limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    if not isinstance(record, RoundRecord):
        raise TypeError('record must be RoundRecord')
    ring, child = _round_rings(j, pp, limits)
    k = pp.arithmetic.k
    payload = _join((_uint(j), *(_blob(_module_bytes(module, target, k, limits), limits)
                                for module, target in ((record.L_vec, ring), (record.R_vec, ring),
                                                       (record.L_poly, child), (record.R_poly, child)))), limits)
    return _frame(_TAG_ROUND, payload, limits)


@_decoder
def decode_round_record(raw: bytes, j: int, pp: ProtocolParameters, *,
                        limits: WireLimits = DEFAULT_LIMITS) -> RoundRecord:
    ring, child = _round_rings(j, pp, limits)
    r = _unframe(raw, _TAG_ROUND, limits)
    if r.uint(max_bytes=8) != j:
        raise DecodeError('round record index mismatch')
    modules = tuple(_read_module(r.blob(max_bytes=limits.max_blob_bytes), target,
                                 pp.arithmetic.k, limits) for target in (ring, ring, child, child))
    r.finish()
    return RoundRecord(*modules)


def encode_proof(proof: EpochProof, context: EpochContext, *,
                 limits: WireLimits = DEFAULT_LIMITS) -> bytes:
    if not isinstance(proof, EpochProof):
        raise TypeError('proof must be EpochProof')
    binding = context_binding(context, limits=limits)
    if proof.context_digest != binding:
        raise ValueError('proof context binding mismatch')
    pp = context.registration.pp
    if len(proof.records) != pp.arithmetic.d:
        raise ValueError('proof must contain exactly d records')
    def parts():
        yield _blob(proof.context_digest, limits)
        yield _uint(len(proof.records))
        for j, record in enumerate(proof.records):
            yield _blob(encode_round_record(record, j, pp, limits=limits), limits)
        yield encode_sint(proof.opening, max_bytes=limits.max_integer_bytes)
    return _frame(_TAG_PROOF, _join(parts(), limits), limits)


@_decoder
def decode_proof(raw: bytes, context: EpochContext, *,
                 limits: WireLimits = DEFAULT_LIMITS) -> EpochProof:
    # Check raw size/type/domain before hashing or traversing an external context.
    r = _unframe(raw, _TAG_PROOF, limits)
    binding = r.blob(max_bytes=32)
    if len(binding) != 32 or binding != context_binding(context, limits=limits):
        raise DecodeError('proof context binding mismatch')
    pp = context.registration.pp
    count = r.uint(max_bytes=8)
    if count != pp.arithmetic.d or count > limits.max_records:
        raise DecodeError('proof must contain exactly d records')
    # Each nested round needs at least a blob length; opening needs sign+length.
    if 4 * count + 5 > len(r.raw) - r.offset:
        raise DecodeError('truncated proof records or missing opening')
    records = tuple(decode_round_record(r.blob(max_bytes=limits.max_blob_bytes), j, pp, limits=limits)
                    for j in range(count))
    opening = r.sint(max_bytes=limits.max_integer_bytes)
    r.finish()
    return EpochProof(binding, records, opening)

