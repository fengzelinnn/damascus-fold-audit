"""Public fixed-block ternary byte codec approved for legal registration.

For each block of r <= 32 bytes, the unsigned big-endian value is written in
exactly c(r) least-significant-first base-three digits, where 3**c(r) >= 2**(8*r)
and c(r) is minimal. Digits 0,1,2 map to coefficients 0,1,-1. Blocks follow file
order and flatten as polynomial_index*n + degree, followed by zero padding.

The registered byte length is essential: at fixed length the block partition,
radix representation, and byte reconstruction are unique. Different lengths
of all-zero bytes share a padded witness but have different registered lengths.
The protocol binds both this full descriptor and that length. This supplies the
paper's public injective legal codec without changing folding or security bounds.

iterencode uses at most a 32-byte block conversion integer and never converts a
whole file into one integer. encode still materializes the entire N-by-n witness;
decode materializes the original bytes. Streaming conversion is not a claim
that the reference protocol can process gigabyte witnesses in bounded memory.
Callers must enforce practical resource budgets before materializing a witness.
"""

from io import BytesIO
from itertools import chain, islice, repeat
from sys import maxsize
from typing import BinaryIO, Iterator

from .algebra import Witness, require_integer, validate_witness
from .codecs import FileCodec
from .fold import FoldParameters


TERNARY32_DESCRIPTOR = (
    b'DF-Ternary32-v1;block-bytes=32;block-integer=unsigned-big-endian;'
    b'block-trits=min-c:3^c>=2^(8*r);trit-order=least-significant-first;'
    b'digit-map=0:0,1:1,2:-1;block-order=file;partial-block=actual-r-bytes;'
    b'high-trit-padding=0;flat-index=poly*n+degree;n=2^d;'
    b'global-padding=0-to-4^d;byte-length=registered-ell'
)


def trits_for_bytes(byte_count: int) -> int:
    """Return exact minimal c(r), including c(0)=0 and c(32)=162."""
    require_integer(byte_count, 'byte_count')
    if not 0 <= byte_count <= 32:
        raise ValueError('byte_count must be between zero and 32')
    target = 1 << (8 * byte_count)
    power, count = 1, 0
    while power < target:
        power *= 3
        count += 1
    return count


_TRIT_COUNTS = tuple(trits_for_bytes(length) for length in range(33))


def required_coefficients(file_length: int) -> int:
    """Return 162*floor(ell/32)+c(ell mod 32), without allocating file data."""
    require_integer(file_length, 'file_length')
    if file_length < 0:
        raise ValueError('file_length must be nonnegative')
    blocks, remainder = divmod(file_length, 32)
    return 162 * blocks + _TRIT_COUNTS[remainder]


def _dimensions(parameters: FoldParameters) -> tuple[int, int]:
    if not isinstance(parameters, FoldParameters):
        raise TypeError('parameters must be FoldParameters')
    # This is an implementation indexing limit, not a security parameter or a
    # change to the codec's mathematics. Reject impossible native sequence sizes
    # before shifting by a caller-supplied enormous depth.
    if parameters.d > (maxsize.bit_length() - 1) // 2:
        raise ValueError('witness shape exceeds native sequence indexing capacity')
    n = 1 << parameters.d
    return n, n * n


def _layout(file_length: int, parameters: FoldParameters) -> tuple[int, int, int]:
    required = required_coefficients(file_length)
    n, capacity = _dimensions(parameters)
    if required > capacity:
        raise ValueError('file exceeds coefficient capacity for this fold depth')
    return n, capacity, required


def _read_exact(read, byte_count: int) -> bytes:
    block = bytearray()
    while len(block) < byte_count:
        remaining = byte_count - len(block)
        chunk = read(remaining)
        if type(chunk) is not bytes:
            raise TypeError('binary reader.read must return bytes')
        if len(chunk) > remaining:
            raise ValueError('binary reader returned more than the requested bytes')
        if not chunk:
            raise ValueError('file is truncated before its declared byte length')
        block.extend(chunk)
    return bytes(block)


def _require_eof(read) -> None:
    extra = read(1)
    if type(extra) is not bytes:
        raise TypeError('binary reader.read must return bytes')
    if extra:
        raise ValueError('file has extra bytes after its declared byte length')


class Ternary32Codec(FileCodec):
    """Stateless fixed codec; no parameters may change its public descriptor."""
    __slots__ = ()

    @property
    def descriptor(self) -> bytes:
        return TERNARY32_DESCRIPTOR

    def iterencode(self, reader: BinaryIO, file_length: int,
                   parameters: FoldParameters) -> Iterator[int]:
        """Yield exactly M flat ternary coefficients from an exact-length stream.

        Reads request at most 32 bytes and support short reads. The final EOF
        check occurs before yielding the final data block or any global padding.
        Truncated or overlong input raises; a consumer must not register a
        partially consumed iterator. This method does not close the reader.
        Capacity/type preflight is immediate; actual I/O starts on iteration.
        """
        _, capacity, required = _layout(file_length, parameters)
        read = getattr(reader, 'read', None)
        if not callable(read):
            raise TypeError('reader must provide a binary read method')

        def coefficients() -> Iterator[int]:
            remaining = file_length
            if remaining == 0:
                _require_eof(read)
            while remaining:
                byte_count = min(32, remaining)
                block = _read_exact(read, byte_count)
                remaining -= byte_count
                if remaining == 0:
                    _require_eof(read)
                value = int.from_bytes(block, 'big', signed=False)
                for _ in range(_TRIT_COUNTS[byte_count]):
                    value, digit = divmod(value, 3)
                    yield -1 if digit == 2 else digit
            yield from repeat(0, capacity - required)

        return coefficients()

    def encode(self, data: bytes, parameters: FoldParameters) -> Witness:
        """Materialize the exact immutable initial witness, with global padding."""
        if type(data) is not bytes:
            raise TypeError('file data must be bytes')
        n, _, _ = _layout(len(data), parameters)
        coefficients = self.iterencode(BytesIO(data), len(data), parameters)
        return tuple(tuple(islice(coefficients, n)) for _ in range(n))

    def decode(self, witness: Witness, file_length: int,
               parameters: FoldParameters) -> bytes:
        """Reject all values outside this codec's image for the registered ell."""
        n, _, _ = _layout(file_length, parameters)
        validate_witness(witness, n, n)
        if any(value not in (-1, 0, 1) for polynomial in witness for value in polynomial):
            raise ValueError('witness coefficients must be ternary integers')
        coefficients = chain.from_iterable(witness)
        decoded = bytearray()
        remaining = file_length
        while remaining:
            byte_count = min(32, remaining)
            block = tuple(islice(coefficients, _TRIT_COUNTS[byte_count]))
            value = 0
            for coefficient in reversed(block):
                value = 3 * value + (2 if coefficient == -1 else coefficient)
            if value >= 1 << (8 * byte_count):
                raise ValueError('surplus ternary block codeword is outside the byte range')
            decoded.extend(value.to_bytes(byte_count, 'big', signed=False))
            remaining -= byte_count
        if any(coefficient != 0 for coefficient in coefficients):
            raise ValueError('nonzero global padding is not a legal codec image')
        return bytes(decoded)
