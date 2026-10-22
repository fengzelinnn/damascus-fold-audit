"""Explicit file-codec contract. No raw-byte mapping is selected by this module.

The frozen paper requires an injective public ternary codec, original byte
length and padding, but does not specify their concrete format. Production
callers must supply that implementation and bind its descriptor in pp.
"""
from abc import ABC, abstractmethod

from .algebra import Witness, require_integer, require_tuple, validate_witness
from .fold import FoldParameters


class FileCodec(ABC):
    @property
    @abstractmethod
    def descriptor(self) -> bytes:
        """Stable public identity of the complete codec and padding convention."""

    @abstractmethod
    def encode(self, data: bytes, parameters: FoldParameters) -> Witness:
        """Encode exactly these bytes as the specified initial witness shape."""

    @abstractmethod
    def decode(self, witness: Witness, file_length: int,
               parameters: FoldParameters) -> bytes:
        """Decode the original bytes using the registered original length."""


def _check_codec(codec: FileCodec, descriptor: bytes) -> None:
    if not isinstance(codec, FileCodec):
        raise TypeError('an explicit FileCodec implementation is required')
    if type(descriptor) is not bytes or not descriptor:
        raise TypeError('codec descriptor must be nonempty bytes')
    if type(codec.descriptor) is not bytes or codec.descriptor != descriptor:
        raise ValueError('codec implementation descriptor does not match pp.codec')


def _check_witness(witness: Witness, parameters: FoldParameters) -> None:
    if not isinstance(parameters, FoldParameters):
        raise TypeError('parameters must be FoldParameters')
    require_tuple(witness, 'witness')
    n = len(witness)
    # Inspect supplied shape before any shift by a caller-controlled depth.
    if n < 1 or n & (n - 1) or n.bit_length() - 1 != parameters.d:
        raise ValueError('encoded witness shape does not match fold depth')
    validate_witness(witness, n, n)
    if any(value not in (-1, 0, 1) for poly in witness for value in poly):
        raise ValueError('encoded witness coefficients must be ternary integers')


def checked_decode(codec: FileCodec, descriptor: bytes, witness: Witness,
                   file_length: int, parameters: FoldParameters) -> bytes:
    """Validate an encoded registration against the explicit codec's image.

    Merely having small coefficients does not establish legal byte encoding.
    Exact decode length and encode(decode(witness)) equality check padding and
    canonical representation. Injectivity of the codec on its entire domain
    remains a requirement on the supplied codec, not something samples prove.
    """
    _check_codec(codec, descriptor)
    require_integer(file_length, 'file_length')
    if file_length < 0:
        raise ValueError('file_length must be nonnegative')
    _check_witness(witness, parameters)
    decoded = codec.decode(witness, file_length, parameters)
    if type(decoded) is not bytes or len(decoded) != file_length:
        raise ValueError('codec decode must return the exact registered byte length')
    canonical = codec.encode(decoded, parameters)
    _check_witness(canonical, parameters)
    if canonical != witness:
        raise ValueError('encoded witness is not canonical for the selected codec')
    return decoded


def checked_encode(codec: FileCodec, descriptor: bytes, data: bytes,
                   parameters: FoldParameters) -> Witness:
    _check_codec(codec, descriptor)
    if type(data) is not bytes:
        raise TypeError('file data must be bytes')
    witness = codec.encode(data, parameters)
    decoded = checked_decode(codec, descriptor, witness, len(data), parameters)
    if decoded != data:
        raise ValueError('codec does not roundtrip the supplied original bytes')
    return witness
