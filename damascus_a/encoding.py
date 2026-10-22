"""Canonical framing primitives, NOT an approved Damascus wire profile or file codec.

Lengths are unsigned 32-bit big endian. Integer magnitudes are minimal big endian,
zero uses an empty magnitude. Signed values carry a single 0/1 sign byte. These
primitives are tested independently; no protocol transcript is encoded with them.
"""

MAX_BLOB = 8 * 1024 * 1024
MAX_INTEGER = 64 * 1024


class DecodeError(ValueError):
    pass


def _integer(value, name):
    if type(value) is not int:
        raise TypeError(f'{name} must be an integer, not bool or coercible text')


def _limit(value, name):
    _integer(value, name)
    if value < 0 or value > 0xffffffff:
        raise ValueError(f'invalid {name}')


def encode_bytes(value: bytes, *, max_bytes=MAX_BLOB) -> bytes:
    if type(value) is not bytes:
        raise TypeError('bytes required')
    _limit(max_bytes, 'max_bytes')
    if len(value) > max_bytes:
        raise ValueError('length limit exceeded')
    return len(value).to_bytes(4, 'big') + value


def encode_uint(value: int, *, max_bytes=MAX_INTEGER) -> bytes:
    _integer(value, 'value')
    if value < 0:
        raise ValueError('unsigned integer must be nonnegative')
    _limit(max_bytes, 'max_bytes')
    size = (value.bit_length() + 7) // 8
    if size > max_bytes:
        raise ValueError('integer limit exceeded')
    return encode_bytes(value.to_bytes(size, 'big'), max_bytes=max_bytes)


def encode_sint(value: int, *, max_bytes=MAX_INTEGER) -> bytes:
    _integer(value, 'value')
    return bytes([int(value < 0)]) + encode_uint(abs(value), max_bytes=max_bytes)


def _field_width(q):
    _integer(q, 'q')
    if q < 2:
        raise ValueError('q must be at least two')
    width = (q.bit_length() + 7) // 8
    if width > MAX_INTEGER:
        raise ValueError('field width limit exceeded')
    return width


def encode_field(value: int, q: int) -> bytes:
    width = _field_width(q)
    _integer(value, 'value')
    if not 0 <= value < q:
        raise ValueError('noncanonical field residue')
    return value.to_bytes(width, 'big')


def decode_field(raw: bytes, q: int) -> int:
    width = _field_width(q)
    if type(raw) is not bytes or len(raw) != width:
        raise DecodeError('incorrect field width')
    value = int.from_bytes(raw, 'big')
    if value >= q:
        raise DecodeError('noncanonical field residue')
    return value


class Reader:
    def __init__(self, raw: bytes, *, max_total=16*1024*1024):
        _limit(max_total, 'max_total')
        if type(raw) is not bytes or len(raw) > max_total:
            raise DecodeError('input type or total-size limit')
        self.raw = raw
        self.offset = 0

    def take(self, size: int) -> bytes:
        _limit(size, 'size')
        end = self.offset + size
        if end > len(self.raw):
            raise DecodeError('truncated input')
        value = self.raw[self.offset:end]
        self.offset = end
        return value

    def blob(self, *, max_bytes=MAX_BLOB) -> bytes:
        _limit(max_bytes, 'max_bytes')
        size = int.from_bytes(self.take(4), 'big')
        if size > max_bytes:
            raise DecodeError('declared length exceeds limit')
        return self.take(size)

    def uint(self, *, max_bytes=MAX_INTEGER) -> int:
        raw = self.blob(max_bytes=max_bytes)
        if raw and raw[0] == 0:
            raise DecodeError('nonminimal integer magnitude')
        return int.from_bytes(raw, 'big')

    def sint(self, *, max_bytes=MAX_INTEGER) -> int:
        sign = self.take(1)[0]
        if sign not in (0, 1):
            raise DecodeError('invalid integer sign')
        value = self.uint(max_bytes=max_bytes)
        if sign and value == 0:
            raise DecodeError('negative zero is not canonical')
        return -value if sign else value

    def finish(self):
        if self.offset != len(self.raw):
            raise DecodeError('trailing bytes')


def frame(tag: bytes, payload: bytes) -> bytes:
    if not tag:
        raise ValueError('empty frame type')
    return encode_bytes(tag, max_bytes=32) + encode_bytes(payload)


def read_frame(raw: bytes) -> tuple[bytes, bytes]:
    reader = Reader(raw)
    tag = reader.blob(max_bytes=32)
    if not tag:
        raise DecodeError('empty frame type')
    payload = reader.blob()
    reader.finish()
    return tag, payload
