"""Immutable public objects for the versioned protocol execution path.

These types validate structure, not certification, codec semantics, parameter
security, or proof acceptance. Those checks belong to their configured layers.
"""

from dataclasses import dataclass, fields

from .algebra import require_integer, require_tuple
from .fold import FoldParameters, PublicState, RoundRecord


def _nonempty_bytes(value: object, name: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f'{name} must be immutable bytes')
    if not value:
        raise ValueError(f'{name} must be nonempty')


@dataclass(frozen=True, slots=True)
class ProtocolParameters:
    arithmetic: FoldParameters
    codec: bytes
    suite: bytes = b'DF-SHAKE256-v1'

    def __post_init__(self) -> None:
        if not isinstance(self.arithmetic, FoldParameters):
            raise TypeError('arithmetic must be FoldParameters')
        _nonempty_bytes(self.codec, 'codec')
        _nonempty_bytes(self.suite, 'suite')


@dataclass(frozen=True, slots=True)
class Registration:
    pp: ProtocolParameters
    file_id: bytes
    file_length: int
    initial: PublicState

    def __post_init__(self) -> None:
        if not isinstance(self.pp, ProtocolParameters):
            raise TypeError('pp must be ProtocolParameters')
        _nonempty_bytes(self.file_id, 'file_id')
        require_integer(self.file_length, 'file_length')
        if self.file_length < 0:
            raise ValueError('file_length must be nonnegative')
        if not isinstance(self.initial, PublicState):
            raise TypeError('initial must be PublicState')
        if self.initial.level != 0:
            raise ValueError('registration must start at level zero')
        if self.initial.parameters != self.pp.arithmetic:
            raise ValueError('registration arithmetic does not match pp')


@dataclass(frozen=True, slots=True)
class EpochContext:
    registration: Registration
    epoch: bytes
    seed: bytes
    deadline: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.registration, Registration):
            raise TypeError('registration must be Registration')
        for name in ('epoch', 'seed', 'deadline'):
            _nonempty_bytes(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class EpochProof:
    context_digest: bytes
    records: tuple[RoundRecord, ...]
    opening: int

    def __post_init__(self) -> None:
        if type(self.context_digest) is not bytes:
            raise TypeError('context_digest must be bytes')
        if len(self.context_digest) != 32:
            raise ValueError('context_digest must contain exactly 32 bytes')
        require_tuple(self.records, 'records')
        if any(not isinstance(record, RoundRecord) for record in self.records):
            raise TypeError('records must contain RoundRecord values')
        require_integer(self.opening, 'opening')


@dataclass(frozen=True, slots=True)
class WireLimits:
    """Finite parser/encoder budgets, independent of security parameters."""
    max_total_bytes: int = 16 * 1024 * 1024
    max_blob_bytes: int = 8 * 1024 * 1024
    max_metadata_bytes: int = 4096
    max_integer_bytes: int = 65536
    max_q_bytes: int = 65536
    max_depth: int = 20
    max_ring_degree: int = 65536
    max_module_rank: int = 1024
    max_coefficients: int = 1048576
    max_records: int = 64
    max_file_length: int = (1 << 64) - 1

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            require_integer(value, field.name)
            maximum = (1 << 64) - 1 if field.name == 'max_file_length' else 0xffffffff
            if not 0 <= value <= maximum:
                raise ValueError(f'invalid {field.name}')
        if self.max_q_bytes > 65536 or self.max_integer_bytes > 65536:
            raise ValueError('integer budgets exceed canonical primitive limit')

