"""Static, bounded collection planning without witness or generator allocation.

These budgets only bound this local correctness collector. The work and Python
memory models are estimates, not timings, measured memory, or guaranteed peaks.
They do not change arithmetic, codec, wire, or protocol acceptance rules.
"""
from dataclasses import asdict, dataclass, fields
from types import MappingProxyType

from . import wire
from .file_codec import Ternary32Codec, required_coefficients
from .fold import FoldParameters
from .protocol_types import ProtocolParameters


HARD_CAPS = MappingProxyType({
    'max_input_bytes': 4096,
    'max_epochs': 32,
    'max_depth': 7,
    'max_generator_coefficients': 262144,
    'max_registered_coefficients': 270336,
    'max_wire_payload_bytes': 8 * 1024 * 1024,
    'max_estimated_python_bytes': 512 * 1024 * 1024,
    'max_estimated_operations': 1000000000,
})


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    """Explicit work budgets may exceed the default, but never the hard cap."""
    max_input_bytes: int = 4096
    max_epochs: int = 32
    max_depth: int = 7
    max_generator_coefficients: int = 262144
    max_registered_coefficients: int = 270336
    max_wire_payload_bytes: int = 8 * 1024 * 1024
    max_estimated_python_bytes: int = 512 * 1024 * 1024
    max_estimated_operations: int = 100000000

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int:
                raise TypeError(f'{field.name} must be an integer, not a bool')
            if not 1 <= value <= HARD_CAPS[field.name]:
                raise ValueError(f'{field.name} must be between 1 and {HARD_CAPS[field.name]}')


def _checked_shape(parameters: FoldParameters) -> tuple[int, int]:
    if not isinstance(parameters, FoldParameters):
        raise TypeError('parameters must be FoldParameters')
    # Keep the existing wire limits. encode_pp checks d before shifting and
    # coefficient/byte counts before any public generators are materialized.
    wire.encode_pp(ProtocolParameters(parameters, Ternary32Codec().descriptor))
    return 1 << parameters.d, (parameters.q.bit_length() + 7) // 8


def _codec_capacity(coefficient_capacity: int) -> int:
    # Every nonempty file uses more coefficients than bytes, so high is a
    # strict upper bound. required_coefficients never allocates file content.
    low, high = 0, coefficient_capacity + 1
    while low + 1 < high:
        middle = (low + high) // 2
        if required_coefficients(middle) <= coefficient_capacity:
            low = middle
        else:
            high = middle
    return low


def codec_max_file_bytes(parameters: FoldParameters) -> int:
    """Exact Ternary32 byte capacity for a shape accepted by existing wire limits."""
    n, _ = _checked_shape(parameters)
    return _codec_capacity(n * n)


def _within(value: int, name: str, budget: ResourceBudget) -> None:
    limit = getattr(budget, name)
    if value > limit:
        raise ValueError(f'{name} exceeded: {value} > {limit}')


def preflight_resources(parameters: FoldParameters, file_bytes: int, epochs: int,
                        budget: ResourceBudget = ResourceBudget()) -> dict:
    """Plan one setup plus the caller's total epoch work before large allocation.

The caller must include warmup epochs in ``epochs``. A successful return only
means the declared static counts and estimates fit these budgets. It neither
reserves resources nor guarantees completion or a particular memory peak.
"""
    if not isinstance(parameters, FoldParameters):
        raise TypeError('parameters must be FoldParameters')
    if not isinstance(budget, ResourceBudget):
        raise TypeError('budget must be ResourceBudget')
    for name, value, minimum in (('file_bytes', file_bytes, 0), ('epochs', epochs, 1)):
        if type(value) is not int:
            raise TypeError(f'{name} must be an integer, not a bool')
        if value < minimum:
            raise ValueError(f'{name} must be at least {minimum}')
    _within(file_bytes, 'max_input_bytes', budget)
    _within(epochs, 'max_epochs', budget)
    # Check the local depth budget BEFORE wire encoding or computing 2**d.
    _within(parameters.d, 'max_depth', budget)
    n, width = _checked_shape(parameters)
    witness_coefficients = n * n
    generator_coefficients = parameters.k * witness_coefficients
    registered_coefficients = parameters.k * n * (n + 1)
    registered_payload_bytes = registered_coefficients * width
    _within(generator_coefficients, 'max_generator_coefficients', budget)
    _within(registered_coefficients, 'max_registered_coefficients', budget)
    _within(registered_payload_bytes, 'max_wire_payload_bytes', budget)
    maximum = _codec_capacity(witness_coefficients)
    required = required_coefficients(file_bytes)
    if file_bytes > maximum:
        raise ValueError(f'file_bytes exceeds codec capacity: {file_bytes} > {maximum}')

    # Versioned planning models, not exact implementation allocation counts.
    # The added integer width is a workload allowance for integer intermediates;
    # it is never used as a protocol norm bound or to validate an opening.
    modeled_integer_bytes = width + (2 * parameters.d * parameters.T.bit_length() + 7) // 8
    modeled_slot_bytes = 64 + modeled_integer_bytes
    slots = witness_coefficients + registered_coefficients
    estimated_python_bytes = (8 * slots * modeled_slot_bytes
                              + (epochs + 4) * registered_payload_bytes + file_bytes)
    estimated_operations = (parameters.k * n**3 * (1 + epochs * (1 + 8 * parameters.d))
                            + epochs * (parameters.d + 1) * registered_coefficients)
    _within(estimated_python_bytes, 'max_estimated_python_bytes', budget)
    _within(estimated_operations, 'max_estimated_operations', budget)

    return dict(
        status='within_declared_budgets', file_bytes=file_bytes, epochs=epochs,
        ring_degree=n, witness_coefficients=witness_coefficients,
        generator_coefficients=generator_coefficients,
        registered_coefficients=registered_coefficients,
        wire_width_bytes=width, registered_payload_bytes=registered_payload_bytes,
        max_file_bytes=maximum, codec_max_file_bytes=maximum,
        required_input_coefficients=required,
        estimated_python_bytes=estimated_python_bytes,
        estimated_operations=estimated_operations, budget=asdict(budget),
        estimates=dict(
            version='collection-resource-model-v1', measured=False, guarantees_fit=False,
            python_bytes_formula='8*(n*n + k*n*(n+1))*(64 + modeled_integer_bytes) '
                                 '+ (epochs+4)*registered_payload_bytes + file_bytes',
            modeled_integer_bytes=modeled_integer_bytes,
            modeled_integer_bytes_formula='wire_width_bytes + ceil(2*d*T.bit_length()/8)',
            operations_formula='k*n**3*(1 + epochs*(1+8*d)) + epochs*(d+1)*k*n*(n+1)',
            operations_unit='modeled coefficient work',
            scope='one setup and the supplied total epoch count, including warmups',
            limitations=[
                'Python memory uses assumed object/copy allowances, not measured allocations',
                'registered_payload_bytes counts coefficient bytes only, excluding wire framing',
                'operation estimate does not model integer bit cost, hashing, serialization, I/O or wall time',
                'no resource reservation, OS memory-limit enforcement or completion guarantee',
            ],
        ),
    )
