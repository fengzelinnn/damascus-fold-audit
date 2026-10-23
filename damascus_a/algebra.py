"""Exact reference arithmetic for Z_q[X]/(X^n + 1).

This module provides arithmetic only. Ring construction does not establish
primality, parameter security, serialization, or a cryptographic protocol.
"""

from dataclasses import dataclass
from math import gcd

from .backend import get_arithmetic_backend


def require_integer(value: object, name: str) -> None:
    """Reject booleans and implicit numeric conversions at typed boundaries."""
    if type(value) is not int:
        raise TypeError(f'{name} must be a Python integer')


def require_tuple(value: object, name: str) -> None:
    if type(value) is not tuple:
        raise TypeError(f'{name} must be an immutable tuple')


@dataclass(frozen=True, slots=True)
class Ring:
    q: int
    n: int

    def __post_init__(self) -> None:
        require_integer(self.q, 'q')
        require_integer(self.n, 'n')
        if self.q < 3 or self.q % 2 == 0:
            raise ValueError('q must be an odd integer at least 3; primality is not asserted')
        if self.n < 1 or self.n & (self.n - 1):
            raise ValueError('n must be a positive power of two')

    def element(self, coefficients: tuple[int, ...]) -> 'RingElement':
        """Explicitly reduce an integer polynomial; not a public-data decoder."""
        require_tuple(coefficients, 'coefficients')
        if len(coefficients) != self.n:
            raise ValueError('coefficient count differs from ring degree')
        for value in coefficients:
            require_integer(value, 'coefficient')
        return RingElement(self, tuple(value % self.q for value in coefficients))

    def zero(self) -> 'RingElement':
        return RingElement(self, (0,) * self.n)

    def inverse_scalar(self, scalar: int) -> int:
        require_integer(scalar, 'scalar')
        if gcd(scalar, self.q) != 1:
            raise ValueError('scalar must be invertible modulo q')
        return pow(scalar, -1, self.q)


@dataclass(frozen=True, slots=True)
class RingElement:
    ring: Ring
    coefficients: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.ring, Ring):
            raise TypeError('ring must be a Ring')
        require_tuple(self.coefficients, 'coefficients')
        if len(self.coefficients) != self.ring.n:
            raise ValueError('coefficient count differs from ring degree')
        for value in self.coefficients:
            require_integer(value, 'coefficient')
            if not 0 <= value < self.ring.q:
                raise ValueError('public coefficients must be canonical residues in [0,q)')

    def _same_ring(self, other: 'RingElement') -> None:
        if not isinstance(other, RingElement):
            raise TypeError('operand must be a RingElement')
        if self.ring != other.ring:
            raise ValueError('ring mismatch')

    def __add__(self, other: 'RingElement') -> 'RingElement':
        self._same_ring(other)
        return self.ring.element(tuple(a + b for a, b in zip(self.coefficients, other.coefficients)))

    def __sub__(self, other: 'RingElement') -> 'RingElement':
        self._same_ring(other)
        return self.ring.element(tuple(a - b for a, b in zip(self.coefficients, other.coefficients)))

    def __mul__(self, other: 'RingElement') -> 'RingElement':
        self._same_ring(other)
        n = self.ring.n
        result = [0] * n
        for i, a in enumerate(self.coefficients):
            for j, b in enumerate(other.coefficients):
                degree = i + j
                if degree < n:
                    result[degree] += a * b
                else:
                    result[degree - n] -= a * b
        return self.ring.element(tuple(result))

    def scale(self, scalar: int) -> 'RingElement':
        require_integer(scalar, 'scalar')
        return self.ring.element(tuple(scalar * value for value in self.coefficients))

    def times_variable(self) -> 'RingElement':
        """Multiply by the current variable; degree one therefore negates."""
        return self.ring.element((-self.coefficients[-1],) + self.coefficients[:-1])

    def split_even_odd(self) -> tuple['RingElement', 'RingElement']:
        if self.ring.n == 1:
            raise ValueError('the terminal ring cannot be split')
        child = Ring(self.ring.q, self.ring.n // 2)
        return (RingElement(child, self.coefficients[::2]),
                RingElement(child, self.coefficients[1::2]))


IntegerPolynomial = tuple[int, ...]
Witness = tuple[IntegerPolynomial, ...]
Module = tuple[RingElement, ...]
Generators = tuple[Module, ...]  # N generators, each with k ring coordinates.


def validate_module(module: Module, ring: Ring, k: int, name: str = 'module') -> None:
    require_tuple(module, name)
    if len(module) != k or k < 1:
        raise ValueError(f'{name} must have exactly k positive coordinates')
    for element in module:
        if not isinstance(element, RingElement):
            raise TypeError(f'{name} entries must be RingElements')
        if element.ring != ring:
            raise ValueError(f'{name} ring mismatch')


def validate_witness(witness: Witness, count: int, n: int) -> None:
    require_tuple(witness, 'witness')
    if len(witness) != count:
        raise ValueError('witness vector length mismatch')
    for polynomial in witness:
        require_tuple(polynomial, 'integer polynomial')
        if len(polynomial) != n:
            raise ValueError('witness polynomial degree mismatch')
        for coefficient in polynomial:
            require_integer(coefficient, 'witness coefficient')


def module_inner(witness: Witness, generators: Generators) -> Module:
    """Compute sum_i witness[i] * generators[i] without changing the witness."""
    require_tuple(generators, 'generators')
    if not generators:
        raise ValueError('generator vector must be nonempty')
    require_tuple(generators[0], 'generator')
    if not generators[0] or not isinstance(generators[0][0], RingElement):
        raise ValueError('generator module must be nonempty and contain ring elements')
    ring, k = generators[0][0].ring, len(generators[0])
    validate_witness(witness, len(generators), ring.n)
    for generator in generators:
        validate_module(generator, ring, k, 'generator')
    backend = get_arithmetic_backend()
    if backend is not None:
        return tuple(RingElement(ring, backend.accumulate_negacyclic(
            ((polynomial, generator[coordinate].coefficients)
             for polynomial, generator in zip(witness, generators)),
            n=ring.n, q=ring.q)) for coordinate in range(k))
    result = [ring.zero() for _ in range(k)]
    for polynomial, generator in zip(witness, generators):
        reduced = ring.element(polynomial)
        for coordinate in range(k):
            result[coordinate] = result[coordinate] + reduced * generator[coordinate]
    return tuple(result)
