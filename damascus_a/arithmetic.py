"""Optional exact CPU arithmetic; no fixed-width or approximate operations."""
from collections.abc import Iterable
from typing import Protocol


PolynomialPair = tuple[tuple[int, ...], tuple[int, ...]]


class ExactArithmeticBackend(Protocol):
    """Native backend contract, with no dynamic loading or dependency discovery.

    Consume a finite iterable once, without mutating its integer polynomials.
    Return exactly n canonical Python ints for sum(left*right) in
    Z_q[X]/(X^n+1), retaining arbitrary precision throughout. Implementations
    must not truncate, approximate, or silently fall back after a failure.
    """

    def accumulate_negacyclic(self, terms: Iterable[PolynomialPair], *,
                             n: int, q: int) -> tuple[int, ...]:
        ...


class CpuFusedBackend:
    """Accumulate all products before the final output reduction modulo q."""
    __slots__ = ()

    def accumulate_negacyclic(self, terms: Iterable[PolynomialPair], *,
                             n: int, q: int) -> tuple[int, ...]:
        if type(n) is not int or type(q) is not int:
            raise TypeError('ring dimensions and modulus must be Python integers')
        if n < 1 or n & (n - 1):
            raise ValueError('n must be a positive power of two')
        if q < 3 or q % 2 == 0:
            raise ValueError('q must be an odd integer at least 3')
        result = [0] * n
        for pair in terms:
            if type(pair) is not tuple or len(pair) != 2:
                raise TypeError('each product must be an immutable polynomial pair')
            left, right = pair
            for polynomial in pair:
                if type(polynomial) is not tuple:
                    raise TypeError('polynomials must be immutable tuples')
                if len(polynomial) != n:
                    raise ValueError('coefficient count differs from ring degree')
                if any(type(value) is not int for value in polynomial):
                    raise TypeError('coefficients must be Python integers')
            # Only temporary operands are reduced. In particular, the original
            # signed witness and its integer lift are never replaced or mutated.
            # Reducing operands also avoids multiplying arbitrarily large lifts.
            left = tuple(value % q for value in left)
            right = tuple(value % q for value in right)
            for i, a in enumerate(left):
                if a == 0:
                    continue
                for j, b in enumerate(right):
                    if b == 0:
                        continue
                    degree = i + j
                    if degree < n:
                        result[degree] += a * b
                    else:
                        result[degree - n] -= a * b
        return tuple(value % q for value in result)
