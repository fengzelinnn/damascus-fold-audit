"""Exact integer-lift folds and public algebra replay from the frozen paper.

Challenges are explicit test inputs. This is NOT authenticated Damascus Verify:
there is no file codec, Fiat--Shamir suite, certified context, deadline, replay
registry, or claim that the arithmetic configuration is cryptographically secure.
"""

from dataclasses import dataclass

from .algebra import (Generators, Module, Ring, RingElement, Witness, module_inner,
                      require_integer, require_tuple, validate_module, validate_witness)


@dataclass(frozen=True, slots=True)
class FoldParameters:
    """Arithmetic-only configuration; use the separate parameter audit for gates."""
    d: int
    T: int
    k: int
    q: int

    def __post_init__(self) -> None:
        for name in ('d', 'T', 'k', 'q'):
            require_integer(getattr(self, name), name)
        if self.d < 0 or self.k < 1:
            raise ValueError('d must be nonnegative and k must be positive')
        if self.T < 4 or self.T & (self.T - 1):
            raise ValueError('T must be a power of two at least 4')
        Ring(self.q, 1)
        if self.q <= self.T:
            raise ValueError('q must exceed T')

    @property
    def terminal_bound(self) -> int:
        """Honest integer norm bound B with fixed beta0=1; not extraction bound."""
        return (1 + self.T) ** (2 * self.d)


def _validate_generators(parameters: FoldParameters, level: int, generators: Generators,
                         intermediate: bool) -> Ring:
    if not isinstance(parameters, FoldParameters):
        raise TypeError('parameters must be FoldParameters')
    require_integer(level, 'level')
    if not 0 <= level <= parameters.d:
        raise ValueError('level must be between zero and d')
    require_tuple(generators, 'generators')
    if not generators:
        raise ValueError('generators must be nonempty')
    require_tuple(generators[0], 'generator')
    if not generators[0] or not isinstance(generators[0][0], RingElement):
        raise ValueError('generator module must contain ring elements')
    ring = generators[0][0].ring
    # Compare supplied sizes before constructing 2**(d-level); enormous malformed
    # depths therefore reject without allocating an enormous ring or vector.
    if ring.q != parameters.q or ring.n.bit_length() - 1 != parameters.d - level:
        raise ValueError('ring degree/modulus does not match the current level')
    expected_count = ring.n // 2 if intermediate else ring.n
    if intermediate and ring.n == 1:
        raise ValueError('there is no vector stage at the terminal level')
    if len(generators) != expected_count:
        raise ValueError('generator count does not match the current stage')
    for generator in generators:
        validate_module(generator, ring, parameters.k, 'generator')
    return ring


@dataclass(frozen=True, slots=True)
class PublicState:
    parameters: FoldParameters
    level: int
    generators: Generators
    commitment: Module

    def __post_init__(self) -> None:
        ring = _validate_generators(self.parameters, self.level, self.generators, False)
        validate_module(self.commitment, ring, self.parameters.k, 'commitment')

    @property
    def ring(self) -> Ring:
        return self.commitment[0].ring


@dataclass(frozen=True, slots=True)
class VectorPublicState:
    """Intermediate stage: N has halved but the polynomial degree has not."""
    parameters: FoldParameters
    level: int
    generators: Generators
    commitment: Module

    def __post_init__(self) -> None:
        ring = _validate_generators(self.parameters, self.level, self.generators, True)
        validate_module(self.commitment, ring, self.parameters.k, 'commitment')

    @property
    def ring(self) -> Ring:
        return self.commitment[0].ring


@dataclass(frozen=True, slots=True)
class WitnessState:
    public: PublicState
    witness: Witness

    def __post_init__(self) -> None:
        if not isinstance(self.public, PublicState):
            raise TypeError('public must be a PublicState')
        validate_witness(self.witness, len(self.public.generators), self.public.ring.n)


@dataclass(frozen=True, slots=True)
class VectorWitnessState:
    public: VectorPublicState
    witness: Witness

    def __post_init__(self) -> None:
        if not isinstance(self.public, VectorPublicState):
            raise TypeError('public must be a VectorPublicState')
        validate_witness(self.witness, len(self.public.generators), self.public.ring.n)


@dataclass(frozen=True, slots=True)
class RoundRecord:
    L_vec: Module
    R_vec: Module
    L_poly: Module
    R_poly: Module

    def __post_init__(self) -> None:
        require_tuple(self.L_vec, 'L_vec')
        if not self.L_vec or not isinstance(self.L_vec[0], RingElement):
            raise ValueError('L_vec must contain ring elements')
        ring, k = self.L_vec[0].ring, len(self.L_vec)
        if ring.n == 1:
            raise ValueError('a round record needs a nonterminal ring')
        child = Ring(ring.q, ring.n // 2)
        validate_module(self.L_vec, ring, k, 'L_vec')
        validate_module(self.R_vec, ring, k, 'R_vec')
        validate_module(self.L_poly, child, k, 'L_poly')
        validate_module(self.R_poly, child, k, 'R_poly')


@dataclass(frozen=True, slots=True)
class RoundResult:
    record: RoundRecord
    vector_state: VectorWitnessState
    next_state: WitnessState


@dataclass(frozen=True, slots=True)
class PublicRoundResult:
    vector_state: VectorPublicState
    next_state: PublicState


def _add(left: Module, right: Module) -> Module:
    return tuple(a + b for a, b in zip(left, right))


def _scale(module: Module, scalar: int) -> Module:
    return tuple(element.scale(scalar) for element in module)


def _variable(module: Module) -> Module:
    return tuple(element.times_variable() for element in module)


def _split(module: Module) -> tuple[Module, Module]:
    parts = tuple(element.split_even_odd() for element in module)
    return tuple(pair[0] for pair in parts), tuple(pair[1] for pair in parts)


def _challenge(state: PublicState, value: int) -> int:
    require_integer(value, 'challenge')
    if not 1 <= value <= state.parameters.T:
        raise ValueError('challenge must lie in 1..T')
    return state.ring.inverse_scalar(value)


def _within_honest_bound(value: int, parameters: FoldParameters, level: int) -> bool:
    """Compare |value| <= (1+T)**(2*level) without building a huge power.

    Since 2**(b-1) <= base < 2**b, bit bounds decide distant cases.
    In the remaining case the power has at most roughly twice the bit length
    of the supplied value, so computing it cannot expand with an arbitrary d.
    """
    magnitude = abs(value)
    if magnitude <= 1:
        return True
    exponent = 2 * level
    if exponent == 0:
        return False
    base = 1 + parameters.T
    bits, base_bits = magnitude.bit_length(), base.bit_length()
    if exponent * (base_bits - 1) >= bits:
        return True
    if exponent * base_bits < bits:
        return False
    return magnitude <= base ** exponent


def _check_round_state(state: PublicState) -> None:
    if not isinstance(state, PublicState):
        raise TypeError('state must be a PublicState')
    if state.level == state.parameters.d:
        raise ValueError('cannot fold the terminal state')


def _vector_public(state: PublicState, L: Module, R: Module, x: int,
                   inverse_x: int) -> VectorPublicState:
    half = len(state.generators) // 2
    generators = tuple(_add(left, _scale(right, inverse_x))
                       for left, right in zip(state.generators[:half], state.generators[half:]))
    commitment = _add(_add(state.commitment, _scale(L, inverse_x)), _scale(R, x))
    return VectorPublicState(state.parameters, state.level, generators, commitment)


def _polynomial_public(state: VectorPublicState, L: Module, R: Module, y: int,
                       inverse_y: int) -> PublicState:
    even, odd = _split(state.commitment)
    if odd != _add(L, R):
        raise ValueError('polynomial parity check failed: odd(Ctilde) != L_poly + R_poly')
    generators = tuple(_add(ge, _scale(_variable(go), inverse_y))
                       for ge, go in (_split(generator) for generator in state.generators))
    commitment = _add(_add(even, _scale(_variable(L), inverse_y)), _scale(R, y))
    return PublicState(state.parameters, state.level + 1, generators, commitment)


def initialize(parameters: FoldParameters, witness: Witness, generators: Generators) -> WitnessState:
    """Create a mathematical initial state from explicit ternary coefficients."""
    ring = _validate_generators(parameters, 0, generators, False)
    validate_witness(witness, len(generators), ring.n)
    if any(abs(value) > 1 for polynomial in witness for value in polynomial):
        raise ValueError('initial witness must have integer coefficients in {-1,0,1}')
    public = PublicState(parameters, 0, generators, module_inner(witness, generators))
    return WitnessState(public, witness)


def round_prove(state: WitnessState, x: int, y: int) -> RoundResult:
    """Compute one source-equation round for caller-supplied test challenges."""
    if not isinstance(state, WitnessState):
        raise TypeError('state must be a WitnessState')
    public = state.public
    _check_round_state(public)
    inverse_x, inverse_y = _challenge(public, x), _challenge(public, y)
    magnitude = max(abs(value) for poly in state.witness for value in poly)
    if not _within_honest_bound(magnitude, public.parameters, public.level):
        raise ValueError('integer witness exceeds the honest bound for its level')
    if module_inner(state.witness, public.generators) != public.commitment:
        raise ValueError('witness does not open the supplied commitment')
    half = len(state.witness) // 2
    left, right = state.witness[:half], state.witness[half:]
    L_vec = module_inner(left, public.generators[half:])
    R_vec = module_inner(right, public.generators[:half])
    vector_witness = tuple(tuple(a + x*b for a, b in zip(a_poly, b_poly))
                           for a_poly, b_poly in zip(left, right))
    vector_public = _vector_public(public, L_vec, R_vec, x, inverse_x)
    fe = tuple(polynomial[::2] for polynomial in vector_witness)
    fo = tuple(polynomial[1::2] for polynomial in vector_witness)
    parts = tuple(_split(generator) for generator in vector_public.generators)
    ge, go = tuple(pair[0] for pair in parts), tuple(pair[1] for pair in parts)
    # Original source definitions: there is NO Y factor inside L_poly.
    L_poly, R_poly = module_inner(fe, go), module_inner(fo, ge)
    record = RoundRecord(L_vec, R_vec, L_poly, R_poly)
    next_public = _polynomial_public(vector_public, L_poly, R_poly, y, inverse_y)
    next_witness = tuple(tuple(a + y*b for a, b in zip(a_poly, b_poly))
                         for a_poly, b_poly in zip(fe, fo))
    return RoundResult(record, VectorWitnessState(vector_public, vector_witness),
                       WitnessState(next_public, next_witness))


def round_update(state: PublicState, record: RoundRecord, x: int, y: int) -> PublicRoundResult:
    """Replay one public algebra round, including generator folding and parity."""
    _check_round_state(state)
    if not isinstance(record, RoundRecord):
        raise TypeError('record must be a RoundRecord')
    inverse_x, inverse_y = _challenge(state, x), _challenge(state, y)
    child = Ring(state.parameters.q, state.ring.n // 2)
    validate_module(record.L_vec, state.ring, state.parameters.k, 'L_vec')
    validate_module(record.R_vec, state.ring, state.parameters.k, 'R_vec')
    validate_module(record.L_poly, child, state.parameters.k, 'L_poly')
    validate_module(record.R_poly, child, state.parameters.k, 'R_poly')
    vector_public = _vector_public(state, record.L_vec, record.R_vec, x, inverse_x)
    next_public = _polynomial_public(vector_public, record.L_poly, record.R_poly, y, inverse_y)
    return PublicRoundResult(vector_public, next_public)


def replay(initial: PublicState, records: tuple[RoundRecord, ...],
           challenges: tuple[tuple[int, int], ...]) -> PublicState:
    """Replay exactly d ordered records with explicit challenges from level zero."""
    if not isinstance(initial, PublicState):
        raise TypeError('initial must be a PublicState')
    if initial.level != 0:
        raise ValueError('replay must start from the initial public state')
    require_tuple(records, 'records')
    require_tuple(challenges, 'challenges')
    if len(records) != initial.parameters.d or len(challenges) != initial.parameters.d:
        raise ValueError('replay requires exactly d records and d challenge pairs')
    for pair in challenges:
        require_tuple(pair, 'challenge pair')
        if len(pair) != 2:
            raise ValueError('each challenge pair must contain exactly x and y')
    state = initial
    for record, (x, y) in zip(records, challenges):
        state = round_update(state, record, x, y).next_state
    return state


def check_terminal(state: PublicState, opening: int) -> bool:
    """Check raw integer norm and all k terminal coordinates; NOT full Verify."""
    if not isinstance(state, PublicState):
        raise TypeError('state must be a PublicState')
    if state.level != state.parameters.d:
        raise ValueError('terminal opening requires level d')
    require_integer(opening, 'opening')
    if not _within_honest_bound(opening, state.parameters, state.parameters.d):
        return False
    return state.commitment == tuple(g.scale(opening) for g in state.generators[0])


def final_open(state: WitnessState) -> int:
    """Return the unchanged signed terminal integer after its local math checks."""
    if not isinstance(state, WitnessState):
        raise TypeError('state must be a WitnessState')
    if state.public.level != state.public.parameters.d:
        raise ValueError('final_open requires level d')
    opening = state.witness[0][0]
    if not check_terminal(state.public, opening):
        raise ValueError('terminal integer norm or commitment opening failed')
    return opening
