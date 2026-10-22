"""Exact integer-lift folds and public algebra replay from the frozen paper.

Challenges are supplied by the caller, either as test inputs or by the separate
protocol layer. These arithmetic stages do not implement authenticated Damascus
Verify, a file codec, Fiat--Shamir suite, certified context, deadline, or replay
registry, and do not establish that any arithmetic configuration is secure.
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


def _challenge(state: PublicState | VectorPublicState, value: int) -> int:
    require_integer(value, 'challenge')
    if not 1 <= value <= state.parameters.T:
        raise ValueError('challenge must lie in 1..T')
    return state.ring.inverse_scalar(value)


def _within_honest_bound(value: int, parameters: FoldParameters, level: int,
                         *, vector_stage: bool = False) -> bool:
    """Compare the exact full-round or intermediate integer norm bound.

    Since 2**(b-1) <= base < 2**b, bit bounds decide distant cases.
    In the remaining case the power has at most roughly twice the bit length
    of the supplied value, so computing it cannot expand with an arbitrary d.
    """
    magnitude = abs(value)
    if magnitude <= 1:
        return True
    exponent = 2 * level + int(vector_stage)
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
    PublicState.__post_init__(state)
    if state.level == state.parameters.d:
        raise ValueError('cannot fold the terminal state')


def _check_vector_state(state: VectorPublicState) -> None:
    if not isinstance(state, VectorPublicState):
        raise TypeError('state must be a VectorPublicState')
    VectorPublicState.__post_init__(state)


def _check_prover_state(state: WitnessState | VectorWitnessState, *, vector_stage: bool) -> None:
    expected_type = VectorWitnessState if vector_stage else WitnessState
    if not isinstance(state, expected_type):
        raise TypeError(f'state must be a {expected_type.__name__}')
    public = state.public
    if vector_stage:
        _check_vector_state(public)
    else:
        _check_round_state(public)
    validate_witness(state.witness, len(public.generators), public.ring.n)
    magnitude = max(abs(value) for poly in state.witness for value in poly)
    if not _within_honest_bound(magnitude, public.parameters, public.level,
                                vector_stage=vector_stage):
        raise ValueError('integer witness exceeds the honest bound for its stage')
    if module_inner(state.witness, public.generators) != public.commitment:
        raise ValueError('witness does not open the supplied commitment')


def _select_cross_terms(expected: tuple[Module, Module], L: Module | None,
                        R: Module | None, ring: Ring, k: int) -> tuple[Module, Module]:
    if L is None and R is None:
        return expected
    if L is None or R is None:
        raise ValueError('both cross terms must be supplied together')
    validate_module(L, ring, k, 'L')
    validate_module(R, ring, k, 'R')
    if (L, R) != expected:
        raise ValueError('supplied cross terms do not match the witness and generators')
    return L, R


def vector_cross_terms(state: WitnessState) -> tuple[Module, Module]:
    """Validate the witness state and compute terms to bind before deriving x."""
    _check_prover_state(state, vector_stage=False)
    half = len(state.witness) // 2
    return (module_inner(state.witness[:half], state.public.generators[half:]),
            module_inner(state.witness[half:], state.public.generators[:half]))


def vector_generators(state: PublicState, x: int) -> Generators:
    """Replay only vector generator arithmetic, including typed input checks."""
    _check_round_state(state)
    inverse_x = _challenge(state, x)
    half = len(state.generators) // 2
    return tuple(_add(left, _scale(right, inverse_x))
                 for left, right in zip(state.generators[:half], state.generators[half:]))


def vector_commitment(state: PublicState, L: Module, R: Module, x: int) -> Module:
    """Replay only vector commitment arithmetic; no witness authenticity claim."""
    _check_round_state(state)
    validate_module(L, state.ring, state.parameters.k, 'L_vec')
    validate_module(R, state.ring, state.parameters.k, 'R_vec')
    inverse_x = _challenge(state, x)
    return _add(_add(state.commitment, _scale(L, inverse_x)), _scale(R, x))


def vector_update(state: PublicState, L: Module, R: Module, x: int) -> VectorPublicState:
    """Public vector fold from well-typed terms and an explicit challenge."""
    commitment = vector_commitment(state, L, R, x)
    generators = vector_generators(state, x)
    return VectorPublicState(state.parameters, state.level, generators, commitment)


def vector_prove(state: WitnessState, x: int, L: Module | None = None,
                 R: Module | None = None) -> VectorWitnessState:
    """Fold an integer witness; optional prebound terms must match recomputation."""
    terms = vector_cross_terms(state)
    L, R = _select_cross_terms(terms, L, R, state.public.ring, state.public.parameters.k)
    public = vector_update(state.public, L, R, x)
    half = len(state.witness) // 2
    witness = tuple(tuple(a + x*b for a, b in zip(left, right))
                    for left, right in zip(state.witness[:half], state.witness[half:]))
    return VectorWitnessState(public, witness)


def parity_validate(state: VectorPublicState, L: Module, R: Module) -> None:
    """Validate polynomial shapes and odd(Ctilde)=L+R before deriving y."""
    _check_vector_state(state)
    child = Ring(state.parameters.q, state.ring.n // 2)
    validate_module(L, child, state.parameters.k, 'L_poly')
    validate_module(R, child, state.parameters.k, 'R_poly')
    _, odd = _split(state.commitment)
    if odd != _add(L, R):
        raise ValueError('polynomial parity check failed: odd(Ctilde) != L_poly + R_poly')


def polynomial_cross_terms(state: VectorWitnessState) -> tuple[Module, Module]:
    """Compute original polynomial terms with no Y in L; check parity before y."""
    _check_prover_state(state, vector_stage=True)
    fe = tuple(polynomial[::2] for polynomial in state.witness)
    fo = tuple(polynomial[1::2] for polynomial in state.witness)
    parts = tuple(_split(generator) for generator in state.public.generators)
    ge, go = tuple(pair[0] for pair in parts), tuple(pair[1] for pair in parts)
    L, R = module_inner(fe, go), module_inner(fo, ge)
    parity_validate(state.public, L, R)
    return L, R


def polynomial_generators(state: VectorPublicState, y: int) -> Generators:
    """Replay generator arithmetic after the caller's pre-challenge parity check."""
    _check_vector_state(state)
    inverse_y = _challenge(state, y)
    return tuple(_add(ge, _scale(_variable(go), inverse_y))
                 for ge, go in (_split(generator) for generator in state.generators))


def polynomial_commitment(state: VectorPublicState, L: Module, R: Module, y: int) -> Module:
    """Check parity first, then replay only polynomial commitment arithmetic."""
    parity_validate(state, L, R)
    inverse_y = _challenge(state, y)
    even, _ = _split(state.commitment)
    return _add(_add(even, _scale(_variable(L), inverse_y)), _scale(R, y))


def polynomial_update(state: VectorPublicState, L: Module, R: Module, y: int) -> PublicState:
    """Public polynomial fold; standalone use also rechecks parity before y."""
    commitment = polynomial_commitment(state, L, R, y)
    generators = polynomial_generators(state, y)
    return PublicState(state.parameters, state.level + 1, generators, commitment)


def polynomial_prove(state: VectorWitnessState, y: int, L: Module | None = None,
                     R: Module | None = None) -> WitnessState:
    """Finish the integer fold; supplied prebound terms must equal recomputation."""
    terms = polynomial_cross_terms(state)
    child = Ring(state.public.parameters.q, state.public.ring.n // 2)
    L, R = _select_cross_terms(terms, L, R, child, state.public.parameters.k)
    public = polynomial_update(state.public, L, R, y)
    witness = tuple(tuple(a + y*b for a, b in zip(polynomial[::2], polynomial[1::2]))
                    for polynomial in state.witness)
    return WitnessState(public, witness)


def initialize(parameters: FoldParameters, witness: Witness, generators: Generators) -> WitnessState:
    """Create a mathematical initial state from explicit ternary coefficients."""
    ring = _validate_generators(parameters, 0, generators, False)
    validate_witness(witness, len(generators), ring.n)
    if any(abs(value) > 1 for polynomial in witness for value in polynomial):
        raise ValueError('initial witness must have integer coefficients in {-1,0,1}')
    public = PublicState(parameters, 0, generators, module_inner(witness, generators))
    return WitnessState(public, witness)


def round_prove(state: WitnessState, x: int, y: int) -> RoundResult:
    """Compatibility round API, composed from the validated staged prover."""
    L_vec, R_vec = vector_cross_terms(state)
    vector = vector_prove(state, x, L_vec, R_vec)
    L_poly, R_poly = polynomial_cross_terms(vector)
    next_state = polynomial_prove(vector, y, L_poly, R_poly)
    return RoundResult(RoundRecord(L_vec, R_vec, L_poly, R_poly), vector, next_state)


def round_update(state: PublicState, record: RoundRecord, x: int, y: int) -> PublicRoundResult:
    """Compatibility public round API, composed from the validated stages."""
    _check_round_state(state)
    if not isinstance(record, RoundRecord):
        raise TypeError('record must be a RoundRecord')
    child = Ring(state.parameters.q, state.ring.n // 2)
    validate_module(record.L_vec, state.ring, state.parameters.k, 'L_vec')
    validate_module(record.R_vec, state.ring, state.parameters.k, 'R_vec')
    validate_module(record.L_poly, child, state.parameters.k, 'L_poly')
    validate_module(record.R_poly, child, state.parameters.k, 'R_poly')
    vector = vector_update(state, record.L_vec, record.R_vec, x)
    next_state = polynomial_update(vector, record.L_poly, record.R_poly, y)
    return PublicRoundResult(vector, next_state)


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
