# Mathematical reference core API

The core implements the equations in frozen `sources/paper/main.tex` lines 474–659, SHA-256 `481a41f1bb3c7dd0f971d6cee87151242910214fda3315887778b48dc9da9bd0`. Its Python integers have arbitrary precision. Every public record and state is an immutable dataclass containing immutable tuples.

This is an **algebra correctness harness**, not a complete authenticated Damascus `Verify`. A passing terminal check says only that a supplied public mathematical state satisfies the integer bound and module equation. There is no file encoder, wire profile, Fiat–Shamir hash, certified seed or context, timestamp or deadline validation, replay registry, security certification, optimized backend, or performance claim. No unresolved protocol choice is selected by this module.

## Arithmetic

```python
from damascus_a.algebra import Ring, RingElement, module_inner

ring = Ring(q=2147483647, n=2)
public_element = RingElement(ring, (1, 2147483646))
computed_element = ring.element((1, -1))
assert public_element == computed_element
```

`Ring(q, n)` requires an odd integer `q >= 3` and a positive power-of-two degree `n`. It does not prove primality or security. `RingElement(ring, coefficients)` requires an exact tuple of exactly `n` Python integers in `[0, q)`. Booleans, floats, mutable lists, and noncanonical residues reject. Public data must use this strict constructor. `ring.element(tuple_of_integers)` is a separate, explicit reduction operation for internal arithmetic and fixture construction; it must not be used to normalize malformed public inputs.

| Operation | Result |
|---|---|
| `a + b`, `a - b`, `a * b` | Canonical ring element; mixed rings reject |
| `a.scale(integer)` | Scalar multiplication modulo `q` |
| `a.times_variable()` | Multiply by the current ring variable, negacyclically |
| `a.split_even_odd()` | Pair in degree `n/2`; rejects at degree one |
| `ring.zero()` | Zero ring element |
| `ring.inverse_scalar(integer)` | Modular inverse; nonunits reject |
| `module_inner(witness, generators)` | Tuple of all `k` commitment coordinates |

At degree one, the current variable equals `-1`; `times_variable()` negates. Polynomial multiplication is an intentionally simple quadratic reference routine.

Aliases describe the tuple layout:

```python
IntegerPolynomial = tuple[int, ...]
Witness = tuple[IntegerPolynomial, ...]   # N polynomials, each n integers
Module = tuple[RingElement, ...]          # k coordinates
Generators = tuple[Module, ...]           # N generators, each k coordinates
```

The witness remains signed integers throughout every fold. `module_inner` reduces a temporary polynomial for multiplication but never rewrites the witness.

## State and result types

`FoldParameters(d, T, k, q)` checks local arithmetic shape constraints: integer `d >= 0`, positive integer `k`, power-of-two `T >= 4`, and odd `q > T`. This is deliberately separate from `validate_current_parameters` and does not gate arithmetic experiments on cryptographic security. Inverses are checked for each supplied challenge. `parameters.terminal_bound` returns the exact honest bound `B=(1+T)**(2*d)` with fixed `beta0=1`; it is not an extraction bound. Callers should select small fixture dimensions; the direct Python API is not a bounded network parser.

| Type | Fields |
|---|---|
| `PublicState` | `parameters`, `level`, `generators`, `commitment` |
| `WitnessState` | `public: PublicState`, `witness` |
| `VectorPublicState` | Same fields as `PublicState` at the intermediate vector stage |
| `VectorWitnessState` | `public: VectorPublicState`, `witness` |
| `RoundRecord` | `L_vec`, `R_vec`, `L_poly`, `R_poly` |
| `RoundResult` | `record`, `vector_state: VectorWitnessState`, `next_state: WitnessState` |
| `PublicRoundResult` | `vector_state: VectorPublicState`, `next_state: PublicState` |

The public state types expose a `.ring` property. At full round level `j`, `N=n=2**(d-j)`. At the vector intermediate state, `N` halves while `n` stays unchanged. A round record has vector terms in degree `n`, polynomial terms in degree `n/2`, and exactly `k` coordinates for every term. Constructors reject shape, ring, type, and canonicality errors. They do not certify any context or assert that a witness opens a public state merely because a dataclass exists.

## Functions

```python
initialize(parameters, witness, generators) -> WitnessState
round_prove(state: WitnessState, x: int, y: int) -> RoundResult
round_update(state: PublicState, record: RoundRecord, x: int, y: int) -> PublicRoundResult
replay(initial: PublicState,
       records: tuple[RoundRecord, ...],
       challenges: tuple[tuple[int, int], ...]) -> PublicState
final_open(state: WitnessState) -> int
check_terminal(state: PublicState, opening: int) -> bool
```

`initialize` accepts an explicit ternary coefficient array, not a file or a byte string. It checks `abs(coefficient) <= 1` and computes the initial commitment.

`round_prove` checks the current integer witness bound and its commitment equation, requires explicit `x,y` in `1..T` with inverses modulo `q`, and returns both stage states. Witness arithmetic never reduces modulo `q`.

`round_update` needs only the public state, record, and explicit challenges. It folds the generator family and commitment and rejects a failed polynomial parity check. `replay` requires level zero and exactly `d` ordered records and challenge pairs. These challenges are caller-supplied mathematical inputs, never represented as Fiat–Shamir challenges or authenticated randomness.

`final_open` returns the signed terminal integer unchanged after checking its terminal bound and opening. `check_terminal` compares the transmitted integer to `B` **before** reducing for the equation, then checks every module coordinate. The norm comparison uses exact bit bounds to avoid constructing an enormous power for a small opening; no norm approximation or additional parameter cap is introduced. Explicitly requesting `parameters.terminal_bound` still constructs that exact integer. A validly typed terminal state with a failed norm or equation returns `False`. Malformed types/shapes, nonterminal calls, invalid challenges, inconsistent prover states, or parity failures raise `TypeError` or `ValueError`.

The original source equations are preserved:

```text
L_vec = <f_L, g_R>                 R_vec = <f_R, g_L>
f_tilde = f_L + x*f_R              g_tilde = g_L + x^-1*g_R
C_tilde = C + x^-1*L_vec + x*R_vec

L_poly = <f_even, g_odd>            R_poly = <f_odd, g_even>
odd(C_tilde) = L_poly + R_poly
f_next = f_even + y*f_odd          g_next = g_even + (Y/y)*g_odd
C_next = even(C_tilde) + (Y/y)*L_poly + y*R_poly
```

There is no `Y` factor inside `L_poly`. Swapping polynomial cross terms preserves their sum and can pass parity; it is not sufficient to test parity alone.

## Minimal fixture

This fixture is not a secure parameter recommendation and produces no paper benchmark data.

```python
from damascus_a.algebra import Ring
from damascus_a.fold import (FoldParameters, initialize, round_prove,
                             replay, final_open, check_terminal)

p = FoldParameters(d=1, T=4, k=1, q=2**31-1)
r = Ring(p.q, 2)
initial = initialize(p, ((1, 0), (0, 1)),
                     ((r.element((1, 2)),), (r.element((3, 5)),)))
result = round_prove(initial, x=2, y=3)
terminal = replay(initial.public, (result.record,), ((2, 3),))
opening = final_open(result.next_state)
assert opening == 7
assert terminal.generators[0][0].coefficients == (1,)
assert terminal.commitment[0].coefficients == (7,)
assert check_terminal(terminal, opening)
assert not check_terminal(terminal, opening + p.q)
```

## Verification coverage

Run `python -m unittest discover -s tests -v` for the repository suite. The core tests compare negacyclic products against an independent ordinary integer polynomial product followed by a separate reduction. They run 120 seeded chains at `d=1,2`, checking both stage commitments, cross terms, integer witnesses, and generators independently. The fixture moduli `2**31-1` and `2**521-1` are explicitly correctness fixtures; their use does not imply Module-SIS hardness.

Counterexamples cover original cross-term orientation, swapped terms, parity corruption, omission of `Y`, the degree-one sign, negative integer lifts, values larger than 64 bits, same-residue out-of-bound openings, wrong terminal coordinates, malformed shapes and types, noncanonical residues, and missing/extra/reordered records, and huge synthetic-depth norm comparisons without materializing the bound. The zero-depth identity is also tested as a mathematical boundary case, without treating it as a deployable storage-audit configuration.
