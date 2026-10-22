"""Check only the frozen paper's current sufficient parameter conditions.

Source: main.tex lines 346-347, 381-405, 483-488, and 644-659.
The extraction bound is NOT a hardness condition. No return status certifies
security or deployment readiness. The two-child candidate is not implemented.
All exponentiation is capped by the input modulus; huge depths are rejected
using its bit length before constructing 4**d.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ParameterValidation:
    status: str
    arithmetic_status: str
    primality_status: str
    derived: dict[str, int] = field(default_factory=dict)
    rejections: tuple[str, ...] = ()
    attacks: tuple[str, ...] = ()
    security_status: str = "not_established"


def _bounded_multiply(a: int, b: int, limit: int) -> int | None:
    """Return a*b or None without allocating a product exceeding limit."""
    if a == 0 or b == 0:
        return 0
    if a > limit // b:
        return None
    return a * b


def _bounded_power(base: int, exponent: int, limit: int) -> int | None:
    """Exact nonnegative power, with all intermediate values <= limit."""
    if limit < 1:
        return None
    result = 1
    while exponent:
        if exponent & 1:
            result = _bounded_multiply(result, base, limit)
            if result is None:
                return None
        exponent >>= 1
        if exponent:
            base = _bounded_multiply(base, base, limit)
            if base is None:
                return None
    return result


def _small_prime_status(q: int) -> str:
    """Bounded trial division; passing the screen is not a primality proof."""
    if q < 2 or (q != 2 and q % 2 == 0):
        return "composite"
    if q == 2:
        return "proven_by_trial_division"
    for divisor in range(3, 1000, 2):
        if divisor * divisor > q:
            return "proven_by_trial_division"
        if q % divisor == 0:
            return "composite"
    return "unproven"


def screen_terminal_sis(*, k: int, M: int, q: int, beta: int) -> tuple[str, ...]:
    """Certify simple attacks on the source's centered-infinity SIS relation.

    The centered-kernel screen assumes the source-required prime modulus.
    The LLL screen uses det(Lambda_perp(A)) <= q**k, so does not assume full
    row rank or estimate a rank not provided here. It uses rigorous integer
    bit bounds, which are sufficient but not exhaustive. An empty return is
    NOT evidence of hardness. Submatrix/BKZ/combinatorial attacks remain open.

    The paper requires z != 0 modulo q: q*e_j is NOT a valid witness here.
    """
    if any(type(value) is not int for value in (k, M, q, beta)):
        raise ValueError("SIS dimensions, modulus, and bound must be integers")
    if k < 1 or M < 1 or q < 3 or q % 2 == 0 or beta < 1:
        raise ValueError("positive dimensions/bound and odd q >= 3 required")
    attacks = []
    if k < M and beta >= (q - 1) // 2:
        attacks.append("terminal_centered_kernel")
    # For a 3/4-LLL basis, ||b1||_2 <= 2**((M-1)/4)*q**(k/M).
    # q < 2**q_bits; beta >= 2**(beta_bits-1). Raising to 4M gives
    # the following conservative sufficient inequality, without large powers.
    # beta < q guarantees a nonzero integer vector is nonzero modulo q.
    if k < M and beta < q:
        q_bits, beta_log_lower = q.bit_length(), beta.bit_length() - 1
        if M * (M - 1) + 4 * k * q_bits <= 4 * M * beta_log_lower:
            attacks.append("terminal_lll_bit_bound")
    return tuple(attacks)


def validate_current_parameters(*, d: int, T: int, k: int, q: int) -> ParameterValidation:
    """Validate beta0=1, M=4**d, B=(1+T)**(2*d), and the current H bound.

    ``arithmetic_status='satisfied'`` covers the explicit integer constraints,
    excluding primality and cryptographic hardness. Larger moduli are only
    screened by trial divisors <1000 and remain ``primality_status='unproven'``.
    Outputs always retain ``security_status='not_established'``.

    d=0 is the algebraic zero-round boundary; this function does not claim
    that it is a useful storage-time protocol. NTT congruence is not enforced:
    that optional condition appears only in a commented source paragraph.
    """
    values = {"d": d, "T": T, "k": k, "q": q}
    invalid_types = tuple(f"{name}_integer" for name, value in values.items()
                          if type(value) is not int)
    if invalid_types:
        return ParameterValidation("rejected_constraints", "failed", "not_checked",
                                   rejections=invalid_types)
    rejections = []
    if d < 0:
        rejections.append("depth_nonnegative")
    if T < 4 or (T & (T - 1)) != 0:
        rejections.append("challenge_bound")
    if k < 1:
        rejections.append("module_rank_positive")
    if q < 3 or q % 2 == 0:
        rejections.append("modulus_odd")
    if rejections:
        return ParameterValidation("rejected_constraints", "failed", "not_checked",
                                   rejections=tuple(rejections))

    q_bits = q.bit_length()
    derived = {"q_bits": q_bits}
    # T>=4 and B>=1 imply q > 2**(M*M+7), hence q_bits >= M*M+8.
    # The first comparison checks 2**(4*d) against q_bits without shifting.
    if 4 * d >= q_bits.bit_length():
        return ParameterValidation("rejected_constraints", "failed", "not_checked", derived,
                                   ("extraction_modulus_bit_bound",))
    M_squared = 1 << (4 * d)  # Now <= q_bits: bounded by supplied input size.
    if q_bits < M_squared + 8:
        return ParameterValidation("rejected_constraints", "failed", "not_checked", derived,
                                   ("extraction_modulus_bit_bound",))

    M, mu = 1 << (2 * d), 2 * d
    derived.update(M=M, mu=mu, beta_0=1, n_0=1 << d, N_0=1 << d)
    beta_limit = (q - 1) // 2  # Exact strict test q > 2*beta_ext.
    B = _bounded_power(T + 1, mu, beta_limit)
    H_mu = _bounded_power(2 * T, (M_squared - 1) // 3, beta_limit)
    beta_ext = 1
    if B is None or H_mu is None:
        beta_ext = None
    else:
        for factor in (2, T, T, T, B, H_mu):
            beta_ext = _bounded_multiply(beta_ext, factor, beta_limit)
            if beta_ext is None:
                break
    if beta_ext is None:
        return ParameterValidation("rejected_constraints", "failed", "not_checked", derived,
                                   ("extraction_modulus_bound",))
    derived.update(B=B, H_mu=H_mu, beta_ext=beta_ext)

    primality = _small_prime_status(q)
    attacks = screen_terminal_sis(k=k, M=M, q=q, beta=beta_ext)
    if primality == "composite":
        status, rejections = "rejected_constraints", ["modulus_composite"]
    elif attacks:
        status = "rejected_known_attack"
    elif primality == "unproven":
        status = "pending_primality_and_security_review"
    else:
        status = "pending_security_review"
    return ParameterValidation(status, "satisfied", primality, derived,
                               tuple(rejections), attacks)
