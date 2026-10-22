"""Backend routing must never turn a GPU label into a CPU timing silently."""
from dataclasses import dataclass


class BackendUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class BackendSelection:
    requested: str
    actual: str
    fallback: bool
    reason: str | None


def select_backend(requested: str, *, allow_cpu_fallback=False) -> BackendSelection:
    if type(allow_cpu_fallback) is not bool:
        raise TypeError('allow_cpu_fallback must be a bool')
    if requested == 'cpu-reference':
        return BackendSelection(requested, requested, False, None)
    if requested != 'gpu':
        raise ValueError('backend must be cpu-reference or gpu')
    reason = 'GPU backend is not implemented for the frozen manuscript profile'
    if not allow_cpu_fallback:
        raise BackendUnavailable(reason)
    return BackendSelection(requested, 'cpu-reference', True, reason)
