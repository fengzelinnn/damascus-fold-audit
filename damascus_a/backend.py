"""Backend routing must never turn a GPU label into a CPU timing silently."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from .arithmetic import CpuFusedBackend, ExactArithmeticBackend


_ACTIVE_BACKEND = ContextVar('damascus_arithmetic_backend', default='cpu-reference')
_CPU_FUSED: ExactArithmeticBackend = CpuFusedBackend()


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
    if requested in ('cpu-reference', 'cpu-fused'):
        return BackendSelection(requested, requested, False, None)
    if requested != 'gpu':
        raise ValueError('backend must be cpu-reference, cpu-fused or gpu')
    reason = 'GPU backend is not implemented for the frozen manuscript profile'
    if not allow_cpu_fallback:
        raise BackendUnavailable(reason)
    return BackendSelection(requested, 'cpu-reference', True, reason)


def get_arithmetic_backend() -> ExactArithmeticBackend | None:
    """Return the optional kernel; None preserves the original reference path."""
    return _CPU_FUSED if _ACTIVE_BACKEND.get() == 'cpu-fused' else None


@contextmanager
def using_backend(name: str):
    """Activate an actual backend in this context, restoring it on every exit.

    A caller permitting GPU fallback must first call select_backend and pass
    its actual value here; execution never performs an implicit fallback.
    """
    selection = select_backend(name)
    token = _ACTIVE_BACKEND.set(selection.actual)
    try:
        yield
    finally:
        _ACTIVE_BACKEND.reset(token)
