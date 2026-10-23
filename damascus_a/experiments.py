"""Bounded, explicitly low-security full-protocol experiments.

Every case runs in a separate Python process. Measurements use actual protocol
execution on generated input bytes; external evidence remains TEST_ONLY. This
entry does not change strict production policy or formal publication admission.
"""
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256, shake_256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from time import perf_counter_ns

from .backend import select_backend
from .file_codec import required_coefficients
from .fold import FoldParameters
from .telemetry import machine_info


PROFILE = 'toy-ternary32-full-v1'
SECURITY_STATUS = 'not_established_low_security_experiment'


def parse_depths(value: str) -> tuple[int, ...]:
    try:
        depths = tuple(int(item) for item in value.split(','))
    except (ValueError, AttributeError) as error:
        raise ValueError('depths must be distinct comma-separated integers in 1..7') from error
    _check_depths(depths)
    return depths


def _check_depths(depths: tuple[int, ...]) -> None:
    if (type(depths) is not tuple or not depths or len(depths) > 7
            or any(type(d) is not int or not 1 <= d <= 7 for d in depths)
            or len(set(depths)) != len(depths)):
        raise ValueError('depths must be distinct integers in 1..7')


def _capacity(d: int) -> int:
    """Exact capacity of the existing codec, no witness allocation."""
    slots = 1 << (2 * d)
    low, high = 0, slots
    while low < high:
        middle = (low + high + 1) // 2
        if required_coefficients(middle) <= slots:
            low = middle
        else:
            high = middle - 1
    return low


def _dump(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def run_experiment_matrix(output: Path, *, depths: tuple[int, ...] = (2, 3, 4),
        q: int = (1 << 31) - 1, T: int = 4, k: int = 2, epochs: int = 3,
        repetitions: int = 2, backend: str = 'cpu-fused',
        context_modes: tuple[str, ...] = ('decode', 'retained'),
        test_seed: int = 20261023, experimental_only: bool = False,
        timeout_seconds: int = 120, memory_mib: int = 512, work_budget: int = 100000000,
        environment_label: str = 'unspecified') -> dict:
    """Run complete NEW epochs at exact codec capacities, recording failures.

    Memory is checked using a conservative estimate, not an OS memory limit.
    The subprocess timeout is enforced and includes process startup and I/O.
    Input generation is deterministic test data, not simulated timing data.
    """
    if experimental_only is not True:
        raise ValueError('explicit experimental_only=True / --experimental-only is required')
    _check_depths(depths)
    for name, value, maximum in (('epochs', epochs, 32), ('repetitions', repetitions, 8),
                                 ('timeout_seconds', timeout_seconds, 600),
                                 ('memory_mib', memory_mib, 512)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f'{name} must be an integer in 1..{maximum}')
    if type(test_seed) is not int:
        raise TypeError('test_seed must be an integer')
    if (type(context_modes) is not tuple or not context_modes
            or len(set(context_modes)) != len(context_modes)
            or any(mode not in ('decode', 'retained') for mode in context_modes)):
        raise ValueError('context_modes must contain distinct decode/retained modes')
    if type(environment_label) is not str or not 1 <= len(environment_label) <= 80:
        raise ValueError('environment_label must be a nonempty string of at most 80 characters')
    selection = select_backend(backend)  # No implicit accelerator fallback.
    from .resources import ResourceBudget, preflight_resources
    budget = ResourceBudget(max_estimated_python_bytes=memory_mib * 1024**2,
                            max_estimated_operations=work_budget)
    plans = []
    for depth in depths:
        parameters = FoldParameters(depth, T, k, q)
        file_bytes = _capacity(depth)
        preflight = preflight_resources(parameters, file_bytes, epochs, budget)
        plans.append(dict(d=depth, file_bytes=file_bytes, preflight=preflight))

    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    incomplete = out / 'RUN_INCOMPLETE.json'
    _dump(incomplete, {'status': 'incomplete', 'security_status': SECURITY_STATUS})
    (out / 'inputs').mkdir()
    manifest = dict(schema='DF-experimental-matrix-v1', profile=PROFILE,
        data_kind='low_security_experiment', security_status=SECURITY_STATUS,
        security_established=False, production_ready=False, formal_measurement=False,
        external_evidence='TEST_ONLY_SIMULATED_PROVIDER',
        external_authentication_latency_measured=False,
        created_at=datetime.now(timezone.utc).isoformat(), environment_label=environment_label,
        actual_environment=machine_info(include_gpu=False), backend=asdict(selection),
        parameter_family=dict(q=hex(q), T=T, k=k, depths=list(depths)),
        epochs=epochs, repetitions=repetitions, test_seed=test_seed,
        timeout_seconds=timeout_seconds, memory_budget=asdict(budget),
        input_kind='deterministically_generated_bytes_actually_encoded_and_proved',
        process_scope='one fresh process per depth/context mode/repetition; RSS includes setup, proving, verification and diagnostics',
        cache_scope='context decoding or immutable decoded registration reuse; no generator memoization; OS/hardware caches uncontrolled',
        security_note='q bit length is a modulus size, not a security-bit estimate; per-run existing audit is retained',
        cases=[])
    for plan in plans:
        depth, file_bytes = plan['d'], plan['file_bytes']
        data = shake_256(f'DF-experimental-input-v1/{test_seed}/{depth}'.encode()).digest(file_bytes)
        input_path = out / 'inputs' / f'd{depth}.bin'
        input_path.write_bytes(data)
        for repetition in range(repetitions):
            for mode in context_modes:
                case_id = f'd{depth}-{mode}-r{repetition}'
                relative = Path('cases') / case_id
                run_output = out / relative
                command = [sys.executable, '-m', 'damascus_a', 'protocol-experiment',
                    '--output', str(run_output), '--experimental-only', '--d', str(depth),
                    '--T', str(T), '--k', str(k), '--q', hex(q), '--epochs', str(epochs),
                    '--input-file', str(input_path), '--test-seed', str(test_seed + repetition),
                    '--backend', selection.actual, '--context-mode', mode,
                    '--memory-mib', str(memory_mib), '--work-budget', str(work_budget),
                    '--profile', PROFILE]
                case = dict(case_id=case_id, d=depth, file_bytes=file_bytes,
                    context_mode=mode, repetition=repetition, profile=PROFILE,
                    security_status=SECURITY_STATUS, preflight=plan['preflight'],
                    input_sha256=sha256(data).hexdigest())
                started = perf_counter_ns()
                try:
                    result = subprocess.run(command, cwd=Path(__file__).resolve().parent.parent,
                        capture_output=True, text=True, timeout=timeout_seconds, check=False)
                    case['process_wall_ns'] = perf_counter_ns() - started
                    report_path = run_output / 'protocol-experiment.json'
                    if result.returncode != 0 or not report_path.is_file():
                        case.update(status='failed', returncode=result.returncode,
                                    error=result.stderr[-4000:])
                    else:
                        raw = report_path.read_bytes()
                        report = json.loads(raw)
                        expected_parameters = dict(d=depth, T=T, k=k,
                            q=hex(q) if q.bit_length() > 256 else q)
                        if (report.get('data_kind') != 'low_security_experiment'
                                or report.get('security_established') is not False
                                or report.get('profile') != PROFILE
                                or report.get('security_status') != SECURITY_STATUS
                                or report.get('parameters') != expected_parameters
                                or report.get('file_bytes') != file_bytes
                                or report.get('context_mode') != mode
                                or report.get('backend', {}).get('actual') != selection.actual
                                or report.get('input', {}).get('sha256') != sha256(data).hexdigest()
                                or report.get('evidence_provider', {}).get('kind') != 'TEST_ONLY_SIMULATED_PROVIDER'
                                or len(report.get('epochs', [])) != epochs
                                or any(row.get('accepted') is not True or row.get('admitted') is not True
                                       for row in report['epochs'])
                                or (run_output / 'RUN_INCOMPLETE.json').exists()):
                            case.update(status='failed', error='worker report is incomplete or mislabeled')
                        else:
                            case.update(status='ok', report=str(relative / report_path.name),
                                        report_sha256=sha256(raw).hexdigest())
                except subprocess.TimeoutExpired:
                    case.update(status='timeout', process_wall_ns=perf_counter_ns() - started,
                                error='enforced whole-worker timeout; no accepted measurement')
                except (OSError, ValueError, KeyError) as error:
                    case.update(status='failed', process_wall_ns=perf_counter_ns() - started,
                                error=str(error))
                manifest['cases'].append(case)
                _dump(out / 'matrix.json', manifest)
    manifest['status'] = ('complete' if all(case['status'] == 'ok' for case in manifest['cases'])
                          else 'complete_with_failures')
    _dump(out / 'matrix.json', manifest)
    if manifest['status'] == 'complete':
        incomplete.unlink()
    return manifest


def protocol_experiment(args) -> dict:
    """Bounded CLI input loading before calling the complete protocol runner."""
    if args.experimental_only is not True:
        raise ValueError('explicit experimental_only=True / --experimental-only is required')
    from .resources import ResourceBudget, preflight_resources
    from .protocol_run import run_protocol_experiment
    parameters = FoldParameters(args.d, args.T, args.k, args.q)
    if type(args.memory_mib) is not int or not 1 <= args.memory_mib <= 512:
        raise ValueError('memory_mib must be an integer in 1..512')
    budget = ResourceBudget(max_estimated_python_bytes=args.memory_mib * 1024**2,
                            max_estimated_operations=args.work_budget)
    if args.input_file is not None:
        if not stat.S_ISREG(args.input_file.stat().st_mode):
            raise ValueError('input must be a regular file')
        # O_NONBLOCK prevents a swapped-in FIFO from blocking before fstat on
        # POSIX. Check the opened descriptor too, and preflight its actual size.
        flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
        with os.fdopen(os.open(args.input_file, flags), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError('input must be a regular file')
            file_bytes = opened.st_size
            preflight_resources(parameters, file_bytes, args.epochs, budget)
            data = stream.read(file_bytes + 1)
        if len(data) != file_bytes:
            raise ValueError('input file changed size during bounded read')
    else:
        if len(args.input_hex) > 2 * budget.max_input_bytes:
            raise ValueError('input hex exceeds the bounded input budget')
        data = bytes.fromhex(args.input_hex)
        preflight_resources(parameters, len(data), args.epochs, budget)
    report = run_protocol_experiment(args.output, parameters=parameters, profile=args.profile,
        data=data, epochs=args.epochs, test_seed=args.test_seed, backend=args.backend,
        allow_cpu_fallback=args.allow_cpu_fallback, experimental_only=True,
        context_mode=args.context_mode, resource_budget=budget)
    print(json.dumps(dict(output=str(args.output), data_kind=report['data_kind'],
        profile=report['profile'], security_status=SECURITY_STATUS,
        accepted_epochs=len(report['epochs']), context_mode=args.context_mode)))
    return report
