"""Figures for explicitly low-security, complete-protocol local experiments.

This separate path does not relax the formal aggregator's publication gate.
Byte evidence is checked against saved artifacts; timings remain the collector's
measured observations, not external authentication or production-security data.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
import os
from pathlib import Path
from statistics import fmean


_STATUS = 'not_established_low_security_experiment'
_STAGES = ('verifier_init', 'parsing_context', 'challenges', 'generator_replay',
           'commitment_parity', 'norm', 'opening', 'admission', 'other')
_CONTEXT_LABELS = {'decode': 'wire context decode',
                   'retained-first-decode': 'retained: first decode',
                   'retained-reuse': 'retained: registration reuse'}


def _inside(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError('artifact/report path must be relative')
    target = (root / relative).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError('artifact/report path escapes its directory')
    return target


def _artifact(root: Path, item: dict) -> bytes:
    if (not isinstance(item, dict) or type(item.get('bytes')) is not int
            or not 0 <= item['bytes'] <= 16 * 1024 * 1024):
        raise ValueError('invalid artifact byte count')
    path = _inside(root, item.get('path'))
    if path.stat().st_size != item['bytes']:
        raise ValueError('artifact size mismatch')
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != item.get('sha256'):
        raise ValueError('artifact hash mismatch')
    return raw


def _ns(value, description: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError('invalid timing: ' + description)
    return value


def _scope(document: dict, profile: str) -> None:
    if (document.get('data_kind') != 'low_security_experiment'
            or document.get('profile') != profile
            or document.get('security_status') != _STATUS):
        raise ValueError('explicit low-security experimental scope is required')
    for key in ('security_established', 'publication_eligible', 'production_ready', 'certify_real_time'):
        if document.get(key, False) is not False:
            raise ValueError('experimental results cannot claim ' + key)


def summarize_experimental(matrix_path: Path) -> dict:
    """Validate collection evidence and return aggregate-only figure inputs.

    No protocol proof is re-admitted here. Complete acceptance/admission is a
    recorded collector result; hashing artifacts checks their integrity, not the
    security of parameters, an authority, or the measurement machine.
    """
    matrix_path = Path(matrix_path)
    matrix_raw = matrix_path.read_bytes()
    matrix = json.loads(matrix_raw)
    profile = matrix.get('profile')
    if matrix.get('schema') != 'DF-experimental-matrix-v1' or not isinstance(profile, str) or not profile:
        raise ValueError('unsupported experimental matrix')
    _scope(matrix, profile)
    environment = matrix.get('environment_label')
    if not isinstance(environment, str) or not environment.strip():
        raise ValueError('actual environment label is required')
    communication, verification, amortization, rss = (defaultdict(list) for _ in range(4))
    descriptions, source_hashes, failures, hardware = {}, [], [], {}
    seen_reports, seen_runs = set(), set()
    successful = 0
    for case in matrix.get('cases', []):
        if case.get('status') != 'ok':
            failures.append({key: case.get(key) for key in ('status', 'd', 'file_bytes', 'context_mode')})
            continue
        path = _inside(matrix_path.parent, case.get('report'))
        report_raw = path.read_bytes()
        if ('report_sha256' in case
                and sha256(report_raw).hexdigest() != case['report_sha256']):
            raise ValueError('report hash mismatch')
        report = json.loads(report_raw)
        run_id = report.get('run_id')
        if not isinstance(run_id, str) or not run_id:
            raise ValueError('unique report run_id is required')
        if path in seen_reports or run_id in seen_runs:
            raise ValueError('duplicate report/run cannot be a new repetition')
        seen_reports.add(path)
        seen_runs.add(run_id)
        _scope(report, profile)
        if report.get('evidence_provider', {}).get('kind') != 'TEST_ONLY_SIMULATED_PROVIDER':
            raise ValueError('this renderer requires the explicit TEST_ONLY provider scope')
        mode = case.get('context_mode')
        if mode not in ('decode', 'retained') or report.get('context_mode') != mode:
            raise ValueError('context mode mismatch')
        parameters = report['parameters']
        file_bytes = report['file_bytes']
        if case.get('d') != parameters['d'] or case.get('file_bytes') != file_bytes:
            raise ValueError('case parameter/input mismatch')
        if len(_artifact(path.parent, report['input'])) != file_bytes:
            raise ValueError('actual input artifact length mismatch')
        backend = report['backend']['actual']
        key = (report['parameter_id'], backend, file_bytes, report['hardware_id'])
        descriptions[key] = dict(parameter_id=key[0], parameters=parameters,
            backend=backend, file_bytes=file_bytes, hardware_id=report['hardware_id'])
        hardware[report['hardware_id']] = report['hardware']
        setup = _ns(report['setup_once_ns'], 'setup_once_ns')
        _ns(report['ledger_init_ns'], 'ledger_init_ns')
        seen, cumulative = set(), 0
        rows = report.get('epochs', [])
        if not rows:
            raise ValueError('no measured epochs')
        for index, row in enumerate(rows, 1):
            _scope(row, profile)
            if (row.get('accepted') is not True or row.get('admitted') is not True
                    or row.get('status') != 'ok' or row.get('epoch_sequence') != index
                    or row.get('epoch_id') in seen):
                raise ValueError('each sample must be an accepted, admitted NEW epoch')
            seen.add(row['epoch_id'])
            if row.get('context_mode') != mode or row.get('file_bytes') != file_bytes:
                raise ValueError('epoch context/input mismatch')
            first_decode = row.get('first_context_decode')
            if type(first_decode) is not bool:
                raise ValueError('explicit first_context_decode flag required')
            if mode == 'retained' and first_decode != (index == 1):
                raise ValueError('retained registration must decode on its first epoch only')
            stages = row.get('stages_ns', {})
            if set(stages) != set(_STAGES):
                raise ValueError('complete Verify timing stages are required')
            total = _ns(row.get('verify_ns'), 'verify_ns')
            call = _ns(row.get('verify_call_ns'), 'verify_call_ns')
            init = _ns(row.get('verifier_init_ns'), 'verifier_init_ns')
            if (sum(_ns(stages[name], name) for name in _STAGES) != total
                    or total != call + init or stages['verifier_init'] != init):
                raise ValueError('Verify timing intervals do not partition the full scope')
            if row.get('setup_ns') != (setup if index == 1 else 0):
                raise ValueError('setup timing must occur exactly once per run')
            serialized = row['serialization']
            proof = _artifact(path.parent, serialized['full_proof'])
            registration = _artifact(path.parent, serialized['registration'])
            parts, offset, rounds = [], 0, []
            for part in serialized['parts']:
                raw = _artifact(path.parent, part['artifact'])
                if part.get('offset') != offset:
                    raise ValueError('proof partition offsets are inconsistent')
                parts.append(raw)
                offset += len(raw)
                if part['kind'] == 'round_record':
                    rounds.append(len(raw))
            if b''.join(parts) != proof or len(rounds) != parameters['d']:
                raise ValueError('proof partition does not reproduce the complete proof')
            for artifact in row.get('auxiliary_artifacts', {}).values():
                _artifact(path.parent, artifact)
            communication[key].append((len(proof), len(registration), rounds))
            sample = ('decode' if mode == 'decode' else
                      'retained-first-decode' if first_decode else 'retained-reuse')
            verification[key + (sample,)].append(stages)
            cumulative += _ns(row.get('prove_ns'), 'prove_ns') + total
            amortization[key + (mode, index)].append(((setup + cumulative) / index,
                                                     cumulative / index))
        peak = report.get('resources', {}).get('peak_rss_bytes')
        if peak is not None and (type(peak) is not int or peak < 0):
            raise ValueError('invalid measured peak RSS')
        if peak is not None:
            rss[key + (mode,)].append(peak)
        source_hashes.append(sha256(report_raw).hexdigest())
        successful += 1
    if not successful:
        raise ValueError('no successful experimental cases to render')
    byte_rows, verify_rows, amortized_rows, rss_rows = [], [], [], []
    order = lambda key: (key[2], repr(key))
    for key, values in sorted(communication.items(), key=lambda item: order(item[0])):
        byte_rows.append(dict(descriptions[key], samples=len(values),
            full_proof_bytes=fmean(item[0] for item in values),
            registration_bytes=fmean(item[1] for item in values),
            round_record_bytes=[fmean(item[2][index] for item in values)
                                for index in range(len(values[0][2]))]))
    for key, values in sorted(verification.items(), key=lambda item: order(item[0])):
        verify_rows.append(dict(descriptions[key[:4]], context_sample=key[4], samples=len(values),
            stages_ns={stage: fmean(row[stage] for row in values) for stage in _STAGES}))
    for key, values in sorted(amortization.items(), key=lambda item: order(item[0])):
        amortized_rows.append(dict(descriptions[key[:4]], context_mode=key[4], epoch_count=key[5],
            sample_runs=len(values), including_setup_ns=fmean(item[0] for item in values),
            excluding_setup_ns=fmean(item[1] for item in values)))
    for key, values in sorted(rss.items(), key=lambda item: order(item[0])):
        rss_rows.append(dict(descriptions[key[:4]], context_mode=key[4], samples=len(values),
            peak_rss_bytes=fmean(values), minimum_bytes=min(values), maximum_bytes=max(values)))
    modes = {row['context_sample'] for row in verify_rows}
    return dict(schema='DF-experimental-figures-v1', data_kind='low_security_experiment',
        profile=profile, security_status=_STATUS, security_established=False,
        publication_eligible=False, environment_label=environment,
        source_matrix_sha256=sha256(matrix_raw).hexdigest(), source_report_sha256=source_hashes,
        hardware=hardware, successful_cases=successful, failed_cases=failures,
        evidence_provider='TEST_ONLY_SIMULATED_PROVIDER',
        limitations=['Implementation efficiency only; no production security claim.',
            'TEST_ONLY provider validation does not measure external authentication latency.',
            'Context modes concern decoding/reusing immutable registration; OS and hardware caches uncontrolled.',
            'A3 includes setup/registration once; ledger creation, artifact I/O and diagnostic replay are excluded.',
            'RSS is whole worker process high-water mark, including setup/prove/verify; not operation-local.',
            'No user i5/i9 measurements or VRAM samples are supplied; A5 baselines remain pending.'],
        figures={
            'A1': {'status': 'available', 'scope': 'Actual full proof, registration and round-record wire bytes; not network traffic.'},
            'A2': {'status': 'available' if {'decode', 'retained-reuse'} <= modes else 'partial',
                   'scope': 'Complete Verify + separately measured context initialization; first retained decode shown separately.'},
            'A3': {'status': 'available', 'scope': 'Cumulative average over distinct admitted NEW epochs.'},
            'A4': {'status': 'partial', 'scope': 'Actual environment RSS supplement only; two user platforms and VRAM pending.'},
            'A5': {'status': 'pending', 'scope': 'No comparable baseline source measurements supplied.'}},
        communication=byte_rows, verify=verify_rows, amortization=amortized_rows, rss=rss_rows)


def render_experimental(matrix_path: Path, output: Path) -> dict:
    """Render SVG/PNG and aggregate-only metadata after validating all inputs."""
    summary = summarize_experimental(matrix_path)
    # Match the existing plotting entry's cache location on read-only-home hosts.
    os.environ.setdefault('MPLCONFIGDIR', '/tmp/damascus-a-matplotlib')
    os.environ.setdefault('XDG_CACHE_HOME', '/tmp/damascus-a-cache')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    footer = (f"LOW-SECURITY EXPERIMENT | TEST_ONLY providers | actual {summary['environment_label']} environment\n"
              f"{summary['profile']} | not production security")

    def save(fig, name, note=''):
        fig.text(.5, .02, footer + ('\n' + note if note else ''), ha='center', va='bottom', fontsize=8)
        fig.tight_layout(rect=(0, .12 if note else .10, 1, 1))
        for suffix in ('svg', 'png'):
            fig.savefig(output / f'{name}.{suffix}', dpi=150)
        plt.close(fig)

    with plt.rc_context({'svg.fonttype': 'none', 'font.size': 10}):
        fig, ax = plt.subplots(figsize=(9, 5.5))
        series = summary['communication']
        sizes = [row['file_bytes'] for row in series]
        for field, label in (('full_proof_bytes', 'Complete proof (including opening)'),
                             ('registration_bytes', 'Registration (including public generators)')):
            ax.plot(sizes, [row[field] for row in series], marker='o', label=label)
        for index in range(max(len(row['round_record_bytes']) for row in series)):
            points = [row for row in series if len(row['round_record_bytes']) > index]
            ax.plot([row['file_bytes'] for row in points],
                    [row['round_record_bytes'][index] for row in points], marker='.',
                    linestyle='--', label=f'Round {index + 1} record')
        ax.set(xlabel='Actual input file bytes', ylabel='Serialized bytes (mean of observed artifacts)',
               title='A1 — Actual serialized communication objects', yscale='log')
        ax.legend(fontsize=8)
        ax.grid(alpha=.2)
        save(fig, 'A1', 'Context and TEST_ONLY evidence are separate objects; these are not network transfer measurements.')

        series = summary['verify']
        fig, ax = plt.subplots(figsize=(max(9, min(18, len(series) * .7)), 6))
        positions, bottom = list(range(len(series))), [0.0] * len(series)
        for stage in _STAGES:
            heights = [row['stages_ns'][stage] / 1e6 for row in series]
            ax.bar(positions, heights, bottom=bottom, label=stage.replace('_', ' '))
            bottom = [a + b for a, b in zip(bottom, heights)]
        ax.set_xticks(positions, [f"{row['file_bytes']} B\n{_CONTEXT_LABELS[row['context_sample']]}"
                                 for row in series], rotation=35, ha='right', fontsize=8)
        ax.set(ylabel='Complete Verify including initialization (ms)',
               title='A2 — Complete Verify: context preparation and all verification stages')
        ax.legend(ncol=3, fontsize=8)
        ax.grid(axis='y', alpha=.2)
        save(fig, 'A2', 'Registration reuse only; OS/hardware caches uncontrolled. First retained decode is a separate sample class.')

        modes = sorted({row['context_mode'] for row in summary['amortization']})
        fig, axes = plt.subplots(1, len(modes), figsize=(max(9, 6 * len(modes)), 5.7), squeeze=False)
        for ax, mode in zip(axes[0], modes):
            grouped = defaultdict(list)
            for row in summary['amortization']:
                if row['context_mode'] == mode:
                    grouped[(row['parameter_id'], row['backend'], row['hardware_id'])].append(row)
            for values in grouped.values():
                values.sort(key=lambda row: row['epoch_count'])
                line, = ax.plot([row['epoch_count'] for row in values],
                    [row['including_setup_ns'] / 1e6 for row in values], marker='o',
                    label=f"{values[0]['file_bytes']} B, with setup")
                ax.plot([row['epoch_count'] for row in values],
                    [row['excluding_setup_ns'] / 1e6 for row in values], linestyle='--',
                    color=line.get_color(), label=f"{values[0]['file_bytes']} B, without setup")
            ax.set(xlabel='Distinct admitted NEW epochs', ylabel='Average cost per epoch (ms)',
                   title=f'A3 — {mode} context', yscale='log')
            ax.legend(fontsize=8)
            ax.grid(alpha=.2)
        save(fig, 'A3', 'Prove + complete Verify; setup/registration counted once. Ledger creation and artifact I/O excluded.')

        series = summary['rss']
        fig, ax = plt.subplots(figsize=(9, 5.5))
        if series:
            means = [row['peak_rss_bytes'] / (1 << 20) for row in series]
            errors = [[(row['peak_rss_bytes'] - row['minimum_bytes']) / (1 << 20) for row in series],
                      [(row['maximum_bytes'] - row['peak_rss_bytes']) / (1 << 20) for row in series]]
            ax.bar(range(len(series)), means, yerr=errors, capsize=3)
            ax.set_xticks(range(len(series)), [f"{row['file_bytes']} B\n{row['context_mode']}" for row in series],
                          fontsize=8)
        else:
            ax.text(.5, .5, 'RSS unavailable on this environment', transform=ax.transAxes, ha='center')
        ax.set(ylabel='Worker lifetime peak RSS (MiB)',
               title=f"A4 supplement — {summary['environment_label']} environment only")
        ax.grid(axis='y', alpha=.2)
        save(fig, 'A4-cloud-supplement', 'Includes process loading, setup, prove and verify. User i5/i9 panels and VRAM: pending.')
    (output / 'A5-status.md').write_text(
        '# A5 experimental status\n\n' + footer.replace('\n', ' — ') + '\n\n'
        '| Entry | Evidence available | Status |\n| --- | --- | --- |\n'
        '| Damascus Fold | Complete low-security implementation runs in this matrix | Experimental only |\n'
        '| ADJ21 | No comparable baseline measurements supplied | pending |\n'
        '| ePoSt | No comparable baseline measurements supplied | pending |\n\n'
        'No heterogeneous timing ranking or invented baseline is plotted. '
        'Protocol semantics and baseline measurement scope require source material.\n', encoding='utf-8')
    (output / 'figures.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary
