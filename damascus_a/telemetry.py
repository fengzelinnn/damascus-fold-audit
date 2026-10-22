"""Local preflight and true elapsed timings. No hardware specifications assumed."""
from contextlib import contextmanager
import json
import os
import platform
import subprocess
from time import perf_counter_ns
from pathlib import Path


class Timer:
    def __init__(self):
        self.stages_ns = {}

    @contextmanager
    def stage(self, name):
        if not isinstance(name, str) or not name or name in self.stages_ns:
            raise ValueError('stage names must be unique nonempty strings')
        self.stages_ns[name] = None
        started = perf_counter_ns()
        try:
            yield
        finally:
            self.stages_ns[name] = perf_counter_ns() - started


def peak_rss_bytes():
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if platform.system() == 'Darwin' else value * 1024)
    except (ImportError, OSError, ValueError):
        return None


def machine_info(*, include_gpu=True):
    result = {'os': platform.system(), 'os_release': platform.release(),
              'architecture': platform.machine(), 'python': platform.python_version(),
              'logical_cpu_count': os.cpu_count(), 'cpu_model': None,
              'ram_total_bytes': None, 'gpus': [], 'gpu_query_status': 'not_requested'}
    if platform.system() == 'Linux':
        try:
            for line in Path('/proc/cpuinfo').read_text().splitlines():
                if line.startswith('model name'):
                    result['cpu_model'] = line.split(':', 1)[1].strip(); break
            for line in Path('/proc/meminfo').read_text().splitlines():
                if line.startswith('MemTotal:'):
                    result['ram_total_bytes'] = int(line.split()[1]) * 1024; break
        except (OSError, ValueError):
            pass
    elif platform.system() == 'Windows':
        # PowerShell only reads model and memory; never hostnames, serials or users.
        try:
            command = '@{cpu=(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name);ram=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory} | ConvertTo-Json -Compress'
            p = subprocess.run(['powershell', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=10, check=True)
            values = json.loads(p.stdout)
            result['cpu_model'] = values.get('cpu'); result['ram_total_bytes'] = int(values['ram'])
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    if include_gpu:
        try:
            p = subprocess.run(['nvidia-smi','--query-gpu=name,memory.total,driver_version',
                                '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=5, check=True)
            for line in p.stdout.strip().splitlines():
                name, memory, driver = [item.strip() for item in line.rsplit(',', 2)]
                result['gpus'].append({'name':name,'vram_total_bytes':int(memory)*1024*1024,'driver_version':driver})
            result['gpu_query_status'] = 'ok'
        except FileNotFoundError:
            result['gpu_query_status'] = 'nvidia_smi_not_found'
        except (OSError, ValueError, subprocess.SubprocessError):
            result['gpu_query_status'] = 'nvidia_smi_failed'
    return result
