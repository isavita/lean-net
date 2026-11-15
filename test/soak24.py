#!/usr/bin/env python3
"""Strict 24-hour, rate-controlled plain/TLS HTTP/2 soak controller.

This tool never builds. It snapshots committed binaries and source, starts two
servers, warms persistent h2load sessions, and measures a common 86,400-second
window. --smoke-seconds exercises orchestration but can NEVER pass the soak gate.
See test/production-hardening.md for the JSON contract and exact acceptance.
"""
import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import http.client
from importlib.metadata import version
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tls/test"))
from tls_test_support import create_certificates, NAMES, openssl_binary

DAY = 86400
FLOOR_RPS = 10000
OFFERED_RPS = 10200
LOG_HEALTH_METRICS = {
    'accepted': 'lean_net_access_log_accepted_total',
    'written': 'lean_net_access_log_written_total',
    'dropped': 'lean_net_access_log_dropped_total',
    'io_errors': 'lean_net_access_log_io_errors_total',
    'pending': 'lean_net_access_log_pending_records',
}
# Global native limits: at most256 worker lanes, each at most65536 records.
# Actual CLI queues are smaller. Pending is transient, not a zero-valued gate.
LOG_MAX_PENDING_RECORDS = 256 * 65536
METRIC_LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+[^\s]+)?$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"(?:,|$)')


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def checked(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed {command}: {result.stderr}")
    return result.stdout.strip()


class ClockGuard:
    """Reject suspend/clock discontinuities and blind monitoring intervals.

    macOS monotonic time can exclude system sleep. Comparing it to UTC wall
    time catches that pause; checking both deltas also catches SIGSTOP or a
    scheduler outage when both clocks advance together. Limits are fixed.
    """
    MAX_DIVERGENCE_SECONDS = 2.0
    MAX_OBSERVATION_GAP_SECONDS = 5.0

    def __init__(self, wall, monotonic):
        self.first_wall = self.last_wall = wall
        self.first_monotonic = self.last_monotonic = monotonic
        self.checks = 0
        self.max_divergence = self.max_wall_gap = self.max_monotonic_gap = 0.0

    def check(self, wall, monotonic):
        if not math.isfinite(wall) or not math.isfinite(monotonic):
            raise RuntimeError('nonfinite soak clock reading')
        wall_gap = wall - self.last_wall
        monotonic_gap = monotonic - self.last_monotonic
        divergence = (wall - self.first_wall) - (monotonic - self.first_monotonic)
        self.checks += 1
        self.max_divergence = max(self.max_divergence, abs(divergence))
        self.max_wall_gap = max(self.max_wall_gap, wall_gap)
        self.max_monotonic_gap = max(self.max_monotonic_gap, monotonic_gap)
        self.last_wall, self.last_monotonic = wall, monotonic
        if monotonic_gap < 0:
            raise RuntimeError('soak monotonic clock moved backward')
        if abs(divergence) > self.MAX_DIVERGENCE_SECONDS:
            raise RuntimeError('soak wall/monotonic divergence exceeded2s (suspend or clock discontinuity)')
        if wall_gap > self.MAX_OBSERVATION_GAP_SECONDS or monotonic_gap > self.MAX_OBSERVATION_GAP_SECONDS:
            raise RuntimeError('soak monitoring gap exceeded5s (suspend, stop or scheduler outage)')

    def summary(self):
        return {'checks': self.checks, 'max_divergence_seconds': self.max_divergence,
                'max_wall_gap_seconds': self.max_wall_gap, 'max_monotonic_gap_seconds': self.max_monotonic_gap,
                'allowed_divergence_seconds': self.MAX_DIVERGENCE_SECONDS,
                'allowed_observation_gap_seconds': self.MAX_OBSERVATION_GAP_SECONDS,
                'wall_elapsed_seconds': self.last_wall - self.first_wall,
                'monotonic_elapsed_seconds': self.last_monotonic - self.first_monotonic}


def counter(text, selector):
    """Sum matching integer samples; absent/malformed counters are failures."""
    result, matches, identities = 0, 0, set()
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        match = METRIC_LINE.fullmatch(line)
        if not match:
            raise ValueError('malformed Prometheus sample: ' + line[:160])
        if match[1] != selector['name']:
            continue
        labels, position = {}, 0
        raw = match[2] or ''
        while position < len(raw):
            label = LABEL.match(raw, position)
            if not label or label[1] in labels:
                raise ValueError('malformed/duplicate Prometheus label')
            labels[label[1]] = json.loads('"' + label[2] + '"')
            position = label.end()
        if any(labels.get(key) != value for key, value in selector.get('labels', {}).items()):
            continue
        identity = tuple(sorted(labels.items()))
        if identity in identities:
            raise ValueError('duplicate selected Prometheus series')
        identities.add(identity)
        value = Decimal(match[3])
        if not value.is_finite() or value < 0 or value != int(value):
            raise ValueError('required counter is not a nonnegative integer')
        result += int(value)
        matches += 1
    if not matches:
        raise ValueError('required metric selector has no samples: ' + repr(selector))
    return result


def parse_load(text, expected_size, planned_requests=None):
    count = re.search(r'requests:\s*(\d+) total,\s*(\d+) started,\s*(\d+) done,\s*(\d+) succeeded,\s*(\d+) failed,\s*(\d+) errored,\s*(\d+) timeout', text)
    status = re.search(r'status codes:\s*(\d+) 2xx,\s*(\d+) 3xx,\s*(\d+) 4xx,\s*(\d+) 5xx', text)
    data = re.search(r'\((\d+)\) data', text)
    rate = re.search(r'finished in ([^,]+),\s*([\d.]+) req/s', text)
    proto = re.search(r'Application protocol:\s*(\S+)', text)
    if not all((count, status, data, rate, proto)):
        raise ValueError('unrecognized h2load summary')
    total, started, done, succeeded, failed, errored, timeout = map(int, count.groups())
    valid = (total == started == done == succeeded and done > 0 and failed == errored == timeout == 0
             and (planned_requests is None or total == planned_requests)
             and list(map(int, status.groups())) == [done, 0, 0, 0]
             and int(data[1]) == succeeded * expected_size and proto[1] in ('h2', 'h2c'))
    return {'total': total, 'started': started, 'done': done, 'succeeded': succeeded,
            'failed': failed, 'errored': errored, 'timeouts': timeout,
            'data_bytes': int(data[1]), 'status_counts': list(map(int, status.groups())),
            'protocol': proto[1], 'reported_rps': float(rate[2]), 'valid': valid}


def loader_command(binary, server, warmup, duration, tail):
    """Finite requests let final active streams finish instead of canceling."""
    pacing_seconds = math.ceil(warmup + duration + tail + 10)
    connections, rps = server.get('connections', 10), server.get('rps_per_client', 510)
    requests = pacing_seconds * connections * rps
    if not 0 < requests <= 2**64 - 1:
        raise ValueError('planned h2load request count exceeds unsigned 64-bit range')
    command = [str(binary), '-n', str(requests), '-c', str(connections),
               '-m', '100', '-t', '1', '--rps=' + str(rps), '-N', '10s',
               '--alpn-list=h2', '--connect-to=127.0.0.1:' + str(server['port']),
               f"{server['scheme']}://{server['authority']}:{server['port']}{server['path']}"]
    return command, {'planned_requests': requests, 'planned_requests_per_client': requests // connections,
                     'planned_pacing_seconds': pacing_seconds, 'termination': 'finite_count_drain'}


def loader_completion_bounds(servers, plans):
    if len(servers) != len(plans):
        raise ValueError('loader completion plan count mismatch')
    offered = [server.get('connections', 10) * server.get('rps_per_client', 510) for server in servers]
    rows = []
    for server, plan, rate in zip(servers, plans, offered):
        other_offered = sum(offered) - rate
        minimum = FLOOR_RPS - other_offered
        if minimum <= 0:
            raise ValueError('offered split lacks a positive minimum feasible per-loader completion rate')
        deadline = plan['planned_requests'] / minimum + 30
        rows.append({'name': server['name'], 'offered_rps': rate, 'other_loaders_offered_rps': other_offered,
                     'minimum_feasible_rps': minimum, 'planned_requests': plan['planned_requests'],
                     'nominal_pacing_seconds': plan['planned_pacing_seconds'],
                     'deadline_seconds_from_load_start': deadline,
                     'maximum_extra_seconds_over_nominal': deadline - plan['planned_pacing_seconds']})
    return {'formula': 'minimum_feasible_rps = required aggregate floor - other loaders offered RPS; deadline = max(planned requests / minimum feasible RPS +30 seconds)',
            'measured_window_and_rate_gate_unchanged': True, 'loaders': rows,
            'deadline_seconds_from_load_start': max(row['deadline_seconds_from_load_start'] for row in rows)}


def process_resources(pid):
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes
        class Memory(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD),
                        *[(name, ctypes.c_size_t) for name in ('peak_rss', 'rss', 'peak_pool', 'pool', 'peak_nonpool', 'nonpool', 'pagefile', 'peak_pagefile')]]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetProcessHandleCount.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000 | 0x10, False, pid)
        if not handle:
            raise OSError(ctypes.get_last_error(), 'OpenProcess')
        try:
            memory = Memory(); memory.cb = ctypes.sizeof(memory)
            count = wintypes.DWORD()
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb) or not kernel.GetProcessHandleCount(handle, ctypes.byref(count)):
                raise OSError(ctypes.get_last_error(), 'process resource sampling')
            created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
            exit_code = wintypes.DWORD()
            if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel_time), ctypes.byref(user_time)) or not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                raise OSError(ctypes.get_last_error(), 'process lifetime sampling')
            if exit_code.value != 259 or exited.dwHighDateTime or exited.dwLowDateTime:
                raise RuntimeError('process family member has exited')
            image = ctypes.create_unicode_buffer(32768); image_size = wintypes.DWORD(len(image))
            if not kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(image_size)):
                raise OSError(ctypes.get_last_error(), 'process image sampling')
            identity = (created.dwHighDateTime << 32) | created.dwLowDateTime
            return {'rss_bytes': memory.rss, 'fds_or_handles': count.value, 'resource_kind': 'process_handles', 'start_identity': str(identity), 'executable': image.value}
        finally:
            kernel.CloseHandle(handle)
    rss = int(checked(['ps', '-o', 'rss=', '-p', str(pid)])) * 1024
    directory = Path(f'/proc/{pid}/fd')
    if directory.is_dir():
        descriptors = len(list(directory.iterdir()))
    else:
        output = checked(['lsof', '-nP', '-F', 'f', '-p', str(pid)])
        descriptors = len({int(line[1:]) for line in output.splitlines() if re.fullmatch(r'f[0-9]+', line)})
    if sys.platform == 'darwin':
        import ctypes
        libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        libproc.proc_pidpath.restype = ctypes.c_int
        image = ctypes.create_string_buffer(4096)
        if libproc.proc_pidpath(pid, image, len(image)) <= 0:
            raise OSError(ctypes.get_errno(), 'process executable sampling')
        executable = os.fsdecode(image.value)
    else:
        executable = os.readlink(f'/proc/{pid}/exe')
    return {'rss_bytes': rss, 'fds_or_handles': descriptors, 'resource_kind': 'numeric_file_descriptors', 'executable': executable}


def process_table():
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes
        class Entry(ctypes.Structure):
            _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                        ('pid', wintypes.DWORD), ('heap', ctypes.c_size_t),
                        ('module', wintypes.DWORD), ('threads', wintypes.DWORD),
                        ('parent_pid', wintypes.DWORD), ('priority', wintypes.LONG),
                        ('flags', wintypes.DWORD), ('exe', wintypes.WCHAR * 260)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        kernel.Process32FirstW.restype = wintypes.BOOL
        kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        kernel.Process32NextW.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), 'process snapshot')
        result = {}
        try:
            entry = Entry(); entry.dwSize = ctypes.sizeof(entry)
            valid = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while valid:
                if len(result) >= 100000:
                    raise RuntimeError('process snapshot entry budget exceeded')
                result[int(entry.pid)] = {'parent_pid': int(entry.parent_pid), 'command': entry.exe,
                                          'state': 'running'}
                valid = kernel.Process32NextW(snapshot, ctypes.byref(entry))
            if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
                raise OSError(ctypes.get_last_error(), 'process enumeration')
            return result
        finally:
            kernel.CloseHandle(snapshot)
    text = checked(['ps', '-axo', 'pid=,ppid=,lstart=,stat='], env={**os.environ, 'LC_ALL': 'C'})
    if len(text) > 16 * 1024**2:
        raise RuntimeError('process snapshot byte budget exceeded')
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 8:
            raise RuntimeError('unrecognized process-table identity format')
        result[int(fields[0])] = {'parent_pid': int(fields[1]), 'start_identity': ' '.join(fields[2:7]),
                                  'state': fields[7]}
    return result


def family_members(root_pid, table):
    if root_pid not in table:
        raise RuntimeError('server process is absent from process census')
    family = {root_pid: table[root_pid]}
    for _ in range(64):
        added = {pid: item for pid, item in table.items()
                 if pid not in family and item['parent_pid'] in family}
        if not added:
            return family
        family.update(added)
        if len(family) > 64:
            raise RuntimeError('server process-family budget exceeded')
    raise RuntimeError('process-family traversal budget exhausted')


def sample_process_family(root_pid):
    before = family_members(root_pid, process_table())
    members = []
    kind = None
    for pid, item in sorted(before.items()):
        if item['state'].startswith('Z'):
            raise RuntimeError('server process-family member is a zombie')
        resources = process_resources(pid)
        kind = resources['resource_kind']
        identity = resources.get('start_identity', item.get('start_identity'))
        stat = Path(f'/proc/{pid}/stat')
        if sys.platform == 'linux':
            # proc start ticks distinguish PID reuse at finer resolution than ps.
            values = stat.read_text().rsplit(')', 1)[1].split()
            if len(values) < 20 or values[0] == 'Z':
                raise RuntimeError('invalid/exited process-family identity')
            identity = 'proc_ticks:' + values[19]
        if identity is None:
            raise RuntimeError('process-family creation identity is unavailable')
        members.append({'pid': pid, 'parent_pid': item['parent_pid'], 'start_identity': identity,
                        'state': item['state'], **resources})
    after = family_members(root_pid, process_table())
    if any(item['state'].startswith('Z') for item in after.values()):
        raise RuntimeError('server process-family member exited during census')
    if before != after:
        # Run/sleep state naturally changes; membership, parents and creation
        # identities must remain fixed across this single census.
        clean = lambda data: {pid: {key: value for key, value in item.items() if key != 'state'} for pid, item in data.items()}
        if clean(before) != clean(after):
            raise RuntimeError('server process family changed while sampling')
    return {'rss_bytes': sum(row['rss_bytes'] for row in members),
            'fds_or_handles': sum(row['fds_or_handles'] for row in members),
            'resource_kind': 'family_sum_' + str(kind), 'family_count': len(members),
            'child_count': len(members) - 1, 'family': members}


def tls_context(ca, protocol):
    context = ssl.create_default_context(cafile=str(ca))
    context.set_alpn_protocols([protocol])
    return context


def connect(server, context=None):
    raw = socket.create_connection(('127.0.0.1', server['port']), timeout=5)
    try:
        return context.wrap_socket(raw, server_hostname=server['authority']) if context else raw
    except BaseException:
        raw.close()
        raise


def metrics(server, ca, clients):
    sock = clients.get(server['name'])
    if sock is None:
        sock = connect(server, tls_context(ca, 'http/1.1') if server['scheme'] == 'https' else None)
        clients[server['name']] = sock
    sock.sendall(f"GET {server['metrics_path']} HTTP/1.1\r\nHost: {server['authority']}\r\nConnection: keep-alive\r\n\r\n".encode())
    response = http.client.HTTPResponse(sock); response.begin()
    body = response.read(65537)
    if response.status != 200 or len(body) > 65536 or not response.isclosed() or response.will_close:
        raise RuntimeError('invalid, oversized or nonpersistent metrics response')
    text = body.decode('utf-8')
    log_health(text)
    return {name: counter(text, selector) for name, selector in server['metrics'].items()}, text


def log_health(text):
    """Fixed native schema; independent of the four configured request selectors."""
    health = {key: counter(text, {'name': name}) for key, name in LOG_HEALTH_METRICS.items()}
    check_log_health(health)
    return health


def check_log_health(health):
    if health['dropped'] or health['io_errors']:
        raise RuntimeError('access log dropped records or reported an I/O error')
    if health['pending'] > LOG_MAX_PENDING_RECORDS:
        raise RuntimeError('access log pending records exceed native global queue bounds')


def probe(server, ca, clients):
    from http2_test_support import H2Client
    # Persistent independent sessions keep sampling from adding connection churn
    # or manufacturing resets. Histories are cleared while HPACK state survives.
    client = clients.get(server['name'])
    if client is None:
        sock = connect(server, tls_context(ca, 'h2') if server['scheme'] == 'https' else None)
        try:
            if isinstance(sock, ssl.SSLSocket) and sock.selected_alpn_protocol() != 'h2':
                raise RuntimeError('verified TLS probe failed ALPN h2')
            client = H2Client(sock=sock, authority=server['authority'].encode(), scheme=server['scheme'].encode())
            client.soak_stream = 1
            clients[server['name']] = client
        except BaseException:
            sock.close()
            raise
    stream = client.soak_stream
    if stream > 0x7fffffff:
        raise RuntimeError('independent probe stream budget exhausted')
    client.request(stream, server['path'].encode())
    body = client.response(stream)
    if body != bytes.fromhex(server['body_hex']):
        raise RuntimeError('independent response-body mismatch: ' + body[:64].hex())
    client.soak_stream += 2
    client.frames.clear(); client.blocks.clear(); client.data_order.clear()
    client.headers.clear(); client.bodies.clear(); client.ended.clear()
    return len(body)


def close_probe(client):
    # Called after server SIGINT: consume GOAWAY and the transport's graceful
    # end, including TLS close_notify, then acknowledge TLS shutdown.
    try:
        for _ in range(128):
            try:
                client.read()
            except EOFError:
                if client.buffer:
                    raise RuntimeError('truncated frame during probe shutdown')
                break
        else:
            raise RuntimeError('probe shutdown frame budget exceeded')
        if isinstance(client.sock, ssl.SSLSocket):
            raw = client.sock.unwrap(); raw.close()
    finally:
        client.close()


def available_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def terminate(process, graceful=False):
    if process.poll() is None:
        if graceful:
            process.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGINT)
        else:
            process.kill()
        try:
            return process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)
            raise RuntimeError('bounded process shutdown deadline exceeded')
    return process.returncode


def validate(config, smoke):
    servers = config.get('servers', [])
    if len({item.get('name') for item in servers}) != len(servers):
        raise ValueError('server names must be unique')
    if len(servers) != 2 or {item.get('scheme') for item in servers} != {'http', 'https'}:
        raise ValueError('exactly one plain and one TLS server is required')
    duration = float(smoke if smoke is not None else config.get('duration_seconds', DAY))
    warmup, tail = float(config.get('warmup_seconds', 300)), float(config.get('tail_seconds', 30))
    sample = float(config.get('sample_seconds', 60))
    if not all(math.isfinite(v) for v in (duration, warmup, tail, sample)) or duration <= 0 or (smoke is None and duration < DAY) or warmup < 1 or tail < 10 or not 60 <= sample <= 300:
        raise ValueError('invalid duration/warmup/tail/sample bounds; short runs require explicit --smoke-seconds')
    aggregate = 0
    for server in servers:
        for field in ('name', 'binary', 'args', 'path', 'body_hex', 'metrics'):
            if field not in server:
                raise ValueError('missing server field: ' + field)
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', server['name']) or not server['path'].startswith('/') or len(bytes.fromhex(server['body_hex'])) > 65536:
            raise ValueError('invalid server name/path/body bounds')
        if set(server['metrics']) != {'completed', 'errors', 'timeouts', 'resets'}:
            raise ValueError('completed/errors/timeouts/resets metric selectors are required')
        for selector in server['metrics'].values():
            if not re.fullmatch(r'[a-zA-Z_:][a-zA-Z0-9_:]*', selector['name']):
                raise ValueError('invalid metric selector')
        connections = server.get('connections', 10); rps = server.get('rps_per_client', 510)
        if type(connections) is not int or type(rps) is not int:
            raise ValueError('loader rate and connection count must be exact integers')
        if not isinstance(server['args'], list) or not all(isinstance(value, str) for value in server['args']):
            raise ValueError('server args must be an array of literal argument strings')
        if any(value == '--reload-certs-ms' or value.startswith('--reload-certs-ms=') for value in server['args']):
            raise ValueError('periodic certificate reload must be disabled during the strict soak')
        if not 1 <= connections <= 1000 or not 1 <= rps <= 100000:
            raise ValueError('invalid loader request/connection rate')
        aggregate += connections * rps
    if aggregate != OFFERED_RPS:
        raise ValueError('predeclared offered aggregate must be exactly 10,200 RPS')
    for server in servers:
        rate = server.get('connections', 10) * server.get('rps_per_client', 510)
        if FLOOR_RPS - (aggregate - rate) <= 0:
            raise ValueError('offered split lacks a positive minimum feasible per-loader completion rate')
    return duration, warmup, tail, sample


def assess_sample(previous, current, baseline, require_rate=True):
    completed = 0
    if [row['name'] for row in previous['servers']] != [row['name'] for row in current['servers']]:
        raise RuntimeError('resource sample server identity/order changed')
    for before, row, first in zip(previous['servers'], current['servers'], baseline['servers']):
        for value in (first['log_health'], before['log_health'], row['log_health']):
            check_log_health(value)
        for key in ('accepted', 'written', 'dropped', 'io_errors'):
            if row['log_health'][key] < before['log_health'][key]:
                raise RuntimeError('access log counter reset/decrease during measurement')
        if not row.get('family') or not first.get('family'):
            raise RuntimeError('missing whole-service process-family census')
        signature = lambda value: [(p['pid'], p['parent_pid'], p['start_identity']) for p in value['family']]
        if signature(row) != signature(first):
            raise RuntimeError('server process-family identity/count changed')
        for member, original in zip(row['family'], first['family']):
            if member['fds_or_handles'] > original['fds_or_handles']:
                raise RuntimeError('FD/handle count increased in a process-family member')
        for key in ('completed', 'errors', 'timeouts', 'resets'):
            if row['counters'][key] < before['counters'][key]:
                raise RuntimeError('counter reset/decrease during measurement')
        if row['counters']['errors'] != first['counters']['errors'] or row['counters']['timeouts'] != first['counters']['timeouts'] or row['counters']['resets'] != first['counters']['resets']:
            raise RuntimeError('request error or connection reset during measured window')
        count = row['counters']['completed'] - before['counters']['completed'] - (row['probes_completed'] - before['probes_completed'])
        if count < 0:
            raise RuntimeError('completion/probe counters violate conservation')
        completed += count
        if first['rss_bytes'] <= 0 or row['rss_bytes'] * 100 >= first['rss_bytes'] * 101:
            raise RuntimeError('RSS growth reached/exceeded strict 1% limit')
        if row['fds_or_handles'] > first['fds_or_handles']:
            raise RuntimeError('FD/handle count increased during steady persistent load')
    elapsed = current['monotonic'] - previous['monotonic']
    if elapsed <= 0:
        raise RuntimeError('nonpositive sample duration')
    if require_rate and completed / elapsed < FLOOR_RPS:
        raise RuntimeError('achieved successful request rate fell below 10,000 RPS in sample interval')
    return {'successful_requests': completed, 'seconds': elapsed, 'achieved_rps': completed / elapsed}


def run(args):
    config = json.loads(args.config.read_text())
    duration, warmup, tail, interval = validate(config, args.smoke_seconds)
    if args.output.exists():
        raise ValueError('output already exists; choose fresh evidence directory')
    args.output.mkdir(parents=True)
    source_sha = checked(['git', 'rev-parse', 'HEAD'], cwd=ROOT)
    dirty = checked(['git', 'status', '--porcelain'], cwd=ROOT)
    if args.smoke_seconds is None and (dirty or source_sha != args.source_sha):
        raise ValueError('full soak requires clean source and exact --source-sha at launch')
    if version('hpack') != '4.2.0':
        raise ValueError('independent decoder must be pinned hpack4.2.0')
    h2load = shutil.which(args.h2load)
    if not h2load:
        raise ValueError('h2load executable not found')
    help_text = checked([h2load, '--help'])
    if '--rps=' not in help_text or 'for each  client' not in help_text:
        raise ValueError('installed h2load lacks verified per-client request-rate option')
    report = {'started_utc': utc(), 'source_sha': source_sha, 'source_dirty': dirty,
              'profile': 'smoke' if args.smoke_seconds is not None else 'full24h',
              'measured_duration_required': duration, 'warmup_seconds': warmup, 'tail_seconds': tail,
              'offered_aggregate_rps': OFFERED_RPS, 'required_achieved_rps': FLOOR_RPS,
              'rss_growth_must_be_less_than_percent': 1, 'fd_growth_allowed': 0,
              'resource_scope': 'whole server process family; root and every descendant, including log-writer helper; RSS sums intentionally retain shared-map double charges',
              'certificate_reload_during_measurement': False,
              'counter_publication_max_lag_seconds': 1,
              'access_log_health_metrics': LOG_HEALTH_METRICS,
              'access_log_health_policy': 'Dropped and I/O-error counters must be zero, including baseline. Accepted/written counters cannot decrease. Transient pending records are allowed within native queue bounds; no equality or zero-pending assertion is made while traffic is active or after metrics shutdown. Helper draining/join is covered by bounded shutdown and separate native tests.',
              'measurement_boundary_note': 'Published counter snapshots are at most1s old. Raw counter differences are exact; their alignment with monotonic measurement boundaries has up to1s publication uncertainty. The final conservative rate subtracts two full offered-rate seconds plus all possible in-flight requests.',
              'passed': False, 'smoke_completed': False, 'servers': [], 'loaders': [],
              'h2load_binary_sha256': digest(h2load),
              'helper_source_sha256': {name: digest(ROOT / name) for name in ('c/access_log.c', 'c/access_log_helper.c')},
              'tool_versions': {'h2load': checked([h2load, '--version']), 'python': sys.version,
                                'platform': platform.platform(), 'hpack': version('hpack'),
                                'openssl': checked([openssl_binary(), 'version']), 'lean': checked(['lean', '--version'])}}
    (args.output / 'h2load-help.txt').write_text(help_text)
    shutil.copy2(args.config, args.output / 'configuration.json')
    checked(['git', 'archive', '--format=tar', '--output=' + str((args.output / 'source.tar').resolve()), source_sha,
             'LeanNet', 'c', 'tls/LeanNetTLS', 'tls/c', 'lakefile.lean', 'tls/lakefile.lean', 'lean-toolchain', 'HTTPMain.lean', 'Main.lean', 'test/soak24.py', 'test/http2_test_support.py',
             'test/requirements-http2.txt', 'tls/test/tls_test_support.py'], cwd=ROOT)
    certificates = create_certificates(args.output / 'pki')
    for path in (args.output / 'pki').glob('*.key'):
        path.chmod(0o600)
    artifacts = args.output / 'artifacts'; artifacts.mkdir()
    h2snapshot = artifacts / 'h2load'; shutil.copy2(h2load, h2snapshot); h2snapshot.chmod(0o555)
    processes, loaders, streams = [], [], []
    probe_clients = {}
    metric_clients = {}
    paths = []
    failure = None
    clock_guard = None
    samples = args.output / 'samples.jsonl'
    completed_probes = {server['name']: 0 for server in config['servers']}
    def persist():
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    def sample(label):
        rows = []
        for server, process in zip(report['servers'], processes):
            if process.poll() is not None:
                raise RuntimeError('server exited early: ' + server['name'])
            counters, text = metrics(server, certificates.ca, metric_clients)
            resources = sample_process_family(process.pid)
            expected_images = {os.path.normcase(os.path.realpath(server['binary'])), os.path.normcase(os.path.realpath(server['log_helper']))}
            if any(os.path.normcase(os.path.realpath(member['executable'])) not in expected_images for member in resources['family']):
                raise RuntimeError('service family is running an executable outside the immutable server/helper snapshots')
            rows.append({'name': server['name'], 'counters': counters, 'log_health': log_health(text),
                         'probes_completed': completed_probes[server['name']], **resources})
            if label in ('measurement_start', 'measurement_end'):
                (args.output / (server['name'] + '-' + label + '.prom')).write_text(text)
        wall, monotonic = time.time(), time.monotonic()
        if clock_guard is not None:
            clock_guard.check(wall, monotonic)
        row = {'utc': utc(), 'wall_epoch_seconds': wall, 'monotonic': monotonic, 'label': label, 'servers': rows}
        with samples.open('a') as stream:
            stream.write(json.dumps(row) + '\n')
        return row
    def heartbeat():
        for server in report['servers']:
            probe(server, certificates.ca, probe_clients)
            completed_probes[server['name']] += 1
            metrics(server, certificates.ca, metric_clients)
    try:
        for item in config['servers']:
            server = dict(item)
            original = Path(server['binary']).resolve()
            server_artifacts = artifacts / server['name']; server_artifacts.mkdir()
            snapshot = server_artifacts / original.name
            shutil.copy2(original, snapshot); snapshot.chmod(0o555)
            helper_name = 'lean-net-access-log-helper' + ('.exe' if os.name == 'nt' else '')
            helper_original = Path(server.get('log_helper', original.parent / helper_name)).resolve()
            if not helper_original.is_file():
                raise RuntimeError('built sibling access-log helper is missing: ' + str(helper_original))
            helper_snapshot = server_artifacts / helper_name
            shutil.copy2(helper_original, helper_snapshot); helper_snapshot.chmod(0o555)
            server.update({'original_binary': str(original), 'binary': str(snapshot.resolve()), 'binary_sha256': digest(snapshot),
                           'original_log_helper': str(helper_original), 'log_helper': str(helper_snapshot.resolve()),
                           'log_helper_sha256': digest(helper_snapshot),
                           'port': available_port(), 'authority': server.get('authority', NAMES[0]),
                           'metrics_path': server.get('metrics_path', '/metrics')})
            substitutions = {'port': str(server['port']), 'cert': str(certificates.chains[0]), 'key': str(certificates.keys[0]),
                             'null': os.devnull, 'helper': str(helper_snapshot.resolve())}
            arguments = [part.format(**substitutions) for part in server['args']]
            if any(part.startswith('--log-helper=') for part in arguments):
                raise ValueError('use separate --log-helper argument tokens')
            if arguments.count('--log-helper') > 1:
                raise ValueError('duplicate --log-helper configuration')
            if '--log-helper' in arguments:
                helper_index = arguments.index('--log-helper') + 1
                if helper_index == len(arguments):
                    raise ValueError('missing --log-helper argument')
                arguments[helper_index] = str(helper_snapshot.resolve())
            else:
                arguments += ['--log-helper', str(helper_snapshot.resolve())]
            command = [str(snapshot.resolve()), *arguments]
            server['command'] = command
            log = (args.output / (server['name'] + '-server.log')).open('w'); streams.append(log)
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
            processes.append(process); report['servers'].append(server); paths.append(snapshot)
        deadline = time.monotonic() + 60
        for server in report['servers']:
            while True:
                try:
                    probe(server, certificates.ca, probe_clients); completed_probes[server['name']] += 1
                    metrics(server, certificates.ca, metric_clients)
                    break
                except (OSError, EOFError):
                    if time.monotonic() >= deadline or any(p.poll() is not None for p in processes):
                        raise
                    time.sleep(.05)
        load_start = time.monotonic()
        clock_guard = ClockGuard(time.time(), load_start)
        for server in report['servers']:
            # Preserve pacing past the common measured window, then finish
            # every requested stream naturally. Duration mode cancels its
            # last active streams and violates strict started==completed QA.
            command, plan = loader_command(h2snapshot, server, warmup, duration, tail)
            log_path = args.output / (server['name'] + '-h2load.log')
            stream = log_path.open('w'); streams.append(stream)
            loaders.append(subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT))
            report['loaders'].append({'name': server['name'], 'command': command, 'log': str(log_path), **plan})
        report['loader_completion_bound'] = loader_completion_bounds(report['servers'], report['loaders'])
        report['load_started_utc'] = utc(); persist()
        next_heartbeat = time.monotonic() + 5
        while time.monotonic() < load_start + warmup:
            clock_guard.check(time.time(), time.monotonic())
            if any(p.poll() is not None for p in processes + loaders):
                raise RuntimeError('server/loader exited during warmup')
            if time.monotonic() >= next_heartbeat:
                heartbeat(); next_heartbeat = time.monotonic() + 5
            time.sleep(min(1, max(0, load_start + warmup - time.monotonic())))
        baseline = sample('measurement_start')
        report['measurement_started_utc'] = baseline['utc']; report['baseline'] = baseline; persist()
        end = baseline['monotonic'] + duration
        next_sample = min(end, baseline['monotonic'] + interval)
        previous = baseline
        while True:
            clock_guard.check(time.time(), time.monotonic())
            if any(p.poll() is not None for p in processes + loaders):
                raise RuntimeError('server/loader exited before the common measured window ended')
            if any(path.stat().st_size > 64 * 1024**2 for path in args.output.glob('*.log')):
                raise RuntimeError('bounded raw log budget exceeded')
            now = time.monotonic()
            if now >= next_heartbeat:
                heartbeat(); next_heartbeat = time.monotonic() + 5
            if now < next_sample:
                time.sleep(min(1, next_sample - now)); continue
            for server in report['servers']:
                probe(server, certificates.ca, probe_clients); completed_probes[server['name']] += 1
            current = sample('measurement_end' if now >= end else 'measured')
            assess_sample(previous, current, baseline, args.smoke_seconds is None)
            previous = current
            if current['monotonic'] >= end:
                break
            next_sample = min(end, next_sample + interval)
        report['measurement_finished_utc'] = current['utc']; report['final'] = current
        # Let the <=1-second metrics publication lag drain while both loaders
        # remain active. This prevents a reset/error in the final measured
        # second from disappearing behind the last published snapshot.
        guard_deadline = time.monotonic() + 2
        while time.monotonic() < guard_deadline:
            clock_guard.check(time.time(), time.monotonic())
            if any(p.poll() is not None for p in processes + loaders):
                raise RuntimeError('server/loader exited during counter-publication guard')
            time.sleep(.1)
        guard = sample('publication_guard')
        assess_sample(current, guard, baseline, False)
        report['counter_publication_guard'] = guard
        measured_seconds = current['monotonic'] - baseline['monotonic']
        wall_measured_seconds = current['wall_epoch_seconds'] - baseline['wall_epoch_seconds']
        rate_seconds = max(measured_seconds, wall_measured_seconds)
        successful = sum(row['counters']['completed'] - first['counters']['completed'] - (row['probes_completed'] - first['probes_completed'])
                         for first, row in zip(baseline['servers'], current['servers']))
        uncertainty = 2 * OFFERED_RPS + sum(int(server.get('connections', 10)) * 100 for server in report['servers'])
        conservative_successful = max(0, successful - uncertainty)
        report.update({'measured_seconds': measured_seconds, 'successful_load_requests_counter_delta_minus_probes': successful,
                       'wall_measured_seconds': wall_measured_seconds,
                       'rate_denominator_seconds': rate_seconds,
                       'achieved_rps_from_counter_delta': successful / rate_seconds,
                       'boundary_uncertainty_request_budget': uncertainty,
                       'successful_load_requests_conservative': conservative_successful,
                       'achieved_rps': conservative_successful / rate_seconds})
        persist()
        wait_deadline = load_start + report['loader_completion_bound']['deadline_seconds_from_load_start']
        while any(p.poll() is None for p in loaders):
            clock_guard.check(time.time(), time.monotonic())
            if time.monotonic() >= next_heartbeat:
                heartbeat(); next_heartbeat = time.monotonic() + 5
            if time.monotonic() > wait_deadline or any(p.poll() is not None for p in processes):
                raise RuntimeError('loader completion/server lifetime deadline exceeded')
            time.sleep(.25)
        for server, loader, record in zip(report['servers'], loaders, report['loaders']):
            text = Path(record['log']).read_text()
            result = parse_load(text, len(bytes.fromhex(server['body_hex'])), record['planned_requests'])
            record['result'] = result; record['exit_code'] = loader.returncode
            if loader.returncode or not result['valid'] or re.search(r'ECONNRESET|connection reset|RST_STREAM|error:', text, re.I):
                raise RuntimeError('h2load reports errors, resets, bad statuses or aggregate body bytes')
            probe(server, certificates.ca, probe_clients)
            if digest(server['log_helper']) != server['log_helper_sha256']:
                raise RuntimeError('immutable logger helper snapshot changed')
            if digest(server['binary']) != server['binary_sha256']:
                raise RuntimeError('immutable binary snapshot changed')
        report['smoke_completed'] = args.smoke_seconds is not None
        report['passed'] = args.smoke_seconds is None and measured_seconds >= DAY and report['achieved_rps'] >= FLOOR_RPS
    except BaseException as error:
        failure = error; report['failure'] = repr(error)
    finally:
        for loader in loaders:
            try:
                terminate(loader)
            except BaseException as error:
                report['passed'] = False; report['shutdown_failure'] = repr(error)
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGINT)
        for sock in metric_clients.values():
            try:
                if isinstance(sock, ssl.SSLSocket):
                    raw = sock.unwrap(); raw.close()
                else:
                    sock.close()
            except OSError as error:
                report['passed'] = False; report['shutdown_failure'] = repr(error)
                sock.close()
        for client in probe_clients.values():
            try:
                close_probe(client)
            except BaseException as error:
                report['passed'] = False; report['shutdown_failure'] = repr(error)
        for process in processes:
            try:
                code = process.wait(timeout=10)
                if code:
                    report['passed'] = False; report['shutdown_failure'] = f'server exit {code}'
            except BaseException as error:
                report['passed'] = False; report['shutdown_failure'] = repr(error)
                terminate(process)
        for stream in streams:
            stream.close()
        if report.get('shutdown_failure'):
            report['smoke_completed'] = False
        report['clock_guard'] = clock_guard.summary() if clock_guard is not None else None
        report['finished_utc'] = utc(); persist()
    print(json.dumps({'passed_24h_soak': report['passed'], 'smoke_completed': report['smoke_completed'],
                      'failure': report.get('failure') or report.get('shutdown_failure'), 'report': str(args.output / 'report.json')}))
    return 0 if not failure and not report.get('shutdown_failure') and (report['passed'] or report['smoke_completed']) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-sha', help='Required exact clean HEAD for the real 24-hour gate')
    parser.add_argument('--h2load', default='h2load')
    parser.add_argument('--smoke-seconds', type=float, help='Explicit orchestration check; can never satisfy the soak gate')
    args = parser.parse_args()
    existed_before = args.output.exists()
    try:
        return run(args)
    except Exception as error:
        if not existed_before and args.output.is_dir():
            (args.output / 'startup-failure.json').write_text(json.dumps({'passed': False, 'failure': repr(error), 'utc': utc()}, indent=2) + '\n')
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
