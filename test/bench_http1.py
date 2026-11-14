#!/usr/bin/env python3
"""Snapshot a real HTTP server and verify every response during fixed-count load.

Connection setup is excluded; one request is outstanding per connection. This
is characterization, not an HTTP/2 gate. The server CLI receives PORT followed
by --server-arg entries. Default arguments target the advanced test fixture.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def info(command):
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def h2load_result(output, requests, body_bytes):
    counts = re.search(r'requests:\s*(\d+) total,\s*(\d+) started,\s*(\d+) done,\s*(\d+) succeeded,\s*(\d+) failed,\s*(\d+) errored,\s*(\d+) timeout', output)
    rate = re.search(r'finished in ([^,]+),\s*([\d.]+) req/s', output)
    data = re.search(r'\((\d+)\) data', output)
    statuses = re.search(r'status codes:\s*(\d+) 2xx,\s*(\d+) 3xx,\s*(\d+) 4xx,\s*(\d+) 5xx', output)
    if not counts or not rate or not data or not statuses:
        raise RuntimeError(f'unrecognized h2load summary: {output}')
    total, started, done, succeeded, failed, errored, timeout = map(int, counts.groups())
    if [total, started, done, succeeded] != [requests] * 4 or failed or errored or timeout or int(data.group(1)) != requests * body_bytes or list(map(int, statuses.groups())) != [requests, 0, 0, 0]:
        raise RuntimeError(f'h2load request/status/data validation failed: {output}')
    return {'requests': requests, 'requests_per_second': float(rate.group(2)),
            'duration_text': rate.group(1), 'failed': failed, 'errored': errored,
            'timeouts': timeout, 'response_data_bytes': int(data.group(1)), 'raw_stdout': output}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / '.lake/build/bin/lean-net-http1-reactor-fixture')
    parser.add_argument('--server-arg', action='append', default=[])
    parser.add_argument('--connections', type=int, default=100)
    parser.add_argument('--requests', type=int, default=200000)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--client', choices=['native', 'h2load'], default='native')
    parser.add_argument('--threads', type=int, default=4, help='h2load native client threads')
    parser.add_argument('--path', default='/binary')
    parser.add_argument('--body-hex', default='00ff0d0a41')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file() or args.connections <= 0 or args.requests < args.connections or args.rounds <= 0 or args.threads <= 0:
        parser.error('binary and positive workload bounds are required')
    try:
        expected = bytes.fromhex(args.body_hex)
    except ValueError:
        parser.error('body-hex must encode expected response bytes')
    if not expected:
        parser.error('expected body must not be empty')
    sources = ['test/bench_http1.c', 'test/bench_http1.py', 'test/HTTP1ReactorFixture.lean',
               'LeanNet/HTTP/ReactorServer.lean', 'LeanNet/HTTP/WorkerPool.lean',
               'LeanNet/HTTP1/Protocol.lean', 'LeanNet/HTTP1/Encoding.lean', 'LeanNet/HTTP1/Parser.lean',
               'LeanNet/HTTP1/Machine.lean', 'LeanNet/HTTP1/Config.lean', 'LeanNet/Reactor/Basic.lean',
               'c/reactor_posix.c', 'c/reactor_group.c', 'lakefile.lean']
    sources += [str(path.relative_to(ROOT)) for path in (ROOT / 'LeanNet/HTTP').rglob('*.lean')]
    sources = sorted(set(sources))
    report = {'environment': {'platform': platform.platform(), 'logical_cpus': os.cpu_count(),
              'cpu': info(['sysctl', '-n', 'machdep.cpu.brand_string']), 'compiler': info(['cc', '--version']),
              'lean': info(['lean', '--version']), 'h2load': info(['h2load', '--version']),
              'openssl_cli': info(['openssl', 'version'])},
              'git_head': info(['git', 'rev-parse', 'HEAD']), 'git_status': info(['git', 'status', '--short']),
              'binary': str(args.binary.resolve()), 'binary_sha256': digest(args.binary),
              'source_sha256': {name: digest(ROOT / name) for name in sources if (ROOT / name).is_file()},
              'server_args': args.server_arg, 'path': args.path, 'expected_body_hex': expected.hex(),
              'configuration': {'fixture_mode': args.server_arg[0] if args.server_arg else None, 'bench_mode_max_clients': 128, 'bench_mode_requested_output_buffers': 512, 'flights_per_client': 4, 'native': 'defaults', 'machine': 'defaults'} if args.server_arg[:1] == ['bench'] else None,
              'client': args.client, 'client_threads': 1 if args.client == 'native' else args.threads,
              'method': 'fixed-count closed-loop HTTP/1.1, no pipelining, one outstanding request/connection; connects excluded; every200status/CL/body verified' if args.client == 'native' else 'h2load --h1, no pipelining; connection setup included; request/status counts and aggregate body bytes checked; body contents separately checked by native verified-client report',
              'runs': []}
    with tempfile.TemporaryDirectory(prefix='lean-net-http1-bench-') as directory:
        directory = Path(directory); client = directory / 'client'; binary = directory / 'server'
        shutil.copy2(args.binary, binary)
        if args.client == 'native':
            subprocess.run(['cc', '-O3', '-std=c11', '-Wall', '-Wextra', '-Wpedantic', '-Werror', str(ROOT / 'test/bench_http1.c'), '-o', str(client)], check=True)
        for round_index in range(args.rounds):
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            with tempfile.TemporaryFile(mode='w+') as log:
                server = subprocess.Popen([str(binary), str(port), *args.server_arg], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 8
                    while True:
                        if server.poll() is not None:
                            log.seek(0); raise RuntimeError(f'startup exit: {log.read()}')
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise RuntimeError('server startup timed out')
                            time.sleep(.01)
                    if args.client == 'native':
                        command = [str(client), str(port), str(args.connections), str(args.requests), args.path, expected.hex()]
                    else:
                        command = ['h2load', '--h1', '-n', str(args.requests), '-c', str(args.connections), '-t', str(args.threads), '-m', '1', '-N', '10s', '-T', '120s', f'http://127.0.0.1:{port}{args.path}']
                    result = subprocess.run(command, capture_output=True, text=True, timeout=130)
                    if result.returncode:
                        raise RuntimeError(f'verified client exit{result.returncode}: {result.stderr}')
                    run = json.loads(result.stdout) if args.client == 'native' else h2load_result(result.stdout, args.requests, len(expected))
                    run['round'] = round_index + 1; run['command'] = command
                    report['runs'].append(run); print(json.dumps(run), flush=True)
                finally:
                    if server.poll() is None:
                        server.send_signal(signal.SIGINT)
                    try:
                        code = server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill(); server.wait(timeout=5)
                        raise RuntimeError('server failed to join after SIGINT')
                    if code:
                        log.seek(0); raise RuntimeError(f'server shutdown exit{code}: {log.read()}')
    if digest(args.binary) != report['binary_sha256']:
        raise RuntimeError('original binary changed during measurements; snapshot report retained in memory')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
