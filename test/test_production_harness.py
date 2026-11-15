#!/usr/bin/env python3
"""Pure acceptance checks for soak accounting; never starts a server or load."""
from copy import deepcopy
import os
import subprocess
import sys
import unittest

from soak24 import ClockGuard, assess_sample, counter, log_health, parse_load, sample_process_family, validate, DAY, LOG_HEALTH_METRICS, LOG_MAX_PENDING_RECORDS


def config():
    return {'servers': [dict(name=name, scheme=scheme, binary='unused', args=['{port}'], path='/', body_hex='00ff',
                            metrics={key: {'name': key, 'labels': {'protocol': 'h2'}} for key in ('completed', 'errors', 'timeouts', 'resets')})
                        for name, scheme in [('plain', 'http'), ('tls', 'https')]]}


def sample(time, completed, probes=0):
    return {'monotonic': time, 'servers': [dict(name=name, counters={'completed': completed, 'errors': 0, 'timeouts': 0, 'resets': 0},
                 log_health={'accepted': completed, 'written': completed - 1, 'dropped': 0, 'io_errors': 0, 'pending': 1},
                 probes_completed=probes, rss_bytes=10000, fds_or_handles=20,
                 family=[{'pid': index + 10, 'parent_pid': 1, 'start_identity': 'fixed', 'rss_bytes': 10000, 'fds_or_handles': 20}]) for index, name in enumerate(['plain', 'tls'])]}


class SoakAccounting(unittest.TestCase):
    def test_mac_sleep_and_joint_clock_gap_cannot_pass(self):
        guard = ClockGuard(1000, 100)
        guard.check(1001, 101)
        with self.assertRaisesRegex(RuntimeError, 'divergence'):
            guard.check(1301, 102)  # UTC advances across sleep; monotonic pauses.
        guard = ClockGuard(1000, 100)
        with self.assertRaisesRegex(RuntimeError, 'monitoring gap'):
            guard.check(1010, 110)  # SIGSTOP/scheduler pause; both advance.
        self.assertGreater(guard.summary()['max_monotonic_gap_seconds'], 5)

    def test_clock_drift_is_recorded_and_bounded(self):
        guard = ClockGuard(1000, 100)
        guard.check(1001.25, 101)
        guard.check(1002.5, 102)
        self.assertEqual(guard.summary()['max_divergence_seconds'], .5)
        with self.assertRaisesRegex(RuntimeError, 'divergence'):
            guard.check(1000, 104)
        with self.assertRaisesRegex(RuntimeError, 'backward'):
            ClockGuard(1000, 100).check(1001, 99)

    def test_counter_exact_integer_labels_and_absence(self):
        text = '# TYPE completed counter\ncompleted{protocol="h2",worker="0"} 9007199254740993\ncompleted{protocol="h2",worker="1"} 2\ncompleted{protocol="http1"} 999\n'
        self.assertEqual(counter(text, {'name': 'completed', 'labels': {'protocol': 'h2'}}), 9007199254740995)
        for invalid in ['completed -1', 'completed NaN', 'completed 1.5', 'completed 1\ncompleted 2']:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                counter(invalid, {'name': 'completed'})
        with self.assertRaises(ValueError):
            counter(text, {'name': 'absent'})
        health_text = '\n'.join(f'{name} {2 if key == "accepted" else 1 if key in ("written", "pending") else 0}'
                                for key, name in LOG_HEALTH_METRICS.items())
        self.assertEqual(log_health(health_text)['pending'], 1)
        with self.assertRaises(ValueError):
            log_health(health_text.replace(LOG_HEALTH_METRICS['written'], 'missing_metric'))

    def test_duration_and_offered_rate_cannot_be_relaxed(self):
        self.assertEqual(validate(config(), None)[0], DAY)
        for duration in [1, DAY - 1, float('nan'), float('inf')]:
            value = config(); value['duration_seconds'] = duration
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                validate(value, None)
        self.assertEqual(validate(config(), 5)[0], 5)
        for rate in [500, 510.1, True]:
            value = config(); value['servers'][0]['rps_per_client'] = rate
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                validate(value, None)
        for argument in ('--reload-certs-ms', '--reload-certs-ms=25'):
            value = config(); value['servers'][1]['args'] += [argument, '25']
            with self.subTest(argument=argument), self.assertRaisesRegex(ValueError, 'certificate reload'):
                validate(value, None)

    def test_probe_subtraction_floor_and_counter_conservation(self):
        before = sample(10, 1000)
        after = sample(15, 26001, 1)
        self.assertEqual(assess_sample(before, after, before)['successful_requests'], 50000)
        after['servers'][0]['counters']['completed'] -= 1
        with self.assertRaisesRegex(RuntimeError, 'below 10,000'):
            assess_sample(before, after, before)
        negative = sample(15, 1000, 1)
        with self.assertRaisesRegex(RuntimeError, 'conservation'):
            assess_sample(before, negative, before, False)
        decreasing = sample(15, 999)
        with self.assertRaisesRegex(RuntimeError, 'decrease'):
            assess_sample(before, decreasing, before)

    def test_strict_rss_flat_descriptors_and_zero_resets(self):
        before = sample(10, 1000)
        after = sample(15, 26500)
        for field, value, reason in [('rss_bytes', 10100, '1%'), ('fds_or_handles', 21, 'FD')]:
            bad = deepcopy(after); bad['servers'][1][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, reason):
                assess_sample(before, bad, before)
        for kind in ('errors', 'timeouts', 'resets'):
            bad = deepcopy(after); bad['servers'][1]['counters'][kind] = 1
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, 'request error or connection reset'):
                assess_sample(before, bad, before)
        after['servers'][1]['rss_bytes'] = 10099
        self.assertGreater(assess_sample(before, after, before)['achieved_rps'], 10000)
        for key in ('dropped', 'io_errors'):
            for position in ('baseline', 'measured'):
                first, last = deepcopy(before), deepcopy(after)
                (first if position == 'baseline' else last)['servers'][0]['log_health'][key] = 1
                with self.subTest(key=key, position=position), self.assertRaisesRegex(RuntimeError, 'access log dropped'):
                    assess_sample(first, last, first)
        for key in ('accepted', 'written'):
            bad = deepcopy(after); bad['servers'][0]['log_health'][key] = before['servers'][0]['log_health'][key] - 1
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'log counter reset'):
                assess_sample(before, bad, before)
        bad = deepcopy(after); bad['servers'][0]['log_health']['pending'] = LOG_MAX_PENDING_RECORDS + 1
        with self.assertRaisesRegex(RuntimeError, 'queue bounds'):
            assess_sample(before, bad, before)

    def test_process_family_identity_and_helper_descriptor_leak(self):
        before = sample(10, 1000)
        after = sample(15, 26500)
        added = deepcopy(after)
        added['servers'][0]['family'].append({'pid': 999, 'parent_pid': 10, 'start_identity': 'new', 'rss_bytes': 1, 'fds_or_handles': 0})
        with self.assertRaisesRegex(RuntimeError, 'family identity'):
            assess_sample(before, added, before)
        recycled = deepcopy(after)
        recycled['servers'][0]['family'][0]['start_identity'] = 'recycled-pid'
        with self.assertRaisesRegex(RuntimeError, 'family identity'):
            assess_sample(before, recycled, before)
        with_helper_before, with_helper_after = deepcopy(before), deepcopy(after)
        for value in (with_helper_before, with_helper_after):
            value['servers'][0]['family'].append({'pid': 90, 'parent_pid': 10, 'start_identity': 'helper-fixed', 'rss_bytes': 1000, 'fds_or_handles': 3})
            value['servers'][0]['rss_bytes'] += 1000
            value['servers'][0]['fds_or_handles'] += 3
        leaked = deepcopy(with_helper_after)
        # An aggregate count can remain flat while a helper leaks a descriptor
        # and another family member releases one. The per-PID gate catches it.
        leaked['servers'][0]['family'][0]['fds_or_handles'] -= 1
        leaked['servers'][0]['family'][1]['fds_or_handles'] += 1
        with self.assertRaisesRegex(RuntimeError, 'process-family member'):
            assess_sample(with_helper_before, leaked, with_helper_before)

    def test_actual_nested_process_family_census(self):
        code = """import subprocess,sys
helper=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(helper.pid,flush=True)
try:
    sys.stdin.readline()
finally:
    helper.terminate()
    helper.wait(timeout=5)
"""
        parent = subprocess.Popen([sys.executable, '-u', '-c', code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        helper_pid = None
        try:
            helper_pid = int(parent.stdout.readline().strip())
            first = sample_process_family(parent.pid)
            second = sample_process_family(parent.pid)
            self.assertEqual({row['pid'] for row in first['family']}, {parent.pid, helper_pid})
            self.assertEqual(first['family_count'], 2)
            self.assertEqual(first['child_count'], 1)
            self.assertEqual(first['rss_bytes'], sum(row['rss_bytes'] for row in first['family']))
            self.assertEqual(first['fds_or_handles'], sum(row['fds_or_handles'] for row in first['family']))
            self.assertTrue(all(row['rss_bytes'] > 0 and row['start_identity'] and row['executable'] for row in first['family']))
            identity = lambda value: [(row['pid'], row['parent_pid'], row['start_identity']) for row in value['family']]
            self.assertEqual(identity(first), identity(second))
        finally:
            try:
                parent.communicate('stop\n', timeout=10)
            except subprocess.TimeoutExpired:
                parent.kill(); parent.communicate(timeout=5)
                if helper_pid:
                    try:
                        os.kill(helper_pid, 15)
                    except OSError:
                        pass
        self.assertEqual(parent.returncode, 0)

    def test_loader_summary_checks_every_request_status_and_body_byte(self):
        text = '''Application protocol: h2
finished in 1.00s, 10000.00 req/s
requests: 10000 total, 10000 started, 10000 done, 10000 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 10000 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 1MB (1000000) total, 1KB (1000) headers, 20KB (20000) data
'''
        self.assertTrue(parse_load(text, 2)['valid'])
        for bad in [text.replace('(20000) data', '(19999) data'), text.replace('0 failed', '1 failed'),
                    text.replace('10000 2xx', '9999 2xx'), text.replace('10000 started', '10001 started'),
                    text.replace('protocol: h2', 'protocol: http/1.1')]:
            self.assertFalse(parse_load(bad, 2)['valid'])
        with self.assertRaises(ValueError):
            parse_load('partial crashed loader output', 2)


if __name__ == '__main__':
    unittest.main()
