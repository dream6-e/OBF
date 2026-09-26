"""End-to-end checks of upstream fixtures and genuine failure paths."""
from pathlib import Path
import hashlib
import json
import unittest

from support import ENGINE, REPO, RuntimeMixin, cli, run


class LuraphIntegrationTests(RuntimeMixin, unittest.TestCase):
    def fixture(self, version):
        return REPO / 'SON.LUA' if version == '15' else ENGINE / ('v' + version + '.txt')

    def test_supplied_v147_v148_v149_v15_are_lifted_not_traced(self):
        for version, expected in [('14.7', 'hii!! luraph 14.7'),
                                  ('14.8', 'hiiiii luraph 14.8'), ('14.9', 'Hi luraph 14.9'), ('15', 'hello')]:
            with self.subTest(version=version):
                output = self.output(version + '.lua')
                result = cli('deob.py', self.fixture(version), '--no-pypy', '--timeout', '25', '-o', output)
                self.assert_lifted(result, output, expected)

    def test_fixture_renaming_and_leading_whitespace_do_not_change_lift(self):
        for version, expected in [('14.7', 'hii!! luraph 14.7'), ('14.8', 'hiiiii luraph 14.8'),
                                  ('14.9', 'Hi luraph 14.9')]:
            with self.subTest(version=version):
                src = self.work / ('renamed-' + version + '.lua')
                src.write_bytes(b'\n\t  \n' + self.fixture(version).read_bytes())
                output = self.output()
                self.assert_lifted(cli('deob.py', src, '--no-pypy', '--timeout', '25', '-o', output), output, expected)

    def test_headerless_sample_uses_explicit_engine(self):
        for version, expected in [('14.8', 'hiiiii luraph 14.8'), ('14.9', 'Hi luraph 14.9')]:
            with self.subTest(version=version):
                src = self.work / ('no-banner-' + version + '.lua')
                src.write_bytes(self.fixture(version).read_bytes().split(b'\n', 1)[1])
                output = self.output()
                result = cli('cli.py', src, '--engine', version, '-o', output, '--timeout', '25')
                self.assert_lifted(result, output, expected)

    def test_v15_default_trace_keeps_real_print(self):
        output = self.output()
        result = cli('deob.py', self.fixture('15'), '--no-devirt', '--no-pypy', '--timeout', '25', '-o', output)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = output.read_text()
        self.assertIn('print("hello")', text)
        self.assertIn('RESULT: behavior trace', text)
        # Parse only: the trace contains simulated Roblox calls.
        parsed = run([ENGINE / 'bin/luau-ast', output])
        self.assertEqual(parsed.returncode, 0, parsed.stderr)

    def test_cli_raw_default_writes_file_without_closing_stdout(self):
        output = self.output()
        result = cli('cli.py', self.fixture('14.8'), '--raw', '-o', output, '--timeout', '25')
        self.assert_lifted(result, output, 'hiiiii luraph 14.8')
        self.assertTrue(Path(str(output) + '.raw.txt').is_file())
        self.assertIn(str(output), result.stdout)

    def test_real_runtime_error_is_not_reported_as_reconstruction(self):
        src = self.work / 'actual-error.lua'
        src.write_text('-- This file was protected using Luraph Obfuscator v14.9 [https://lura.ph/]\n'
                       'error("intentional target error")')
        output = self.output()
        result = cli('deob.py', src, '--no-hooks', '--no-pypy', '--timeout', '25', '-o', output)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.assertIn('intentional target error', result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_error_trace_fallback_requires_explicit_request(self):
        src = self.work / 'actual-error.lua'
        src.write_text('-- This file was protected using Luraph Obfuscator v14.9 [https://lura.ph/]\n'
                       'error("intentional target error")')
        output = self.output()
        result = cli('cli.py', src, '--no-hooks', '--trace-fallback', '--timeout', '25', '-o', output)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = output.read_text()
        self.assertIn('RESULT: behavior trace', text)
        self.assertIn('script error:', text)
        self.assertIn('intentional target error', text)
        self.assertNotIn('-- Devirtualized', text)

    def test_v149_dump_finishes_and_records_snapshot_observer_failures(self):
        src = self.work / 'dump-case.lua'
        src.write_bytes(self.fixture('14.9').read_bytes())
        raw = self.work / 'raw.txt'
        result = cli('cli.py', src, '--no-devirt', '--cfg', 'devirt=true', '--debug',
                     '--raw', raw, '--timeout', '25', '-o', self.output())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('run status: finished', result.stderr)
        self.assertNotIn('run 2', result.stderr)
        self.assertIn('snapshot coverage is incomplete', result.stderr)
        text = raw.read_text()
        self.assertIn('print("Hi luraph 14.9")', text)
        self.assertNotIn('\x00ALLOCTRIGGER', text)
        dump = json.loads(next(self.work.rglob('*.protos.json')).read_text())
        self.assertGreater(dump['snapshot_failures'], 0)
        self.assertGreater(len(dump['protos']), 1)
        self.assertGreater(len(dump['tables']), 1)
        self.assertIn(str(dump['root_callee']), dump['protos'])
        def check_refs(value):
            if isinstance(value, dict):
                if 't' in value:
                    self.assertIn(str(value['t']), dump['tables'])
                for child in value.values():
                    check_refs(child)
            elif isinstance(value, list):
                for child in value:
                    check_refs(child)
        check_refs(dump['protos'])
        check_refs(dump['tables'])
        self.assertEqual(src.read_bytes(), self.fixture('14.9').read_bytes())

    def test_v149_lift_matches_uninstrumented_observable_print(self):
        raw = self.work / 'baseline.txt'
        baseline = cli('deob.py', self.fixture('14.9'), '--obfuscator', 'generic', '--no-devirt',
                       '--no-pypy', '--no-fold', '--keep-preamble', '--timeout', '25',
                       '--raw', raw, '-o', self.output('trace.lua'))
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertIn('run status: finished', baseline.stderr)
        original_prints = [line for line in raw.read_text().splitlines() if line.startswith('print(')]
        output = self.output('lift.lua')
        result = cli('deob.py', self.fixture('14.9'), '--no-pypy', '--timeout', '25', '-o', output)
        self.assert_lifted(result, output, 'Hi luraph 14.9')
        lifted_prints = [line for line in output.read_text().splitlines() if line.startswith('print(')]
        self.assertEqual(lifted_prints, original_prints)

    def test_no_input_can_be_overwritten(self):
        for script in ('cli.py', 'deob.py'):
            with self.subTest(script=script):
                src = self.work / 'protected.lua'
                src.write_bytes(self.fixture('14.8').read_bytes())
                before = hashlib.sha256(src.read_bytes()).hexdigest()
                result = cli(script, src, '-o', src)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('must not overwrite', result.stderr)
                self.assertEqual(hashlib.sha256(src.read_bytes()).hexdigest(), before)

    def test_zero_rounds_are_rejected_before_running(self):
        for script in ('cli.py', 'deob.py'):
            result = cli(script, self.fixture('14.8'), '--devirt-rounds', '0')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('must be positive', result.stderr)
            self.assertNotIn('tracing', result.stderr)


    def test_raw_diagnostics_cannot_overwrite_protected_input(self):
        for script in ('cli.py', 'deob.py'):
            src = self.work / 'protected.lua'
            src.write_bytes(self.fixture('14.8').read_bytes())
            before = src.read_bytes()
            result = cli(script, src, '--raw', src, '-o', self.output())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('must not overwrite', result.stderr)
            self.assertEqual(src.read_bytes(), before)

    def test_failed_debug_run_cannot_reuse_previous_v15_lift(self):
        src = self.work / 'ordinary.lua'
        src.write_text('print("plain input, no VM capture")')
        trace = self.work / 'case.deobf.luau'
        stale = self.work / 'case.devirt.luau'
        stale.write_text('print("stale, must not be returned")')
        result = cli('deob.py', src, '--obfuscator', 'luraph_v15', '--no-hooks',
                     '--debug', '--no-pypy', '--timeout', '10', '-o', trace)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(stale.exists())


    def test_actual_invalid_allocation_is_not_swallowed_by_snapshot_guard(self):
        src = self.work / 'invalid-allocation.lua'
        src.write_text('-- This file was protected using Luraph Obfuscator v14.9 [https://lura.ph/]\n'
                       'table.create(-1)')
        result = cli('deob.py', src, '--no-hooks', '--no-pypy', '--timeout', '10', '-o', self.output())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('size out of range', result.stderr)
        self.assertFalse(self.output().exists())

    def test_successful_snapshots_still_restore_scrambled_arrays(self):
        import harness
        import re
        source = '''
local a, b = {1, 2}, {3, 4}
local proto = {a, b}
__PID[proto] = 1
__PA[proto] = {}
__PA[proto].self = proto
__PA[proto].__seq = 1
for i = 1, 2 do a[i] = 20000000 + i; b[i] = 30000000 + i end
print("target-saw", a[1])
'''
        body, error = harness.run_once(str(ENGINE / 'bin/luau'), source,
                                       {'devirt': True, 'time_budget': 10},
                                       str(self.work / 'snapshot.harness.luau'), 15, False)
        self.assertIsNone(error)
        self.assertIn('-- run status: finished', body)
        self.assertIn('print("target-saw", 20000001)', body)
        self.assertIn('\x00UNSCRAMBLED 1', body)
        dump = json.loads(re.search(r'\x00PROTOS ([^\n]+)', body)[1])
        self.assertEqual(dump['snapshot_failures'], 0)
        proto = dump['tables'][str(dump['protos']['1']['self']['t'])]
        arrays = [dump['tables'][str(ref['t'])]['arr'] for ref in proto['arr']]
        self.assertEqual(arrays, [[1, 2], [3, 4]])


if __name__ == '__main__':
    unittest.main()
