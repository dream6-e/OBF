import importlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from support import ENGINE
import cli
import deob
import obfuscators
import tidy
import traceout

VERSIONS = ('7', '8', '9')


def driver(v):
    return importlib.import_module('obfuscators.luraph_v14_' + v + '.driver')


def mapper(v):
    return importlib.import_module('obfuscators.luraph_v14_' + v + '.vmmap')


def local(name, location):
    return {'name': name, 'location': location}


def ref(decl):
    return {'type': 'AstExprLocal', 'local': decl}


def fn(body, args=()):
    return {'type': 'AstExprFunction', 'args': list(args), 'body': {'type': 'AstStatBlock', 'body': body}}


class DetectionTests(unittest.TestCase):
    def test_registered_versions(self):
        for version, plugin in [('14.7', 'luraph_v14_7'), ('14.8', 'luraph_v14_8'),
                                ('14.9', 'luraph_v14_9'), ('15.0', 'luraph_v15')]:
            with self.subTest(version=version):
                text = '-- This file was protected using Luraph Obfuscator v' + version + ' [https://lura.ph/]\nreturn {}'
                found, confidence = obfuscators.detect(text)
                self.assertEqual(found.name, plugin)
                self.assertEqual(confidence, 1.0)

    def test_headerless_v14_is_not_guessed(self):
        src = 'local init = (function(...) return({x=bit32.bxor}) end)(...)'
        self.assertIsNone(cli.detect_version(src))
        for v in VERSIONS:
            with self.subTest(version=v):
                self.assertLess(obfuscators.by_name('luraph_v14_' + v).detect(src), 0.5)

    def test_parser_shared_options_do_not_conflict(self):
        args = deob.parser().parse_args(['sample.lua', '--obfuscator', 'luraph_v14_9', '--trace-fallback'])
        self.assertTrue(args.trace_fallback)
        self.assertEqual(args.max_runs, 12)

    def test_raw_is_optional_path_not_stdout_fd(self):
        self.assertIsNone(cli.parser().parse_args(['sample.lua']).raw)
        self.assertIs(cli.parser().parse_args(['sample.lua', '--raw']).raw, True)
        self.assertEqual(cli.parser().parse_args(['sample.lua', '--raw', 'diagnostic.txt']).raw, 'diagnostic.txt')


class RootSelectionTests(unittest.TestCase):
    def test_tail_called_payload_beats_busy_bootstrap(self):
        text = ('--@1 100:1,200:2\nprobe()\n' * 50
                + '--@1 777:80\nprint("payload")\n')
        for v in VERSIONS:
            with self.subTest(version=v):
                self.assertEqual(driver(v)._trace_root_candidates(text)[0], 777)

    def test_tail_payload_can_call_its_own_helper(self):
        text = '--@1 100:1,200:2\nprobe()\n--@1 777:80,900:81\nprint("payload")\n'
        for v in VERSIONS:
            self.assertEqual(driver(v)._trace_root_candidates(text)[0], 777)

    def test_bootstrap_itself_is_not_a_detached_payload(self):
        text = '--@1 100:1,200:2\nprobe()\n--@1 100:1\nprobe()\n'
        for v in VERSIONS:
            self.assertNotEqual(driver(v)._trace_root_hint(text), 100)

    def test_empty_trace_has_no_root(self):
        for v in VERSIONS:
            self.assertEqual(driver(v)._trace_root_candidates('--@1 \n'), [])

    def test_root_hint_only_selects_captured_protos(self):
        import json
        text = '--@1 100:1,200:2\nprobe()\n--@1 777:80\nprint("payload")\n'
        data = json.dumps({'protos': {'200': {}, '777': {}}, 'root_callee': 200})
        for v in VERSIONS:
            new, hint = driver(v)._apply_root_hint(data, text)
            self.assertEqual(hint, 777)
            self.assertEqual(json.loads(new)['root_callee'], 777)


    def test_observed_runtime_root_beats_more_frequent_probe(self):
        import json
        body = ('--@1 100:1,200:2\nprobe()\n' * 50
                + '--@1 100:1,777:80\nprint("payload")\n')
        data = json.dumps({'protos': {'200': {}, '777': {}}, 'root_callee': 777})
        for v in VERSIONS:
            self.assertEqual(driver(v)._trace_root_candidates(body, 777)[0], 777)
            updated, hint = driver(v)._apply_root_hint(data, body)
            self.assertEqual(hint, 777)
            self.assertEqual(json.loads(updated)['root_callee'], 777)

    def test_unobserved_runtime_root_is_not_trusted(self):
        body = '--@1 100:1,200:2\nprobe()\n'
        for v in VERSIONS:
            self.assertEqual(driver(v)._trace_root_candidates(body, 777), [200])

    def test_detached_payload_beats_stale_runtime_root(self):
        body = '--@1 100:1,200:2\nprobe()\n--@1 777:80\nprint("payload")\n'
        for v in VERSIONS:
            self.assertEqual(driver(v)._trace_root_candidates(body, 200)[0], 777)


class LexicalCaptureTests(unittest.TestCase):
    def test_descendant_locals_are_not_outer_captures(self):
        true_outer = local('environment', '0,0 - 0,11')
        own = local('proto', '1,0 - 1,5')
        nested = local('registers', '2,0 - 2,9')
        child = fn([{'type': 'AstStatLocal', 'vars': [nested], 'values': []},
                    ref(nested), ref(own), ref(true_outer)])
        maker = fn([child], [own])
        for v in VERSIONS:
            with self.subTest(version=v):
                captures = mapper(v)._outer_captures({'maker': maker})
                self.assertEqual([(c['name'], c['decl']) for c in captures],
                                 [('environment', true_outer['location'])])

    def test_nested_parameters_and_loop_variables_stay_local(self):
        parameter = local('arg', '2,0 - 2,3')
        counter = local('index', '3,0 - 3,5')
        child = fn([{'type': 'AstStatFor', 'var': counter, 'body': [ref(counter), ref(parameter)]}], [parameter])
        for v in VERSIONS:
            self.assertEqual(mapper(v)._outer_captures({'maker': fn([child])}), [])

    def test_true_outer_binding_survives_shadowing_in_another_child(self):
        outer = local('same_name', '0,0 - 0,9')
        inner = local('same_name', '2,0 - 2,9')
        maker = fn([fn([ref(inner)], [inner]), fn([ref(outer)])])
        for v in VERSIONS:
            captures = mapper(v)._outer_captures({'maker': maker})
            self.assertEqual([c['decl'] for c in captures], [outer['location']])


class TraceIntegrityTests(unittest.TestCase):
    def test_folding_must_not_replace_body_with_comment(self):
        def fake_fold(body, stats):
            stats['helpers'] = 1
            return 'print("must survive")'
        with patch.object(tidy.fold, 'fold', side_effect=fake_fold):
            result = tidy.tidy('-- header\n\nprint("before")', preamble=False)
        self.assertIn('print("must survive")', result)

    def test_probe_removal_note_is_valid_lua_comment(self):
        text = ('local Path2D = Instance.new("Path2D")\n'
                'Path2D:GetLength()\nprint("payload")')
        result = tidy.strip_preamble(text)
        self.assertIn('print("payload")', result)
        self.assertTrue(result.startswith('-- Removed'), result)

    def test_trace_header_cannot_claim_complete_source(self):
        header = traceout.header('arbitrary.lua')
        self.assertIn('NOT reconstructed source', header)
        self.assertIn('arbitrary.lua', header)

    def test_missing_runtime_string_binding_is_present(self):
        text = (ENGINE / 'envlog.luau').read_text()
        self.assertIn('gmatch = string.gmatch', text)


    def test_snapshot_diagnostics_do_not_enter_behavior_trace(self):
        import harness
        body = '\x00SNAPSHOTFAILURES 2\n-- run status: finished\nprint("payload")\n'
        with patch('sys.stderr') as stderr:
            cleaned, strings = traceout.take_strings(body)
        self.assertNotIn('SNAPSHOTFAILURES', cleaned)
        self.assertIn('print("payload")', cleaned)
        self.assertIsNone(strings)
        self.assertTrue(stderr.write.called)
        self.assertEqual(harness.trace_text(body), harness.trace_text(cleaned))


class LiftCompletenessTests(unittest.TestCase):
    def test_alternate_root_is_written_as_valid_json(self):
        import json
        import tempfile
        from pathlib import Path
        for v in VERSIONS:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'dump.json'
                path.write_text(json.dumps({'protos': {'3': {}, '9': {}}, 'root_callee': 3}))
                self.assertTrue(driver(v)._set_dump_root(path, 9))
                self.assertEqual(json.loads(path.read_text())['root_callee'], 9)
                self.assertFalse(driver(v)._set_dump_root(path, 12345))

    def test_round_limit_is_not_convergence(self):
        for version in ('luraph_v14_7', 'luraph_v14_8', 'luraph_v14_9', 'luraph_v15'):
            with self.subTest(version=version):
                mod = importlib.import_module('obfuscators.' + version + '.driver')
                devirt = importlib.import_module('obfuscators.' + version + '.devirt')
                stats = dict(functions=1, walked=1, errors=0, fallbacks=0)
                job = SimpleNamespace(args=SimpleNamespace(devirt_rounds=1), source_path='unused',
                                      credit_header=lambda: '', write=lambda *a: self.fail('incomplete lift was written'))
                with patch.object(devirt, 'run_big_stack', side_effect=[
                    (stats, set(), 'new-buffer-patch'),
                    ('print("payload")', stats, set(), 'new-buffer-patch')
                ]), patch.object(devirt, 'same_patches', return_value=False):
                    self.assertFalse(mod.devirtualize(job, 'absent-dump', 'absent-output', {}, None))


if __name__ == '__main__':
    unittest.main()
