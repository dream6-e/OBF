"""Diagnostic source capture: no user payloads in the regression suite."""
import importlib.util
from pathlib import Path
import sys
import unittest

from support import ENGINE, RuntimeMixin, run

PROBE = Path(__file__).resolve().parents[1] / 'probes' / 'capture_loadstrings.py'
spec = importlib.util.spec_from_file_location('capture_loadstrings_probe', PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class CaptureSourceTests(RuntimeMixin, unittest.TestCase):
    def test_capture_sites_fail_closed_and_preserve_line_count(self):
        template = ('\tif not f then return nil, err end\n\tR.setfenv(f, ENV)\n'
                    'for _, hook in R.ipairs(CHAIN.endHooks or {}) do\nend\n')
        result = probe.instrument(template)
        self.assertEqual(template.count('\n'), result.count('\n'))
        self.assertIn('CHAIN.observedLoadstrings[src] = true', result)
        for bad in ('', template + template, template.replace('endHooks', 'otherHooks')):
            with self.assertRaises(ValueError):
                probe.instrument(bad)

    def test_records_preserve_bytes_deduplicate_and_check_lengths(self):
        data = b'\x00\xff\r\n'
        record = '\x00LOADSTRING_SOURCE 4 ' + data.hex() + '\n'
        self.assertEqual(probe.source_records(record * 2), [data])
        self.assertEqual(probe.SOURCE_RECORD.sub('', 'before\n' + record + 'after\n'),
                         'before\nafter\n')
        with self.assertRaises(ValueError):
            probe.source_records('\x00LOADSTRING_SOURCE 5 00ff0d0a\n')

    def test_real_runtime_keeps_source_out_of_rendered_trace(self):
        src = self.work / 'input.lua'
        raw, output = self.work / 'raw.txt', self.work / 'trace.luau'
        src.write_text('local f = assert(loadstring("return 42"))\n'
                       'print(f())\n'
                       'local bad = loadstring("local =")\n'
                       'assert(bad == nil)\n')
        original = src.read_bytes()
        result = run([sys.executable, '-B', PROBE, ENGINE, src,
                      '--obfuscator', 'generic', '--no-devirt', '--no-hooks', '--no-pypy',
                      '--no-tidy', '--no-fold', '--timeout', '10', '--raw', raw, '-o', output])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(probe.source_records(raw.read_text()), [b'return 42'])
        text = output.read_text()
        self.assertIn('print(42)', text)
        self.assertIn('behavior trace, NOT reconstructed source', text)
        self.assertNotIn('LOADSTRING_SOURCE', text)
        self.assertNotIn('\x00', text)
        self.assertEqual(src.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
