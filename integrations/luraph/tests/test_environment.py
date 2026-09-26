"""Synthetic environment regressions; no user-sample bytes or expected answers."""
import re
from pathlib import Path
import unittest

from support import ENGINE, RuntimeMixin, cli, run


class GuiLayoutTests(RuntimeMixin, unittest.TestCase):
    def simulate(self, source, **cfg):
        import harness
        body, error = harness.run_once(
            str(ENGINE / 'bin/luau'), source, {'time_budget': 5, **cfg},
            str(self.work / 'gui.harness.luau'), 10, False)
        self.assertIsNone(error)
        self.assertIsNotNone(body)
        return body, harness.LAST_RAW[0]

    def test_unknown_layout_never_becomes_zero(self):
        for cls in ('Frame', 'TextLabel', 'ImageButton', 'ScrollingFrame', 'ScreenGui'):
            for prop in ('AbsolutePosition', 'AbsoluteSize', 'AbsoluteRotation'):
                with self.subTest(cls=cls, prop=prop):
                    body, _ = self.simulate(
                        f'local g = Instance.new("{cls}"); local v = g.{prop}; print("incorrect continuation", v)')
                    self.assertIn('-- run status: aborted: unsupported environment:', body)
                    self.assertIn(f'{cls}.{prop}', body)
                    self.assertNotIn('print("incorrect continuation"', body)
                    self.assertNotIn('run status: finished', body)

    def test_catching_missing_layout_cannot_mark_run_finished(self):
        for call in ('pcall', 'xpcall'):
            with self.subTest(call=call):
                body, _ = self.simulate(f'''
local g = Instance.new("Frame")
local ok = {call}(function() return g.AbsolutePosition.X end, function(e) return e end)
return ok
''')
                self.assertIn('aborted: unsupported environment:', body)
                self.assertNotIn('run status: finished', body)

    def test_deferred_missing_layout_is_not_finished(self):
        body, _ = self.simulate('''
task.defer(function()
    local g = Instance.new("TextLabel")
    return g.AbsoluteSize.X
end)
''')
        self.assertIn('aborted: unsupported environment:', body)
        self.assertIn('TextLabel.AbsoluteSize', body)

    def test_real_vector_math_and_assigned_properties_still_work(self):
        body, _ = self.simulate('''
local g = Instance.new("Frame")
g.Size = UDim2.fromOffset(23, 47)
g.Position = UDim2.fromScale(0.25, 0.5)
g.AnchorPoint = Vector2.new(0.5, 1)
assert(g.Size.X.Offset == 23 and g.Size.Y.Offset == 47)
assert(g.Position.X.Scale == 0.25 and g.AnchorPoint.Y == 1)
assert(Vector2.new(3, 4).Magnitude == 5)
print("known values preserved")
''')
        self.assertIn('run status: finished', body)
        self.assertIn('print("known values preserved")', body)

    def test_guard_uses_class_ancestry_not_just_property_name(self):
        body, _ = self.simulate('''
local f = Instance.new("Folder")
local symbolic = f.AbsolutePosition
local t = {AbsoluteSize = 19}
assert(t.AbsoluteSize == 19)
print("unrelated properties unchanged")
''')
        self.assertIn('run status: finished', body)
        self.assertNotIn('unsupported environment', body)

    def test_property_trace_disambiguates_instances(self):
        _, raw = self.simulate('''
local a, b = Instance.new("Frame"), Instance.new("Frame")
a.Rotation = 10
b.Rotation = 20
assert(a.Rotation == 10 and b.Rotation == 20)
''', ptrace=True)
        reads = re.findall(r'\[index\]\tFrame\tRotation\tid=(\d+)', raw)
        writes = re.findall(r'\[newindex\]\tFrame\tRotation\tnumber\tid=(\d+)', raw)
        self.assertEqual(len(set(reads)), 2, raw)
        self.assertEqual(reads, writes)

    def test_studio_calibration_probe_parses(self):
        # Syntax only: real Roblox layout semantics cannot be tested in Luau CLI.
        probe = Path(__file__).resolve().parents[1] / 'probes/gui_layout_probe.luau'
        result = run([ENGINE / 'bin/luau-ast', probe])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_rejects_layout_failure_without_writing_source(self):
        src = self.work / 'gui-unavailable.lua'
        src.write_text('-- This file was protected using Luraph Obfuscator v14.9 [https://lura.ph/]\n'
                       'local f = Instance.new("Frame"); print(f.AbsolutePosition.X)')
        result = cli('cli.py', src, '--no-hooks', '--timeout', '10', '-o', self.output())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('GUI layout unavailable for Frame.AbsolutePosition', result.stderr)
        self.assertFalse(self.output().exists())
        self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
