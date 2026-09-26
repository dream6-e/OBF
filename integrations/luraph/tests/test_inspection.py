"""Synthetic opcode-inspection tests; no user-file opcode/prototype constants."""
import contextlib
import importlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from support import ENGINE  # adds the tested checkout to sys.path


class OpcodeInspectionTests(unittest.TestCase):
    def inspect(self, version, *, grouped=False, conditional=False, mode=0, forced=None):
        d = importlib.import_module(f'obfuscators.luraph_v{version}.devirt')
        array = {'type': 'AstExprLocal', 'local': {'name': 'OPS'}}
        fetch = {'type': 'AstExprIndexExpr', 'expr': array,
                 'index': {'type': 'AstExprLocal', 'local': {'name': 'PC'}}}
        if grouped:
            fetch = {'type': 'AstExprGroup', 'expr': fetch}
        loop = {'body': {'body': [{'values': [fetch]}]}}
        cond = {'left': {'type': 'AstExprLocal'},
                'right': {'type': 'AstExprConstantNumber', 'value': 7}}
        stepper = SimpleNamespace(loops=[(1, {} if conditional else None, loop)],
                                  conds={1: cond} if conditional else {}, cs=None,
                                  _fresh_scopes=lambda *a: (None, 'scope'))
        vm = SimpleNamespace(maker_decls={}, vmobj_of=lambda c: None, proto_of=lambda c: None)
        prog = SimpleNamespace(dump=SimpleNamespace(protos={'demo': {}}),
                               vm_of=lambda c: vm, globals=None, lines=[], root=None)
        arr = Mock(); arr.get.return_value = 41
        interp = Mock(); interp.eval.return_value = arr
        output = io.StringIO()
        with patch.object(d, 'ProtoLifter', return_value=object()), \
             patch.object(d, 'make_stepper', return_value=stepper), \
             patch.object(d.S, 'Interp', return_value=interp), \
             patch.object(d.vmmap, 'find_dispatchers', return_value=[
                 {'node': loop, 'arr': 'OPS', 'tree': 'tree', 'op': 'op'}]), \
             patch.object(d.vmmap, 'resolve', return_value={'body': []}) as resolve, \
             patch.object(d.vmmap, 'text_of', return_value='synthetic handler'), \
             contextlib.redirect_stdout(output):
            d.show_op(prog, 'demo', mode, 3, forced)
        return output.getvalue(), interp, arr, array, resolve

    def test_unconditional_dispatcher_accepts_plain_and_grouped_fetch(self):
        for version in ('14_7', '14_8', '14_9'):
            for grouped in (False, True):
                with self.subTest(version=version, grouped=grouped):
                    text, interp, arr, array, resolve = self.inspect(version, grouped=grouped)
                    self.assertIn('mode 0 pc 3: op 41 (array OPS)', text)
                    self.assertIn('synthetic handler', text)
                    interp.eval.assert_called_once_with(array, 'scope')
                    arr.get.assert_called_once_with(3)
                    resolve.assert_called_once_with('tree', 'op', 41)

    def test_conditional_dispatch_and_forced_opcode_preserved(self):
        for version in ('14_7', '14_8', '14_9'):
            with self.subTest(version=version):
                text, _, arr, _, resolve = self.inspect(version, grouped=True,
                                                       conditional=True, mode=7, forced=53)
                self.assertIn('mode 7 pc 3: op 53', text)
                arr.get.assert_not_called()
                resolve.assert_called_once_with('tree', 'op', 53)

    def test_wrong_modes_do_not_inspect_unrelated_dispatcher(self):
        for version in ('14_7', '14_8', '14_9'):
            for conditional in (False, True):
                with self.subTest(version=version, conditional=conditional):
                    text, interp, _, _, resolve = self.inspect(version, conditional=conditional, mode=9)
                    self.assertIn('no loop for mode 9', text)
                    interp.eval.assert_not_called()
                    resolve.assert_not_called()


if __name__ == '__main__':
    unittest.main()
