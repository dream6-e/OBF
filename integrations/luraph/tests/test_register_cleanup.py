"""Synthetic register-cleanup tests, with real Luau differential execution."""
import json
import os
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from support import ENGINE, RuntimeMixin, run
import luasym as S
import register_cleanup as RC
from ir import Assign, CallStmt, Node, Next, Ret, SetList
from obfuscators.luraph_v14_7 import devirt as D, driver, vmmap
import backend


class RegisterCleanupTests(RuntimeMixin, unittest.TestCase):
    def parse(self, loop, cutoff=3, registers=None):
        path = self.work / 'loop.lua'
        path.write_text('local registers, limit, other\n' + loop)
        ast = vmmap.load_ast(str(path))
        scope = S.Scope()
        for local in ast['body'][0]['vars']:
            scope.vars[local['location']] = {
                'registers': S.RegFile() if registers is None else registers,
                'limit': cutoff, 'other': S.RegFile(),
            }[local['name']]
        interp = S.Interp(SimpleNamespace(special={}))
        return ast['body'][-1], interp, scope

    def lower(self, order, **kwargs):
        return RC.lower_cleanups(order, synthetic_base=D.JIT_TMP,
                                 frame_types=(D.FrameArg, D.FrameProxy), box_type=D.MaybeBox, **kwargs)

    def test_recognizes_renamed_parenthesized_and_inverted_forms(self):
        forms = [
            'for slot in registers do if slot > limit then registers[slot] = nil end end',
            'for key in (registers) do if (limit) < (key) then (registers)[key] = (nil) end end',
            'for j in registers do if not(j > limit) then else registers[j] = nil end end',
            'for j in registers do if j <= limit then else registers[j] = nil end end',
            'for j in registers do if limit >= j then else registers[j] = nil end end',
            'for j in registers do if not(not(j > limit)) then registers[j] = nil end end',
        ]
        for loop in forms:
            with self.subTest(loop=loop):
                st, it, scope = self.parse(loop)
                self.assertEqual(RC.match_cleanup(st, it, scope), (True, 3))

    def test_does_not_accept_other_loop_effects_or_comparisons(self):
        forms = [
            'for k in registers do if k > limit then registers[k] = false end end',
            'for k in registers do if k > limit then other[k] = nil end end',
            'for k in registers do if k > limit then registers[k+1] = nil end end',
            'for k in registers do if k >= limit then registers[k] = nil end end',
            'for k in registers do if k < limit then registers[k] = nil end end',
            'for k in registers do if k > limit then registers[k] = nil; print(k) end end',
            'for k in registers do if k > limit then registers[k] = nil else print(k) end end',
            'for k in registers do if k > k then registers[k] = nil end end',
            'for k, v in registers do if k > limit then registers[k] = nil end end',
            'for k in pairs(registers) do if k > limit then registers[k] = nil end end',
            'for k in registers do if k > getLimit() then registers[k] = nil end end',
        ]
        for loop in forms:
            with self.subTest(loop=loop):
                st, it, scope = self.parse(loop)
                self.assertFalse(RC.match_cleanup(st, it, scope)[0])

    def test_unknown_invalid_bounds_and_non_register_tables_are_not_guessed(self):
        loop = 'for k in registers do if k > limit then registers[k] = nil end end'
        for cutoff in (S.Reg(7), None, True, b'3', float('inf'), float('nan'), 10**400):
            with self.subTest(cutoff=cutoff):
                self.assertFalse(RC.match_cleanup(*self.parse(loop, cutoff))[0])
        self.assertFalse(RC.match_cleanup(*self.parse(loop, registers=S.LTable()))[0])
        for cutoff in (-3, 0, 2.5):
            self.assertEqual(RC.match_cleanup(*self.parse(loop, cutoff)), (True, cutoff))

    def test_scalar_fact_cleanup_preserves_boundary_and_synthetic_temporaries(self):
        facts = {1: ('c', 7), 3: ('c', False), 5: ('t',), D.JIT_TMP: ('c', 42)}
        D.apply_stmt_facts(RC.ClearRegistersAbove(3), facts, None)
        self.assertEqual(facts, {1: ('c', 7), 3: ('c', False), 5: ('c', None), D.JIT_TMP: ('c', 42)})
        self.assertNotIn(100, facts)  # sparse propagation stays conservative

    def test_frontend_hook_invalidates_cached_packs_and_register_aliases(self):
        lf = object.__new__(D.ProtoLifter)
        lf.special = {}
        lf.packs = {7: S.SymList([11])}
        lf.pack_copies = {7: lf.packs[7]}
        lf.pack_read = set()
        lf.pack_killed = set()
        lf.jvals = {2: 9, 6: 8, 9: D.FRAME, D.JIT_TMP: 17}
        lf.jump_regs = {6}
        lf.stack_base = None
        lf.out = []
        st, _, scope = self.parse('for k in registers do if k > limit then registers[k] = nil end end')
        S.Interp(lf).exec_stmt(st, scope)
        self.assertEqual(lf.jvals, {2: 9, D.JIT_TMP: 17})
        self.assertFalse(lf.packs)
        self.assertFalse(lf.pack_copies)
        self.assertIsInstance(lf.out[-1], RC.ClearRegistersAbove)
        self.assertEqual([x.target.n for x in lf.out[:-1]], [6, 7, 9])

    def test_clear_covers_future_reads_tests_returns_and_closure_captures(self):
        closure = S.ClosureExpr(S.LTable(), [D.MaybeBox(8), S.Reg(9)])
        child = Node([], outcome=Ret(S.Multi([S.Reg(12)])))
        n = Node([RC.ClearRegistersAbove(3), CallStmt('t', S.Global('use'), S.Multi([S.Reg(7), closure]))],
                 cond=S.Reg(6), then=child, els=Node([], outcome=Ret(S.Multi([S.Reg(3)]))))
        self.assertEqual(self.lower([((), n)]), 1)
        self.assertEqual([x.target.n for x in n.stmts if isinstance(x, Assign)], [6, 7, 8, 9, 12])
        self.assertTrue(all(x.value.v is None for x in n.stmts if isinstance(x, Assign)))
        self.assertIsInstance(n.stmts[-1], CallStmt)

    def test_lowering_preserves_overwrites_and_multiple_clear_positions(self):
        overwrite = Assign(S.Reg(7), S.Const(99))
        n = Node([RC.ClearRegistersAbove(2), overwrite, RC.ClearRegistersAbove(8)],
                 outcome=Ret(S.Multi([S.Reg(2), S.Reg(7), S.Reg(10), S.Reg(D.JIT_TMP)])))
        self.assertEqual(self.lower([((), n)]), 2)
        self.assertEqual([(x.target.n, x.value.v) for x in n.stmts],
                         [(7, None), (10, None), (7, 99), (10, None)])

    def test_dynamic_or_escaping_frames_are_refused_before_graph_mutation(self):
        expressions = [S.RegFile(), D.FrameArg(-1),
                       S.ClosureExpr(S.LTable(), [S.RegFile()]),
                       S.ClosureExpr(S.LTable(), [S.LTable({1: 3, 2: S.RegFile()})])]
        for value in expressions:
            with self.subTest(value=value):
                effect = RC.ClearRegistersAbove(1)
                n = Node([effect], outcome=Ret(S.Multi([value])))
                with self.assertRaisesRegex(S.Unsupported, 'escaping register frame'):
                    self.lower([((), n)])
                self.assertIs(n.stmts[0], effect)
        # SetList, Close and explicit captures also contribute physical reads.
        n = Node([RC.ClearRegistersAbove(1), SetList(S.Reg(5), 1, S.Multi([S.Reg(8)])), D.Close(9)])
        self.lower([((), n)], captured_regs=(11,))
        self.assertEqual([x.target.n for x in n.stmts if isinstance(x, Assign)], [5, 8, 9, 11])
        n = Node([RC.ClearRegistersAbove(1)])
        with self.assertRaisesRegex(S.Unsupported, 'dynamically indexed'):
            self.lower([((), n)], dynamic_arrays=True)

    def test_physical_slots_cannot_be_mistaken_for_compiler_temporaries(self):
        for slot in (D.JIT_TMP, D.JIT_TMP + 5, 1.5, b"field", True):
            with self.subTest(slot=slot):
                lf = object.__new__(D.ProtoLifter)
                lf.cleanup_unsafe_slots = False
                lf._note_physical_slot(slot)
                self.assertTrue(lf.cleanup_unsafe_slots)
                n = Node([RC.ClearRegistersAbove(3)])
                with self.assertRaisesRegex(S.Unsupported, 'reserved physical slots'):
                    self.lower([((), n)], unsafe_slots=lf.cleanup_unsafe_slots)
        lf = object.__new__(D.ProtoLifter)
        lf.cleanup_unsafe_slots = False
        lf._note_physical_slot(7)
        self.assertFalse(lf.cleanup_unsafe_slots)

    def test_graph_without_cleanup_is_unchanged(self):
        n = Node([CallStmt('t', S.Global('f'), S.Multi([S.RegFile()]))])
        stmts = n.stmts
        self.assertEqual(self.lower([((), n)], dynamic_arrays=True), 0)
        self.assertIs(n.stmts, stmts)

    def test_cleanup_stays_in_its_branch_through_backend(self):
        start, join = D.State(0, 1, None), D.State(0, 2, None)
        branch = Node([Assign(S.Reg(4), S.Const(44))], cond=S.Global('choose'),
                      then=Node([RC.ClearRegistersAbove(2)], outcome=Next(join)),
                      els=Node([], outcome=Next(join)))
        end = Node([], outcome=Ret(S.Multi([S.Reg(4)])))
        order = [(start.key(None), branch), (join.key(None), end)]
        self.lower(order)
        self.assertEqual(len(branch.stmts), 1)
        self.assertEqual(len(branch.then.stmts), 1)
        self.assertFalse(branch.els.stmts)
        lines, _, errors, fallbacks = backend.lower(start.key(None), order, D, None, 'r', {},
                                                    lambda *a: self.fail('unexpected closure'))
        self.assertEqual((errors, fallbacks), (0, 0))
        src = self.work / 'branch.lua'
        src.write_text('local choose\nlocal function lifted()\n' + '\n'.join(lines) + '\nend\n'
                       'choose=true; assert(lifted()==nil)\n'
                       'choose=false; assert(lifted()==44)\nprint("branch-preserved")\n')
        result = run([ENGINE / 'bin/luau', src])
        self.assertEqual(result.returncode, 0, result.stderr + src.read_text())
        self.assertEqual(result.stdout.strip(), 'branch-preserved')

    def test_generated_luau_matches_real_sparse_table_deletion(self):
        # Full backend lowering + real Luau execution, NOT a regex assertion.
        for cutoff in (-1, 0, 2.5, 3, 9, 20):
            with self.subTest(cutoff=cutoff):
                slots = [-2, 0, 1, 3, 7, 13]
                values = [22, False, 11, 33, 77, False]
                n = Node([Assign(S.Reg(r), S.Const(v)) for r, v in zip(slots, values)] +
                         [RC.ClearRegistersAbove(cutoff), Assign(S.Reg(7), S.Const(99))],
                         outcome=Ret(S.Multi([S.Reg(r) for r in slots] + [S.Reg(19)])))
                state = D.State(0, 1, None)
                order = [(state.key(None), n)]
                self.lower(order)
                lines, _, errors, fallbacks = backend.lower(state.key(None), order, D, None, 'r', {},
                                                            lambda *a: self.fail('unexpected closure'))
                self.assertEqual((errors, fallbacks), (0, 0))
                literal = lambda x: 'false' if x is False else str(x)
                original = 'local R = {' + ','.join(f'[{r}]={literal(v)}' for r, v in zip(slots, values)) + '}\n'
                original += f'for k in R do if k > {cutoff} then R[k] = nil end end\nR[7] = 99\n'
                original += 'return ' + ','.join(f'R[{r}]' for r in slots + [19])
                src = self.work / 'differential.lua'
                src.write_text('local function original()\n' + original + '\nend\n'
                               'local function lifted()\n' + '\n'.join(lines) + '\nend\n'
                               'local a,b=table.pack(original()),table.pack(lifted())\n'
                               'assert(a.n == b.n)\nfor i=1,a.n do assert(a[i] == b[i], "slot "..i) end\n'
                               'print("cleanup-equivalent")\n')
                result = run([ENGINE / 'bin/luau', src])
                self.assertEqual(result.returncode, 0, result.stderr + src.read_text())
                self.assertEqual(result.stdout.strip(), 'cleanup-equivalent')


class ServedRootTests(unittest.TestCase):
    trace = '--@1 10:1,20:2\nprobe()\n--@1 70:3\npayload()\n'

    def reply(self, protos=('20', '70')):
        return '\x00PROTOS ' + json.dumps({'protos': {p: {} for p in protos}, 'root_callee': None}) + '\n'

    def root(self, body):
        return json.loads(re.search(r'\x00PROTOS ([^\n]+)', body)[1])['root_callee']

    def test_same_session_reply_keeps_verified_payload_root(self):
        self.assertEqual(self.root(driver._hint_served_dump(self.reply(), self.trace)), 70)

    def test_missing_or_unverified_roots_are_not_reused(self):
        body = self.reply()
        self.assertEqual(driver._hint_served_dump(body, None), body)
        self.assertEqual(driver._hint_served_dump(body, ''), body)
        self.assertIsNone(self.root(driver._hint_served_dump(self.reply(('91',)), self.trace)))
        error = '\x00PROTOS error: capture failed\n'
        self.assertEqual(driver._hint_served_dump(error, self.trace), error)

    def test_lift_only_carries_hints_in_verified_live_session(self):
        # Exercise the actual rerun closure, including repeated constant replies
        # and fallback to a new runner whose proto IDs must NOT inherit hints.
        for mode in ('live', 'different-trace', 'request-failure', 'first-failure'):
            with self.subTest(mode=mode):
                hs = Mock()
                hs.reply.return_value = (None, 'failed') if mode == 'first-failure' else (self.trace, None)
                hs.request.return_value = (None, 'failed') if mode == 'request-failure' else (self.reply(), None)
                runner = SimpleNamespace(bridge=None, luau='unused', run=Mock(return_value=(self.reply(), None)))
                job = SimpleNamespace(args=SimpleNamespace(timeout=3))
                seen = []
                def fake_devirtualize(job, ppath, dpath, cfg, rerun, chunks, live):
                    for _ in range(2):
                        body, err = rerun({})
                        self.assertIsNone(err)
                        seen.append(self.root(body))
                with patch.dict(os.environ, {}, clear=True), \
                     patch.object(driver.harness, 'HarnessServer', return_value=hs), \
                     patch.object(driver.harness, 'same_trace', return_value=mode != 'different-trace'), \
                     patch.object(driver, 'devirtualize', side_effect=fake_devirtualize):
                    driver.lift(job, runner, '', {}, {}, self.trace, 'dump', 'output', ())
                self.assertEqual(seen, [70, 70] if mode == 'live' else [None, None])
                self.assertTrue(hs.close.called)
                if mode != 'live':
                    self.assertTrue(runner.run.called)


if __name__ == '__main__':
    unittest.main()
