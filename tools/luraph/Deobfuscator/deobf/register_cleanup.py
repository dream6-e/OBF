"""Exact, narrow lowering of VM register-tail deletion (not arbitrary for-in).

The symbolic register file is not a concrete iterable table. Keep the deletion
as an IR effect until the full instruction graph tells us which physical slots
can be observed. Do not confuse table.create's capacity with a register bound.
"""
import math

import luasym as S
from ir import IRStmt, Assign, CallStmt, SetList, ForPrep, Close, Ret


class ClearRegistersAbove(IRStmt):
    def __init__(self, cutoff):
        self.cutoff = cutoff

    def __repr__(self):
        return "clear VM registers above %r" % self.cutoff


def unwrap(n):
    while isinstance(n, dict) and n.get("type") == "AstExprGroup":
        n = n["expr"]
    return n


def local_decl(n):
    n = unwrap(n)
    return n["local"]["location"] if n and n.get("type") == "AstExprLocal" else None


def match_cleanup(st, interp, scope):
    """Return (matched, cutoff) for `for k in R do if k > N then R[k]=nil end end`.

    Only local, concrete RegFile targets and finite constant cutoffs qualify.
    No extra loop variables, calls or additional branch effects are erased.
    Comparing against a symbolic bound remains unsupported by the interpreter.
    """
    if st.get("type") != "AstStatForIn" or len(st["values"]) != 1 or len(st["vars"]) != 1:
        return False, None
    table_decl = local_decl(st["values"][0])
    key_decl = st["vars"][0]["location"]
    if table_decl is None or table_decl == key_decl:
        return False, None
    body = st["body"]["body"]
    if len(body) != 1 or body[0]["type"] != "AstStatIf":
        return False, None
    branch = body[0]
    otherwise = branch.get("elsebody")
    if otherwise is not None and otherwise.get("type") != "AstStatBlock":
        return False, None
    yes = branch["thenbody"]["body"]
    no = otherwise["body"] if otherwise is not None else []
    if bool(yes) == bool(no):
        return False, None  # both arms empty, or extra effects on the other arm
    deletion_when_true = bool(yes)
    body = yes if yes else no
    cond = unwrap(branch["condition"])
    while cond.get("type") == "AstExprUnary" and cond.get("op") == "Not":
        deletion_when_true = not deletion_when_true
        cond = unwrap(cond["expr"])
    if cond.get("type") != "AstExprBinary":
        return False, None
    if local_decl(cond["left"]) == key_decl and cond["op"] == ("CompareGt" if deletion_when_true else "CompareLe"):
        bound = unwrap(cond["right"])
    elif local_decl(cond["right"]) == key_decl and cond["op"] == ("CompareLt" if deletion_when_true else "CompareGe"):
        bound = unwrap(cond["left"])
    else:
        return False, None
    if bound["type"] not in ("AstExprLocal", "AstExprConstantNumber") or local_decl(bound) == key_decl:
        return False, None
    if len(body) != 1 or body[0]["type"] != "AstStatAssign":
        return False, None
    store = body[0]
    if len(store["vars"]) != 1 or len(store["values"]) != 1:
        return False, None
    target = unwrap(store["vars"][0])
    if (target["type"] != "AstExprIndexExpr" or local_decl(target["expr"]) != table_decl
            or local_decl(target["index"]) != key_decl
            or unwrap(store["values"][0])["type"] != "AstExprConstantNil"):
        return False, None
    if not isinstance(interp.eval(st["values"][0], scope), S.RegFile):
        return False, None
    cutoff = interp.eval(bound, scope)
    if type(cutoff) not in (int, float):
        return False, None
    try:
        if not math.isfinite(cutoff):
            return False, None
    except OverflowError:
        return False, None
    return True, cutoff


def clear_facts(effect, facts, *, synthetic_base):
    # A sparse fact map only promises knowledge of these slots. Unknown slots
    # stay unknown rather than inventing a bound/allocating an infinite map.
    for r in list(facts):
        if type(r) is int and effect.cutoff < r < synthetic_base:
            facts[r] = ("c", None)


def lower_cleanups(order, captured_regs=(), *, synthetic_base, dynamic_arrays=False, unsafe_slots=False,
                   frame_types=(), box_type=()):
    """Replace the effect with nil stores to every observable physical slot.

    Inspect the ENTIRE graph, including branch tests, return values and closure
    captures, so even slots first read after the deletion are cleared. Compiler
    scratch registers are not VM slots. Reject escaping/dynamic storage: a
    finite set of scalar registers cannot describe its observable contents.
    """
    nodes, seen = [], set()
    stack = [n for _, n in order]
    while stack:
        n = stack.pop()
        if n is None or id(n) in seen:
            continue
        seen.add(id(n))
        nodes.append(n)
        stack.extend((n.then, n.els))
    effects = [s for n in nodes for s in n.stmts if isinstance(s, ClearRegistersAbove)]
    if not effects:
        return 0
    if unsafe_slots:
        raise S.Unsupported("register cleanup with non-integer or reserved physical slots")
    if dynamic_arrays:
        raise S.Unsupported("register cleanup with dynamically indexed register storage")
    regs = set()
    seen_values = {}

    def visit(x):
        if x is None or id(x) in seen_values:
            return
        seen_values[id(x)] = x
        if isinstance(x, S.Reg):
            if type(x.n) is not int:
                raise S.Unsupported("register cleanup with non-integer register index")
            if x.n < synthetic_base:
                regs.add(x.n)
        elif isinstance(x, S.RegFile) or (frame_types and isinstance(x, frame_types)):
            raise S.Unsupported("register cleanup with an escaping register frame")
        elif box_type and isinstance(x, box_type):
            visit(S.Reg(x.reg))
        elif isinstance(x, S.ClosureExpr):
            # The proto itself is VM data, not IR. Only its captured values are
            # expressions in this function's register namespace.
            visit(x.upvals)
        elif isinstance(x, S.LTable):
            # Upvalue boxes can contain frames; do not silently overlook them.
            visit(tuple(x.h.keys()))
            visit(tuple(x.h.values()))
        elif isinstance(x, (S.Expr, S.Multi, S.SymList, S.TempTail, S.VarargTail)):
            for value in vars(x).values():
                visit(value)
        elif isinstance(x, (list, tuple)):
            for value in x:
                visit(value)
        elif isinstance(x, dict):
            for key, value in x.items():
                visit(key)
                visit(value)

    for r in captured_regs:
        visit(S.Reg(r))
    for n in nodes:
        visit(n.cond)
        if isinstance(n.outcome, Ret):
            visit(n.outcome.values)
        for s in n.stmts:
            if isinstance(s, Assign):
                visit(s.target)
                visit(s.value)
            elif isinstance(s, CallStmt):
                visit(s.fn)
                visit(s.args)
            elif isinstance(s, SetList):
                visit(s.tbl)
                visit(s.start)
                visit(s.values)
            elif isinstance(s, Close):
                visit(S.Reg(s.reg))
            elif isinstance(s, ForPrep):
                raise S.Unsupported("register cleanup with unexpanded loop bookkeeping")
            elif not isinstance(s, ClearRegistersAbove):
                raise S.Unsupported("register cleanup with unknown IR effect")
    # No mutation until the entire graph has passed the safety checks.
    ordered = sorted(regs)
    for n in nodes:
        out = []
        for s in n.stmts:
            if isinstance(s, ClearRegistersAbove):
                out.extend(Assign(S.Reg(r), S.Const(None)) for r in ordered if r > s.cutoff)
            else:
                out.append(s)
        n.stmts = out
    return len(effects)
