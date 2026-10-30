#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Luau 源码静态结构分析器（不执行、不解密）。

设计目标：给 luraph14.9.lua 这类「单行 + 巨型长字符串 + 扁平大表」产物
做结构层面（非语义层面）的测量：

  * 词法：字符串/注释/数字（含 0X.. 0B.. 带下划线）正确跳过
  * 结构：括号栈 + 关键字块栈双轨，得到准确的「表字段边界」和块嵌套
  * 度量：字段数、函数体大小、控制流构造计数、嵌套深度
  * 调用图雏形：`X:Name(` / `.Name` / `[Name]` 的引用计数（判死代码）

用法:
    python3 tools/luraph_scan.py luraph14.9.lua            # 概览
    python3 tools/luraph_scan.py luraph14.9.lua --fields    # 字段表
    python3 tools/luraph_scan.py luraph14.9.lua --funcs     # 函数度量
    python3 tools/luraph_scan.py luraph14.9.lua --dead      # 疑似死代码
"""
import re
import sys
from collections import Counter, defaultdict


# ---------------------------------------------------------------- 词法

class Tok:
    __slots__ = ("kind", "val", "pos", "end", "idx")

    def __init__(self, kind, val, pos, end, idx=0):
        self.kind = kind   # comment/name/kw/num/str/op/eof
        self.val = val
        self.pos = pos
        self.end = end
        self.idx = idx

    def __repr__(self):
        return "%s(%r)" % (self.kind, self.val)


KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while", "continue",
}

OPS = [
    "...", "..=", "//=", "->", "==", "~=", "<=", ">=", "..", "//", "::",
    "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=",
    "+", "-", "*", "/", "%", "^", "#", "&", "~", "|", "<<", ">>",
    "<", ">", "=", "(", ")", "{", "}", "[", "]", ";", ":", ",", ".", "@",
]

_NUM = re.compile(
    r"""0[xX][0-9a-fA-F_]*(?:\.[0-9a-fA-F_]*)?(?:[pP][+-]?\d+)?
      | 0[bB][01_]*
      | (?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d+)?
    """, re.X)
_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


def _long_bracket(s, i):
    j = i + 1
    lvl = 0
    while j < len(s) and s[j] == "=":
        lvl += 1
        j += 1
    if j < len(s) and s[j] == "[":
        return lvl, j + 1
    return None


def tokenize(s, keep_comments=False):
    toks = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t\r\n\f\v":
            i += 1
            continue
        if c == "-" and i + 1 < n and s[i + 1] == "-":
            j = i + 2
            k = None
            if j < n and s[j] == "[":
                lb = _long_bracket(s, j)
                if lb:
                    lvl, st = lb
                    close = "]" + "=" * lvl + "]"
                    k = s.find(close, st)
                    k = n if k < 0 else k + len(close)
            if k is None:
                k = s.find("\n", j)
                k = n if k < 0 else k
            if keep_comments:
                toks.append(Tok("comment", s[i:k], i, k))
            i = k
            continue
        if c in "\"'":
            j = i + 1
            while j < n:
                ch = s[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == c:
                    j += 1
                    break
                if ch == "\n":
                    break
                j += 1
            toks.append(Tok("str", s[i:j], i, j))
            i = j
            continue
        if c == "[":
            lb = _long_bracket(s, i)
            if lb:
                lvl, st = lb
                close = "]" + "=" * lvl + "]"
                k = s.find(close, st)
                k = n if k < 0 else k + len(close)
                toks.append(Tok("str", s[i:k], i, k))
                i = k
                continue
        if c.isdigit() or (c == "." and i + 1 < n and s[i + 1].isdigit()):
            m = _NUM.match(s, i)
            if m and m.end() > i:
                toks.append(Tok("num", m.group(0), i, m.end()))
                i = m.end()
                continue
        m = _NAME.match(s, i)
        if m:
            w = m.group(0)
            toks.append(Tok("kw" if w in KEYWORDS else "name", w, i, m.end()))
            i = m.end()
            continue
        for op in OPS:
            if s.startswith(op, i):
                toks.append(Tok("op", op, i, i + len(op)))
                i += len(op)
                break
        else:
            toks.append(Tok("op", c, i, i + 1))
            i += 1
    toks.append(Tok("eof", "", n, n))
    for k, t in enumerate(toks):
        t.idx = k
    return toks


# ---------------------------------------------------------------- 结构栈

OPEN_KW = {"function", "if", "while", "for", "do", "repeat"}


class Frame:
    __slots__ = ("kind", "tokidx", "depth", "children", "parent", "closed_at")

    def __init__(self, kind, tokidx, depth, parent):
        self.kind = kind
        self.tokidx = tokidx
        self.depth = depth
        self.children = []
        self.parent = parent
        self.closed_at = None

    def __repr__(self):
        return "Frame(%s@%d)" % (self.kind, self.tokidx)


def parse_blocks(toks):
    """返回 (roots, frames)。只按关键字块建树，括号只用于跳过。

    注意 while/for 的 `do` 属于其语法成分，不算独立块。
    """
    roots, stack = [], []
    bracket = 0
    expect_do = []      # 栈上等待 do 的层号
    for t in toks:
        if t.kind == "op":
            if t.val in "({[":
                bracket += 1
            elif t.val in ")}]":
                bracket -= 1
            continue
        if t.kind != "kw":
            continue
        v = t.val
        if v in ("while", "for"):
            parent = stack[-1] if stack else None
            f = Frame(v, t.idx, len(stack), parent)
            (parent.children if parent else roots).append(f)
            stack.append(f)
            expect_do.append(len(stack))
        elif v == "do":
            if expect_do and expect_do[-1] == len(stack):
                expect_do.pop()
                continue
            parent = stack[-1] if stack else None
            f = Frame(v, t.idx, len(stack), parent)
            (parent.children if parent else roots).append(f)
            stack.append(f)
        elif v in ("function", "if", "repeat"):
            parent = stack[-1] if stack else None
            f = Frame(v, t.idx, len(stack), parent)
            (parent.children if parent else roots).append(f)
            stack.append(f)
        elif v in ("end", "until"):
            if stack:
                stack.pop().closed_at = t.idx
    for f in stack:
        f.closed_at = len(toks) - 1
    return roots, [f for r in roots for f in walk(r)]


def walk(f):
    yield f
    for c in f.children:
        yield from walk(c)


def find_table_fields(toks, open_idx):
    """定位外层大表 `{` 的字段。返回 [(name|None, kind, start_tok, end_tok, text)]。

    kind: function / str / name / num / op / call / table ...
    依据：括号深度 == 1（表内）且关键字块栈为空。
    """
    fields = []
    depth = 1
    kwdepth = 0
    expect_do = []
    i = open_idx + 1
    field_start = i
    field_name = None
    awaiting_value = False
    n = len(toks)

    def close_field(endtok):
        if endtok <= field_start:
            return
        a = toks[field_start]
        kind = a.kind
        if a.kind == "kw" and a.val == "function":
            kind = "function"
        elif a.kind == "op" and a.val == "(":
            kind = "op/paren"
        elif a.kind == "op" and a.val == "{":
            kind = "table"
        elif a.kind == "name":
            # 一串 name 说明是表达式（如 table.create）
            j = field_start
            while j + 1 < endtok and toks[j + 1].kind == "name":
                j += 1
            kind = "name" if j == field_start else "ref"
            if any(toks[k].kind == "op" and toks[k].val in ("(", ":")
                   for k in range(field_start, endtok)):
                kind = "call"
        elif a.kind == "kw" and a.val in ("nil", "true", "false"):
            kind = "kw"
        fields.append((field_name, kind, field_start, endtok,
                       toks[field_start].pos, toks[endtok - 1].end))

    while i < n:
        t = toks[i]
        if t.kind == "op":
            if t.val in "({[":
                depth += 1
                i += 1
                continue
            if t.val in ")}]":
                depth -= 1
                if depth == 0:
                    close_field(i)
                    break
                i += 1
                continue
        if t.kind == "kw":
            v = t.val
            if v in ("while", "for"):
                if kwdepth == 0 and depth >= 2:
                    pass
                kwdepth += 1
                expect_do.append(kwdepth)
                i += 1
                continue
            if v == "do":
                if expect_do and expect_do[-1] == kwdepth:
                    expect_do.pop()
                    i += 1
                    continue
                kwdepth += 1
                i += 1
                continue
            if v in ("function", "if", "repeat"):
                kwdepth += 1
                i += 1
                continue
            if v in ("end", "until"):
                kwdepth -= 1
                i += 1
                continue
        if depth == 1 and kwdepth == 0:
            if t.kind in ("name", "kw", "str") and i + 1 < n \
                    and toks[i + 1].kind == "op" and toks[i + 1].val == "=":
                field_name = t.val if t.kind == "name" else "[%s]" % t.val
                i += 2
                field_start = i
                continue
            if t.kind == "op" and t.val == ",":
                close_field(i)
                i += 1
                field_start = i
                field_name = None
                continue
        i += 1
    return fields


def block_text(s, toks, a, b):
    return s[toks[a].pos:toks[b - 1].end]


def skeleton(toks, a, b, depth=0):
    """把一段 token 归约成语句级骨架（只保留控制流关键字与函数调用名）。"""
    out = []
    kwdepth = 0
    for k in range(a, b):
        t = toks[k]
        if t.kind == "kw" and t.val in OPEN_KW:
            kwdepth += 1
            if depth == 0 or kwdepth <= 2:
                out.append(t.val)
        elif t.kind == "kw" and t.val in ("end", "until"):
            kwdepth -= 1
    return out


# ---------------------------------------------------------------- 度量

def func_metrics(toks, a, b):
    m = Counter()
    kwdepth = 0
    maxd = 0
    expect_do = []
    for k in range(a, b):
        t = toks[k]
        if t.kind != "kw":
            continue
        v = t.val
        if v in ("while", "for"):
            m[v] += 1
            kwdepth += 1
            expect_do.append(kwdepth)
        elif v == "do":
            if expect_do and expect_do[-1] == kwdepth:
                expect_do.pop()
                continue
            m["do"] += 1
            kwdepth += 1
        elif v in ("function", "if", "repeat"):
            m[v] += 1
            kwdepth += 1
        elif v in ("end", "until"):
            kwdepth -= 1
        elif v in ("break", "continue", "return"):
            m[v] += 1
        maxd = max(maxd, kwdepth)
    m["maxdepth"] = maxd
    return m


DISPATCH = re.compile(
    r"while true do (\w+),?(\w*)=")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "luraph14.9.lua"
    mode = sys.argv[2] if len(sys.argv) > 2 else "--overview"
    s = open(path, encoding="utf-8", errors="replace").read()
    toks = tokenize(s)

    # 外层表
    open_idx = None
    for t in toks:
        if t.kind == "op" and t.val == "{":
            open_idx = t.idx
            break
    fields = find_table_fields(toks, open_idx)

    print("== 文件 ==")
    print("  字符数 %d  token 数 %d" % (len(s), len(toks)))
    print("  token 分类", dict(Counter(t.kind for t in toks)))
    print("  字段数 %d" % len(fields))
    tot = sum(toks[b - 1].end - toks[a].pos for _, _, a, b, _, _ in fields)
    print("  字段正文合计 %d 字符 (%.1f%%)" % (tot, tot / len(s) * 100))
    big = [(n, k, a, b) for n, k, a, b, _, _ in fields
           if toks[b - 1].end - toks[a].pos > 5000]
    for n, k, a, b in big:
        print("  超大字段 %s: %d 字符" % (n, toks[b - 1].end - toks[a].pos))

    if mode == "--fields":
        print("\n%s %6s %10s %8s  %s" % ("name", "kind", "chars", "tokspan", "head"))
        for n, k, a, b, p0, p1 in fields:
            print("%-6s %-9s %10d %8s  %r" % (
                n, k, p1 - p0, "%d..%d" % (a, b), s[p0:min(p0 + 42, p1)]))
        return

    if mode in ("--funcs", "--dead", "--overview"):
        # 引用计数：把 fields 里 1-3 字符的名字在全文里数引用
        names = [n for n, k, a, b, _, _ in fields if n and not n.startswith("[")]
        cnt = {}
        for n in set(names):
            c = 0
            c += len(re.findall(r"[.:]\s*" + re.escape(n) + r"\b", s))
            c += len(re.findall(r"\[\s*" + re.escape(n) + r"\s*\]", s))
            c += len(re.findall(r"\[\s*0[xX][0-9a-fA-F_]+[^\]]*\]\s*=\s*" + re.escape(n) + r"\b", s))
            cnt[n] = c
        if mode == "--dead":
            print("\n== 疑似死字段（引用 0 次）==")
            dead = [n for n in names if cnt[n] == 0]
            for n in sorted(set(dead)):
                print("  ", n)
            print("  共 %d / %d" % (len(set(dead)), len(set(names))))
            return
        if mode == "--funcs":
            rows = []
            for n, k, a, b, p0, p1 in fields:
                if k != "function":
                    continue
                m = func_metrics(toks, a, b)
                rows.append((p1 - p0, n, m, cnt.get(n, 0)))
            rows.sort(reverse=True)
            print("\n%8s %6s %6s %5s %5s %5s %5s %5s %6s %s" % (
                "chars", "name", "refs", "while", "if", "for", "rep", "func", "depth", "brk/cnt"))
            for ln, n, m, refs in rows:
                print("%8d %6s %6d %5d %5d %5d %5d %5d %6d %d/%d" % (
                    ln, n, refs, m["while"], m["if"], m["for"], m["repeat"],
                    m["function"], m["maxdepth"], m["break"], m["continue"]))
            return


if __name__ == "__main__":
    main()
