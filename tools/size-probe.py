#!/usr/bin/env python3
"""Read-only size profiler for an emitted VM script.

Every number it prints is a *measurement of the emitted text*, not a claim about a
code change: it reports how many bytes each candidate peephole currently spends, so
a follow-up can decide whether the win is worth taking. Nothing here is wired into
the build or the test matrix.

Usage: python3 tools/size-probe.py FILE [FILE...]
"""
import collections
import re
import sys

WORD = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def string_spans(text):
    """Byte offsets covered by string/long-bracket literals (payload, not code)."""
    spans = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        m = re.compile(r"\[(=*)\[").match(text, i)
        if m:
            close = "]" + m.group(1) + "]"
            end = text.find(close, i + m.end())
            end = n if end < 0 else end + len(close)
            spans.append((i, end))
            i = end
            continue
        if c in "\"'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    j += 1
                    break
                j += 1
            spans.append((i, j))
            i = j
            continue
        i += 1
    return spans


def in_spans(spans, pos):
    for a, b in spans:
        if a <= pos < b:
            return True
    return False


def space_is_needed(prev, nxt):
    """Conservative: a space may be dropped unless the two sides could merge."""
    if prev in WORD and nxt in WORD:
        return True
    if prev.isdigit() and nxt in ".eExX":
        return True
    if prev == "." and nxt == ".":
        return True
    if prev == "-" and nxt in "-[":
        return True
    if prev == "[" and nxt == "[":
        return True
    if prev == "]" and nxt == "]":
        return False
    return False


def semicolon_is_needed(text, pos, nxt):
    """A ';' is droppable when the next token cannot continue the previous
    expression and does not start with a character that could extend it."""
    if nxt == "(":
        return True
    if nxt == "[":
        return True
    if nxt == "-" and text[pos + 1 : pos + 2] == "-":
        return True  # would open a comment
    return False


def analyse(name):
    text = open(name, encoding="utf-8").read()
    total = len(text)
    spans = string_spans(text)
    code = [(i, ch) for i, ch in enumerate(text) if not in_spans(spans, i)]
    print(f"=== {name}: {total} B")

    # 1. escapes: values, and the shortest escape that is unambiguous in context.
    esc = collections.Counter()
    esc_waste = 0
    for m in re.finditer(r"\\(\d{1,3})", text):
        if not in_spans(spans, m.start()):
            continue
        val = int(m.group(1))
        digits = len(m.group(1))
        esc[val] += 1
        nxt = text[m.end() : m.end() + 1]
        need = 3 if (val >= 100 or (nxt.isdigit() and digits < 3)) else digits
        best = 1 if val < 10 and not nxt.isdigit() else (2 if val < 100 else 3)
        while best < 3 and nxt.isdigit():
            best += 1
        if digits > best:
            esc_waste += digits - best
    print(f"  转义: 共 {sum(esc.values())} 处，最短安全拼写还能省 {esc_waste} B")
    print(f"    被转义字节值分布: {sorted(esc.items())[:12]}")

    # 2. whitespace between code tokens.
    drop_sp = 0
    for i, ch in code:
        if ch != " ":
            continue
        prev = text[i - 1] if i else ""
        nxt = ""
        for j in range(i + 1, len(text)):
            if in_spans(spans, j):
                break
            nxt = text[j]
            break
        if prev and nxt and not space_is_needed(prev, nxt):
            drop_sp += 1
    print(f"  代码区空格: {sum(1 for _, c in code if c == ' ')} 个，其中 {drop_sp} 个可安全删")

    # 3. separators.
    drop_semi = 0
    for i, ch in code:
        if ch == ";" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt and not semicolon_is_needed(text, i + 1, nxt):
                drop_semi += 1
    print(f"  分号: {sum(1 for _, c in code if c == ';')} 个，{drop_semi} 个后面的语句不会与前者粘连")

    # 4. adjacent `local` statements (merging is a statement-count change: flagged).
    boundary = re.compile(r"\bend\b|\bthen\b|\bdo\b|\bfunction\b|\breturn\b|\belse\b|\{|\}")
    adj = 0
    positions = [m.start() for m in re.finditer(r"\blocal\b", text) if not in_spans(spans, m.start())]
    for a, b in zip(positions, positions[1:]):
        if not boundary.search(text[a:b]):
            adj += 1
    print(f"  `local` 关键字（代码区）: {len(positions)} 次；紧接另一条 local 声明的有 {adj} 处（并写每处省 ~6 B）")

    # 5. numbers in code: what they are spent on.
    kinds = collections.Counter()
    weight = collections.Counter()
    for m in re.finditer(r"\d+", text):
        if in_spans(spans, m.start()):
            continue
        before = text[max(0, m.start() - 2) : m.start()]
        after = text[m.end() : m.end() + 2]
        if before.endswith("[") and after.startswith("]"):
            kind = "table 数值键 [N]"
        elif before.endswith("]"):
            kind = "键读取 x[N]"
        elif before.endswith("."):
            kind = "小数位"
        else:
            kind = "裸整数字面量"
        kinds[kind] += 1
        weight[kind] += len(m.group(0))
    for kind, cnt in kinds.most_common():
        print(f"  {kind}: {cnt} 个，数字文本 {weight[kind]} B")
    lens = collections.Counter(len(m.group(0)) for m in re.finditer(r"\d+", text) if not in_spans(spans, m.start()))
    print(f"  数字长度分布: {sorted(lens.items())}")

    # 6. decoy writes `X[N]=N`.
    decoys = re.findall(r"\b([A-Za-z_]\w*)\[(\d+)\]=(\d+)", text)
    decoy_bytes = sum(len(a) + len(b) + len(c) + 4 for a, b, c in decoys)
    print(f"  诱饵写入 X[N]=N: {len(decoys)} 条，文本 {decoy_bytes} B（键/值平均 {len(decoys) and sum(len(b)+len(c) for _,b,c in decoys)//max(1,len(decoys))} 字符）")

    # 7. most repeated code substrings (duplication that no pass can currently fold).
    grams = collections.Counter()
    step = text
    for size in (16, 24):
        for i in range(0, len(step) - size, 1):
            g = step[i : i + size]
            if in_spans(spans, i):
                continue
            if any(ch in "\"'" for ch in g):
                continue
            grams[(size, g)] += 1
    top = [(c, g) for (s, g), c in grams.items() if c > 3]
    print(f"  重复 ≥4 次的 16/24 字符代码片段数: {len(top)}")
    for c, g in sorted(top, key=lambda t: -t[0])[:5]:
        print(f"    x{c}: {g[:44]!r}")


if __name__ == "__main__":
    for path in sys.argv[1:] or ["vm_lua51.out.lua", "vm_luau.out.lua"]:
        analyse(path)
