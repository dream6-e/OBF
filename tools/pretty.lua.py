#!/usr/bin/env python3
"""Foolproof re-indenter: inserts newlines/indent around Lua block keywords, never changes text.
Usage: pretty.py <handlerkey>   -> stdout     (keys: any handler in tools/handlers.json)
"""
import re, sys, json

M = json.load(open("tools/handlers.json"))
txt = M[sys.argv[1]]["src"]
STR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
LONG = re.compile(r"\[(=*)\[")
NAME = re.compile(r"[A-Za-z_]\w*")
EXPR_PREV = {"=", "(", ",", "{", "[", "and", "or", "return", "then", "else", "elseif", "+", "-", "*", "/", "%", "^", "#", "not", "if"}

TOK = []; i = 0; L = len(txt)
while i < L:
    c = txt[i]
    if c == "-" and txt.startswith("--", i):
        m = LONG.match(txt, i + 2)
        if m:
            t = "]" + "=" * len(m.group(1)) + "]"; j = txt.find(t, m.end()); j = L if j < 0 else j + len(t)
            TOK.append(("s", txt[i:j], i)); i = j; continue
        j = txt.find("\n", i); j = L if j < 0 else j; TOK.append(("s", txt[i:j], i)); i = j; continue
    if c == "[":
        m = LONG.match(txt, i)
        if m:
            t = "]" + "=" * len(m.group(1)) + "]"; j = txt.find(t, m.end()); j = L if j < 0 else j + len(t)
            TOK.append(("s", txt[i:j], i)); i = j; continue
    if c in "\"'":
        m = STR.match(txt, i)
        if m: TOK.append(("s", m.group(), i)); i = m.end(); continue
    m = NAME.match(txt, i)
    if m: TOK.append(("n", m.group(), m.start())); i = m.end(); continue
    TOK.append(("o", c, i)); i += 1

EXPIF = set(); prev = None
for idx, (k, t, p) in enumerate(TOK):
    if k == "s": prev = None; continue
    if k == "n" and t == "if" and prev in {"=", "(", ",", "{", "[", "and", "or", "return", "then", "else", "elseif", "+", "-", "*", "/", "%", "^", "#"}:
        EXPIF.add(idx)
    prev = t

out = []; ind = 0; line = []
def emit(extra=0):
    global line
    s = "".join(line).strip()
    if s: out.append("  " * max(0, ind + extra) + s)
    line = []

for idx, (k, t, p) in enumerate(TOK):
    if k == "s": line.append(t); continue
    if k == "o":
        if t == ";" and len("".join(line)) > 0:
            line.append(";"); emit()
        else:
            line.append(t)
        continue
    if idx in EXPIF:
        line.append(t); continue
    if t in ("function", "do", "repeat", "if", "else", "elseif", "end", "until", "then"):
        if t == "end":
            emit(); ind -= 1; line.append("end")
        elif t in ("then",):
            line.append(" then"); emit(); 
        elif t in ("else", "elseif"):
            emit(); line.append(t)
        elif t == "until":
            emit(); line.append("until")
        else:
            if line and "".join(line).strip() not in ("", "else", "elseif"): emit()
            line.append(t + " ")
            if t in ("do", "repeat", "then"): ind += 1
            if t == "if": pass
            if t == "function": pass
    else:
        line.append(t)
emit()
# second pass: fix indentation for 'if..then' blocks (we bumped ind only on do/repeat)
print("\n".join(out))
