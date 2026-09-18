# -*- coding: utf-8 -*-
# Tolerant Luau-dialect tokenizer for luraph14.9.lua
# Handles: identity escapes (\X -> X), \a\b\f\n\r\t\v\\\"\' \z \xNN \ddd \u{...},
#          0b/0B, 0x/0X, underscores, -- comments, --[[ ]] comments, [[ ]] long strings
import re, sys

SRC = open('/home/user/work/luraph14.9.lua').read()

KW = {'and','break','do','else','elseif','end','false','for','function','if','in',
      'local','nil','not','or','repeat','return','then','true','until','while','continue'}
MULTI_OPS = ['...', '..', '==', '~=', '<=', '>=', '::', '->', '//', '+=', '-=', '*=', '/=', '%=', '^=', '..=']

def decode_escapes(raw):
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c != '\\':
            out += c.encode('latin1'); i += 1; continue
        i += 1
        if i >= n:
            out.append(0x5c); break
        e = raw[i]; i += 1
        if e == 'a': out.append(7)
        elif e == 'b': out.append(8)
        elif e == 'f': out.append(12)
        elif e == 'n': out.append(10)
        elif e == 'r': out.append(13)
        elif e == 't': out.append(9)
        elif e == 'v': out.append(11)
        elif e == '\\': out.append(0x5c)
        elif e == '"': out.append(0x22)
        elif e == "'": out.append(0x27)
        elif e == 'z':
            while i < n and raw[i] in ' \t\r\n': i += 1
        elif e == 'x':
            h = raw[i:i+2]; i += 2
            out.append(int(h, 16))
        elif e == 'u' and i < n and raw[i] == '{':
            i += 1
            j = raw.index('}', i)
            cp = int(raw[i:j], 16); i = j + 1
            out += chr(cp).encode('utf-8')
        elif e.isdigit():
            d = e
            for _ in range(2):
                if i < n and raw[i].isdigit():
                    d += raw[i]; i += 1
                else: break
            out.append(int(d, 10) & 0xff)
        else:
            out += e.encode('latin1')   # identity escape
    return bytes(out)

def parse_number(s, i):
    m = re.match(r'(0[xX][0-9a-fA-F_]+(\.[0-9a-fA-F_]*)?|0[bB][01_]+|\d[\d_]*(\.[\d_]*)?([eE][+-]?\d+)?|\.[\d_]+)', s[i:])
    txt = m.group(0); t = txt.replace('_', '')
    try:
        if t[:2].lower() == '0x':
            v = int(t, 16) if '.' not in t else float.fromhex(t)
        elif t[:2].lower() == '0b':
            v = int(t[2:], 2)
        else:
            v = float(t) if ('.' in t or 'e' in t.lower()) else int(t)
    except ValueError:
        v = None
    return ('num', v, txt), i + len(txt)

def tokenize(s):
    toks = []
    i, n = 0, len(s)
    lineno = 1
    while i < n:
        c = s[i]
        if c in ' \t\r':
            i += 1; continue
        if c == '\n':
            lineno += 1; i += 1; continue
        if s.startswith('--[[', i):
            j = s.find(']]', i + 4); i = n if j < 0 else j + 2; continue
        if s.startswith('--', i):
            j = s.find('\n', i); i = n if j < 0 else j; continue
        if c=='[':
            m2=re.match(r'\[(=*)\[', s[i:])
            if m2:
                eqs=m2.group(1); close=']'+eqs+']'
                body_start=i+2+len(eqs)
                j=s.find(close,body_start)
                raw=s[body_start:(n if j<0 else j)]
                toks.append(('str', raw.encode('latin1'), s[i:(n if j<0 else j+len(close))]))
                i = n if j<0 else j+len(close); continue
        if c == '"' or c == "'":
            q = c; j = i + 1
            while j < n:
                if s[j] == '\\': j += 2; continue
                if s[j] == q: break
                j += 1
            raw = s[i+1:j]
            toks.append(('str', decode_escapes(raw), s[i:j+1]))
            i = j + 1; continue
        if c.isdigit() or (c == '.' and i + 1 < n and s[i+1].isdigit()):
            tok, i = parse_number(s, i); toks.append(tok); continue
        if c.isalpha() or c == '_':
            m = re.match(r'[A-Za-z_][A-Za-z0-9_]*', s[i:])
            w = m.group(0)
            toks.append(('kw' if w in KW else 'name', w, w))
            i += len(w); continue
        matched = False
        for op in MULTI_OPS:
            if s.startswith(op, i):
                toks.append(('op', op, op)); i += len(op); matched = True; break
        if matched: continue
        toks.append(('op', c, c)); i += 1
    return toks

if __name__ == '__main__':
    toks = tokenize(SRC)
    print('tokens:', len(toks))
    from collections import Counter
    print(Counter(t[0] for t in toks))
    # string stats
    strs = [(t[1], t[2]) for t in toks if t[0] == 'str']
    print('strings:', len(strs))
    lens = Counter(len(v) for v, _ in strs)
    print('long(>=200):', sum(1 for v,_ in strs if len(v) >= 200),
          'ident-like(1..40, printable):', sum(1 for v,_ in strs if 1 <= len(v) <= 40 and all(32 <= b < 127 for b in v)))
    # save
    import pickle
    pickle.dump(toks, open('/home/user/work/luraph/toks.pkl', 'wb'))
