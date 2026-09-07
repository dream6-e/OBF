import pickle
protos = pickle.load(open('protos.pkl','rb'))
d = pickle.load(open('stage2.pkl','rb'))
ab = d['ab']; we = d['we']

def decode_instructions(z):
    """[6983] varint decoder + class table; returns list of (stored_op, A, B, C)."""
    pos = 0
    out = []
    def varint():
        nonlocal pos
        b0 = z[pos]; pos += 1
        v = b0 % 128
        if b0 >= 128:
            b1 = z[pos]; pos += 1
            v = v + (b1 % 128) * 128
            assert v >= 128
            if b1 >= 128:
                b2 = z[pos]; pos += 1
                v = v + (b2 % 128) * 16384
                assert v >= 16384
                if b2 >= 128:
                    b3 = z[pos]; pos += 1
                    v = v + (b3 % 128) * 2097152
                    assert v >= 2097152
                    assert b3 < 128
        return v
    while pos < len(z):
        op = z[pos]; pos += 1
        cls = ab[op]
        assert cls is not None and 1 <= cls <= 5, f"class {cls} for op {op}"
        if cls == 1:
            V = varint(); assert V <= 0xFFFFFF
            A = V % 256; V2 = (V - V % 256)//256
            B = V2 % 256; C = (V2 - V2 % 256)//256
        elif cls == 2:
            A = varint(); assert A <= 255; B = 0; C = 0
        elif cls == 3:
            A = varint(); assert A <= 255; B = varint(); assert B <= 255; C = 0
        elif cls == 4:
            A = varint(); assert A <= 255
            V = varint(); assert V <= 65535
            B = V % 256; C = (V - V % 256)//256
        else:
            A = varint(); assert A <= 255
            B = varint(); assert B <= 255
            C = varint(); assert C <= 255
        out.append((op, A, B, C))
    return out

for p in protos:
    ins = decode_instructions(p['z'])
    assert len(ins) == p['ninstr'], (len(ins), p['ninstr'])
    # remap to canonical via we ([7244] re-encode char(we[op],A,B,C))
    canon = [(we[op], A, B, C) for (op, A, B, C) in ins]
    p['instrs'] = canon
    last = canon[-1]
    assert last[0] in (62, 245, 55), f"last op {last[0]} not a return op"
    p['stored'] = ins

print("instruction decode OK for all protos")
print("proto0 first 12 (stored->canonical):")
for s, c in list(zip(protos[0]['stored'], protos[0]['instrs']))[:12]:
    print(f"  stored {s[0]:>3} class {ab[s[0]]}  ->  canon {c[0]:>3}  A={c[1]} B={c[2]} C={c[3]}")
canon_ops = sorted({i[0] for p in protos for i in p['instrs']})
print("canonical opcodes used:", canon_ops)
print("count:", len(canon_ops))
pickle.dump(protos, open('protos2.pkl','wb'))
