#!/usr/bin/env python3
"""
audit.py —— 静态泄漏自检（对应 核心抗静态技术.md §3）

任一 FAIL = 这个 build 能被纯静态分析推进一步。
用法:  python3 tools/audit.py <protected.lua>            # 检查某个产物
       python3 tools/audit.py <protected.lua> --words W   # 用真实字流跑第 8/9 项
"""
import re, sys, math, collections
from functools import reduce

path = sys.argv[1]
words_file = None
if "--words" in sys.argv:
    words_file = sys.argv[sys.argv.index("--words") + 1]

src = open(path, encoding="utf-8").read()
BODY = src.split("\n")[-1]
gcd_all = lambda v: reduce(math.gcd, v) if v else 0
F = []

# [1] 漂亮常数（radix 位权 / 2^32 邻域）：出现 >2 次即泄露
nice = {85 ** k for k in range(1, 5)} | {2**32, 2**32 - 1, 2**32 + 1, 2**31, 2**16 - 1, 2**16, 256}
for n in nice:
    c = len(re.findall(r"(?<![\d.])%d(?![\d.])" % n, BODY))
    if c > 2:
        F.append(f"[1] 漂亮常数 {n} 出现 {c} 次 → 可直接定位编解码函数")

# [2] 载荷字符集连续 → radix 可判定
m = re.search(r"\[=+\[(?:.{0,8})(.*?)\]=+\]", BODY, re.S)
if m:
    cs = sorted(set(m.group(1)))
    if len(cs) > 8:
        span = ord(cs[-1]) - ord(cs[0]) + 1
        if span - len(cs) <= 12:
            F.append(f"[2] 载荷字符集近似连续（{len(cs)} 个字符 / span {span}）→ radix 与 offset 暴露")

# [3] 噪声常数对之和 == 2^32（可无条件抵消 ⇒ opaque predicate 失效）
for a, b in re.findall(r"MUL\((\d+),\s*4294967295\)[^\n]{0,240}?MUL\((\d+),", BODY) \
          + re.findall(r"iL\((\d+),4294967295\)[^\n]{0,240}?iL\((\d+),", BODY):
    if (int(a) + int(b)) & (2**32 - 1) == 0:
        F.append(f"[3] 噪声对 {a}+{b} = 2^32 → 可无条件抵消")

# [4] 状态阈值密度 → 状态机规模泄露
ths = [int(x) for x in re.findall(r"(?:\w+)\s*<=\s*(\d{1,4})\b", BODY)]
if ths and max(ths) < 3 * len(set(ths)):
    F.append(f"[4] 比较阈值过密（{len(set(ths))} 个, max={max(ths)}）→ 状态数/规模泄露")

# [5] 同型模板重复（循环回边、解密器的特征形状）
shapes = collections.Counter()
for pat in (r"local \w+=\w+-128[^\n]{0,60}", r"\bband\(\w+,\w+\)%\d+"):
    for x in re.findall(pat, BODY):
        shapes[re.sub(r"\w+", "X", x)] += 1
for k, c in shapes.items():
    if c > 4:
        F.append(f"[5] 同型模板重复 {c} 次: {k[:44]}")

# [6] 开场别名串：右边全是 b[数字] ⇒ 一次还原全表
for mm in re.finditer(r"local ([A-Za-z_,\s]+)=((?:b\[\d+\][,;]\s*){6,})", BODY):
    F.append("[6] 开场别名串一次性暴露 ≥6 个 import 槽")

# [7] 死表诱饵（零引用 ⇒ 一眼否掉）
for mm in re.finditer(r"(\w+)={(?:\d{6,},){2,}\d{6,}}", BODY):
    n = mm.group(1)
    if len(re.findall(r"(?<![\w.])%s\b" % re.escape(n), BODY)) <= 1:
        F.append(f"[7] 表 {n} 含多个大常数但引用数≤1 → 诱饵被一眼识破")

# [8/9] 密文统计：重复距离 gcd + 均匀性 + 长度整除性
vals = None
if words_file:
    vals = [int(x) for x in re.findall(r"\d+", open(words_file).read())]
else:
    blob = m.group(1) if m else ""
    if blob:
        digits = [ord(c) - 40 for c in blob]
        vals = []
        for i in range(0, len(digits) - 4, 5):
            v = 0
            for d in digits[i:i + 5]:
                v = v * 85 + d
            vals.append(v)
if vals:
    pos = collections.defaultdict(list)
    for i, v in enumerate(vals):
        pos[v & (2**32 - 1)].append(i)
    d = []
    for p in pos.values():
        d += [b - a for a, b in zip(p, p[1:])]
    g = gcd_all(d)
    if g > 1:
        F.append(f"[8] 密文重复距离 gcd={g} → 密钥流与位置无关（见 T5）")
    n = len(vals)
    if n > 500:
        frac = sum(1 for v in vals if v >= 2**32) / n
        exp = 1 - 2**32 / 85**5
        sig = abs(frac - exp) / math.sqrt(exp * (1 - exp) / n)
        F.append(f"[9] 均匀性自检: 实测 >=2^32 比例 {frac*100:.3f}% vs 理论 {exp*100:.3f}% "
                 f"({sig:.2f}σ) —— {'<1σ: 载荷确为均匀随机(白化)且框架对齐正确' if sig < 1 else '偏差大: 先怀疑自己的分组/窗口'}")
    print(f"(统计基于 {n} 个 5 字符组{' ← 来自 --words' if words_file else ' ← 从载荷自行推导'})")

print("\n".join(F) if F else "audit: clean")
print(f"\n共 {len(F)} 项 FAIL")
sys.exit(1 if F else 0)
