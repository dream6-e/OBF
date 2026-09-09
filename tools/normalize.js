// Offset-preserving rewrite of Luau-isms so luaparse (Lua 5.3 grammar) can build an AST.
//   `continue`            -> `do end  `        (same length)
//   `=if C then A else B end` -> `= (C) and (A) or (B)` padded to same length
//   compound assign `a op= b` -> `a =  b`       (same length)
// Only used to obtain structure + exact byte ranges of the ORIGINAL file.
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const lineOff = src.split('\n').slice(0, 2).reduce((a, l) => a + l.length + 1, 0);
let B = src.split('\n')[2];
const L = B.length;
let stats = { cont: 0, ifex: 0, cmp: 0 };

function padTo(arr, from, to, text) {
  // write text into [from,to) padded with spaces; abort if too long
  if (text.length > to - from) return false;
  for (let i = 0; i < to - from; i++) arr[from + i] = (text[i] || ' ');
  return true;
}
let out = B.split('');

// 1) continue
for (let m of [...B.matchAll(/\bcontinue\b/g)]) {
  for (let i = 0; i < 8; i++) out[m.index + i] = 'do end  '[i] || ' ';
  stats.cont++;
}
// 2) compound assignment
const s2 = out.join('');
for (const m of [...s2.matchAll(/([+\-*\/%^])=(?!=)/g)]) { out[m.index] = '='; out[m.index + 1] = ' '; stats.cmp++; }
// 3) if-expressions: find `if` whose preceding non-space char is one of = ( , or followed `return`
let B3 = out.join('');
let guard = 0;
for (;;) {
  const re = /[=(,]\s*\bif\b/g; let m = null, mm;
  B3 = out.join('');
  while ((mm = re.exec(B3)) !== null) {
    const p = B3.indexOf('if', mm.index);
    // skip if it's a statement-if: previous meaningful char is ';' '{' 'then' 'do' 'else' '(' of block
    const before = B3.slice(0, p).replace(/\s+$/, '');
    if (/[;{}]$|then$|else$|do$|&&$/.test(before.slice(-6))) continue;
    if (!/[=(,]$/.test(before)) continue;
    // find matching 'end' for this if
    let d = 0, i = p;
    const tk = /\b(if|then|else|elseif|end|for|while|do|function|repeat|until)\b|\[=*\[[^\]]*\]=*\]|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g;
    tk.lastIndex = p; let e;
    while ((e = tk.exec(B3)) !== null) {
      if (e[0][0] === '"' || e[0][0] === "'" || e[0][0] === '[') { continue; }
      const w = e[1];
      if (w === 'if' || w === 'for' || w === 'while' || w === 'do' || w === 'function' || w === 'repeat') d++;
      else if (w === 'end' || w === 'until') { d--; if (d === 0) break; }
    }
    if (d !== 0) break;
    const endAt = e.index, endTo = endAt;   // keep the `end`: it closes the enclosing if-statement
    const inner = B3.slice(p + 2, endAt);           // ` C then A else B `
    const km = /^([\s\S]*?)\bthen\b([\s\S]*)\belse\b([\s\S]*)$/m.exec(inner);
    if (!km) { console.log('unparsed if-expr at', p, JSON.stringify(inner.slice(0, 60))); break; }
    const cl=x=>x.trim().replace(/;+\s*$/,'').trim();
    const A=cl(km[1]),Bv=cl(km[2]),Cv=cl(km[3]);
    const cands=[`(${A}) and (${Bv}) or (${Cv})`,`${A} and (${Bv}) or (${Cv})`,`${A} and ${Bv} or ${Cv}`,`(${A})and(${Bv})or(${Cv})`];
    const rep=cands.find(x=>x.length<=endTo-p)||cands[cands.length-1];
    if (!padTo(out, p, endTo, rep)) { console.log('if-expr too long at', p, rep.length, endTo - p); break; }
    stats.ifex++;
    m = 1; break;
  }
  if (!m || ++guard > 60) break;
}
let res = out.join('');
const rm = /^return(\s+)/.exec(res);
if (rm) { const pre = '__r =' + ' '.repeat(rm[0].length - 5); res = pre + res.slice(rm[0].length); }
if (res.length !== L) console.log('!! LENGTH CHANGED', res.length, L);
fs.writeFileSync(process.argv[3], res);
console.log('stats', stats, 'len', res.length);
