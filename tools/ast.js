// AST-level structural analysis (parse only, never executed).
const fs = require('fs');
const lp = require('luaparse');
const src = fs.readFileSync('/tmp/body.lua', 'utf8');
const ast = lp.parse(src, { luaVersion: '5.3', ranges: true, locations: true });
const body = fs.readFileSync('/tmp/body.lua', 'utf8');

// find the table expression inside __r = setmetatable( TABLE , {} ) :FC()(...)
let table = null;
function findTable(n) {
  if (!n || typeof n !== 'object') return;
  if (n.type === 'CallStatement' && n.expression && n.expression.type === 'Call' &&
      n.expression.base && n.expression.base.type === 'Index' && n.expression.base.index &&
      n.expression.base.index.value === 'setmetatable') { table = n.expression.arguments[0]; return; }
  for (const k in n) { if (k === 'range' || k === 'loc') continue; const v = n[k];
    if (Array.isArray(v)) v.forEach(findTable); else if (v && typeof v === 'object') findTable(v); }
}
findTable(ast.body[0] ? { body: ast.body } : ast);
if (!table) { // fallback: first TableCallExpression... just search for a Table with >100 fields
  let best = null;
  (function w(n){ if(!n||typeof n!=='object')return; if(n.type==='Table'&&(n.fields||[]).length>((best&&best.fields.length)||0))best=n;
    for(const k in n){if(k==='range'||k==='loc')continue;const v=n[k];if(Array.isArray(v))v.forEach(w);else if(v&&typeof v==='object')w(v);} })(ast);
  table = best;
}
console.log('table fields:', table.fields.length);

function src_of(n) { return body.slice(n.range[0], n.range[1] + 1); }

// ---- collect the fields ----
const funcs = {}, vals = {}, keyOrder = [];
for (const f of table.fields) {
  let key;
  if (f.key) key = f.key.type === 'StringLiteral' ? f.key.value : (f.key.type === 'NumericLiteral' ? f.key.value : null);
  if (key === null && f.key && f.key.type === 'Identifier') key = f.key.name;
  if (key === undefined || key === null) { key = '(pos)'; }
  keyOrder.push(key);
  const v = f.value;
  const rec = { key, start: f.range[0], end: f.range[1], src: src_of(f) };
  if (v && (v.type === 'FunctionDeclaration' || v.type === 'Function')) {
    rec.params = v.isVararg ? (v.id ? v.id.names.length + 1 : 1) : (v.id ? v.id.names.length : 0);
    rec.vararg = !!v.isVararg;
    rec.names = v.id ? v.id.names : [];
    funcs[key] = rec;
  } else rec.value = v ? v.type : 'none', vals[key] = rec;
  (vals[key] = vals[key] || (v && v.type !== 'FunctionDeclaration' && v.type !== 'Function' ? rec : null));
}
fs.writeFileSync('/tmp/table.json', JSON.stringify({ keyOrder, funcs: Object.keys(funcs), vals: Object.keys(vals) }, null, 0));

// dump per-function detail
const detail = {};
for (const k in funcs) {
  const f = funcs[k];
  detail[k] = { start: f.start, end: f.end, len: f.end - f.start + 1, params: f.names, vararg: f.vararg, src: f.src };
}
fs.writeFileSync('/tmp/funcs.json', JSON.stringify(detail));
console.log('funcs:', Object.keys(funcs).length, 'vals:', Object.keys(vals).length);
console.log('non-func fields:');
for (const k in vals) if (!funcs[k]) console.log('  ', k, '=', vals[k].src.slice(vals[k].src.indexOf('=') + 1, 90).trim());
console.log('\nlargest funcs:');
Object.entries(funcs).sort((a, b) => (b[1].end - b[1].start) - (a[1].end - a[1].start)).slice(0, 10)
  .forEach(([k, f]) => console.log(`   ${k}  len=${f.end - f.start + 1}`));
