const fs=require('fs');
const luaparse=require('luaparse');
let src=fs.readFileSync('/home/user/work/src_norm.lua','utf8');
const ast=luaparse.parse(src,{luaVersion:'5.3',comments:false,ranges:false});
const W={e:256,h:4294967296,u:33659,aa:65536,ab:65521,ac:3001000,ad:8000000};
function num(v){return {type:'NumericLiteral',value:v,raw:String(v)};}
const T={type:'BooleanLiteral',value:true,raw:'true'};
const F={type:'BooleanLiteral',value:false,raw:'false'};
function ev(n){
  if(!n)return undefined;
  if(n.type==='NumericLiteral')return n.value;
  if(n.type==='MemberExpression'&&n.indexer==='.'&&n.base.type==='Identifier'&&n.base.name==='w'&&W.hasOwnProperty(n.identifier.name))return W[n.identifier.name];
  if(n.type==='UnaryExpression'&&n.operator==='-'){const a=ev(n.argument);return a===undefined?undefined:-a;}
  if(n.type==='BinaryExpression'){
    const a=ev(n.left),b=ev(n.right);
    if(a===undefined||b===undefined)return undefined;
    switch(n.operator){case '+':return a+b;case '-':return a-b;case '*':return a*b;case '/':return a/b;
      case '%':return ((a%b)+b)%b;case '^':return Math.pow(a,b);case '//':return Math.floor(a/b);default:return undefined;}
  }
  return undefined;
}
function src_(n){ // cheap structural key
  return JSON.stringify(n,(k,v)=>k==='raw'?undefined:v);
}
let stats={arith:0,tern:0,taut:0,ifs:0};
// Tautology detector: conditions that are always true/false for any numeric var v
// patterns: v-v==0, v-v==v-v, v*0==0, (v//1)==v, v<=v, not(v<v), v~=v-1, (v-i)==(v-i),
// (t+C)-C==t, v<v, i<i, q%1==0 (for ints), (j<=j and j or 0)~=j ...
function isVar(n){return n&&n.type==='Identifier';}
function tautology(n){
  if(!n||n.type!=='BinaryExpression'&&n.type!=='UnaryExpression'&&n.type!=='LogicalExpression')return undefined;
  if(n.type==='UnaryExpression'&&n.operator==='not'){const a=tautology(n.argument);return a===undefined?undefined:!a;}
  if(n.type!=='BinaryExpression')return undefined;
  const L=n.left,R=n.right,op=n.operator;
  const lk=src_(L),rk=src_(R);
  // X op X
  if(lk===rk){
    if(op==='=='||op==='<='||op==='>=')return true;
    if(op==='~='||op==='<'||op==='>')return false;
  }
  // v-v == 0  /  v*0 == 0
  const lv=ev(L),rv=ev(R);
  function zeroish(x){ // expression provably 0 for any numeric
    if(!x)return false;
    if(x.type==='NumericLiteral')return x.value===0;
    if(x.type==='BinaryExpression'&&x.operator==='-'&&src_(x.left)===src_(x.right))return true;
    if(x.type==='BinaryExpression'&&x.operator==='*'&&((ev(x.right)===0)||(ev(x.left)===0)))return true;
    return false;
  }
  if(zeroish(L)&&zeroish(R)){if(op==='=='||op==='<='||op==='>=')return true;if(op==='~='||op==='<'||op==='>')return false;}
  // (t+C)-C == t
  function addSubId(x){ // returns identifier key if x is (v+C)-C
    if(x.type==='BinaryExpression'&&x.operator==='-'&&ev(x.right)!==undefined){
      const inner=x.left;
      if(inner.type==='BinaryExpression'&&inner.operator==='+'&&ev(inner.right)===ev(x.right))return src_(inner.left);
    }
    return null;
  }
  const a1=addSubId(L); if(a1&&a1===rk){if(op==='==')return true;if(op==='~=')return false;}
  const a2=addSubId(R); if(a2&&a2===lk){if(op==='==')return true;if(op==='~=')return false;}
  // (v//1)==v : only true for ints — treat as true (obfuscator intends it)
  if(L.type==='BinaryExpression'&&L.operator==='//'&&ev(L.right)===1&&src_(L.left)===rk){if(op==='==')return true;if(op==='~=')return false;}
  // v ~= v-1  -> true
  function vMinus1(x,other){return x.type==='BinaryExpression'&&x.operator==='-'&&ev(x.right)===1&&src_(x.left)===other;}
  if(vMinus1(R,lk)){if(op==='~=')return true;if(op==='==')return false;}
  if(vMinus1(L,rk)){if(op==='~=')return true;if(op==='==')return false;}
  // (j<=j and j or 0) ~= j
  if(L.type==='LogicalExpression'&&L.operator==='or'&&L.left.type==='LogicalExpression'&&L.left.operator==='and'){
    const cond=tautology(L.left.left);
    if(cond===true&&src_(L.left.right)===rk){if(op==='~=')return false;if(op==='==')return true;}
  }
  return undefined;
}
function transform(node){
  if(!node||typeof node!=='object')return node;
  if(Array.isArray(node))return node.map(transform);
  if(!node.type)return node;
  for(const k of Object.keys(node)){if(k==='type')continue;node[k]=transform(node[k]);}
  if(node.type==='BinaryExpression'||node.type==='UnaryExpression'){
    const v=ev(node);
    if(v!==undefined&&Number.isFinite(v)){stats.arith++;return num(v);}
  }
  if(node.type==='LogicalExpression'&&node.operator==='or'&&node.left.type==='LogicalExpression'&&node.left.operator==='and'){
    const x=ev(node.left.right),y=ev(node.right);
    if(x!==undefined&&y!==undefined&&x===y){stats.tern++;return num(x);}
    // also: (TRUE and X) or Y  => X ; (FALSE and X) or Y => Y
    const c=tautology(node.left.left);
    if(c===true){stats.tern++;return node.left.right;}
    if(c===false){stats.tern++;return node.right;}
  }
  const t=tautology(node);
  if(t!==undefined){stats.taut++;return t?T:F;}
  // if-statement simplification
  if(node.type==='IfStatement'){
    const cl=[];let done=false;
    for(const c of node.clauses){
      if(done)break;
      if(c.type==='ElseClause'){cl.push(c);break;}
      const v=c.condition.type==='BooleanLiteral'?c.condition.value:undefined;
      if(v===false){stats.ifs++;continue;}
      if(v===true){stats.ifs++;cl.push({type:cl.length===0?'IfClause':'ElseClause',condition:T,body:c.body});done=true;continue;}
      cl.push(c);
    }
    if(cl.length===0)return {type:'DoStatement',body:[]};
    if(cl.length===1&&cl[0].condition===T&&cl[0].type==='IfClause')return {type:'DoStatement',body:cl[0].body};
    node.clauses=cl;
  }
  return node;
}
// run to fixpoint
for(let i=0;i<6;i++)transform(ast);
fs.writeFileSync('ast_folded.json',JSON.stringify(ast));
console.log(JSON.stringify(stats));
