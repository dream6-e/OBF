const fs=require('fs');
const ast=JSON.parse(fs.readFileSync('ast_folded.json','utf8'));
const clean={
 e:'lrotate',zs:'rshift',o:'lshift',j:'bxor',d:'band',y:'bor',yo:'bnot',
 p:'buf_create',c:'buf_readu8',x:'buf_writeu8',uh:'buf_readu16',r:'buf_readu32',
 mg:'buf_readi32',up:'buf_readf64',ra:'buf_fromstring',ro:'buf_len',mz:'bufferlib',
 mn:'bit32lib',u:'fmt',h:'strsub',m:'strbyte',a:'strchar',z:'tconcat',
 hp:'tfreeze',rf:'tunpack',f:'floor',k:'ERR',ff:'pcall_',n:'loadstring',
 sp:'tonum',ca:'tostr',di:'typeof',zf:'nextf',lb:'rawget_',iu:'rawequal_',
 aq:'getmeta',mi:'setmeta',uu:'select_',er:'packN',g:'dbginfo',s:'debuglib',
 qa:'XOR',is:'XOR2',pk:'adler32',cx:'LIBSTR',zo:'u32le_str',tl:'u32le_str2',
 b:'decstr',mb:'f64le',l:'int_fromstring',xm:'ENV'};
let renamed=0;
function walkExpr(node,scope){
  if(!node||typeof node!=='object')return;
  if(Array.isArray(node)){node.forEach(c=>walkExpr(c,scope));return;}
  if(!node.type)return;
  switch(node.type){
    case 'Identifier':
      if(scope.has(node.name)){node.name=scope.get(node.name);renamed++;}
      return;
    case 'MemberExpression': walkExpr(node.base,scope); return;
    case 'FunctionDeclaration': {
      const s2=new Map(scope);
      for(const p of node.parameters)if(p.type==='Identifier')s2.delete(p.name);
      walkBlock(node.body,s2,false);
      return;
    }
    case 'TableConstructorExpression':
      for(const f of node.fields){ if(f.type==='TableKey')walkExpr(f.key,scope); walkExpr(f.value,scope); }
      return;
    default:
      for(const k in node){if(k==='type')continue;walkExpr(node[k],scope);}
  }
}
function walkBlock(body,scope,isSeed){
  for(const st of body)walkStmt(st,scope,isSeed);
}
function walkStmt(n,scope,isSeed){
  switch(n.type){
    case 'LocalStatement':
      walkExpr(n.init,scope);
      for(const v of n.variables){
        if(isSeed&&clean[v.name]!==undefined&&scope.get(v.name)===clean[v.name]){v.name=clean[v.name];renamed++;}
        else scope.delete(v.name);
      }
      return;
    case 'FunctionDeclaration': {
      if(n.identifier)walkExpr(n.identifier,scope);
      const s2=new Map(scope);
      for(const p of n.parameters)if(p.type==='Identifier')s2.delete(p.name);
      walkBlock(n.body,s2,false);
      return;
    }
    case 'ForNumericStatement': {
      walkExpr(n.start,scope);walkExpr(n.end,scope);walkExpr(n.step,scope);
      const s2=new Map(scope);s2.delete(n.variable.name);
      walkBlock(n.body,s2,false);return;
    }
    case 'ForGenericStatement': {
      walkExpr(n.iterators,scope);
      const s2=new Map(scope);for(const v of n.variables)s2.delete(v.name);
      walkBlock(n.body,s2,false);return;
    }
    case 'IfStatement':
      for(const c of n.clauses){ if(c.condition)walkExpr(c.condition,scope); walkBlock(c.body,new Map(scope),isSeed); }
      return;
    case 'WhileStatement': walkExpr(n.condition,scope); walkBlock(n.body,new Map(scope),isSeed); return;
    case 'RepeatStatement': {const s2=new Map(scope);walkBlock(n.body,s2,isSeed);walkExpr(n.condition,s2);return;}
    case 'DoStatement': walkBlock(n.body,new Map(scope),isSeed); return;
    default:
      for(const k in n){if(k==='type')continue;walkExpr(n[k],scope);}
  }
}
const tbl=ast.body[1].arguments[0].base.base.arguments[0];
for(const f of tbl.fields){
  const key=f.key&&(f.key.raw!==undefined?f.key.raw.replace(/"/g,""):f.key.name);
  if(key==='g'){
    const s=new Map(Object.entries(clean));
    for(const p of f.value.parameters)if(p.type==='Identifier')s.delete(p.name);
    walkBlock(f.value.body,s,true);
  }
}
fs.writeFileSync('ast_named.json',JSON.stringify(ast));
console.log('renamed',renamed);
