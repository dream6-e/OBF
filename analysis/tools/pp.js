const fs=require('fs');
const ast=JSON.parse(fs.readFileSync('ast.json','utf8'));
let out=[];let ind=0;
const pad=()=>'  '.repeat(ind);
function e(n){
  if(!n)return 'nil';
  switch(n.type){
    case 'Identifier': return n.name;
    case 'NumericLiteral': return n.raw;
    case 'StringLiteral': return n.raw;
    case 'BooleanLiteral': return String(n.value);
    case 'NilLiteral': return 'nil';
    case 'VarargLiteral': return '...';
    case 'BinaryExpression': case 'LogicalExpression':
      return '('+e(n.left)+' '+n.operator+' '+e(n.right)+')';
    case 'UnaryExpression': return '('+n.operator+(n.operator.match(/\w/)?' ':'')+e(n.argument)+')';
    case 'MemberExpression': return e(n.base)+n.indexer+e(n.identifier);
    case 'IndexExpression': return e(n.base)+'['+e(n.index)+']';
    case 'CallExpression': return e(n.base)+'('+n.arguments.map(e).join(', ')+')';
    case 'TableCallExpression': return e(n.base)+' '+e(n.arguments);
    case 'StringCallExpression': return e(n.base)+' '+e(n.argument);
    case 'FunctionDeclaration': {
      let s='function('+n.parameters.map(e).join(', ')+')\n';
      ind++; s+=body(n.body); ind--;
      s+=pad()+'end'; return s;
    }
    case 'TableConstructorExpression': {
      if(n.fields.length===0)return '{}';
      let parts=n.fields.map(f=>{
        if(f.type==='TableKey')return '['+e(f.key)+'] = '+e(f.value);
        if(f.type==='TableKeyString')return e(f.key)+' = '+e(f.value);
        return e(f.value);
      });
      let oneline='{'+parts.join(', ')+'}';
      if(oneline.length<=140)return oneline;
      ind++;let s='{\n'+parts.map(p=>pad()+p).join(',\n')+'\n';ind--;s+=pad()+'}';return s;
    }
    default: return '--[['+n.type+']]';
  }
}
function body(stmts){let s='';for(const st of stmts)s+=stmt(st);return s;}
function stmt(n){
  let p=pad();
  switch(n.type){
    case 'LocalStatement': return p+'local '+n.variables.map(e).join(', ')+(n.init.length?' = '+n.init.map(e).join(', '):'')+'\n';
    case 'AssignmentStatement': return p+n.variables.map(e).join(', ')+' = '+n.init.map(e).join(', ')+'\n';
    case 'CallStatement': return p+e(n.expression)+'\n';
    case 'ReturnStatement': return p+'return '+n.arguments.map(e).join(', ')+'\n';
    case 'BreakStatement': return p+'break\n';
    case 'DoStatement': {ind++;let b=body(n.body);ind--;return p+'do\n'+b+p+'end\n';}
    case 'WhileStatement': {ind++;let b=body(n.body);ind--;return p+'while '+e(n.condition)+' do\n'+b+p+'end\n';}
    case 'RepeatStatement': {ind++;let b=body(n.body);ind--;return p+'repeat\n'+b+p+'until '+e(n.condition)+'\n';}
    case 'IfStatement': {
      let s='';
      n.clauses.forEach((c,i)=>{
        if(c.type==='IfClause')s+=p+'if '+e(c.condition)+' then\n';
        else if(c.type==='ElseifClause')s+=p+'elseif '+e(c.condition)+' then\n';
        else s+=p+'else\n';
        ind++;s+=body(c.body);ind--;
      });
      s+=p+'end\n';return s;
    }
    case 'ForNumericStatement': {ind++;let b=body(n.body);ind--;
      return p+'for '+e(n.variable)+' = '+e(n.start)+', '+e(n.end)+(n.step?', '+e(n.step):'')+' do\n'+b+p+'end\n';}
    case 'ForGenericStatement': {ind++;let b=body(n.body);ind--;
      return p+'for '+n.variables.map(e).join(', ')+' in '+n.iterators.map(e).join(', ')+' do\n'+b+p+'end\n';}
    case 'FunctionDeclaration': {
      let name=n.identifier?e(n.identifier):'';
      ind++;let b=body(n.body);ind--;
      return p+(n.isLocal?'local ':'')+'function '+name+'('+n.parameters.map(e).join(', ')+')\n'+b+p+'end\n';
    }
    case 'LabelStatement': return p+'::'+e(n.label)+'::\n';
    case 'GotoStatement': return p+'goto '+e(n.label)+'\n';
    default: return p+'--[[?'+n.type+']]\n';
  }
}
fs.writeFileSync('pretty.lua', body(ast.body));
console.log('written', fs.statSync('pretty.lua').size);
