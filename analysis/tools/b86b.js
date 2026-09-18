const fs=require('fs');
const luaparse=require('luaparse');
let src=fs.readFileSync('/home/user/work/src_norm.lua','utf8');
const ast=luaparse.parse(src,{luaVersion:'5.3',comments:false,ranges:true,encodingMode:'x-user-defined'});
function findAssign(key){let f=null;(function w(n){if(!n||typeof n!=='object')return;if(Array.isArray(n)){n.forEach(w);return;}if(!n.type)return;
 if(n.type==='AssignmentStatement'&&n.variables.length===1){const v=n.variables[0];if(v.type==='IndexExpression'&&v.index.type==='NumericLiteral'&&v.index.value===key)f=n.init[0];}
 for(const k in n){if(k==='type')continue;w(n[k]);}})(ast.body);return f;}
function cs(n){if(n.type==='StringLiteral')return n.value;if(n.type==='BinaryExpression'&&n.operator==='..')return cs(n.left)+cs(n.right);throw 0;}
function extract(fn){let alpha=null,chunks=null;(function w(n){if(!n||typeof n!=='object')return;if(Array.isArray(n)){n.forEach(w);return;}if(!n.type)return;
 if(n.type==='AssignmentStatement'){for(let i=0;i<n.variables.length;i++){const v=n.variables[i],init=n.init[i];if(!init)continue;
  if(v.type==='IndexExpression'){try{const s=cs(init);if(s.length===86&&!alpha)alpha=s;}catch(e){}
   if(init.type==='TableConstructorExpression'&&init.fields.length>3&&!chunks){try{chunks=init.fields.map(f=>cs(f.value));}catch(e){}}}}}
 for(const k in n){if(k==='type')continue;w(n[k]);}})(fn.body);return{alpha,chunks};}

function keyShift(q){ // j[59] from previous plaintext
  if(q===null)return 0;
  let s=0;
  for(let i=0;i<q.length;i++){ s=((s+q[i])*256)%86; }
  s=(s+q.length)%86;
  return s;
}
function b86decode(alpha,chunks,shift){
  const B=86;
  const dig={}; // char -> digit value
  for(let i=0;i<B;i++)dig[alpha[i]]=(i+shift)%B;
  const posOf={}; for(let i=0;i<B;i++)posOf[alpha[i]]=i;
  const order=[];
  for(const c of chunks){const idx=((posOf[c[0]])%B+B)%B; if(idx<1||idx>chunks.length||order[idx]!==undefined)throw new Error('chunk order bad '+idx); order[idx]=c.slice(1);}
  let data=''; for(let i=1;i<=chunks.length;i++){if(order[i]===undefined)throw new Error('missing '+i);data+=order[i];}
  const out=[]; let pos=1;
  function rd(count){let num=0,mul=1;for(let w=1;w<=count;w++){const c=data[pos+w-2];if(c===undefined)throw new Error('eof at '+pos);const d=dig[c];if(d===undefined)throw new Error('badchar');num+=d*mul;mul*=B;}return num;}
  const emit=(n,cnt)=>{for(let x=0;x<cnt;x++){out.push(n%256);n=(n-(n%256))/256;}};
  let num=rd(4); let remaining=num%16777216; let prev=num; pos=5;
  while(remaining>4){
    const m=prev%3; let take=4,bytes=3;
    if(m===1){take=5;bytes=4;}else if(m===2){take=6;bytes=4;}
    const n2=rd(take);prev=n2;pos+=take;emit(n2,bytes);remaining-=bytes;
  }
  if(remaining===4){const m=prev%3;const take=(m%2===1)?6:5;const n2=rd(take);pos+=take;emit(n2,4);}
  else if(remaining===3){const n2=rd(4);pos+=4;emit(n2,3);}
  else if(remaining===2){const n2=rd(3);pos+=3;emit(n2,2);}
  else if(remaining===1){const n2=rd(2);pos+=2;emit(n2,1);}
  if(pos!==data.length+1)throw new Error('trailing mismatch pos='+pos+' need='+(data.length+1));
  return Buffer.from(out);
}
let prevPlain=null; const parts=[];
for(const key of [8255,7919,5850]){
  const {alpha,chunks}=extract(findAssign(key));
  const shift=keyShift(prevPlain);
  const buf=b86decode(alpha,chunks,shift);
  console.log(key,'shift',shift,'->',buf.length,'bytes head',JSON.stringify(buf.slice(0,16).toString('latin1')));
  fs.writeFileSync('stage_'+key+'.bin',buf);
  parts.push(buf); prevPlain=buf;
}
const all=Buffer.concat(parts);
fs.writeFileSync('blob_full.bin',all);
fs.writeFileSync('blob_body.bin',all.slice(4)); // strsub(...,5)
console.log('TOTAL',all.length,'magic',JSON.stringify(all.slice(0,8).toString('latin1')));
