const {test}=require('node:test');
const assert=require('node:assert/strict');
const {Readable}=require('node:stream');
const {createLeadsHandler}=require('../services/bots-leads');
const valid={name:'Teste Automático',email:'TEST@example.com',plan:'Pro',consent:true,website:''};
async function call(data, options={}){
 const calls=[];
 const handler=createLeadsHandler({database:async(...args)=>{calls.push(args);if(options.fail)throw new Error('SECRET Database details');},origins:['https://workap.com.br']});
 const req=Readable.from([options.raw??JSON.stringify(data)]);req.method=options.method||'POST';req.headers={origin:options.origin||'https://workap.com.br','content-type':options.type||'application/json'};
 const res={status:0,writeHead(n){this.status=n;},end(s){this.body=JSON.parse(s);}};
 await handler(req,res);return {res,calls};
}
test('waitlist normaliza e grava consentimento sem devolver contatos',async()=>{const {res,calls}=await call(valid);assert.equal(res.status,202);assert.deepEqual(res.body,{ok:true});assert.equal(calls[0][2].body.email,'test@example.com');assert.match(calls[0][2].prefer,/ignore-duplicates/);assert.ok(calls[0][2].body.consent_version);});
test('origem não autorizada não grava',async()=>{const r=await call(valid,{origin:'https://attacker.example'});assert.equal(r.res.status,403);assert.equal(r.calls.length,0);});
test('GET não lista leads',async()=>assert.equal((await call(valid,{method:'GET'})).res.status,405));
test('consentimento obrigatório, plano fechado e email válido',async()=>{for(const invalid of [{...valid,consent:false},{...valid,plan:'admin'},{...valid,email:'invalid'},null,[],{...valid,name:'<script>'}]){const r=await call(invalid);assert.equal(r.res.status,400);assert.equal(r.calls.length,0);}});
test('JSON e corpo inválidos têm resposta controlada',async()=>{assert.equal((await call(null,{raw:'{'})).res.status,400);assert.equal((await call(null,{raw:'x'.repeat(4097)})).res.status,413);assert.equal((await call(valid,{type:'text/plain'})).res.status,415);});
test('honeypot não grava',async()=>{const r=await call({...valid,website:'spam'});assert.equal(r.res.status,202);assert.equal(r.calls.length,0);});
test('erro do banco nunca vira falso sucesso ou vaza detalhes',async()=>{const r=await call(valid,{fail:true});assert.equal(r.res.status,503);assert.doesNotMatch(JSON.stringify(r.res.body),/SECRET/);});
