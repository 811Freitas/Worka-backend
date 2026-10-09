import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {JSDOM} from 'jsdom';
import ts from 'typescript';

// Exercise the actual React component in a DOM. Layout/browser rendering is separate.
const src=fs.readFileSync(new URL('../src/LandingPage.tsx',import.meta.url),'utf8');
const compiled=ts.transpileModule(src,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext,jsx:ts.JsxEmit.ReactJSX}});
const target=new URL('../.test-component.mjs',import.meta.url);fs.writeFileSync(target,compiled.outputText);
const dom=new JSDOM('<!doctype html><div id="root"></div>',{url:'https://workap.com.br'});
Object.assign(globalThis,{window:dom.window,document:dom.window.document,HTMLElement:dom.window.HTMLElement,FormData:dom.window.FormData,IS_REACT_ACT_ENVIRONMENT:true});
dom.window.HTMLDialogElement.prototype.showModal=function(){this.setAttribute('open','');};
dom.window.HTMLDialogElement.prototype.close=function(){this.removeAttribute('open');};
const React=await import('react');const {act}=React;const {createRoot}=await import('react-dom/client');const {default:Home}=await import(target.href);
const root=createRoot(document.getElementById('root'));
let requests=[],failure=false;
globalThis.fetch=async(url,options)=>{requests.push({url,options});return {ok:!failure};};
await act(async()=>root.render(React.createElement(Home)));
const button=text=>[...document.querySelectorAll('button')].find(b=>b.textContent.includes(text));
const click=async(el)=>{assert.ok(el,'element exists');await act(async()=>el.click());};
const fill=(name,value)=>{const el=document.querySelector(`[name="${name}"]`);el.value=value;};

test('navigation targets, three plans and mobile menu',async()=>{for(const a of document.querySelectorAll('a[href^="#"]')){const hash=a.getAttribute('href');if(hash.length>1)assert.ok(document.querySelector(hash));}assert.equal(document.querySelectorAll('.price-card').length,3);const toggle=document.querySelector('.mobile-toggle');await click(toggle);assert.equal(toggle.getAttribute('aria-expanded'),'true');await click(toggle);});
test('scenario switches and log tabs work',async()=>{await click(button('Suporte'));assert.match(document.querySelector('.demo-messages').textContent,/número do seu pedido/);await click(button('Logs'));assert.match(document.querySelector('.log-preview').textContent,/personality: suporte/);await click(button('Conversa'));});
test('CTA selects plan and persists via real configured endpoint',async()=>{await click(button('Quero o Starter'));assert.ok(document.querySelector('dialog[open]'));assert.equal(document.querySelector('select').value,'Starter');fill('name','Teste QA');fill('email','qa@example.com');document.querySelector('[name="consent"]').checked=true;await act(async()=>document.querySelector('.lead-form').dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true})));assert.equal(requests.length,1);assert.equal(requests[0].url,'https://worka-backend-awng.onrender.com/public/bots-leads');const body=JSON.parse(requests[0].options.body);assert.equal(body.plan,'Starter');assert.equal(body.consent,true);assert.match(document.querySelector('[role="status"]').textContent,/Interesse registrado/);await click(document.querySelector('.close'));});
test('submission failure keeps form and shows honest error',async()=>{failure=true;await click(button('Criar meu bot grátis'));fill('name','Teste QA');fill('email','qa@example.com');document.querySelector('[name="consent"]').checked=true;await act(async()=>document.querySelector('.lead-form').dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true})));assert.ok(document.querySelector('.lead-form'));assert.match(document.querySelector('[role="alert"]').textContent,/Não foi possível/);await click(document.querySelector('.close'));});
test('login and privacy communicate limits, existing app remains linked',async()=>{await click(button('Login'));assert.match(document.querySelector('dialog').textContent,/acesso às contas será liberado/i);await click(document.querySelector('.close'));await click(button('Privacidade'));assert.match(document.querySelector('dialog').textContent,/98523-8435/);assert.ok(document.querySelector('a[href="/app/"]'));});
process.on('exit',()=>{try{fs.unlinkSync(target)}catch{}});
