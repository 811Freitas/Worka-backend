const {test}=require('node:test');
const assert=require('node:assert/strict');
const {exactPlan,purchasablePlan}=require('../services/cakto-plan');
const catalog={completo:{},pro:{},master:{},chatbot:{}};
const opts={catalog,masterActive:async()=>false,chatbotActive:async()=>false};
test('plano desconhecido, ausente ou herdado nunca vira cobrança',async()=>{
 for(const input of [undefined,null,'','Starter','Enterprise','bots_pro','constructor','__proto__']){
  assert.equal(exactPlan(input,catalog),null);
  assert.equal((await purchasablePlan(input,opts)).status,400);
 }
});
test('normaliza apenas planos conhecidos',async()=>assert.equal((await purchasablePlan(' PRO ',opts)).slug,'pro'));
test('plano desligado não pode ser contratado por chamada direta',async()=>{
 for(const input of ['master','chatbot'])assert.equal((await purchasablePlan(input,opts)).status,409);
});
test('plano chatbot exige habilitação explícita',async()=>assert.equal((await purchasablePlan('chatbot',{...opts,chatbotActive:async()=>true})).slug,'chatbot'));
