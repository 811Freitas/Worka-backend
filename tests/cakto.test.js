const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
function load(start, end, context) {
  const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a);
  const scope = vm.createContext(context);
  vm.runInContext(source.slice(a, b), scope);
  return scope;
}

test('chave do JSON oficial autentica o webhook; uma chave errada é recusada', () => {
  const scope = load('var CABECALHOS_DE_SEGREDO =', '/**\n * Aplica o plano vendido', {
    CONFIG: { CAKTO_WEBHOOK_SECRET: 'segredo-de-teste' }, crypto, Buffer
  });
  const url = new URL('https://exemplo.com/webhook/cakto');
  assert.equal(scope.conferirSegredoDoWebhook(url, {}, { secret: 'segredo-de-teste' }).ok, true);
  assert.equal(scope.conferirSegredoDoWebhook(url, {}, { secret: 'errado' }).ok, false);
  assert.equal(scope.conferirSegredoDoWebhook(url, {}, {}).ok, false);
  assert.equal(scope.conferirSegredoDoWebhook(new URL(url + '?s=segredo-de-teste'), {}, {}).ok, true);
});

test('compra recorrente abre acesso e grava a próxima cobrança do payload oficial', async () => {
  let updated, invalidated;
  const scope = load('async function aplicarAssinaturaCakto(', '/**\n * Confere que o webhook veio', {
    DB: { update: async (table, query, changes) => { updated = { table, query, changes }; } },
    CONFIG: { PLANOS: { chatbot: {} } },
    require: name => name === './services/cakto-plan' ? require('../services/cakto-plan') : require(name),
    esquecerAcesso: id => { invalidated = id; },
    secLog() {}
  });
  await scope.aplicarAssinaturaCakto('empresa-1', {
    product: { id: 'produto-1', type: 'subscription' },
    subscription: { id: 'assinatura-1', next_payment_date: '2026-10-27T15:00:00-03:00' }
  }, 'chatbot');
  assert.equal(updated.table, 'empresas');
  assert.equal(updated.changes.status, 'ativa');
  assert.equal(updated.changes.plano, 'chatbot');
  assert.equal(updated.changes.pagamento_assinatura_id, 'assinatura-1');
  assert.equal(updated.changes.assinatura_ate, '2026-10-27T18:00:00.000Z');
  assert.equal(invalidated, 'empresa-1');
});

test('cada produto novo é inscrito nos eventos antes de entregar o checkout', async () => {
  let request;
  const scope = load('async function registrarWebhookDoProdutoCakto(', '/**\n * Converte para centavos', {
    CONFIG: { CAKTO_WEBHOOK_SECRET: 'chave privada', CAKTO_WEBHOOK_URL: 'https://backend.exemplo.com' },
    CAKTO: { criarWebhook: '/public_api/webhook/' },
    URL,
    caktoRequest: async (...args) => { request = args; }
  });
  await scope.registrarWebhookDoProdutoCakto('produto-novo');
  assert.equal(request[0], 'POST');
  assert.equal(request[1], '/public_api/webhook/');
  assert.equal(request[2].url, 'https://backend.exemplo.com/webhook/cakto?s=chave%20privada');
  assert.deepEqual(Array.from(request[2].products), ['produto-novo']);
  assert.ok(request[2].events.includes('purchase_approved'));
});
