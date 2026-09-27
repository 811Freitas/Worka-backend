const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(require('node:path').join(__dirname, '..', 'index.js'), 'utf8');
function load(start, end, context = {}) {
  const a = source.indexOf(start);
  const b = source.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a, `Função não encontrada: ${start}`);
  const scope = vm.createContext(context);
  vm.runInContext(source.slice(a, b), scope);
  return scope;
}

test('menu, gatilho mais específico e fallback usam o mesmo motor', () => {
  const ctx = load('function montarMenu(', '/**\n * As primeiras opções', {
    normalizarTexto: s => String(s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim()
  });
  const bot = { boas_vindas: 'Olá', fallback: 'Não sei' };
  const itens = [
    { id: '1', tipo: 'opcao', ativo: true, rotulo: 'Horário', resposta: '8h' },
    { id: '2', tipo: 'gatilho', ativo: true, palavras: 'banco', resposta: 'Geral' },
    { id: '3', tipo: 'gatilho', ativo: true, palavras: 'banco de horas', resposta: 'Específico' }
  ];
  assert.equal(ctx.decidirRespostaChatbot(bot, itens, '1').resposta, '8h');
  assert.equal(ctx.decidirRespostaChatbot(bot, itens, 'oi').como, 'menu');
  assert.equal(ctx.decidirRespostaChatbot(bot, itens, 'meu banco de horas').resposta, 'Específico');
  assert.equal(ctx.decidirRespostaChatbot(bot, itens, 'qualquer coisa').resposta, 'Não sei');
});

test('webhook separa mensagens por número e ignora eventos de entrega', () => {
  const ctx = load('function textoDaMensagemWhatsApp(', '/**\n * Atende UMA mensagem', {});
  const entries = [
    { changes: [{ value: { metadata: { phone_number_id: 'A' }, messages: [{ id: 'm1', from: '5511', type: 'text', text: { body: 'oi' } }] } }] },
    { changes: [{ value: { metadata: { phone_number_id: 'B' }, messages: [{ id: 'm2', from: '5522', type: 'interactive', interactive: { button_reply: { title: 'Horário' } } }] } }] },
    { changes: [{ value: { statuses: [{ id: 'm1', status: 'delivered' }] } }] }
  ];
  const messages = ctx.mensagensDoEventoWhatsApp({ entry: entries });
  assert.deepEqual(Array.from(messages, m => [m.phone_number_id, m.id, m.texto]), [
    ['A', 'm1', 'oi'], ['B', 'm2', 'Horário']
  ]);
  assert.equal(messages.filter(m => m.phone_number_id === 'A' && m.id).length, 1);
});

test('falha ao chamar atendente nunca confirma um aviso que não foi criado', async () => {
  const ctx = load('async function rodarFerramentaDoBot(', '/**\n * Uma conversa com o modelo', {
    DB: { insert: async () => { throw new Error('banco indisponível'); } },
    secLog() {}
  });
  const resposta = await ctx.rodarFerramentaDoBot({ id: 'bot', empresa_id: 'empresa' },
    'chamar_atendente', { motivo: 'ajuda' }, 'Cliente');
  assert.match(resposta, /Não consegui avisar/);
  assert.doesNotMatch(resposta, /Avisei a equipe/);
});
