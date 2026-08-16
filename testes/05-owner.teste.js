"use strict";

/**
 * Painel do dono da plataforma.
 *
 * O que estes casos protegem, acima de tudo: a fronteira. Um cliente não
 * pode alcançar rota administrativa nenhuma, e o administrador não pode
 * alcançar o conteúdo das conversas dos clientes. As duas direções
 * importam, e as duas são testadas.
 */

var { teste, igual, verdade, contem, criarConta, conectarWhatsapp,
      webhookMensagem, assinar } = require("./ajuda");
var webhook = require("../src/modulos/whatsapp/webhook");

var G = "Painel do dono da plataforma";

// As mesmas credenciais que o executor coloca no ambiente.
var OWNER = { email: "dono@zapfy.test", senha: "senha-do-dono-987" };

async function entrarComoOwner(ctx) {
  var r = await ctx.cliente.post("/api/owner/login", OWNER);
  if (r.status !== 200) throw new Error("login de owner falhou: " + r.status + " " + JSON.stringify(r.corpo));
  return r.corpo.token;
}

async function entregar(ctx, corpo) {
  var r = await ctx.cliente.post("/webhook", corpo, null,
    { "X-Hub-Signature-256": assinar(corpo, "segredo-do-app") });
  await webhook.aguardarPendentes();
  return r;
}

// ════════════════════════════════════════
// ACESSO
// ════════════════════════════════════════
teste(G, "login administrativo funciona com as credenciais do ambiente", async function (ctx) {
  var r = await ctx.cliente.post("/api/owner/login", OWNER);

  igual(r.status, 200);
  verdade(r.corpo.token, "veio token");
  igual(r.corpo.owner.email, OWNER.email);
});

teste(G, "senha errada é recusada", async function (ctx) {
  var r = await ctx.cliente.post("/api/owner/login",
    { email: OWNER.email, senha: "chute-errado-123" });

  igual(r.status, 401);
  // A mensagem não diz qual dos dois estava errado.
  contem(r.corpo.erro, "E-mail ou senha");
});

teste(G, "e-mail que não é o do dono é recusado", async function (ctx) {
  var r = await ctx.cliente.post("/api/owner/login",
    { email: "qualquer@exemplo.com", senha: OWNER.senha });
  igual(r.status, 401);
});

teste(G, "token de CLIENTE não abre nenhuma rota administrativa", async function (ctx) {
  // O defeito que este caso existe para impedir: um cliente comum
  // conseguir listar — ou suspender — as contas de todo mundo.
  var conta = await criarConta(ctx.cliente, "cliente-curioso");

  var rotas = [
    ["GET", "/api/owner/resumo"],
    ["GET", "/api/owner/contas"],
    ["GET", "/api/owner/saude"],
    ["GET", "/api/owner/acoes"],
    ["GET", "/api/owner/eu"]
  ];

  for (var [metodo, caminho] of rotas) {
    var r = await ctx.cliente.cru(metodo, caminho, null, conta.token);
    igual(r.status, 401, caminho + " aceitou um token de cliente");
  }
});

teste(G, "sem token nenhum também não abre", async function (ctx) {
  var r = await ctx.cliente.get("/api/owner/contas");
  igual(r.status, 401);
});

teste(G, "token administrativo não abre rota de cliente", async function (ctx) {
  // A fronteira vale nos dois sentidos: o token de owner não carrega
  // conta_id, e usá-lo numa rota de cliente tem que parar no portão, não
  // produzir uma consulta com `undefined` no filtro.
  var token = await entrarComoOwner(ctx);

  var r = await ctx.cliente.get("/api/bot", token);
  igual(r.status, 401, "o token de owner passou por uma rota de cliente");
});

// ════════════════════════════════════════
// RESUMO E LISTAGEM
// ════════════════════════════════════════
teste(G, "o resumo conta as contas e o uso da plataforma", async function (ctx) {
  var token = await entrarComoOwner(ctx);
  var antes = await ctx.cliente.get("/api/owner/resumo", token);

  await criarConta(ctx.cliente, "resumo-owner");

  var depois = await ctx.cliente.get("/api/owner/resumo", token);

  igual(depois.status, 200);
  igual(depois.corpo.numeros.contas_total, antes.corpo.numeros.contas_total + 1);
  // Conta recém-criada nasce em trial, não "ativa" — ativa é quem já
  // assinou um plano. É por isso que o resumo tem um contador para cada.
  verdade(depois.corpo.numeros.contas_trial >= 1);
  igual(depois.corpo.serie.length, 14, "quatorze dias, inclusive os vazios");
});

teste(G, "a lista traz o uso real de cada conta", async function (ctx) {
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "listada");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511970000001", "oi"));

  var r = await ctx.cliente.get("/api/owner/contas?busca=listada", token);
  igual(r.status, 200);

  var achada = r.corpo.find(function (c) { return c.id === conta.conta.id; });
  verdade(achada, "a conta não apareceu na busca");
  igual(achada.conexao_status, "conectado");
  igual(achada.usuarios, 1);
  verdade(achada.mensagens_7d >= 1, "deveria contar as mensagens trocadas");
  igual(achada.email_dono, conta.email);
});

teste(G, "filtro de contas sem conexão funciona", async function (ctx) {
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "sem-conectar");

  var r = await ctx.cliente.get("/api/owner/contas?filtro=sem_conexao", token);
  verdade(r.corpo.some(function (c) { return c.id === conta.conta.id; }),
    "conta recém-criada deveria aparecer como sem conexão");
});

teste(G, "a ficha da conta NÃO devolve credenciais nem conversas", async function (ctx) {
  // A linha que o painel administrativo não cruza.
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "privacidade");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511970000002",
    "meu CPF é 000.000.000-00 e moro na rua tal"));

  var r = await ctx.cliente.get("/api/owner/contas/" + conta.conta.id, token);
  igual(r.status, 200);

  var texto = JSON.stringify(r.corpo);
  verdade(texto.indexOf("token-bom") === -1, "o token da Meta vazou para o painel administrativo");
  verdade(texto.indexOf("token_cifrado") === -1, "o campo cifrado nem deveria ser selecionado");
  verdade(texto.indexOf("meu CPF") === -1, "o conteúdo da conversa do cliente vazou");

  // Mas os números operacionais estão lá — é para isso que a tela existe.
  igual(r.corpo.conexao.token_configurado, true);
  verdade(r.corpo.uso.mensagens_total >= 1);
  igual(r.corpo.usuarios.length, 1);
});

// ════════════════════════════════════════
// SUSPENSÃO
// ════════════════════════════════════════
teste(G, "suspender uma conta cala o bot dela na hora", async function (ctx) {
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "suspender");
  var wa = await conectarWhatsapp(ctx, conta.token);

  // Antes: responde normalmente.
  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511970000003", "oi"));
  verdade(ctx.meta.enviadas.length > 0, "deveria responder antes da suspensão");

  var r = await ctx.cliente.post("/api/owner/contas/" + conta.conta.id + "/suspender",
    { motivo: "Falta de pagamento" }, token);
  igual(r.status, 200);
  igual(r.corpo.status, "suspensa");

  // Depois: a mensagem entra no histórico, mas ninguém recebe resposta.
  ctx.meta.limpar();
  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511970000004", "oi"));
  igual(ctx.meta.enviadas.length, 0, "o bot respondeu com a conta suspensa");

  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  verdade(conversas.corpo.length >= 1, "a mensagem do consumidor não pode ser perdida");
});

teste(G, "conta suspensa continua conseguindo entrar no painel", async function (ctx) {
  // Suspensão é cobrança, não banimento: a pessoa precisa entrar para
  // ver o que houve e regularizar.
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "suspensa-login");

  await ctx.cliente.post("/api/owner/contas/" + conta.conta.id + "/suspender", {}, token);

  var login = await ctx.cliente.post("/api/login", { email: conta.email, senha: conta.senha });
  igual(login.status, 200, "cliente suspenso deveria continuar entrando");
  igual(login.corpo.conta.status, "suspensa");
});

teste(G, "reativar devolve o atendimento", async function (ctx) {
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "reativar");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await ctx.cliente.post("/api/owner/contas/" + conta.conta.id + "/suspender", {}, token);
  var r = await ctx.cliente.post("/api/owner/contas/" + conta.conta.id + "/reativar", {}, token);
  igual(r.corpo.status, "ativa");
  igual(r.corpo.suspensa_em, null);

  ctx.meta.limpar();
  await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511970000005", "oi"));
  verdade(ctx.meta.enviadas.length > 0, "o bot não voltou depois de reativar");
});

teste(G, "mudar o plano recusa valor inventado", async function (ctx) {
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "plano");

  var ok = await ctx.cliente.post("/api/owner/contas/" + conta.conta.id + "/plano",
    { plano: "pro" }, token);
  igual(ok.corpo.plano, "pro");

  var ruim = await ctx.cliente.post("/api/owner/contas/" + conta.conta.id + "/plano",
    { plano: "plano-de-ouro" }, token);
  igual(ruim.status, 400);
});

// ════════════════════════════════════════
// SAÚDE E AUDITORIA
// ════════════════════════════════════════
teste(G, "a tela de saúde mostra quem está com a conexão quebrada", async function (ctx) {
  var monitor = require("../src/modulos/monitor");
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "saude-owner");
  await conectarWhatsapp(ctx, conta.token);

  ctx.meta.tokensValidos.delete("token-bom");
  try {
    await monitor.verificarTodas();

    var r = await ctx.cliente.get("/api/owner/saude", token);
    igual(r.status, 200);
    verdade(r.corpo.conexoes_quebradas.some(function (c) { return c.id === conta.conta.id; }),
      "a conta quebrada não apareceu na tela de saúde");
  } finally {
    ctx.meta.tokensValidos.add("token-bom");
  }
});

teste(G, "toda ação administrativa fica registrada na auditoria", async function (ctx) {
  // Suspender a conta de um cliente pagante tem consequência comercial:
  // "quem fez isso, e quando?" precisa ter resposta.
  var token = await entrarComoOwner(ctx);
  var conta = await criarConta(ctx.cliente, "auditada");

  await ctx.cliente.post("/api/owner/contas/" + conta.conta.id + "/suspender",
    { motivo: "teste de auditoria" }, token);
  await ctx.cliente.post("/api/owner/contas/" + conta.conta.id + "/reativar", {}, token);

  var r = await ctx.cliente.get("/api/owner/acoes", token);
  igual(r.status, 200);

  var minhas = r.corpo.filter(function (a) { return a.conta_id === conta.conta.id; });
  igual(minhas.length, 2);
  igual(minhas[0].acao, "reativar");
  igual(minhas[1].acao, "suspender");
  igual(minhas[0].autor, OWNER.email);
  // O nome fica copiado: o registro precisa continuar legível mesmo se a
  // conta for apagada depois.
  contem(minhas[0].conta_nome, "auditada");
});

teste(G, "conta inexistente responde 404, não 500", async function (ctx) {
  var token = await entrarComoOwner(ctx);
  var r = await ctx.cliente.post(
    "/api/owner/contas/11111111-1111-4111-8111-111111111111/suspender", {}, token);
  igual(r.status, 404);
});
