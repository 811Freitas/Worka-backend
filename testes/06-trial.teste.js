"use strict";

/**
 * Trial de 7 dias: nasce em trial, o bot atende durante o trial, avisa
 * quando está acabando, e silencia o bot quando acaba de verdade.
 */

var { teste, igual, verdade, criarConta, conectarWhatsapp,
      webhookMensagem, assinar } = require("./ajuda");
var monitor = require("../src/modulos/monitor");
var webhook = require("../src/modulos/whatsapp/webhook");

var G = "Trial de 7 dias";

/** Mesmo helper de 04-whatsapp.teste.js: entrega e espera o processamento. */
async function entregar(ctx, corpo) {
  var cabecalhos = { "X-Hub-Signature-256": assinar(corpo, "segredo-do-app") };
  var r = await ctx.cliente.post("/webhook", corpo, null, cabecalhos);
  await webhook.aguardarPendentes();
  return r;
}

teste(G, "conta nova nasce em trial, com 7 dias de prazo", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "trial-novo");

  igual(conta.conta.status, "trial");
  verdade(conta.conta.trial_fim, "trial_fim deveria vir preenchido");
  igual(conta.conta.trial_dias_restantes, 7);

  var eu = await ctx.cliente.get("/api/eu", conta.token);
  igual(eu.corpo.conta.status, "trial");
  igual(eu.corpo.conta.trial_dias_restantes, 7);
});

teste(G, "bot responde normalmente durante o trial", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "trial-atende");
  var wa = await conectarWhatsapp(ctx, conta.token);

  var r = await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511977000001", "oi"));
  igual(r.status, 200);

  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  verdade(conversas.corpo.length >= 1, "a conta em trial deveria estar atendendo");
});

teste(G, "o monitor avisa quem está a 2 dias do fim do trial, uma vez só", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "trial-avisa");

  // Empurra o fim do trial para dentro da janela de aviso (1,5 a 2,5
  // dias) direto no banco — é o atalho certo aqui: o que este caso testa
  // é o comportamento do monitor, não o cadastro.
  await ctx.db.consultar(
    "update contas set trial_fim = now() + interval '2 days' where id=$1",
    [conta.conta.id]
  );

  await monitor.verificarTrials();

  var notificacoes = await ctx.cliente.get("/api/notificacoes", conta.token);
  var aviso = notificacoes.corpo.find(function (n) { return n.tipo === "trial_acabando"; });
  verdade(aviso, "deveria ter avisado que o trial está acabando");

  var linha = await ctx.db.uma("select aviso_trial_sent from contas where id=$1", [conta.conta.id]);
  igual(linha.aviso_trial_sent, true);

  // Uma segunda passada do monitor não pode duplicar o aviso — a trava é
  // justamente a coluna aviso_trial_sent.
  await monitor.verificarTrials();
  var depois = await ctx.cliente.get("/api/notificacoes", conta.token);
  var quantos = depois.corpo.filter(function (n) { return n.tipo === "trial_acabando"; }).length;
  igual(quantos, 1, "o aviso não pode ser mandado duas vezes");
});

teste(G, "trial vencido vira inadimplente e o bot para de responder", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "trial-vencido");
  var wa = await conectarWhatsapp(ctx, conta.token);

  await ctx.db.consultar(
    "update contas set trial_fim = now() - interval '1 hour' where id=$1",
    [conta.conta.id]
  );

  await monitor.verificarTrials();

  var eu = await ctx.cliente.get("/api/eu", conta.token);
  igual(eu.corpo.conta.status, "inadimplente");

  var notificacoes = await ctx.cliente.get("/api/notificacoes", conta.token);
  verdade(notificacoes.corpo.some(function (n) { return n.tipo === "trial_expirado"; }),
    "deveria ter avisado que o trial acabou");

  // O login continua funcionando (a pessoa precisa conseguir entrar para
  // assinar um plano) — só o BOT é que se cala.
  var login = await ctx.cliente.post("/api/login", { email: conta.email, senha: conta.senha });
  igual(login.status, 200, "inadimplente ainda consegue entrar no painel");

  var r = await entregar(ctx, webhookMensagem(wa.phone_number_id, "5511977000002", "oi"));
  igual(r.status, 200);   // a Meta sempre recebe 200, mesmo sem resposta

  igual(ctx.meta.enviadas.length, 0, "o bot respondeu estando inadimplente");

  // A mensagem do cliente final continua gravada — só a resposta
  // automática que não sai. Um bot mudo é um problema; uma mensagem
  // perdida é outro, muito pior (mesma regra de conta pausada).
  var conversas = await ctx.cliente.get("/api/conversas", conta.token);
  igual(conversas.corpo.length, 1);
});

teste(G, "o monitor não mexe em conta ativa nem já avisada", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "trial-neutro");

  // Fora da janela de aviso e longe do fim — nenhuma das duas passadas
  // deveria tocar nesta conta.
  var antes = await ctx.db.uma("select status, aviso_trial_sent, aviso_expirado_sent from contas where id=$1",
    [conta.conta.id]);

  await monitor.verificarTrials();

  var depois = await ctx.db.uma("select status, aviso_trial_sent, aviso_expirado_sent from contas where id=$1",
    [conta.conta.id]);

  igual(depois.status, antes.status);
  igual(depois.aviso_trial_sent, false);
  igual(depois.aviso_expirado_sent, false);
});
