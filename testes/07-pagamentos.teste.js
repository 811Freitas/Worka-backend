"use strict";

/**
 * Módulo de pagamento (Cakto): sem credenciais reais no ambiente, tem
 * que falhar de forma clara e segura — nunca fingir que funcionou, e
 * nunca abrir uma conta sem prova de pagamento.
 *
 * A suíte roda sem CAKTO_CLIENT_ID/CAKTO_CLIENT_SECRET/CAKTO_WEBHOOK_SECRET
 * de propósito: é exatamente o estado em que o Zapfy vai para o ar antes
 * de alguém colar as chaves reais, e é esse estado que mais precisa
 * estar coberto.
 */

var { teste, igual, contem, criarConta } = require("./ajuda");

var G = "Pagamento (Cakto)";

teste(G, "checkout exige login", async function (ctx) {
  var r = await ctx.cliente.post("/api/pagamentos/checkout", {});
  igual(r.status, 401);
});

teste(G, "checkout responde claro quando o Cakto não está configurado", async function (ctx) {
  var conta = await criarConta(ctx.cliente, "pagamento");

  var r = await ctx.cliente.post("/api/pagamentos/checkout", {}, conta.token);
  igual(r.status, 503);
  contem(r.corpo.erro, "não está disponível");
});

teste(G, "webhook sem o segredo certo é recusado, mesmo com evento válido", async function (ctx) {
  var r = await ctx.cliente.post("/webhook/cakto", {
    event: "purchase_approved", data: { customer_email: "alguem@exemplo.com" }
  });
  igual(r.status, 401);
});

teste(G, "webhook com segredo forjado na query também é recusado", async function (ctx) {
  var r = await ctx.cliente.post("/webhook/cakto?s=qualquer-coisa", {
    event: "purchase_approved", data: { customer_email: "alguem@exemplo.com" }
  });
  igual(r.status, 401);
});
