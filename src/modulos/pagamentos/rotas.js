"use strict";

/**
 * Assinatura do plano pago, via Cakto.
 *
 * Só o dono da conta pode iniciar uma cobrança — não um operador, que
 * não deveria conseguir comprometer o cartão da empresa sem querer.
 */

var express = require("express");
var db = require("../../db");
var registro = require("../../lib/registro");
var { rota, ErroHttp } = require("../../middlewares/erro");
var { exigirLogin, exigirDono } = require("../../middlewares/autenticar");
var cakto = require("./cakto");

var router = express.Router();

// Preço fixo, único plano — o mesmo valor mostrado em /site. Quando
// existir mais de um plano, isto vira uma tabela; hoje seria
// complexidade sem uso nenhum.
var PLANO_PRO = { nome: "Zapfy Pro", precoCentavos: 19900 };

router.post("/checkout", exigirLogin, exigirDono, rota(async function (req, res) {
  if (!cakto.configurado()) {
    throw new ErroHttp(503, "Pagamento ainda não está disponível. Fale com o suporte.");
  }

  var url = await cakto.criarCobrancaMensal({
    nome: PLANO_PRO.nome + " — " + req.usuario.conta_nome,
    descricao: "Assinatura mensal do Zapfy, plano " + PLANO_PRO.nome + ".",
    precoCentavos: PLANO_PRO.precoCentavos
  });

  registro.info(req.contaId, "checkout_criado", "Link de pagamento gerado.");
  res.json({ url: url });
}));

// ════════════════════════════════════════
// WEBHOOK (rota pública, montada à parte)
// ════════════════════════════════════════
/**
 * Aplica o evento de pagamento a uma conta.
 *
 * A ligação entre "quem pagou" e "qual conta" é o e-mail do dono — não
 * um id que o Zapfy tivesse mandado na criação da cobrança, porque não
 * há confirmação de que a Cakto devolve esse id de volta no aviso do
 * jeito esperado (mesma incerteza documentada em cakto.js). E-mail é o
 * dado mais provável de vir preenchido em qualquer formato de aviso de
 * pagamento, de qualquer gateway.
 */
async function aplicarEvento(tipo, dados) {
  var email = dados && (dados.customer_email || (dados.customer && dados.customer.email) ||
              dados.email || (dados.buyer && dados.buyer.email));
  if (!email) {
    console.warn("[cakto] webhook sem e-mail do cliente — não dá para saber a conta");
    return;
  }

  var usuario = await db.uma(
    "select conta_id from usuarios where lower(email)=lower($1) and papel='dono'", [String(email)]
  );
  if (!usuario) {
    console.warn("[cakto] webhook para um e-mail sem conta no Zapfy:", email);
    return;
  }

  if (cakto.eventoPago(tipo)) {
    await db.consultar(
      "update contas set status='ativa', plano='pro', atualizado_em=now() where id=$1",
      [usuario.conta_id]
    );
    registro.info(usuario.conta_id, "pagamento_confirmado", "Pagamento confirmado via Cakto (" + tipo + ").");
    await registro.notificar(usuario.conta_id, "pagamento_confirmado",
      "Pagamento confirmado!", "Sua assinatura do Zapfy Pro está ativa. Obrigado! 🎉");
  } else if (cakto.eventoCancelado(tipo)) {
    await db.consultar(
      "update contas set status='suspensa', motivo_suspensao='Assinatura cancelada na Cakto', atualizado_em=now() where id=$1",
      [usuario.conta_id]
    );
    registro.aviso(usuario.conta_id, "pagamento_cancelado", "Assinatura cancelada via Cakto (" + tipo + ").");
    await registro.notificar(usuario.conta_id, "pagamento_cancelado",
      "Assinatura cancelada", "O bot parou de responder. Assine de novo quando quiser voltar a atender.");
  }
}

var webhookRouter = express.Router();

webhookRouter.post("/", rota(async function (req, res) {
  if (!cakto.webhookValido(req.query, req.headers)) {
    console.warn("[cakto] webhook recusado: segredo inválido");
    return res.status(401).json({ erro: "segredo inválido" });
  }

  var corpo = req.body || {};
  var id = corpo.id || (corpo.data && corpo.data.id) || corpo.event_id;
  var tipo = corpo.event || corpo.type || (corpo.data && corpo.data.status);

  if (!id) {
    // Sem id não dá para deduplicar; aceita e processa mesmo assim —
    // melhor arriscar um evento repetido do que perder um pagamento.
    await aplicarEvento(tipo, corpo.data || corpo);
    return res.status(200).json({ ok: true });
  }

  var novo = await db.consultar(
    "insert into pagamentos_eventos (id) values ($1) on conflict do nothing", [String(id)]
  );
  if (novo.rowCount === 0) {
    return res.status(200).json({ ok: true, repetido: true });
  }

  await aplicarEvento(tipo, corpo.data || corpo);
  res.status(200).json({ ok: true });
}));

module.exports = { router: router, webhookRouter: webhookRouter };
