"use strict";

/**
 * Histórico de conversas e atendimento humano.
 */

var express = require("express");
var db = require("../../db");
var v = require("../../lib/validar");
var registro = require("../../lib/registro");
var { rota, ErroHttp } = require("../../middlewares/erro");
var { exigirLogin } = require("../../middlewares/autenticar");

var router = express.Router();
router.use(exigirLogin);

/**
 * Confere que a conversa é DESTA conta antes de qualquer coisa.
 *
 * Todo acesso por id passa por aqui. O uuid da URL nunca é autorização
 * por si só: quem tem um id de outra conta receberia os dados dela se a
 * consulta filtrasse só por id — e a requisição pareceria absolutamente
 * normal no log.
 */
async function minhaConversa(contaId, idBruto) {
  var id = v.uuid(idBruto);
  if (!id) throw new ErroHttp(400, "Conversa inválida.");

  var conversa = await db.uma(
    `select c.*, ct.telefone, ct.nome as contato_nome
       from conversas c join contatos ct on ct.id = c.contato_id
      where c.id=$1 and c.conta_id=$2`,
    [id, contaId]
  );
  if (!conversa) throw new ErroHttp(404, "Conversa não encontrada.");
  return conversa;
}

// ════════════════════════════════════════
// LISTA
// ════════════════════════════════════════
router.get("/", rota(async function (req, res) {
  var limite = v.inteiro(req.query.limite, 1, 100, 50);
  var status = v.umDe(req.query.status, ["bot", "humano", "encerrada"]);
  var busca = req.query.busca ? String(req.query.busca).slice(0, 60) : null;

  var condicoes = ["c.conta_id = $1"];
  var params = [req.contaId];

  if (status) { params.push(status); condicoes.push("c.status = $" + params.length); }
  if (busca) {
    params.push("%" + busca + "%");
    condicoes.push("(ct.telefone ilike $" + params.length + " or ct.nome ilike $" + params.length + ")");
  }

  // A última mensagem vem por LATERAL em vez de uma segunda consulta por
  // linha: com 50 conversas na tela, o caminho ingênuo faria 51 idas ao
  // banco para montar uma lista.
  var lista = await db.varias(
    `select c.id, c.status, c.bloco_chave, c.iniciada_em, c.ultima_interacao_em,
            ct.telefone, ct.nome as contato_nome,
            u.texto as ultima_mensagem, u.direcao as ultima_direcao,
            (select count(*)::int from mensagens m where m.conversa_id = c.id) as total_mensagens
       from conversas c
       join contatos ct on ct.id = c.contato_id
       left join lateral (
         select texto, direcao from mensagens m
          where m.conversa_id = c.id order by criado_em desc limit 1
       ) u on true
      where ${condicoes.join(" and ")}
      order by c.ultima_interacao_em desc
      limit ${limite}`,
    params
  );

  res.json(lista);
}));

// ════════════════════════════════════════
// UMA CONVERSA, COM AS MENSAGENS
// ════════════════════════════════════════
router.get("/:id", rota(async function (req, res) {
  var conversa = await minhaConversa(req.contaId, req.params.id);

  var mensagens = await db.varias(
    `select id, direcao, tipo, texto, status, erro, wa_id, criado_em
       from mensagens where conversa_id=$1 and conta_id=$2
      order by criado_em limit 500`,
    [conversa.id, req.contaId]
  );

  res.json({ conversa: conversa, mensagens: mensagens });
}));

// ════════════════════════════════════════
// ASSUMIR / DEVOLVER / ENCERRAR
// ════════════════════════════════════════
router.post("/:id/assumir", rota(async function (req, res) {
  var conversa = await minhaConversa(req.contaId, req.params.id);

  var salva = await db.uma(
    "update conversas set status='humano' where id=$1 and conta_id=$2 returning *",
    [conversa.id, req.contaId]
  );
  registro.info(req.contaId, "conversa_assumida",
    req.usuario.nome + " assumiu a conversa com " + conversa.telefone);
  res.json(salva);
}));

router.post("/:id/devolver", rota(async function (req, res) {
  var conversa = await minhaConversa(req.contaId, req.params.id);

  // O `bloco_chave` é preservado: a pessoa volta ao ponto do fluxo em
  // que estava, não ao começo. Zerar aqui faria quem já respondeu três
  // perguntas ouvir o menu principal de novo, como se a conversa nunca
  // tivesse acontecido.
  var salva = await db.uma(
    "update conversas set status='bot' where id=$1 and conta_id=$2 returning *",
    [conversa.id, req.contaId]
  );
  registro.info(req.contaId, "conversa_devolvida",
    "Conversa com " + conversa.telefone + " devolvida ao bot");
  res.json(salva);
}));

router.post("/:id/encerrar", rota(async function (req, res) {
  var conversa = await minhaConversa(req.contaId, req.params.id);

  var salva = await db.uma(
    "update conversas set status='encerrada' where id=$1 and conta_id=$2 returning *",
    [conversa.id, req.contaId]
  );
  res.json(salva);
}));

module.exports = router;
