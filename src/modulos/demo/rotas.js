"use strict";

/**
 * DEMONSTRAÇÃO PÚBLICA
 * ════════════════════════════════════════════════════════════
 * O mesmo motor que atende no WhatsApp de verdade, sem exigir cadastro,
 * sem tocar no banco e sem custo de infraestrutura por visita.
 *
 * Só é possível porque o motor é puro (veja src/motor/motor.js): o
 * estado da conversa viaja no corpo da requisição e volta na resposta —
 * o navegador do visitante é quem guarda. Não existe "sessão de demo" no
 * servidor para expirar, vazar entre visitantes ou precisar de faxina.
 *
 * O fluxo é sempre o mesmo (BLOCOS_EXEMPLO, o mesmo que toda conta nova
 * ganha) — não é um bot configurável por quem visita, é uma vitrine do
 * que o cliente pode montar.
 * ════════════════════════════════════════════════════════════
 */

var express = require("express");
var v = require("../../lib/validar");
var motor = require("../../motor/motor");
var { rota } = require("../../middlewares/erro");
var { limitar } = require("../../middlewares/limitar");
var { BLOCOS_EXEMPLO } = require("../bots/exemplo");

var router = express.Router();

// Bot fixo da vitrine: sempre ligado, sem horário comercial (a demo
// precisa responder às 3h da manhã de quem está testando fora do
// expediente de todo mundo, inclusive o do próprio visitante).
var BOT_DEMO = {
  ativo: true,
  atendimento_ativo: false,
  expirar_apos_minutos: 60,
  mensagem_boas_vindas: "Olá! 👋 Eu sou um chatbot de exemplo, do tipo que você monta em minutos aqui no Zapfy. Digite algo ou escolha uma opção.",
  mensagem_fallback: "Não entendi — mas no fluxo real você define exatamente o que o bot diz aqui. Tente uma das opções abaixo.",
  mensagem_fora_horario: ""
};

// Limite generoso o bastante para uma conversa de teste real, apertado
// o bastante para não virar backend gratuito de chat para outra coisa.
router.post("/mensagem", limitar(60, 10 * 60 * 1000, "demo"), rota(async function (req, res) {
  var entrada = typeof req.body.mensagem === "string" ? req.body.mensagem.slice(0, 500) : "";
  var estado = (req.body.conversa && typeof req.body.conversa === "object") ? req.body.conversa : {};

  var resultado = motor.processar({
    bot: BOT_DEMO,
    blocos: BLOCOS_EXEMPLO,
    conversa: {
      bloco_chave: typeof estado.bloco_chave === "string" ? estado.bloco_chave : null,
      variaveis: (estado.variaveis && typeof estado.variaveis === "object") ? estado.variaveis : {},
      status: v.umDe(estado.status, ["bot", "humano", "encerrada"]) || "bot",
      ultima_interacao_em: estado.ultima_interacao_em || null
    },
    entrada: entrada,
    agora: new Date(),
    nomeContato: v.texto(req.body.nome_contato, 60) || "Visitante"
  });

  res.json({
    respostas: resultado.respostas,
    conversa: Object.assign({}, resultado.conversa, { ultima_interacao_em: new Date().toISOString() }),
    eventos: resultado.eventos
  });
}));

module.exports = router;
