"use strict";

/**
 * Log operacional que o CLIENTE lê, e avisos que chegam até ele.
 *
 * Diferente do console do servidor: aqui a linguagem é a de quem paga
 * pela plataforma ("mensagem enviada para 5511...", "a Meta recusou o
 * token"), e o dado é filtrado por conta. Sem isto, "meu bot não
 * respondeu" só poderia ser investigado por quem tem acesso ao servidor
 * — ou seja, nunca pelo cliente.
 */

var db = require("../db");

/**
 * Campos cujo nome sugere segredo nunca vão para o banco, nem dentro do
 * `detalhe`. A lista é por NOME e não por valor de propósito: quem grava
 * um log não deveria ter que lembrar de tirar o token — o registro tira.
 */
var CAMPOS_SECRETOS = ["token", "senha", "password", "secret", "hash", "authorization", "apikey", "api_key"];

function limpar(objeto) {
  if (!objeto || typeof objeto !== "object") return null;
  var saida = {};
  for (var [chave, valor] of Object.entries(objeto)) {
    var suspeito = CAMPOS_SECRETOS.some(function (c) { return chave.toLowerCase().includes(c); });
    if (suspeito) {
      saida[chave] = "[oculto]";
    } else if (typeof valor === "string") {
      saida[chave] = valor.slice(0, 500);
    } else if (valor && typeof valor === "object") {
      saida[chave] = limpar(valor);
    } else {
      saida[chave] = valor;
    }
  }
  return saida;
}

/**
 * Grava um registro. Fire-and-forget de propósito: gravar log nunca pode
 * atrasar — muito menos derrubar — a resposta a um cliente. Se o banco
 * cair, o log some e o resto continua de pé, que é a prioridade certa.
 */
function anotar(contaId, nivel, evento, mensagem, detalhe) {
  if (!contaId) return Promise.resolve();

  return db.consultar(
    "insert into registros (conta_id, nivel, evento, mensagem, detalhe) values ($1,$2,$3,$4,$5)",
    [contaId, nivel, String(evento).slice(0, 60), String(mensagem || "").slice(0, 1000), limpar(detalhe)]
  ).catch(function (e) {
    console.error("[registro] não consegui gravar:", e.message);
  });
}

var info = function (c, ev, msg, det) { return anotar(c, "info", ev, msg, det); };
var aviso = function (c, ev, msg, det) { return anotar(c, "aviso", ev, msg, det); };
var erro = function (c, ev, msg, det) { return anotar(c, "erro", ev, msg, det); };

/**
 * Cria uma notificação para o dono da conta.
 *
 * `chaveUnica` evita a enxurrada: o monitor roda a cada 15 minutos e, com
 * um token expirado, criaria 96 notificações idênticas por dia. Com ela,
 * só cria uma enquanto a anterior do mesmo tipo não foi lida — o aviso
 * continua visível sem virar spam que ninguém lê.
 */
async function notificar(contaId, tipo, titulo, mensagem, chaveUnica) {
  if (!contaId) return null;

  try {
    if (chaveUnica) {
      var jaTem = await db.uma(
        "select id from notificacoes where conta_id=$1 and tipo=$2 and not lida limit 1",
        [contaId, tipo]
      );
      if (jaTem) return jaTem;
    }
    return await db.uma(
      "insert into notificacoes (conta_id, tipo, titulo, mensagem) values ($1,$2,$3,$4) returning *",
      [contaId, tipo, String(titulo).slice(0, 200), String(mensagem || "").slice(0, 1000)]
    );
  } catch (e) {
    console.error("[notificar] falhou:", e.message);
    return null;
  }
}

module.exports = { anotar, info, aviso, erro, notificar, limpar };
