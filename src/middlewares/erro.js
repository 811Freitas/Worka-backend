"use strict";

/**
 * Tratamento central de erro.
 *
 * Duas responsabilidades que costumam ser esquecidas juntas:
 * 1. O cliente NUNCA recebe stack trace nem mensagem do Postgres. "duplicate
 *    key value violates unique constraint idx_usuarios_email" entrega o nome
 *    das tabelas, dos índices e a estrutura do banco a quem provocou o erro.
 * 2. O servidor SEMPRE registra o erro inteiro, com a rota, para que a falha
 *    exista em algum lugar mesmo quando a resposta é genérica.
 */

/**
 * Embrulha uma rota async.
 *
 * Express 5 já encaminha promessa rejeitada para o handler de erro, mas o
 * embrulho continua valendo: torna a intenção explícita na leitura de cada
 * rota e sobrevive a uma eventual volta ao Express 4, onde a ausência dele
 * faz a requisição pendurar para sempre, sem resposta e sem erro.
 */
function rota(fn) {
  return function (req, res, proximo) {
    Promise.resolve(fn(req, res, proximo)).catch(proximo);
  };
}

/** Erro com status HTTP intencional — o que a rota QUER dizer ao cliente. */
class ErroHttp extends Error {
  constructor(status, mensagem) {
    super(mensagem);
    this.status = status;
    this.esperado = true;
  }
}

function naoEncontrado(req, res) {
  res.status(404).json({ erro: "Rota não encontrada." });
}

function tratador(err, req, res, proximo) {
  if (res.headersSent) return proximo(err);

  var status = err.status || err.statusCode || 500;

  // Erro que a própria rota levantou de propósito ("e-mail já cadastrado"):
  // a mensagem foi escrita para o cliente ler, então vai inteira.
  if (err.esperado && status < 500) {
    return res.status(status).json({ erro: err.message });
  }

  // Corpo malformado — o body-parser do Express levanta isto quando o JSON
  // não fecha. É erro do cliente, não do servidor, e devolver 500 aqui
  // mandaria investigar o lugar errado.
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ erro: "Corpo da requisição não é um JSON válido." });
  }
  if (err.type === "entity.too.large") {
    return res.status(413).json({ erro: "Requisição grande demais." });
  }

  console.error("[erro]", req.method, req.originalUrl, "-", err.message);
  if (err.stack) console.error(err.stack.split("\n").slice(0, 5).join("\n"));

  res.status(status >= 500 ? 500 : status).json({
    erro: status >= 500 ? "Erro interno. Já registramos o problema." : err.message
  });
}

module.exports = { rota, ErroHttp, naoEncontrado, tratador };
