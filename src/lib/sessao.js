"use strict";

/**
 * Token de sessão (JWT HS256), escrito à mão sobre `crypto`.
 *
 * Sem biblioteca porque HS256 é três linhas de HMAC, e a superfície de
 * ataque histórica dos pacotes de JWT está justamente no que este
 * arquivo NÃO faz: aceitar `alg` vindo do próprio token (inclusive
 * `alg: none`) e verificar assinatura com comparação de strings.
 *
 * Aqui o algoritmo é fixo no código e a comparação é em tempo constante.
 */

var crypto = require("crypto");
var config = require("../config");

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function assinar(dados) {
  var cabecalho = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  var agora = Math.floor(Date.now() / 1000);
  var corpo = base64url(JSON.stringify(Object.assign({}, dados, {
    iat: agora,
    exp: agora + config.JWT_DURACAO_H * 3600
  })));
  var assinatura = crypto
    .createHmac("sha256", config.JWT_SEGREDO)
    .update(cabecalho + "." + corpo)
    .digest("base64url");

  return cabecalho + "." + corpo + "." + assinatura;
}

/**
 * Verifica e devolve o conteúdo, ou null. Nunca lança: um token
 * malformado é entrada hostil comum, não uma situação excepcional.
 */
function verificar(token) {
  if (typeof token !== "string") return null;

  var partes = token.split(".");
  if (partes.length !== 3) return null;

  try {
    var esperada = crypto
      .createHmac("sha256", config.JWT_SEGREDO)
      .update(partes[0] + "." + partes[1])
      .digest("base64url");

    var a = Buffer.from(esperada);
    var b = Buffer.from(partes[2]);
    // timingSafeEqual EXIGE tamanhos iguais — com tamanhos diferentes
    // ele lança, e sem esta checagem o throw viraria um 500 em vez de um
    // 401. A diferença de tamanho já prova que a assinatura está errada.
    if (a.length !== b.length) return null;
    if (!crypto.timingSafeEqual(a, b)) return null;

    var conteudo = JSON.parse(Buffer.from(partes[1], "base64url").toString("utf8"));
    if (!conteudo.exp || conteudo.exp < Math.floor(Date.now() / 1000)) return null;

    return conteudo;
  } catch (e) {
    return null;
  }
}

/** Extrai o token do cabeçalho `Authorization: Bearer ...`. */
function doPedido(req) {
  var cabecalho = req.headers["authorization"] || "";
  return cabecalho.startsWith("Bearer ") ? cabecalho.slice(7) : null;
}

module.exports = { assinar, verificar, doPedido };
