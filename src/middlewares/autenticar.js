"use strict";

/**
 * Portão de autenticação e autorização.
 *
 * A regra central do multi-tenant vive aqui: o `conta_id` usado em TODA
 * consulta vem do token assinado, NUNCA do corpo ou da URL. Aceitar
 * `?conta_id=` do cliente transformaria a API inteira numa porta aberta
 * para ler a conta do vizinho — e é um erro que não deixa rastro, porque
 * a requisição parece perfeitamente normal.
 */

var sessao = require("../lib/sessao");
var db = require("../db");

/** Exige um token válido. Preenche `req.usuario`. */
async function exigirLogin(req, res, proximo) {
  var token = sessao.doPedido(req);
  var conteudo = token ? sessao.verificar(token) : null;

  if (!conteudo) {
    return res.status(401).json({ erro: "Sessão expirada. Entre de novo." });
  }

  // O token é conferido contra o banco a cada requisição, e não aceito
  // pelo que diz. Sem isso, desativar um usuário ou apagar uma conta não
  // teria efeito nenhum até o token vencer — a pessoa demitida hoje
  // continuaria atendendo as conversas até amanhã.
  var usuario = await db.uma(
    `select u.id, u.conta_id, u.nome, u.email, u.papel, u.ativo,
            c.nome as conta_nome, c.plano, c.status as conta_status
       from usuarios u
       join contas c on c.id = u.conta_id
      where u.id = $1`,
    [conteudo.uid]
  );

  if (!usuario || !usuario.ativo) {
    return res.status(401).json({ erro: "Conta sem acesso. Fale com o suporte." });
  }

  req.usuario = usuario;
  req.contaId = usuario.conta_id;
  proximo();
}

/**
 * Exige papel de dono. Operador atende conversas, mas não mexe na
 * conexão do WhatsApp nem no fluxo do bot: quem responde mensagem o dia
 * inteiro não deveria conseguir, sem querer, desconectar o número da
 * empresa.
 */
function exigirDono(req, res, proximo) {
  if (!req.usuario || req.usuario.papel !== "dono") {
    return res.status(403).json({ erro: "Só o dono da conta pode fazer isso." });
  }
  proximo();
}

/**
 * Portão do painel administrativo da plataforma.
 *
 * Separado de exigirLogin de propósito, e não um "papel" a mais dentro
 * dele. Se owner fosse só mais um valor de `papel`, um erro em qualquer
 * checagem de papel — um `!==` trocado por `!=`, uma comparação
 * esquecida — poderia dar acesso administrativo a um cliente. Sendo um
 * middleware próprio, com uma marca própria no token, esse caminho não
 * existe: o token de cliente não tem `owner: true`, e ponto.
 */
function exigirOwner(req, res, proximo) {
  var token = sessao.doPedido(req);
  var conteudo = token ? sessao.verificar(token) : null;

  if (!conteudo || conteudo.owner !== true) {
    return res.status(401).json({ erro: "Acesso administrativo necessário." });
  }

  // O e-mail do token tem que continuar batendo com o do ambiente. É o
  // que faz trocar OWNER_EMAIL invalidar na hora os tokens antigos —
  // sem isso, um token emitido para o dono anterior continuaria valendo
  // até vencer.
  var config = require("../config");
  if (!config.OWNER_EMAIL || conteudo.email !== config.OWNER_EMAIL) {
    return res.status(401).json({ erro: "Sessão administrativa expirada." });
  }

  req.owner = { email: conteudo.email };
  proximo();
}

module.exports = { exigirLogin, exigirDono, exigirOwner };
