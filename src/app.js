"use strict";

/**
 * Montagem do aplicativo HTTP.
 *
 * Separado de servidor.js para que os testes possam subir o app numa
 * porta aleatória, sem monitor, sem banner de inicialização e sem
 * `process.exit` — e ainda assim exercitar exatamente o mesmo
 * roteamento, os mesmos middlewares e o mesmo tratamento de erro que
 * roda em produção. Testar por dentro, chamando as funções, deixaria de
 * fora justamente a camada onde mora o defeito mais caro: a rota que
 * esqueceu de exigir login.
 */

var path = require("path");
var express = require("express");

var config = require("./config");
var { limitar } = require("./middlewares/limitar");
var { naoEncontrado, tratador } = require("./middlewares/erro");

var app = express();

// Atrás de Render/Railway/Cloudflare o IP real vem em X-Forwarded-For.
// Sem isto, todo cliente parece ter o IP do proxy — e o rate limit
// passaria a contar o mundo inteiro num balde só, bloqueando todos
// quando um exagerasse.
app.set("trust proxy", 1);
app.disable("x-powered-by");

// ════════════════════════════════════════
// CABEÇALHOS DE SEGURANÇA
// ════════════════════════════════════════
app.use(function (req, res, proximo) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");

  // CSP restritiva. 'unsafe-inline' em style é o preço de um painel sem
  // etapa de build; script fica SEM ele de propósito — é o que
  // transforma um XSS refletido em nada. O painel não tem um único
  // `<script>` inline por causa desta linha.
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

  if (config.AMBIENTE === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  proximo();
});

// ════════════════════════════════════════
// CORS
// ════════════════════════════════════════
// Só entra em ação quando CORS_ORIGINS está configurado — ou seja,
// quando o painel é servido de outro domínio. No arranjo padrão (painel
// e API no mesmo servidor) não há origem cruzada nenhuma, e liberar
// origens que ninguém usa é superfície de ataque de graça.
app.use(function (req, res, proximo) {
  var origem = req.headers.origin;
  if (origem && config.ORIGENS.indexOf(origem) !== -1) {
    res.setHeader("Access-Control-Allow-Origin", origem);
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Vary", "Origin");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  proximo();
});

// ════════════════════════════════════════
// CORPO DA REQUISIÇÃO
// ════════════════════════════════════════
app.use(express.json({
  // 1MB cobre com folga qualquer payload da Meta e qualquer fluxo
  // salvo pelo editor. Sem teto, uma requisição gigante segura memória
  // do processo — e derruba o atendimento de todos os clientes.
  limit: "1mb",
  // Guarda o corpo CRU, byte a byte, para a verificação da assinatura do
  // webhook. Reserializar o JSON muda espaçamento e ordem das chaves, e
  // o HMAC do texto reserializado nunca confere com o que a Meta
  // assinou.
  verify: function (req, res, buf) {
    if (req.originalUrl.startsWith("/webhook")) {
      req.corpoCru = buf.toString("utf8");
    }
  }
}));

// ════════════════════════════════════════
// SAÚDE DO SERVIÇO
// ════════════════════════════════════════
// Usada pelo monitor de uptime da hospedagem. Não conta nada de
// negócio, não toca no banco: se ela responder, o processo está vivo,
// que é exatamente a pergunta que ela deve responder.
app.get("/saude", function (req, res) {
  res.json({ ok: true, servico: "zapfy", ambiente: config.AMBIENTE, hora: new Date().toISOString() });
});

// ════════════════════════════════════════
// WEBHOOK DA META
// ════════════════════════════════════════
// Montado ANTES do rate limit geral e sem limite próprio: quem chama é a
// Meta, em rajada quando reenvia eventos atrasados. Barrar por IP aqui
// faria o sistema recusar mensagens de clientes reais — que é o oposto
// do que o limite existe para proteger.
var webhook = require("./modulos/whatsapp/webhook");
app.use("/webhook", webhook.router);

// ════════════════════════════════════════
// API
// ════════════════════════════════════════
// Limite geral, folgado: o painel consulta o status da conexão a cada
// poucos segundos com a tela aberta. Cadastro e login têm limites bem
// menores, aplicados nas próprias rotas.
app.use("/api", limitar(600, 60 * 1000, "api"));

// O painel administrativo vem ANTES das rotas de cliente. Não é
// decoração: `/api/owner/login` precisa casar com o roteador de owner,
// e não com o `/login` do cliente — que responderia 401 e deixaria o
// dono da plataforma trancado do lado de fora, sem explicação.
app.use("/api/owner", require("./modulos/owner/rotas"));

app.use("/api", require("./modulos/contas/rotas"));
app.use("/api/painel", require("./modulos/contas/painel"));
app.use("/api/bot", require("./modulos/bots/rotas"));
app.use("/api/whatsapp", require("./modulos/whatsapp/rotas").router);
app.use("/api/conversas", require("./modulos/conversas/rotas"));

// ════════════════════════════════════════
// PAINEL (arquivos estáticos)
// ════════════════════════════════════════
app.use(express.static(path.join(__dirname, "..", "public"), {
  extensions: ["html"],
  // O HTML não pode ser cacheado: uma correção no painel precisa chegar
  // no F5 seguinte, não quando o navegador resolver. CSS e JS levam
  // cache curto — tempo suficiente para a navegação entre telas, curto
  // o bastante para um deploy aparecer no mesmo minuto.
  setHeaders: function (res, caminho) {
    res.setHeader("Cache-Control", caminho.endsWith(".html") ? "no-cache" : "public, max-age=300");
  }
}));

// Rota desconhecida sob /api responde JSON; qualquer outra devolve o
// painel. Sem esta separação, um erro de digitação numa chamada da API
// receberia a página HTML inteira e o front tentaria fazer JSON.parse
// dela — produzindo "Unexpected token <", que não diz nada sobre o
// problema real.
app.use("/api", naoEncontrado);
app.get(/.*/, function (req, res) {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});

app.use(tratador);

module.exports = app;
