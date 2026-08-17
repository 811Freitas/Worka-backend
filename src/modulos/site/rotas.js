"use strict";

/**
 * sitemap.xml e robots.txt
 * ════════════════════════════════════════════════════════════
 * Gerados a partir de PUBLIC_URL, não escritos como arquivo estático em
 * public/. Um sitemap com a URL errada é pior do que não ter sitemap —
 * o Google aprende o domínio errado e demora para esquecer. Como
 * PUBLIC_URL já é a mesma variável usada para montar a URL do webhook
 * mostrada ao cliente, os dois nunca podem divergir por alguém ter
 * esquecido de atualizar um arquivo estático depois de trocar de
 * domínio.
 * ════════════════════════════════════════════════════════════
 */

var express = require("express");
var config = require("../../config");

var router = express.Router();

// Só o que existe para ser encontrado por busca: a apresentação, a
// demonstração pública e a entrada (cadastro/login). O painel do
// cliente e o do owner exigem login — indexá-los não ajudaria ninguém
// a achar o Zapfy, só vazaria que a rota /owner existe.
var PAGINAS_PUBLICAS = [
  { caminho: "/site", prioridade: "1.0", frequencia: "weekly" },
  { caminho: "/demo", prioridade: "0.9", frequencia: "weekly" },
  { caminho: "/",     prioridade: "0.8", frequencia: "monthly" }
];

router.get("/sitemap.xml", function (req, res) {
  var base = config.URL_PUBLICA.replace(/\/+$/, "");
  var hoje = new Date().toISOString().slice(0, 10);

  var urls = PAGINAS_PUBLICAS.map(function (p) {
    return "  <url>\n" +
      "    <loc>" + base + p.caminho + "</loc>\n" +
      "    <lastmod>" + hoje + "</lastmod>\n" +
      "    <changefreq>" + p.frequencia + "</changefreq>\n" +
      "    <priority>" + p.prioridade + "</priority>\n" +
      "  </url>";
  }).join("\n");

  var xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    urls + "\n" +
    "</urlset>\n";

  res.type("application/xml").send(xml);
});

router.get("/robots.txt", function (req, res) {
  var base = config.URL_PUBLICA.replace(/\/+$/, "");

  var texto =
    "User-agent: *\n" +
    "Allow: /\n" +
    // /api e /webhook são conversa entre máquinas (a Cloud API da Meta,
    // o gateway de pagamento, o próprio painel via fetch) — indexá-las
    // não faz sentido nenhum e só gasta o orçamento de rastreamento do
    // buscador. /owner não tem link nenhum apontando para ela em
    // lugar nenhum do site (ver o comentário em owner.js sobre isso);
    // aqui é reforço, não a única defesa.
    "Disallow: /api/\n" +
    "Disallow: /webhook\n" +
    "Disallow: /owner\n" +
    "\n" +
    "Sitemap: " + base + "/sitemap.xml\n";

  res.type("text/plain").send(texto);
});

module.exports = router;
