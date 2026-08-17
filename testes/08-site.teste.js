"use strict";

/**
 * sitemap.xml e robots.txt — geradas a partir de PUBLIC_URL, não
 * arquivo estático. O teste existe para travar essa promessa: se um
 * dia alguém trocar por um arquivo em public/ sem querer, a suíte
 * denuncia a regressão em vez de deixar um sitemap desatualizado ir
 * para produção.
 */

var { teste, igual, contem } = require("./ajuda");

var G = "SEO (sitemap e robots)";

teste(G, "sitemap.xml lista as páginas públicas com a URL do ambiente", async function (ctx) {
  var r = await ctx.cliente.get("/sitemap.xml");

  igual(r.status, 200);
  contem(r.cabecalhos["content-type"], "xml");
  contem(r.texto, "<urlset");
  // process.env.PUBLIC_URL na suíte é "http://127.0.0.1:0" — se a URL
  // real da Meta falsa vazasse aqui em vez dela, seria sinal de que o
  // sitemap parou de ler PUBLIC_URL.
  contem(r.texto, "http://127.0.0.1:0/site");
  contem(r.texto, "http://127.0.0.1:0/demo");
  contem(r.texto, "<loc>http://127.0.0.1:0/</loc>");
});

teste(G, "robots.txt libera o site e bloqueia api/webhook/owner", async function (ctx) {
  var r = await ctx.cliente.get("/robots.txt");

  igual(r.status, 200);
  contem(r.cabecalhos["content-type"], "text/plain");
  contem(r.texto, "Allow: /");
  contem(r.texto, "Disallow: /api/");
  contem(r.texto, "Disallow: /webhook");
  contem(r.texto, "Disallow: /owner");
  contem(r.texto, "Sitemap: http://127.0.0.1:0/sitemap.xml");
});
