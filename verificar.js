#!/usr/bin/env node
/**
 * Verificação do projeto — rode antes de qualquer commit:
 *
 *     node verificar.js
 *
 * POR QUE ISTO EXISTE
 *
 * `node --check` só valida SINTAXE. Ele passa feliz por um arquivo que
 * chama uma função apagada, e o erro só aparece quando alguém clica no
 * botão — em produção, quase sempre no caminho da venda.
 *
 * Aconteceu duas vezes no mesmo dia, as duas por recorte em bloco:
 *
 *  - remover as rotas do Duttyfy levou junto o portão de autenticação
 *    (`var authPayload = requireAuth(req)`), o que faria TODA rota
 *    autenticada responder 500;
 *  - remover a tela de PIX levou junto `mostrarErro()`, que ficou
 *    chamada em 10 lugares e definida em nenhum — o botão de pagamento
 *    parava de responder sem nada aparecer para o cliente.
 *
 * Nenhuma das duas passa por aqui.
 *
 * COMO A CHECAGEM DE FUNÇÕES FUNCIONA
 *
 * A primeira versão procurava `nome(` com expressão regular e deu 74
 * falsos positivos: acusava "página (" de comentário em português e
 * "rgba(" de CSS em string. Tentar limpar comentários e literais na
 * unha tropeça em literal de regex com aspas — é o tipo de coisa que
 * só um parser de verdade resolve.
 *
 * Então a página é CARREGADA num navegador e a pergunta vira
 * `typeof window.X === "function"`. O navegador é o parser, e a
 * resposta é a mesma que o cliente teria. Mais lento, e certo.
 */
var fs   = require("fs");
var vm   = require("vm");
var path = require("path");
var http = require("http");

var RAIZ = __dirname;
var problemas = [];
var avisos = [];

var CHROMIUM = process.env.CHROMIUM_PATH || "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";

// Funções que precisam existir mesmo que nenhum atributo onclick as
// cite — são chamadas de dentro do próprio JavaScript, que é justamente
// o caso que passou despercebido antes.
var CRITICAS = {
  "index.html": [
    "mostrarErro", "abrirCheckout", "fecharCheckout", "resetModal", "mostrarStep",
    "escolherPlano", "aplicarPlanoNaTela", "carregarPlanos", "continuarParaOferta",
    "irParaPagamento", "tratarRetornoDaStripe", "abrirFunil", "fecharFunil",
    "montarSegmentosDoFunil", "montarPlanosDoFunil", "buscarRamos", "botaoOcupado"
  ],
  "app/index.html": [
    "fazerLogin", "botaoOcupado", "escreverComIcones", "abrirGestaoAssinatura",
    "carregarSeguranca", "rodarTestes", "carregarErros", "ownerTab"
  ]
};

function checarSintaxe(codigo, rotulo) {
  try { new vm.Script(codigo); return true; }
  catch (e) { problemas.push(rotulo + " — sintaxe: " + e.message); return false; }
}

// ── 1. Sintaxe de todo JavaScript do projeto ────────────────────────
["index.js", "sw.js", "verificar.js"].forEach(function (rel) {
  var arq = path.join(RAIZ, rel);
  if (fs.existsSync(arq)) checarSintaxe(fs.readFileSync(arq, "utf8"), rel);
});

var paginas = ["index.html", "app/index.html"];
paginas.forEach(function (rel) {
  var html = fs.readFileSync(path.join(RAIZ, rel), "utf8");
  var re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi, m, i = 0;
  while ((m = re.exec(html))) { i++; checarSintaxe(m[1], rel + " script #" + i); }
});

// ── 2. O portão de autenticação do backend ──────────────────────────
var backend = fs.readFileSync(path.join(RAIZ, "index.js"), "utf8");
if (!/var\s+authPayload\s*=\s*requireAuth\(req\)/.test(backend)) {
  problemas.push("index.js — o portão de autenticação (`var authPayload = requireAuth(req)`) sumiu do handler. " +
                 "Sem ele, toda rota autenticada responde 500.");
}

// ── 3. Versão do cache do service worker ────────────────────────────
var sw = fs.readFileSync(path.join(RAIZ, "sw.js"), "utf8");
var versao = /var CACHE = ['"]workap-v(\d+)['"]/.exec(sw);
if (!versao) problemas.push("sw.js — não achei a versão do cache");
else avisos.push("cache do service worker: v" + versao[1] +
                 " — suba o número se index.html, app/index.html ou sw.js mudaram");

// ── 4. As páginas abrem sem erro e as funções existem ───────────────
function checarNoNavegador() {
  var chromium;
  try { chromium = require("playwright").chromium; }
  catch (e) {
    avisos.push("playwright não instalado — pulei a checagem de funções no navegador");
    return Promise.resolve();
  }
  if (!fs.existsSync(CHROMIUM)) {
    avisos.push("Chromium não encontrado em " + CHROMIUM + " — pulei a checagem no navegador");
    return Promise.resolve();
  }

  var TIPOS = { ".html":"text/html", ".js":"text/javascript", ".css":"text/css",
                ".json":"application/json", ".svg":"image/svg+xml", ".png":"image/png" };

  var servidor = http.createServer(function (req, res) {
    var p = decodeURIComponent(req.url.split("?")[0]);
    // Rotas de API respondem vazio: o alvo aqui é o JavaScript da
    // página carregar, não o backend funcionar.
    if (/^\/(ramos|planos|me|empresa)/.test(p)) {
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end('{"ramos":[],"planos":[]}');
    }
    if (p.endsWith("/")) p += "index.html";
    var arq = path.join(RAIZ, p);
    if (!fs.existsSync(arq) || fs.statSync(arq).isDirectory()) { res.writeHead(404); return res.end("404"); }
    var corpo = fs.readFileSync(arq);
    if (arq.endsWith(".html")) {
      corpo = corpo.toString()
        .replace(/(const|var) API_BASE\s*=\s*['"][^'"]*['"]/, "$1 API_BASE = 'http://localhost:8791'")
        // O service worker guardaria a página em cache entre execuções
        // e mascararia justamente o que se quer medir.
        .replace(/navigator\.serviceWorker\.register/g, "(function(){return Promise.resolve()})");
    }
    res.writeHead(200, { "Content-Type": TIPOS[path.extname(arq)] || "text/plain" });
    res.end(corpo);
  });

  return new Promise(function (resolve) {
    servidor.listen(8791, async function () {
      var navegador = await chromium.launch({
        executablePath: CHROMIUM,
        args: ["--no-proxy-server", "--disable-dev-shm-usage"]
      });

      for (var rel of paginas) {
        var pagina = await navegador.newPage();
        var errosJs = [];
        pagina.on("pageerror", function (e) { errosJs.push(e.message); });
        pagina.on("console", function (msg) {
          // Falha de fonte e de CDN não interessa: a rede daqui não é a
          // do cliente. Erro de JavaScript, sim.
          if (msg.type() === "error" && !/net::|Failed to load resource/.test(msg.text())) {
            errosJs.push("console: " + msg.text().slice(0, 160));
          }
        });

        var url = "http://localhost:8791/" + (rel === "index.html" ? "" : "app/");
        await pagina.goto(url, { waitUntil: "domcontentloaded" });
        await pagina.waitForTimeout(900);

        errosJs.forEach(function (e) { problemas.push(rel + " — erro ao carregar: " + e); });

        // Nomes citados em atributos on*= mais a lista curada.
        var html = fs.readFileSync(path.join(RAIZ, rel), "utf8");
        var nomes = new Set(CRITICAS[rel] || []);
        var PALAVRAS = new Set(["if","for","while","switch","return","typeof","new","function","catch","await"]);
        var reAttr = /\son[a-z]+\s*=\s*"([^"]*)"/gi, a;
        while ((a = reAttr.exec(html))) {
          var reCall = /(^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(/g, c;
          while ((c = reCall.exec(a[1]))) if (!PALAVRAS.has(c[2])) nomes.add(c[2]);
        }

        var lista = Array.from(nomes);
        var faltando = await pagina.evaluate(
          "JSON.stringify(" + JSON.stringify(lista) +
          ".filter(function(n){ return typeof window[n] !== 'function'; }))"
        );
        JSON.parse(faltando).forEach(function (n) {
          problemas.push(rel + " — `" + n + "()` é chamada mas não existe no navegador");
        });

        await pagina.close();
      }

      await navegador.close();
      servidor.close();
      resolve();
    });
  });
}

checarNoNavegador().then(function () {
  avisos.forEach(function (a) { console.log("  · " + a); });
  if (problemas.length === 0) {
    console.log("\n✓ Nenhum problema encontrado.");
    process.exit(0);
  }
  console.log("\n✗ " + problemas.length + " problema(s):\n");
  problemas.forEach(function (p) { console.log("  - " + p); });
  process.exit(1);
});
