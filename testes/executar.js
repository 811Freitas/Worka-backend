"use strict";

/**
 * Executor da suíte.
 *
 * A ordem aqui é rígida e importa:
 *   1. sobe a Meta falsa, para saber em que porta ela ficou;
 *   2. define as variáveis de ambiente APONTANDO para ela;
 *   3. só então carrega o sistema.
 *
 * O passo 3 tem que vir depois do 2 porque `config.js` lê o ambiente no
 * momento em que é importado. Carregar o app antes deixaria GRAPH_HOST
 * valendo graph.facebook.com — e a suíte tentaria falar com a Meta de
 * verdade, com um token inventado.
 */

var path = require("path");
var fs = require("fs");
var { criarMetaFalsa } = require("./meta-falsa");
var ajuda = require("./ajuda");

var VERDE = "\x1b[32m", VERMELHO = "\x1b[31m", CINZA = "\x1b[90m",
    AMARELO = "\x1b[33m", NEGRITO = "\x1b[1m", FIM = "\x1b[0m";

async function principal() {
  // ── 1. Meta falsa ────────────────────────────────────
  var meta = criarMetaFalsa();
  var portaMeta = await meta.iniciar();

  // ── 2. Ambiente ──────────────────────────────────────
  process.env.NODE_ENV = "test";
  process.env.DATABASE_URL = process.env.DATABASE_URL_TESTE ||
    "postgres://zapfy:zapfy@127.0.0.1:5432/zapfy_teste";
  process.env.DB_SSL = "false";
  process.env.JWT_SECRET = "segredo-de-teste-com-mais-de-trinta-e-dois-caracteres";
  process.env.CRYPTO_KEY = "chave-de-cifragem-de-teste-1234567890";
  process.env.GRAPH_HOST = "127.0.0.1:" + portaMeta;
  process.env.GRAPH_PROTOCOL = "http";
  process.env.PUBLIC_URL = "http://127.0.0.1:0";
  process.env.MONITOR = "off";     // o teste do monitor o chama na mão

  // Conta administrativa da suíte. O hash é gerado aqui, e não colado
  // como constante, para que a senha em claro e o hash nunca possam
  // divergir — que é como um teste de login passa a falhar por um
  // motivo que não tem nada a ver com o que ele testa.
  process.env.OWNER_EMAIL = "dono@zapfy.test";
  process.env.OWNER_SENHA_HASH =
    require("../node_modules/bcryptjs").hashSync("senha-do-dono-987", 10);

  // ── 3. Sistema ───────────────────────────────────────
  var db = require("../src/db");
  var { migrar } = require("../src/db/migrar");

  console.log(NEGRITO + "\n  zapfy — suíte de testes" + FIM);
  console.log(CINZA + "  banco: " + process.env.DATABASE_URL.replace(/:[^:@/]+@/, ":***@") + FIM);
  console.log(CINZA + "  Meta falsa: 127.0.0.1:" + portaMeta + FIM + "\n");

  // Banco zerado a cada execução. Sem isto, um caso que conta linhas
  // ("3 conversas") passaria na primeira rodada e falharia na segunda —
  // o pior tipo de teste, o que falha por motivo errado.
  await db.consultar("drop schema if exists public cascade");
  await db.consultar("create schema public");
  await migrar(true);

  var limitador = require("../src/middlewares/limitar");
  var app = require("../src/app");
  var servidor = await new Promise(function (resolver) {
    var s = app.listen(0, "127.0.0.1", function () { resolver(s); });
  });
  var porta = servidor.address().port;
  var cliente = ajuda.criarCliente(porta);

  // ── 4. Carrega os arquivos de teste ──────────────────
  var pasta = __dirname;
  var arquivos = fs.readdirSync(pasta)
    .filter(function (f) { return f.endsWith(".teste.js"); })
    .sort();

  for (var arquivo of arquivos) require(path.join(pasta, arquivo));

  // ── 5. Roda ──────────────────────────────────────────
  var contexto = { cliente: cliente, meta: meta, db: db, porta: porta, ajuda: ajuda };

  var passou = 0, falhou = 0;
  var falhas = [];
  var grupoAtual = null;
  var inicioGeral = Date.now();

  for (var caso of ajuda.todos()) {
    if (caso.grupo !== grupoAtual) {
      grupoAtual = caso.grupo;
      console.log(NEGRITO + "  " + grupoAtual + FIM);
    }

    // Cada caso começa com a Meta falsa limpa: um caso que confere "o
    // bot enviou 2 mensagens" não pode contar as do caso anterior.
    meta.limpar();

    // E com o rate limit zerado. Sem isto a suíte se barra sozinha: são
    // dezenas de cadastros vindos todos de 127.0.0.1, contra um limite
    // de 10 por hora que existe justamente para impedir isso. O limite
    // em si é exercitado num caso dedicado, que o desliga do resto.
    limitador.zerar();

    var inicio = Date.now();
    try {
      await caso.fn(contexto);
      var ms = Date.now() - inicio;
      console.log("    " + VERDE + "✓" + FIM + " " + caso.nome +
                  (ms > 300 ? CINZA + " (" + ms + "ms)" + FIM : ""));
      passou++;
    } catch (e) {
      console.log("    " + VERMELHO + "✗" + FIM + " " + caso.nome);
      console.log("      " + VERMELHO + e.message + FIM);
      if (!(e instanceof ajuda.FalhaDeTeste) && e.stack) {
        console.log(CINZA + e.stack.split("\n").slice(1, 4).join("\n") + FIM);
      }
      falhou++;
      falhas.push({ grupo: caso.grupo, nome: caso.nome, erro: e.message });
    }
  }

  // ── 6. Resultado ─────────────────────────────────────
  var total = passou + falhou;
  var segundos = ((Date.now() - inicioGeral) / 1000).toFixed(1);

  console.log("");
  if (falhou === 0) {
    console.log("  " + VERDE + NEGRITO + "✓ " + passou + "/" + total + " passaram" + FIM +
                CINZA + " em " + segundos + "s" + FIM + "\n");
  } else {
    console.log("  " + VERMELHO + NEGRITO + "✗ " + falhou + " de " + total + " falharam" + FIM +
                CINZA + " em " + segundos + "s" + FIM);
    console.log("");
    for (var f of falhas) {
      console.log("    " + AMARELO + f.grupo + " › " + f.nome + FIM);
      console.log("      " + f.erro);
    }
    console.log("");
  }

  servidor.close();
  await meta.parar();
  await db.fechar();

  process.exit(falhou === 0 ? 0 : 1);
}

principal().catch(function (e) {
  console.error(VERMELHO + "\n  a suíte não conseguiu subir: " + e.message + FIM);
  console.error(CINZA + (e.stack || "") + FIM);
  console.error("\n  Confira se o Postgres está de pé e se DATABASE_URL_TESTE aponta para um banco DESCARTÁVEL.");
  console.error("  A suíte APAGA o schema public do banco que ela usar.\n");
  process.exit(1);
});
