"use strict";

/**
 * Migrador.
 *
 * Roda os arquivos de migrations/ em ordem alfabética e anota cada um
 * numa tabela de controle. Rodar duas vezes não repete nada.
 *
 * Por que não um ORM com migrations automáticas: o esquema deste
 * projeto é a parte que mais precisa ser LIDA por quem chega depois. Os
 * .sql são o documento; um gerador que emite `alter table` a partir de
 * um modelo esconde exatamente a informação que interessa (por que a
 * coluna existe), e é justamente ela que está comentada lá.
 */

var fs = require("fs");
var path = require("path");
var config = require("../config");
var db = require("./index");

var PASTA = path.join(__dirname, "..", "..", "migrations");

async function migrar(silencioso) {
  function falar(msg) { if (!silencioso) console.log(msg); }

  await db.consultar(`
    create table if not exists _migracoes (
      nome        text primary key,
      aplicada_em timestamptz not null default now()
    )
  `);

  var arquivos = fs.readdirSync(PASTA)
    .filter(function (f) { return f.endsWith(".sql"); })
    .sort();

  var aplicadas = new Set(
    (await db.varias("select nome from _migracoes")).map(function (l) { return l.nome; })
  );

  var novas = 0;
  for (var arquivo of arquivos) {
    if (aplicadas.has(arquivo)) continue;

    var sql = fs.readFileSync(path.join(PASTA, arquivo), "utf8");

    // Cada migration é uma transação. Um arquivo que falha na metade
    // deixaria o banco num estado que nem está na versão antiga nem na
    // nova — e a próxima execução tentaria criar de novo o que já
    // existe, falhando para sempre.
    await db.transacao(async function (cliente) {
      await cliente.query(sql);
      await cliente.query("insert into _migracoes (nome) values ($1)", [arquivo]);
    });

    falar("  ✓ " + arquivo);
    novas++;
  }

  falar(novas === 0 ? "  banco já está atualizado" : "  " + novas + " migration(s) aplicada(s)");
  return novas;
}

module.exports = { migrar };

// Executado direto (`npm run migrar`) — e não quando importado pelos
// testes, que chamam migrar() e cuidam do próprio encerramento.
if (require.main === module) {
  config.conferir();
  console.log("[migrar] banco:", String(config.DATABASE_URL).replace(/:[^:@/]+@/, ":***@"));
  migrar()
    .then(function () { return db.fechar(); })
    .then(function () { process.exit(0); })
    .catch(function (e) {
      console.error("[migrar] FALHOU:", e.message);
      process.exit(1);
    });
}
