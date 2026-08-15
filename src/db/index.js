"use strict";

/**
 * Acesso ao Postgres.
 *
 * Um pool único para o processo inteiro. Abrir conexão por requisição
 * derruba o banco na primeira rajada de webhooks: a Meta manda em lote
 * quando reenvia atrasados, e cada conexão nova custa mais que a
 * consulta que ela vai fazer.
 */

var { Pool } = require("pg");
var config = require("../config");

var pool = new Pool({
  connectionString: config.DATABASE_URL,
  // Supabase/Neon/Render usam certificado de cadeia própria. `rejectUnauthorized:
  // false` aceita a cadeia deles mantendo o transporte cifrado — o que
  // NÃO é o mesmo que desligar TLS.
  ssl: config.DB_SSL ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  // Sem este teto, uma consulta presa segura uma conexão do pool para
  // sempre; dez delas e o sistema inteiro para sem nenhum erro no log.
  connectionTimeoutMillis: 10000
});

pool.on("error", function (err) {
  // Conexão ociosa derrubada pelo servidor do banco. Sem este handler o
  // Node trata como exceção não capturada e MATA o processo — ou seja,
  // uma queda de rede momentânea derrubaria os bots de todos os
  // clientes. O pool se recupera sozinho; só o log importa.
  console.error("[db] erro em conexão ociosa:", err.message);
});

/**
 * Consulta parametrizada. `texto` NUNCA recebe valor concatenado —
 * todo dado entra por $1, $2..., que é o que impede SQL injection.
 */
async function consultar(texto, valores) {
  var inicio = Date.now();
  var r = await pool.query(texto, valores);
  var ms = Date.now() - inicio;
  // Consulta lenta é o defeito que só aparece quando já tem cliente.
  // Melhor o aviso no log desde o primeiro dia.
  if (ms > 1000) {
    console.warn("[db] consulta lenta (" + ms + "ms):", texto.slice(0, 120).replace(/\s+/g, " "));
  }
  return r;
}

/** Primeira linha, ou null. Evita `r.rows[0]` espalhado por todo lado. */
async function uma(texto, valores) {
  var r = await consultar(texto, valores);
  return r.rows[0] || null;
}

/** Todas as linhas. */
async function varias(texto, valores) {
  var r = await consultar(texto, valores);
  return r.rows;
}

/**
 * Transação. Recebe uma função que ganha o cliente dedicado.
 *
 * Existe porque há operações que só fazem sentido inteiras: criar conta
 * + usuário + bot + blocos de exemplo é uma coisa só. Se o bot falhasse
 * no meio, a pessoa ficaria com um login que entra num painel quebrado,
 * sem bot nenhum, e sem poder se cadastrar de novo (e-mail já em uso).
 */
async function transacao(fn) {
  var cliente = await pool.connect();
  try {
    await cliente.query("begin");
    var resultado = await fn(cliente);
    await cliente.query("commit");
    return resultado;
  } catch (e) {
    await cliente.query("rollback").catch(function () {});
    throw e;
  } finally {
    cliente.release();
  }
}

async function fechar() {
  await pool.end();
}

module.exports = { pool, consultar, uma, varias, transacao, fechar };
