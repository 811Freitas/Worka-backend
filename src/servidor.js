"use strict";

/**
 * Ponto de entrada em produção.
 */

var config = require("./config");

config.conferir();

var app = require("./app");
var db = require("./db");
var monitor = require("./modulos/monitor");
var { migrar } = require("./db/migrar");

async function subir() {
  // Migrar no boot, e não num passo manual de deploy, é uma decisão de
  // operação: a plataforma roda em hospedagem onde "rodar um comando
  // antes do deploy" nem sempre existe. O migrador é idempotente, então
  // subir dez vezes seguidas não repete nada.
  console.log("[boot] conferindo o banco...");
  await migrar(true);

  var servidor = app.listen(config.PORTA, function () {
    console.log("[boot] zapfy no ar na porta " + config.PORTA + " (" + config.AMBIENTE + ")");
    console.log("[boot] webhook: " + config.URL_PUBLICA.replace(/\/+$/, "") + "/webhook");

    if (config.URL_PUBLICA.indexOf("localhost") !== -1 && config.AMBIENTE === "production") {
      // A URL do webhook é copiada desta configuração e colada no painel
      // da Meta pelo cliente. Errada, ele cadastra um endereço que não
      // existe — e a Meta responde com um erro genérico que não menciona
      // em nenhum momento que a culpa é de uma variável de ambiente.
      console.warn("[boot] ATENÇÃO: PUBLIC_URL ainda aponta para localhost. " +
                   "Nenhum cliente vai conseguir validar o webhook.");
    }
  });

  monitor.iniciar();

  // Encerramento limpo. Sem isto, o deploy mata o processo no meio de
  // uma resposta e a Meta reenvia o evento — o cliente final recebe a
  // mesma resposta duas vezes, e ninguém consegue explicar por quê.
  var encerrando = false;
  function encerrar(sinal) {
    if (encerrando) return;
    encerrando = true;
    console.log("[boot] recebido " + sinal + ", encerrando...");

    monitor.parar();
    servidor.close(async function () {
      await db.fechar().catch(function () {});
      process.exit(0);
    });

    // Rede de segurança: uma conexão pendurada seguraria o `close` para
    // sempre, e a hospedagem mataria o processo à força de qualquer jeito.
    setTimeout(function () { process.exit(0); }, 10000).unref();
  }

  process.on("SIGTERM", function () { encerrar("SIGTERM"); });
  process.on("SIGINT", function () { encerrar("SIGINT"); });
}

// Falha inesperada não pode deixar o processo num estado indefinido,
// atendendo requisições pela metade. Melhor morrer alto e deixar a
// hospedagem reerguer — que com a Cloud API não custa conexão nenhuma,
// porque não há sessão de WhatsApp para perder.
process.on("unhandledRejection", function (motivo) {
  console.error("[fatal] promessa rejeitada sem tratamento:", motivo);
});
process.on("uncaughtException", function (e) {
  console.error("[fatal] exceção não capturada:", e.message, e.stack);
  process.exit(1);
});

subir().catch(function (e) {
  console.error("[boot] não consegui subir:", e.message);
  process.exit(1);
});
