"use strict";

/**
 * MONITOR DE SAÚDE
 * ════════════════════════════════════════════════════════════
 * O que faz "24/7" ser verdade em vez de promessa.
 *
 * Com a Cloud API não há socket para cair, e é justamente por isso que o
 * modo de falha é traiçoeiro: quando algo quebra (token expirado,
 * permissão revogada, webhook removido do painel da Meta), NADA acontece.
 * Nenhum erro, nenhuma desconexão visível. O bot simplesmente para de
 * responder, e o cliente descobre pela reclamação de um consumidor —
 * às vezes semanas depois.
 *
 * Este monitor existe para que o sistema descubra primeiro. Ele pergunta
 * à Meta, de tempos em tempos, se cada conexão ainda vale; marca as que
 * não valem; avisa o dono; e volta a marcar como boa a que voltar a
 * funcionar sozinha.
 * ════════════════════════════════════════════════════════════
 */

var db = require("../../db");
var config = require("../../config");
var registro = require("../../lib/registro");
var whatsapp = require("../whatsapp/rotas");

var rodando = false;
var temporizador = null;

/**
 * Uma passada por todas as conexões que deveriam estar de pé.
 *
 * 'pausado' fica de fora de propósito: pausa é decisão do cliente, e
 * revalidar (ou pior, avisar que "caiu") atrapalharia quem escolheu o
 * silêncio. 'desconectado' também: não há o que verificar.
 */
async function verificarTodas() {
  // Trava simples: com o intervalo de 15 minutos isto nunca deveria
  // acontecer, mas uma verificação lenta (Meta instável, muitas contas)
  // pode atravessar a próxima. Duas passadas ao mesmo tempo dobrariam as
  // chamadas à Meta e criariam notificações em duplicata.
  if (rodando) {
    console.warn("[monitor] passada anterior ainda rodando — pulando esta");
    return { pulou: true };
  }
  rodando = true;

  var resumo = { verificadas: 0, ok: 0, quebradas: 0, recuperadas: 0 };

  try {
    var conexoes = await db.varias(
      `select * from conexoes
        where status in ('conectado','erro','aguardando_webhook')
          and token_cifrado is not null
          and phone_number_id is not null`
    );

    for (var conexao of conexoes) {
      resumo.verificadas++;
      var estavaComErro = conexao.status === "erro";

      // Uma conexão por vez, e não Promise.all: em série, um cliente com
      // problema atrasa a verificação dos outros em alguns segundos; em
      // paralelo, 500 contas viram 500 chamadas simultâneas à Meta e o
      // rate limit derruba a verificação de todo mundo de uma vez.
      var r = await whatsapp.revalidar(conexao);

      if (r.ok) {
        resumo.ok++;
        if (estavaComErro) {
          resumo.recuperadas++;
          registro.info(conexao.conta_id, "conexao_recuperada",
            "A conexão voltou a funcionar sozinha.");
          await registro.notificar(conexao.conta_id, "conexao_voltou",
            "Seu WhatsApp voltou ao normal",
            "A conexão foi restabelecida e o bot já está atendendo de novo.");

          // Notificações de queda antigas viram ruído depois que o
          // problema passou: quem abre o painel e vê "seu WhatsApp
          // parou" ao lado de "voltou ao normal" não sabe em qual
          // acreditar.
          await db.consultar(
            "update notificacoes set lida=true where conta_id=$1 and tipo='conexao_caiu' and not lida",
            [conexao.conta_id]
          );
        }
      } else if (r.permanente) {
        resumo.quebradas++;   // revalidar() já marcou o erro e notificou
      }
    }
  } catch (e) {
    console.error("[monitor] falhou:", e.message);
  } finally {
    rodando = false;
  }

  console.log("[monitor]", JSON.stringify(resumo));
  return resumo;
}

/**
 * Faxina do que cresce para sempre.
 *
 * `eventos_recebidos` ganha uma linha por mensagem recebida, de todos os
 * clientes, e nunca é lida depois de alguns segundos. Sem faxina, é a
 * maior tabela do banco em três meses — carregando um índice que só
 * serve para as últimas horas.
 *
 * Sete dias é folga generosa: a Meta desiste de reenviar bem antes disso.
 */
async function limparAntigos() {
  try {
    var eventos = await db.consultar(
      "delete from eventos_recebidos where criado_em < now() - interval '7 days'"
    );

    // Conversa aberta e esquecida trava o índice parcial de "uma aberta
    // por contato" e polui a lista do painel. Encerrar depois de 7 dias
    // parados devolve a lista ao que ela deveria mostrar: o que está
    // acontecendo agora.
    var conversas = await db.consultar(
      `update conversas set status='encerrada'
        where status <> 'encerrada' and ultima_interacao_em < now() - interval '7 days'`
    );

    // Log do cliente com um ano de fundo não ajuda ninguém e ocupa
    // espaço em disco pago.
    var registros = await db.consultar(
      "delete from registros where criado_em < now() - interval '30 days'"
    );

    console.log("[faxina]", JSON.stringify({
      eventos: eventos.rowCount, conversas: conversas.rowCount, registros: registros.rowCount
    }));
  } catch (e) {
    console.error("[faxina] falhou:", e.message);
  }
}

/**
 * Liga o monitor.
 *
 * A primeira passada sai com 30 segundos de atraso, não na hora: subir o
 * servidor e imediatamente disparar N chamadas à Meta atrasaria o
 * atendimento das primeiras requisições reais, que é justamente quando o
 * processo ainda está esquentando.
 */
function iniciar() {
  if (!config.MONITOR_LIGADO) {
    console.log("[monitor] desligado por configuração (MONITOR=off)");
    return null;
  }

  var intervalo = config.MONITOR_MINUTOS * 60 * 1000;

  setTimeout(function () {
    verificarTodas();
    limparAntigos();
  }, 30 * 1000).unref();

  temporizador = setInterval(function () {
    verificarTodas();
    // A faxina roda a cada quatro passadas — de hora em hora com o
    // intervalo padrão. Não precisa da frequência da verificação.
    if (Math.random() < 0.25) limparAntigos();
  }, intervalo);

  console.log("[monitor] ligado, verificando a cada " + config.MONITOR_MINUTOS + " minutos");
  return temporizador;
}

function parar() {
  if (temporizador) clearInterval(temporizador);
  temporizador = null;
}

module.exports = { iniciar, parar, verificarTodas, limparAntigos };
