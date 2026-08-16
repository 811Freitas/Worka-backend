"use strict";

/**
 * Os estados de conta.js e o que cada um significa para o bot.
 *
 * Um lugar só, porque a pergunta "esta conta pode atender agora?" é
 * feita em pontos diferentes do sistema (o webhook decide se responde,
 * o painel decide o que mostrar), e as duas respostas TÊM que concordar.
 * Se cada lugar checasse `status === 'ativa'` na mão, o dia em que
 * 'trial' foi criado uma dessas checagens ficaria esquecida — e ou o
 * bot de quem está no trial ficaria mudo, ou uma conta inadimplente
 * continuaria sendo atendida de graça.
 */

// trial e ativa atendem; suspensa (ação do owner) e inadimplente
// (trial acabou sem virar plano pago) não.
var ESTADOS_QUE_ATENDEM = new Set(["ativa", "trial"]);

function contaAtende(status) {
  return ESTADOS_QUE_ATENDEM.has(status);
}

/** Dias restantes de trial, arredondado para cima — "acaba amanhã" só
 * vira "0 dias" no minuto em que realmente acabou. */
function diasRestantes(trialFim) {
  if (!trialFim) return null;
  var ms = new Date(trialFim).getTime() - Date.now();
  return Math.max(0, Math.ceil(ms / (1000 * 60 * 60 * 24)));
}

module.exports = { ESTADOS_QUE_ATENDEM, contaAtende, diasRestantes };
