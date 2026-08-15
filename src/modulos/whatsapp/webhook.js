"use strict";

/**
 * O webhook público da Meta.
 *
 * UMA URL para todos os clientes da plataforma. Poderia ser uma por
 * conta (/webhook/:id), e não é, por um motivo prático: a Meta valida a
 * URL uma vez, e um endereço com identificador dentro é mais uma coisa
 * para o cliente copiar errado. Aqui a URL é sempre a mesma, e quem
 * identifica a conta é o conteúdo:
 *
 *   - na verificação (GET), o `hub.verify_token`, que é único por conta;
 *   - nas mensagens (POST), o `phone_number_id` dentro do payload.
 *
 * Esta é a rota mais exposta do sistema: endereço público, sem login,
 * chamada por um terceiro. Tudo aqui parte do princípio de que a
 * requisição pode ser de qualquer um.
 */

var express = require("express");
var db = require("../../db");
var cripto = require("../../lib/cripto");
var registro = require("../../lib/registro");
var meta = require("./cloud-api");
var servico = require("./servico");

var router = express.Router();

/**
 * Trabalho em andamento disparado pelo webhook.
 *
 * O webhook responde 200 ANTES de processar — é o que a Meta exige, e
 * quem demora vira reenvio (mensagem repetida para o cliente final).
 * Mas isso deixaria a suíte de testes sem nada para esperar: ela veria o
 * 200 e consultaria o banco antes de a mensagem ter sido gravada.
 *
 * Este conjunto guarda as promessas em voo para que os testes possam
 * aguardar o fim do trabalho real. Em produção ele só enche e esvazia.
 */
var emAndamento = new Set();

function emSegundoPlano(promessa) {
  var p = promessa.catch(function (e) {
    console.error("[webhook] trabalho em segundo plano falhou:", e.message);
  }).finally(function () {
    emAndamento.delete(p);
  });
  emAndamento.add(p);
  return p;
}

/** Usado pelos testes: espera todo o processamento disparado terminar. */
async function aguardarPendentes() {
  // Laço porque processar uma mensagem pode disparar outro trabalho: a
  // primeira espera resolve o que já existia, e o `while` pega o que
  // nasceu durante ela.
  while (emAndamento.size) {
    await Promise.allSettled(Array.from(emAndamento));
  }
}

// ════════════════════════════════════════
// VERIFICAÇÃO DA URL (GET)
// ════════════════════════════════════════
// A Meta chama uma vez, quando o cliente salva o webhook no painel dela,
// e espera receber de volta o `hub.challenge` em TEXTO PURO. Devolver
// JSON aqui — o padrão do resto da API — faz a verificação falhar com
// uma mensagem genérica do lado da Meta, e é um dos erros mais difíceis
// de diagnosticar de fora.
router.get("/", async function (req, res) {
  var modo = req.query["hub.mode"];
  var token = req.query["hub.verify_token"];
  var desafio = req.query["hub.challenge"];

  if (modo !== "subscribe" || !token) {
    return res.status(400).type("text/plain").send("pedido de verificação inválido");
  }

  var conexao = await db.uma("select * from conexoes where verify_token=$1", [String(token)]);
  if (!conexao) {
    // Log sem o token: quem chamou pode ser qualquer um, e gravar o
    // palpite dele não ajuda em nada.
    console.warn("[webhook] verificação recusada: token não confere");
    return res.status(403).type("text/plain").send("token de verificação incorreto");
  }

  // A URL verificada é o último passo da configuração na Meta. Sair de
  // 'aguardando_webhook' aqui é o que faz a tela de conexão do painel
  // virar "conectado" sozinha, sem o cliente ter que adivinhar se deu certo.
  if (conexao.status === "aguardando_webhook") {
    await db.consultar(
      `update conexoes
          set status='conectado', conectado_em=now(), webhook_verificado_em=now(),
              ultimo_erro=null, atualizado_em=now()
        where id=$1`,
      [conexao.id]
    );
    registro.info(conexao.conta_id, "webhook_verificado", "A Meta validou a URL do webhook. Conexão completa.");
    await registro.notificar(conexao.conta_id, "conexao_voltou", "WhatsApp conectado",
      "A Meta validou seu webhook. O bot já está atendendo.");
  } else {
    await db.consultar("update conexoes set webhook_verificado_em=now() where id=$1", [conexao.id]);
    registro.info(conexao.conta_id, "webhook_verificado", "A Meta revalidou a URL do webhook.");
  }

  res.status(200).type("text/plain").send(String(desafio == null ? "" : desafio));
});

// ════════════════════════════════════════
// EVENTOS (POST)
// ════════════════════════════════════════
router.post("/", async function (req, res) {
  var corpo = req.body || {};

  // A Meta considera qualquer resposta que não seja 2xx como falha e
  // REENVIA o evento — por horas, com espaçamento crescente. Por isso
  // este bloco responde 200 quase sempre, inclusive quando o payload não
  // faz sentido: reenviar um evento que já sabemos que não dá para
  // tratar não conserta nada e só multiplica o problema.
  var mensagens = meta.extrairMensagens(corpo);
  var recibos = meta.extrairStatus(corpo);

  if (!mensagens.length && !recibos.length) {
    return res.status(200).json({ ok: true });
  }

  var phoneId = (mensagens[0] && mensagens[0].phone_number_id) ||
                idDoPayload(corpo);

  if (!phoneId) {
    console.warn("[webhook] evento sem phone_number_id — ignorado");
    return res.status(200).json({ ok: true });
  }

  var conexao = await db.uma("select * from conexoes where phone_number_id=$1", [phoneId]);
  if (!conexao) {
    // Número que não pertence a nenhuma conta daqui. Acontece quando um
    // cliente aponta o webhook para cá e depois apaga a conta, e também
    // quando alguém chuta o endereço. 200 para a Meta parar de reenviar.
    console.warn("[webhook] evento para um número desconhecido");
    return res.status(200).json({ ok: true });
  }

  // ── Assinatura ───────────────────────────────────────
  // Prova que o corpo veio de quem tem o app secret do cliente. Sem ela,
  // qualquer pessoa que descubra a URL pode inventar mensagens e fazer o
  // bot responder — gastando cota da Meta e sujando o histórico.
  var appSecret = cripto.decifrar(conexao.app_secret_cifrado);
  var confere = meta.assinaturaValida(req.corpoCru || "", req.headers["x-hub-signature-256"], appSecret);

  if (confere === false) {
    registro.aviso(conexao.conta_id, "assinatura_invalida",
      "Um evento chegou com assinatura inválida e foi descartado.");
    return res.status(401).json({ erro: "assinatura inválida" });
  }
  if (confere === null) {
    // Sem app secret cadastrado não dá para verificar. O evento é aceito
    // (senão o cliente que ainda não preencheu o campo ficaria sem bot),
    // mas o registro acusa — e a tela de conexão mostra isso como um
    // ponto pendente de segurança, não como algo resolvido.
    registro.aviso(conexao.conta_id, "webhook_sem_assinatura",
      "Evento aceito sem verificação de assinatura: cadastre o App Secret na tela de Conexão.");
  }

  // ── 200 primeiro, trabalho depois ────────────────────
  res.status(200).json({ ok: true });

  emSegundoPlano((async function () {
    for (var msg of mensagens) {
      await servico.processarEntrada(conexao, msg);
    }
    for (var recibo of recibos) {
      await servico.processarStatus(conexao, recibo);
    }
  })());
});

/** phone_number_id de um webhook que só traz recibos (sem mensagens). */
function idDoPayload(corpo) {
  for (var entrada of ((corpo && corpo.entry) || [])) {
    for (var mudanca of (entrada.changes || [])) {
      var id = ((mudanca.value || {}).metadata || {}).phone_number_id;
      if (id) return id;
    }
  }
  return null;
}

module.exports = { router: router, aguardarPendentes: aguardarPendentes };
