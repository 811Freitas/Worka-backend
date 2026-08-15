"use strict";

/**
 * O caminho quente: mensagem chega da Meta → motor decide → resposta sai.
 *
 * É o único lugar do sistema onde banco, motor e Cloud API se encontram.
 * Tudo aqui é escrito assumindo que vai rodar milhares de vezes por dia,
 * em paralelo, para clientes diferentes, e que qualquer exceção não
 * tratada some com a mensagem de alguém.
 */

var db = require("../../db");
var cripto = require("../../lib/cripto");
var registro = require("../../lib/registro");
var motor = require("../../motor/motor");
var meta = require("./cloud-api");

/**
 * Devolve o token em claro de uma conexão, ou null.
 *
 * Isolado numa função porque é o ponto exato em que o segredo de um
 * cliente existe em memória. Ele nunca é devolvido por uma rota, nunca
 * entra em log e nunca é guardado numa variável de escopo maior.
 */
function tokenDe(conexao) {
  return cripto.decifrar(conexao.token_cifrado);
}

/**
 * Marca a conexão como quebrada e avisa o dono da conta.
 *
 * Só para erro PERMANENTE (token revogado, permissão faltando). Erro
 * passageiro que marcasse a conexão como caída faria o painel piscar
 * "desconectado" a cada oscilação de rede — e o cliente correria para
 * reconectar um número que nunca saiu do ar.
 */
async function marcarErro(conexao, mensagem) {
  await db.consultar(
    `update conexoes
        set status='erro', ultimo_erro=$1, ultimo_erro_em=now(), atualizado_em=now()
      where id=$2`,
    [String(mensagem).slice(0, 500), conexao.id]
  );

  registro.erro(conexao.conta_id, "conexao_com_erro", mensagem);
  await registro.notificar(
    conexao.conta_id, "conexao_caiu",
    "Seu WhatsApp parou de responder",
    mensagem,
    true   // uma notificação por vez: o monitor roda a cada 15 min
  );
}

/**
 * Envia uma mensagem e grava no histórico.
 *
 * Grava ANTES de ter certeza do resultado, com status 'pendente', e
 * corrige depois. Se o processo morresse entre o envio e o registro, a
 * ordem inversa deixaria uma mensagem entregue ao cliente sem rastro
 * nenhum no painel — e ninguém conseguiria explicar o que o bot disse.
 */
async function enviarEGravar(conexao, conversa, para, texto, opcoes) {
  var linha = await db.uma(
    `insert into mensagens (conta_id, conversa_id, direcao, tipo, texto, status)
     values ($1,$2,'saida',$3,$4,'pendente') returning *`,
    [conexao.conta_id, conversa.id, (opcoes && opcoes.length) ? "interativa" : "texto", texto]
  );

  var token = tokenDe(conexao);
  if (!token) {
    await db.consultar(
      "update mensagens set status='falha', erro=$1 where id=$2",
      ["Credencial ilegível — reconecte o WhatsApp.", linha.id]
    );
    await marcarErro(conexao, "As credenciais guardadas não puderam ser lidas. Reconecte o WhatsApp na tela de Conexão.");
    return { ok: false };
  }

  var r = await meta.enviar(conexao, para, texto, opcoes, token);

  if (r.ok) {
    await db.consultar("update mensagens set status='enviada', wa_id=$1 where id=$2", [r.wa_id, linha.id]);
    await db.consultar("update conexoes set total_enviadas = total_enviadas + 1 where id=$1", [conexao.id]);
    return { ok: true, wa_id: r.wa_id };
  }

  await db.consultar(
    "update mensagens set status='falha', erro=$1 where id=$2",
    [String(r.mensagem).slice(0, 500), linha.id]
  );
  registro.erro(conexao.conta_id, "falha_envio", r.mensagem, { para: para });

  if (r.permanente) await marcarErro(conexao, r.mensagem);
  return { ok: false, mensagem: r.mensagem };
}

/** Contato, criado na primeira mensagem. */
async function acharOuCriarContato(contaId, telefone, nome) {
  var contato = await db.uma(
    `insert into contatos (conta_id, telefone, nome) values ($1,$2,$3)
       on conflict (conta_id, telefone) do update
          -- Só atualiza o nome quando a Meta mandou um: excluded.nome
          -- vem null em boa parte dos webhooks, e sem o coalesce o nome
          -- que já tínhamos seria apagado a cada mensagem.
          set nome = coalesce(excluded.nome, contatos.nome)
     returning *`,
    [contaId, telefone, nome]
  );
  return contato;
}

/** Conversa aberta do contato, ou uma nova. */
async function acharOuCriarConversa(contaId, contato, botId) {
  var aberta = await db.uma(
    "select * from conversas where conta_id=$1 and contato_id=$2 and status <> 'encerrada'",
    [contaId, contato.id]
  );
  if (aberta) return aberta;

  return db.uma(
    `insert into conversas (conta_id, contato_id, bot_id) values ($1,$2,$3) returning *`,
    [contaId, contato.id, botId]
  );
}

/**
 * Processa UMA mensagem recebida.
 *
 * Devolve um resumo para o webhook logar. Nunca lança: uma exceção aqui
 * viraria erro 500 para a Meta, que reenviaria o mesmo evento — e o
 * cliente receberia a resposta em duplicata assim que o defeito fosse
 * corrigido.
 */
async function processarEntrada(conexao, msg) {
  try {
    // ── 1. Idempotência ──────────────────────────────────
    // A Meta reenvia quando não recebe 200 rápido. A chave primária no
    // wamid faz o BANCO recusar a repetição — e é o banco, não uma
    // checagem em JavaScript, porque dois reenvios simultâneos passariam
    // juntos por qualquer `if` que consultasse antes de inserir.
    if (msg.wa_id) {
      var r = await db.consultar(
        "insert into eventos_recebidos (wa_id, conta_id) values ($1,$2) on conflict do nothing",
        [msg.wa_id, conexao.conta_id]
      );
      if (r.rowCount === 0) {
        return { pulou: true, motivo: "evento repetido" };
      }
    }

    var bot = await db.uma("select * from bots where conta_id=$1 and ativo limit 1", [conexao.conta_id]);
    var contato = await acharOuCriarContato(conexao.conta_id, msg.de, msg.nome);
    var conversa = await acharOuCriarConversa(conexao.conta_id, contato, bot && bot.id);
    var agora = new Date();

    // ── 2. Conversa velha demais vira conversa nova ──────
    // Encerrar a antiga (em vez de reaproveitar a linha) é o que faz o
    // histórico do painel ter começo e fim: sem isso, um contato de seis
    // meses viraria uma única conversa infinita, impossível de ler.
    if (motor.expirou(bot, conversa, agora)) {
      await db.consultar("update conversas set status='encerrada' where id=$1", [conversa.id]);
      conversa = await db.uma(
        "insert into conversas (conta_id, contato_id, bot_id) values ($1,$2,$3) returning *",
        [conexao.conta_id, contato.id, bot && bot.id]
      );
    }

    // ── 3. Grava a entrada ───────────────────────────────
    // Antes de qualquer decisão: mesmo que o bot esteja pausado, com
    // erro ou sem fluxo, a mensagem do cliente final precisa aparecer no
    // painel. Um bot mudo é um problema; uma mensagem perdida é outro,
    // muito pior.
    await db.uma(
      `insert into mensagens (conta_id, conversa_id, direcao, tipo, texto, payload, wa_id, status)
       values ($1,$2,'entrada',$3,$4,$5,$6,'entregue') returning id`,
      [conexao.conta_id, conversa.id, msg.tipo || "texto", msg.texto || "",
       JSON.stringify(msg.bruto || {}), msg.wa_id]
    );
    await db.consultar(
      `update conexoes set total_recebidas = total_recebidas + 1 where id=$1`, [conexao.id]
    );
    await db.consultar(
      "update conversas set ultima_interacao_em=$1 where id=$2", [agora, conversa.id]
    );

    // ── 4. Situações em que o bot não responde ───────────
    if (conexao.status === "pausado") {
      registro.info(conexao.conta_id, "bot_pausado",
        "Mensagem recebida com o bot pausado — gravada no histórico, sem resposta automática.");
      return { pulou: true, motivo: "conexão pausada" };
    }

    var conta = await db.uma("select status from contas where id=$1", [conexao.conta_id]);
    if (conta && conta.status !== "ativa") {
      return { pulou: true, motivo: "conta suspensa" };
    }

    // Anexo (áudio, imagem, documento) chega com texto vazio. Deixar
    // seguir levaria ao fallback, o que é aceitável — mas é melhor o
    // painel dizer o que era, para o atendente humano saber que existe
    // um arquivo ali.
    if (!msg.texto && msg.tipo && msg.tipo !== "text") {
      registro.info(conexao.conta_id, "midia_recebida",
        "Recebido um anexo do tipo '" + msg.tipo + "' de " + msg.de, { tipo: msg.tipo });
    }

    // ── 5. Motor ─────────────────────────────────────────
    var blocos = bot
      ? await db.varias("select * from blocos where bot_id=$1 order by ordem", [bot.id])
      : [];

    var resultado = motor.processar({
      bot: bot,
      blocos: blocos,
      conversa: {
        bloco_chave: conversa.bloco_chave,
        variaveis: conversa.variaveis || {},
        status: conversa.status,
        // A expiração já foi resolvida acima com a rotação da conversa;
        // passar null evita que o motor a aplique de novo sobre uma
        // conversa que ele acabaria zerando pela segunda vez.
        ultima_interacao_em: null
      },
      entrada: msg.texto || "",
      agora: agora,
      nomeContato: contato.nome
    });

    // ── 6. Salva o novo estado ───────────────────────────
    // Antes de enviar, não depois: se o envio falhar no meio, o estado
    // já avançou e a pessoa não fica repetindo o mesmo passo para sempre.
    await db.consultar(
      `update conversas
          set bloco_chave=$1, variaveis=$2, status=$3, ultima_interacao_em=$4
        where id=$5`,
      [resultado.conversa.bloco_chave, JSON.stringify(resultado.conversa.variaveis),
       resultado.conversa.status === "encerrada" ? "encerrada" : resultado.conversa.status,
       agora, conversa.id]
    );

    if (resultado.eventos.indexOf("transbordo") !== -1) {
      registro.aviso(conexao.conta_id, "transbordo",
        "Alguém pediu atendimento humano: " + msg.de);
      await registro.notificar(conexao.conta_id, "info", "Cliente pedindo atendimento",
        "O contato " + (contato.nome || msg.de) + " pediu para falar com um atendente.");
    }

    // ── 7. Envia ─────────────────────────────────────────
    var token = tokenDe(conexao);
    if (token && msg.wa_id) meta.marcarLida(conexao, msg.wa_id, token);

    var enviadas = 0;
    for (var resposta of resultado.respostas) {
      if (!resposta.texto) continue;
      var envio = await enviarEGravar(conexao, conversa, msg.de, resposta.texto, resposta.opcoes);
      if (!envio.ok) break;   // credencial quebrada: insistir só gera erro repetido
      enviadas++;
    }

    return { ok: true, respostas: enviadas, eventos: resultado.eventos };

  } catch (e) {
    console.error("[whatsapp] falha ao processar mensagem:", e.message, e.stack);
    registro.erro(conexao.conta_id, "falha_processamento", e.message, { de: msg.de });
    return { erro: e.message };
  }
}

/** Recibos de entrega/leitura, para o painel mostrar o que chegou. */
async function processarStatus(conexao, st) {
  try {
    var novoStatus = { sent: "enviada", delivered: "entregue", read: "lida", failed: "falha" }[st.status];
    if (!novoStatus) return;

    await db.consultar(
      "update mensagens set status=$1, erro=coalesce($2, erro) where wa_id=$3 and conta_id=$4",
      [novoStatus, st.erro, st.wa_id, conexao.conta_id]
    );

    // "failed" no recibo é diferente de erro no envio: a Meta ACEITOU a
    // mensagem e só depois não conseguiu entregar (número inexistente,
    // bloqueio, aparelho sem WhatsApp). É problema do destinatário, não
    // da conexão — por isso registra sem derrubar o status da conexão.
    if (st.status === "failed") {
      registro.aviso(conexao.conta_id, "nao_entregue",
        "A Meta não conseguiu entregar uma mensagem" + (st.erro ? ": " + st.erro : "."));
    }
  } catch (e) {
    console.error("[whatsapp] falha ao aplicar recibo:", e.message);
  }
}

/**
 * Envio manual pelo painel (atendente humano respondendo).
 *
 * Passa pelo mesmo enviarEGravar do bot, então a mensagem do atendente
 * aparece na mesma conversa, na mesma ordem, com o mesmo tratamento de
 * erro. Um caminho separado para o envio humano é como se cria a tela em
 * que "o bot respondeu" e "eu respondi" não conversam entre si.
 */
async function enviarManual(conexao, conversa, telefone, texto) {
  return enviarEGravar(conexao, conversa, telefone, texto, []);
}

module.exports = {
  processarEntrada, processarStatus, enviarManual, enviarEGravar,
  marcarErro, tokenDe, acharOuCriarContato, acharOuCriarConversa
};
