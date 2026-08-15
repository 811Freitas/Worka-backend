"use strict";

/**
 * O construtor de chatbot: configuração do bot, blocos do fluxo e o
 * simulador.
 *
 * Nada aqui toca no WhatsApp. É de propósito — é o que faz "editar o
 * chatbot sem precisar reconectar o WhatsApp" ser verdade por
 * construção, e não por cuidado: as duas coisas nem se conhecem. O motor
 * relê os blocos a cada mensagem, então uma edição vale já na mensagem
 * seguinte, sem reinício de nada.
 */

var express = require("express");
var db = require("../../db");
var v = require("../../lib/validar");
var registro = require("../../lib/registro");
var motor = require("../../motor/motor");
var { rota, ErroHttp } = require("../../middlewares/erro");
var { exigirLogin, exigirDono } = require("../../middlewares/autenticar");
var { BLOCOS_EXEMPLO, criarExemplo } = require("./exemplo");

var router = express.Router();
router.use(exigirLogin);

var TIPOS = ["menu", "texto", "pergunta", "humano", "encerrar"];

/**
 * Busca o bot ativo da conta. Cria um se não houver — a conta sempre tem
 * um bot, e uma tela que responde 404 porque a linha sumiu é um beco sem
 * saída para quem não sabe o que é uma linha.
 */
async function botDaConta(contaId) {
  var bot = await db.uma("select * from bots where conta_id=$1 and ativo limit 1", [contaId]);
  if (bot) return bot;

  return db.transacao(async function (cliente) {
    var novo = (await cliente.query(
      "insert into bots (conta_id) values ($1) returning *", [contaId]
    )).rows[0];
    await criarExemplo(cliente, contaId, novo.id);
    return novo;
  });
}

// ════════════════════════════════════════
// CONFIGURAÇÃO DO BOT
// ════════════════════════════════════════
router.get("/", rota(async function (req, res) {
  res.json(await botDaConta(req.contaId));
}));

router.put("/", exigirDono, rota(async function (req, res) {
  var bot = await botDaConta(req.contaId);
  var c = req.body || {};

  // Cada campo é opcional: o painel salva a tela inteira, mas o
  // simulador e futuras telas mandam só o que mudou. `undefined` mantém
  // o valor atual; string vazia é uma escolha legítima do cliente para
  // "não mande nada nessa situação".
  function ou(novo, atual, max) {
    if (novo === undefined) return atual;
    var limpo = v.textoOpcional(novo, max || v.LIMITES.mensagem);
    return limpo === null ? atual : limpo;
  }

  var atendimentoDias = c.atendimento_dias === undefined
    ? bot.atendimento_dias
    : v.dias(c.atendimento_dias);
  if (atendimentoDias === null) throw new ErroHttp(400, "Dias de atendimento inválidos.");

  var atualizado = await db.uma(
    `update bots set
       nome                  = $1,
       ativo                 = $2,
       mensagem_boas_vindas  = $3,
       mensagem_fallback     = $4,
       mensagem_fora_horario = $5,
       mensagem_transbordo   = $6,
       atendimento_ativo     = $7,
       atendimento_inicio    = $8,
       atendimento_fim       = $9,
       atendimento_dias      = $10,
       fuso                  = $11,
       expirar_apos_minutos  = $12,
       atualizado_em         = now()
     where id = $13 and conta_id = $14
     returning *`,
    [
      v.texto(c.nome, v.LIMITES.nome) || bot.nome,
      v.booleano(c.ativo, bot.ativo),
      ou(c.mensagem_boas_vindas, bot.mensagem_boas_vindas),
      ou(c.mensagem_fallback, bot.mensagem_fallback),
      ou(c.mensagem_fora_horario, bot.mensagem_fora_horario),
      ou(c.mensagem_transbordo, bot.mensagem_transbordo),
      v.booleano(c.atendimento_ativo, bot.atendimento_ativo),
      v.horario(c.atendimento_inicio) || bot.atendimento_inicio,
      v.horario(c.atendimento_fim) || bot.atendimento_fim,
      atendimentoDias,
      v.texto(c.fuso, 60) || bot.fuso,
      // Teto de 7 dias: acima disso "expirar" deixa de proteger de
      // qualquer coisa, e o cliente que quer conversa eterna usa 0.
      v.inteiro(c.expirar_apos_minutos, 0, 10080, bot.expirar_apos_minutos),
      // conta_id no WHERE, e não só o id: sem ele, quem descobrisse o
      // uuid do bot de outra conta poderia reescrever a configuração
      // dela. O id sozinho nunca é autorização.
      bot.id, req.contaId
    ]
  );

  registro.info(req.contaId, "bot_atualizado", "Configuração do bot salva");
  res.json(atualizado);
}));

// ════════════════════════════════════════
// BLOCOS DO FLUXO
// ════════════════════════════════════════
router.get("/blocos", rota(async function (req, res) {
  var bot = await botDaConta(req.contaId);
  res.json(await db.varias(
    "select * from blocos where bot_id=$1 and conta_id=$2 order by ordem, criado_em",
    [bot.id, req.contaId]
  ));
}));

/** Campos comuns a criar e editar, já validados. */
function lerBloco(corpo, atual) {
  var tipo = v.umDe(corpo.tipo, TIPOS) || (atual ? atual.tipo : "menu");

  var opcoes = corpo.opcoes === undefined
    ? (atual ? atual.opcoes : [])
    : v.opcoes(corpo.opcoes);
  if (opcoes === null) {
    throw new ErroHttp(400, "Opções inválidas. Máximo de 10, cada uma com um rótulo de até 24 caracteres.");
  }

  var gatilhos = corpo.gatilhos === undefined
    ? (atual ? atual.gatilhos : [])
    : v.gatilhos(corpo.gatilhos);
  if (gatilhos === null) throw new ErroHttp(400, "Palavras-chave inválidas.");

  var mensagem = corpo.mensagem === undefined
    ? (atual ? atual.mensagem : "")
    : v.textoOpcional(corpo.mensagem, v.LIMITES.mensagem);

  // Um bloco que espera resposta sem dizer nada deixa a pessoa olhando
  // para o nada. Os que só transitam ('texto') podem ser mudos.
  if (!mensagem && (tipo === "menu" || tipo === "pergunta")) {
    throw new ErroHttp(400, "Escreva a mensagem que o bot vai enviar neste bloco.");
  }
  if (tipo === "pergunta" && !v.chave(corpo.salvar_em || (atual && atual.salvar_em))) {
    throw new ErroHttp(400, "Um bloco de pergunta precisa dizer em qual variável guardar a resposta.");
  }

  return {
    titulo: v.texto(corpo.titulo, v.LIMITES.titulo) || (atual ? atual.titulo : "Sem título"),
    tipo: tipo,
    mensagem: mensagem,
    gatilhos: gatilhos,
    opcoes: opcoes,
    proxima_chave: corpo.proxima_chave === undefined
      ? (atual ? atual.proxima_chave : null)
      : (corpo.proxima_chave ? v.chave(corpo.proxima_chave) : null),
    salvar_em: corpo.salvar_em === undefined
      ? (atual ? atual.salvar_em : null)
      : (corpo.salvar_em ? v.chave(corpo.salvar_em) : null),
    ordem: v.inteiro(corpo.ordem, 0, 9999, atual ? atual.ordem : 0)
  };
}

router.post("/blocos", exigirDono, rota(async function (req, res) {
  var bot = await botDaConta(req.contaId);
  var chave = v.chave(req.body.chave);
  if (!chave) throw new ErroHttp(400, "Dê um identificador ao bloco (ex.: 'precos').");

  var dados = lerBloco(req.body, null);
  var querSerInicial = v.booleano(req.body.inicial, false);

  var criado = await db.transacao(async function (cliente) {
    var repetida = (await cliente.query(
      "select id from blocos where bot_id=$1 and chave=$2", [bot.id, chave]
    )).rows[0];
    if (repetida) throw new ErroHttp(409, "Já existe um bloco com o identificador '" + chave + "'.");

    // Só pode haver um bloco inicial. Desmarcar o antigo ANTES de gravar
    // o novo, e dentro da mesma transação, é o que impede o índice
    // parcial de recusar a inserção no meio do caminho.
    if (querSerInicial) {
      await cliente.query("update blocos set inicial=false where bot_id=$1 and inicial", [bot.id]);
    }

    return (await cliente.query(
      `insert into blocos
         (conta_id, bot_id, chave, titulo, tipo, mensagem, gatilhos, inicial, opcoes, proxima_chave, salvar_em, ordem)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) returning *`,
      [req.contaId, bot.id, chave, dados.titulo, dados.tipo, dados.mensagem,
       dados.gatilhos, querSerInicial, JSON.stringify(dados.opcoes),
       dados.proxima_chave, dados.salvar_em, dados.ordem]
    )).rows[0];
  });

  registro.info(req.contaId, "bloco_criado", "Bloco '" + chave + "' criado");
  res.status(201).json(criado);
}));

router.put("/blocos/:id", exigirDono, rota(async function (req, res) {
  var id = v.uuid(req.params.id);
  if (!id) throw new ErroHttp(400, "Bloco inválido.");

  var atual = await db.uma("select * from blocos where id=$1 and conta_id=$2", [id, req.contaId]);
  if (!atual) throw new ErroHttp(404, "Bloco não encontrado.");

  var dados = lerBloco(req.body, atual);
  var querSerInicial = v.booleano(req.body.inicial, atual.inicial);
  var novaChave = req.body.chave === undefined ? atual.chave : v.chave(req.body.chave);
  if (!novaChave) throw new ErroHttp(400, "Identificador do bloco inválido.");

  var salvo = await db.transacao(async function (cliente) {
    if (novaChave !== atual.chave) {
      var conflito = (await cliente.query(
        "select id from blocos where bot_id=$1 and chave=$2 and id<>$3",
        [atual.bot_id, novaChave, id]
      )).rows[0];
      if (conflito) throw new ErroHttp(409, "Já existe um bloco com o identificador '" + novaChave + "'.");

      // Renomear a chave quebraria todos os apontamentos para este bloco
      // — o fluxo continuaria salvo, mas a opção do menu levaria a lugar
      // nenhum. Aqui os vínculos são reescritos junto, em `opcoes`
      // (jsonb) e em `proxima_chave`, para que renomear seja seguro.
      await cliente.query(
        `update blocos set proxima_chave=$1 where bot_id=$2 and proxima_chave=$3`,
        [novaChave, atual.bot_id, atual.chave]
      );
      await cliente.query(
        `update blocos
            set opcoes = (
              select coalesce(jsonb_agg(
                case when item->>'proxima' = $1 then jsonb_set(item, '{proxima}', to_jsonb($2::text)) else item end
              ), '[]'::jsonb)
              from jsonb_array_elements(opcoes) item
            )
          where bot_id=$3 and opcoes @> jsonb_build_array(jsonb_build_object('proxima', $1::text))`,
        [atual.chave, novaChave, atual.bot_id]
      );
    }

    if (querSerInicial && !atual.inicial) {
      await cliente.query("update blocos set inicial=false where bot_id=$1 and inicial", [atual.bot_id]);
    }

    return (await cliente.query(
      `update blocos set
         chave=$1, titulo=$2, tipo=$3, mensagem=$4, gatilhos=$5, inicial=$6,
         opcoes=$7, proxima_chave=$8, salvar_em=$9, ordem=$10, atualizado_em=now()
       where id=$11 and conta_id=$12 returning *`,
      [novaChave, dados.titulo, dados.tipo, dados.mensagem, dados.gatilhos,
       querSerInicial, JSON.stringify(dados.opcoes), dados.proxima_chave,
       dados.salvar_em, dados.ordem, id, req.contaId]
    )).rows[0];
  });

  registro.info(req.contaId, "bloco_editado", "Bloco '" + salvo.chave + "' editado");
  res.json(salvo);
}));

router.delete("/blocos/:id", exigirDono, rota(async function (req, res) {
  var id = v.uuid(req.params.id);
  if (!id) throw new ErroHttp(400, "Bloco inválido.");

  var bloco = await db.uma("select * from blocos where id=$1 and conta_id=$2", [id, req.contaId]);
  if (!bloco) throw new ErroHttp(404, "Bloco não encontrado.");

  // Apagar o ponto de entrada deixaria o fluxo sem começo, e toda
  // conversa nova cairia no "sem_fluxo". Melhor recusar e explicar do
  // que aceitar e quebrar o atendimento sem avisar.
  if (bloco.inicial) {
    var outros = await db.uma(
      "select count(*)::int as total from blocos where bot_id=$1 and id<>$2", [bloco.bot_id, id]
    );
    if (outros.total > 0) {
      throw new ErroHttp(400, "Este é o bloco inicial. Marque outro como inicial antes de apagar este.");
    }
  }

  await db.transacao(async function (cliente) {
    // Limpa os apontamentos para um bloco que deixa de existir. Sem
    // isto, a opção do menu continuaria listada apontando para o vazio —
    // e o motor cairia no "opção sem destino" para sempre.
    await cliente.query(
      "update blocos set proxima_chave=null where bot_id=$1 and proxima_chave=$2",
      [bloco.bot_id, bloco.chave]
    );
    await cliente.query(
      `update blocos
          set opcoes = (
            select coalesce(jsonb_agg(item), '[]'::jsonb)
              from jsonb_array_elements(opcoes) item
             where item->>'proxima' is distinct from $1
          )
        where bot_id=$2 and opcoes @> jsonb_build_array(jsonb_build_object('proxima', $1::text))`,
      [bloco.chave, bloco.bot_id]
    );
    await cliente.query("delete from blocos where id=$1 and conta_id=$2", [id, req.contaId]);
  });

  registro.aviso(req.contaId, "bloco_apagado", "Bloco '" + bloco.chave + "' apagado");
  res.json({ ok: true });
}));

// ════════════════════════════════════════
// RESTAURAR O FLUXO DE EXEMPLO
// ════════════════════════════════════════
// A saída de emergência de quem apagou tudo tentando entender como
// funciona. Sem isto, a única forma de voltar a um fluxo válido seria
// criar conta nova.
router.post("/blocos/restaurar-exemplo", exigirDono, rota(async function (req, res) {
  var bot = await botDaConta(req.contaId);

  await db.transacao(async function (cliente) {
    await cliente.query("delete from blocos where bot_id=$1 and conta_id=$2", [bot.id, req.contaId]);
    await criarExemplo(cliente, req.contaId, bot.id);
  });

  registro.aviso(req.contaId, "fluxo_restaurado", "Fluxo de exemplo restaurado");
  res.json(await db.varias(
    "select * from blocos where bot_id=$1 order by ordem", [bot.id]
  ));
}));

// ════════════════════════════════════════
// SIMULADOR — "testar bot"
// ════════════════════════════════════════
/**
 * Roda o MESMO motor que atende no WhatsApp, contra o fluxo salvo, sem
 * tocar em Meta, conversa ou histórico.
 *
 * O estado da conversa simulada viaja no corpo da requisição e volta na
 * resposta: o navegador é quem guarda. Assim testar não cria linha
 * nenhuma no banco, dois testes ao mesmo tempo não se atrapalham, e
 * "reiniciar a simulação" é simplesmente não mandar o estado de volta.
 *
 * `agora` pode vir do cliente para testar o horário de atendimento sem
 * esperar dar a hora — é o único jeito de conferir "o que meu bot
 * responde às 23h" antes de descobrir com um cliente real.
 */
router.post("/simular", rota(async function (req, res) {
  var bot = await botDaConta(req.contaId);
  var blocos = await db.varias(
    "select * from blocos where bot_id=$1 and conta_id=$2 order by ordem",
    [bot.id, req.contaId]
  );

  var entrada = typeof req.body.mensagem === "string" ? req.body.mensagem : "";
  var estado = (req.body.conversa && typeof req.body.conversa === "object") ? req.body.conversa : {};

  var agora = new Date();
  if (req.body.agora) {
    var proposto = new Date(req.body.agora);
    if (!isNaN(proposto.getTime())) agora = proposto;
  }

  var resultado = motor.processar({
    bot: bot,
    blocos: blocos,
    conversa: {
      bloco_chave: typeof estado.bloco_chave === "string" ? estado.bloco_chave : null,
      variaveis: (estado.variaveis && typeof estado.variaveis === "object") ? estado.variaveis : {},
      status: v.umDe(estado.status, ["bot", "humano", "encerrada"]) || "bot",
      ultima_interacao_em: estado.ultima_interacao_em || null
    },
    entrada: entrada,
    agora: agora,
    nomeContato: v.texto(req.body.nome_contato, 60) || "Visitante"
  });

  res.json({
    respostas: resultado.respostas,
    conversa: Object.assign({}, resultado.conversa, { ultima_interacao_em: agora.toISOString() }),
    // Os eventos são o "porquê" da resposta ("gatilho:precos", "fallback",
    // "expirou"). Aparecem no painel ao lado da conversa simulada: é a
    // diferença entre o cliente ver que o bot errou e o cliente entender
    // ONDE ele errou — que é o que permite consertar sozinho.
    eventos: resultado.eventos
  });
}));

// ════════════════════════════════════════
// DIAGNÓSTICO DO FLUXO
// ════════════════════════════════════════
/**
 * Procura os defeitos que um editor visual deixa passar e que só
 * aparecem quando um cliente real esbarra neles.
 */
router.get("/diagnostico", rota(async function (req, res) {
  var bot = await botDaConta(req.contaId);
  var blocos = await db.varias("select * from blocos where bot_id=$1 order by ordem", [bot.id]);

  var chaves = new Set(blocos.map(function (b) { return b.chave; }));
  var problemas = [];

  if (blocos.length === 0) {
    problemas.push({ nivel: "erro", mensagem: "O fluxo está vazio. Crie ao menos um bloco." });
  }
  if (blocos.length && !blocos.some(function (b) { return b.inicial; })) {
    problemas.push({ nivel: "erro", mensagem: "Nenhum bloco está marcado como inicial — as conversas não sabem por onde começar." });
  }

  // Blocos alcançáveis: começa no inicial, segue opções e próximos.
  // Palavra-chave também conta como porta de entrada.
  var alcancaveis = new Set();
  var fila = blocos.filter(function (b) { return b.inicial || (b.gatilhos || []).length; })
                   .map(function (b) { return b.chave; });
  while (fila.length) {
    var atual = fila.shift();
    if (alcancaveis.has(atual)) continue;
    alcancaveis.add(atual);
    var bloco = blocos.find(function (b) { return b.chave === atual; });
    if (!bloco) continue;
    for (var op of (bloco.opcoes || [])) if (op.proxima) fila.push(op.proxima);
    if (bloco.proxima_chave) fila.push(bloco.proxima_chave);
  }

  for (var b of blocos) {
    for (var opcao of (b.opcoes || [])) {
      if (opcao.proxima && !chaves.has(opcao.proxima)) {
        problemas.push({
          nivel: "erro", bloco: b.chave,
          mensagem: "A opção \"" + opcao.rotulo + "\" aponta para '" + opcao.proxima + "', que não existe."
        });
      }
      if (!opcao.proxima) {
        problemas.push({
          nivel: "aviso", bloco: b.chave,
          mensagem: "A opção \"" + opcao.rotulo + "\" não leva a lugar nenhum — quem escolher vai receber o mesmo menu de novo."
        });
      }
    }

    if (b.proxima_chave && !chaves.has(b.proxima_chave)) {
      problemas.push({
        nivel: "erro", bloco: b.chave,
        mensagem: "O próximo bloco '" + b.proxima_chave + "' não existe."
      });
    }
    if (b.tipo === "menu" && (b.opcoes || []).length === 0) {
      problemas.push({
        nivel: "aviso", bloco: b.chave,
        mensagem: "Menu sem opções: a conversa fica presa aqui até a pessoa digitar uma palavra-chave."
      });
    }
    if (b.tipo === "pergunta" && !b.proxima_chave) {
      problemas.push({
        nivel: "aviso", bloco: b.chave,
        mensagem: "Pergunta sem próximo bloco: a resposta é guardada e a conversa volta ao início."
      });
    }
    if (!alcancaveis.has(b.chave)) {
      problemas.push({
        nivel: "aviso", bloco: b.chave,
        mensagem: "Bloco inacessível: nenhuma opção leva até ele e ele não tem palavra-chave."
      });
    }
  }

  res.json({
    total_blocos: blocos.length,
    problemas: problemas,
    ok: problemas.filter(function (p) { return p.nivel === "erro"; }).length === 0
  });
}));

/** Modelos prontos, para a tela do editor oferecer "começar de um exemplo". */
router.get("/modelos", rota(function (req, res) {
  res.json({ exemplo: BLOCOS_EXEMPLO });
}));

module.exports = router;
