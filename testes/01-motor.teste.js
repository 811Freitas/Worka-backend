"use strict";

/**
 * O motor de conversa, isolado.
 *
 * Sem banco, sem rede, sem WhatsApp. É a suíte que descreve o
 * comportamento do produto: cada caso aqui é uma frase sobre o que o bot
 * faz quando alguém escreve alguma coisa.
 */

var { teste, igual, verdade, contem } = require("./ajuda");
var motor = require("../src/motor/motor");
var { BLOCOS_EXEMPLO } = require("../src/modulos/bots/exemplo");

var G = "Motor de conversa";

/** Bot com os padrões do sistema, ajustável por caso. */
function botDeTeste(ajustes) {
  return Object.assign({
    ativo: true,
    mensagem_boas_vindas: "Olá! Sou o assistente.",
    mensagem_fallback: "Não entendi.",
    mensagem_fora_horario: "Estamos fechados.",
    mensagem_transbordo: "Chamando atendente.",
    atendimento_ativo: false,
    atendimento_inicio: "08:00",
    atendimento_fim: "18:00",
    atendimento_dias: [1, 2, 3, 4, 5],
    fuso: "America/Sao_Paulo",
    expirar_apos_minutos: 60
  }, ajustes || {});
}

function conversar(entrada, estado, ajustesBot, agora) {
  return motor.processar({
    bot: botDeTeste(ajustesBot),
    blocos: BLOCOS_EXEMPLO,
    conversa: estado || {},
    entrada: entrada,
    agora: agora || new Date("2026-03-10T15:00:00Z"),   // terça, 12h em SP
    nomeContato: "Ana"
  });
}

// ── Normalização ────────────────────────────────────────
teste(G, "normaliza acento, caixa e pontuação", function () {
  igual(motor.normalizar("PREÇO!"), "preco");
  igual(motor.normalizar("  Bom   Dia  "), "bom dia");
  igual(motor.normalizar("Não"), "nao");
  igual(motor.normalizar(null), "");
});

teste(G, "interpola variáveis e some com as que não existem", function () {
  igual(motor.interpolar("Oi {{nome}}!", { nome: "Ana" }), "Oi Ana!");
  // Uma variável escrita errada pelo dono do bot não pode virar
  // "{{nomee}}" na tela do consumidor final.
  igual(motor.interpolar("Oi {{nomee}}!", { nome: "Ana" }), "Oi !");
  igual(motor.interpolar("Oi {{ nome }}!", { nome: "Ana" }), "Oi Ana!");
});

// ── Primeira mensagem ───────────────────────────────────
teste(G, "primeira mensagem manda boas-vindas e o menu inicial", function () {
  var r = conversar("oi");

  igual(r.respostas.length, 2, "boas-vindas + menu");
  contem(r.respostas[0].texto, "Olá!");
  igual(r.conversa.bloco_chave, "menu");
  igual(r.respostas[1].opcoes.length, 3);
  verdade(r.eventos.indexOf("iniciou") !== -1);
});

teste(G, "quem já diz o que quer pula o menu", function () {
  // Este é o caso que separa um bot que ajuda de um que obriga a
  // navegar: a pessoa escreveu a intenção na primeira mensagem.
  var r = conversar("quanto custa?");

  igual(r.conversa.bloco_chave, "produtos");
  contem(r.respostas[1].texto, "Plano Básico");
});

// ── Navegação por menu ──────────────────────────────────
teste(G, "escolhe opção pelo número", function () {
  var r = conversar("2", { bloco_chave: "menu" });
  igual(r.conversa.bloco_chave, "horario");
  contem(r.respostas[0].texto, "segunda a sexta");
});

teste(G, "escolhe opção pelo rótulo do botão", function () {
  // É assim que chega quando a pessoa TOCA no botão: a Meta devolve o
  // título, não o número.
  var r = conversar("Ver produtos", { bloco_chave: "menu" });
  igual(r.conversa.bloco_chave, "produtos");
});

teste(G, "escolhe opção pelo rótulo dentro de uma frase", function () {
  var r = conversar("queria ver produtos por favor", { bloco_chave: "menu" });
  igual(r.conversa.bloco_chave, "produtos");
});

teste(G, "número fora da faixa cai no fallback com o menu junto", function () {
  var r = conversar("9", { bloco_chave: "menu" });

  igual(r.eventos[0], "fallback");
  contem(r.respostas[0].texto, "Não entendi");
  // O menu vem junto: só dizer "não entendi" deixa a pessoa exatamente
  // onde ela já estava perdida.
  igual(r.respostas[1].opcoes.length, 3);
  igual(r.conversa.bloco_chave, "menu");
});

// ── Palavras-chave ──────────────────────────────────────
teste(G, "palavra-chave funciona de qualquer ponto do fluxo", function () {
  var r = conversar("horario", { bloco_chave: "produtos" });
  igual(r.conversa.bloco_chave, "horario");
  verdade(r.eventos.some(function (e) { return e.indexOf("gatilho:") === 0; }));
});

teste(G, "palavra-chave casa sem acento", function () {
  var r = conversar("PREÇO", { bloco_chave: "menu" });
  igual(r.conversa.bloco_chave, "produtos");
});

teste(G, "palavra-chave não dispara dentro de outra palavra", function () {
  // "oi" é gatilho do menu. Em "moinho" ele NÃO pode disparar — casar
  // por 'contém' é o defeito que faz o bot saltar de assunto sozinho.
  var achado = motor.acharPorGatilho(BLOCOS_EXEMPLO, motor.normalizar("comprei um moinho"));
  verdade(!achado || achado.chave !== "menu", "gatilho 'oi' disparou dentro de 'moinho'");
});

teste(G, "a opção do menu ganha da palavra-chave", function () {
  // Dentro de um menu, "2" é uma escolha de posição — mesmo que exista
  // um gatilho parecido em outro bloco.
  var r = conversar("2", { bloco_chave: "menu" });
  igual(r.conversa.bloco_chave, "horario");
});

// ── Perguntas e variáveis ───────────────────────────────
teste(G, "pergunta guarda a resposta e usa na mensagem seguinte", function () {
  var passo1 = conversar("1", { bloco_chave: "produtos" });
  igual(passo1.conversa.bloco_chave, "contratar");
  contem(passo1.respostas[0].texto, "Qual é o seu nome?");

  var passo2 = conversar("Maria Silva", passo1.conversa);
  igual(passo2.conversa.variaveis.nome, "Maria Silva");
  contem(passo2.respostas[0].texto, "Prazer, Maria Silva!");
});

teste(G, "a resposta é guardada como foi escrita, não normalizada", function () {
  var r = conversar("João DA Silva", { bloco_chave: "contratar" });
  igual(r.conversa.variaveis.nome, "João DA Silva");
});

// ── Transbordo e encerramento ───────────────────────────
teste(G, "pedir atendente passa a conversa para humano", function () {
  var r = conversar("quero falar com um atendente", { bloco_chave: "menu" });

  igual(r.conversa.status, "humano");
  verdade(r.eventos.indexOf("transbordo") !== -1);
});

teste(G, "com a conversa em atendimento humano o bot fica calado", function () {
  var r = conversar("oi, tem alguém aí?", { bloco_chave: "atendente", status: "humano" });

  igual(r.respostas.length, 0, "o bot não pode falar por cima do atendente");
  verdade(r.eventos.indexOf("em_atendimento_humano") !== -1);
});

teste(G, "despedida encerra a conversa", function () {
  var r = conversar("tchau", { bloco_chave: "menu" });
  igual(r.conversa.status, "encerrada");
});

// ── Horário de atendimento ──────────────────────────────
teste(G, "fora do horário avisa e não entra no fluxo", function () {
  var r = conversar("oi", {}, { atendimento_ativo: true },
    new Date("2026-03-10T05:00:00Z"));   // 2h da manhã em SP

  igual(r.respostas.length, 1);
  contem(r.respostas[0].texto, "fechados");
  verdade(r.eventos.indexOf("fora_horario") !== -1);
});

teste(G, "fora do horário avisa uma vez só", function () {
  var madrugada = new Date("2026-03-10T05:00:00Z");
  var primeira = conversar("oi", {}, { atendimento_ativo: true }, madrugada);
  // Cinco mensagens seguidas às 2h não podem virar cinco "estamos
  // fechados" — isso lê como deboche.
  var segunda = conversar("alguém?", primeira.conversa, { atendimento_ativo: true }, madrugada);

  igual(segunda.respostas.length, 0);
});

teste(G, "domingo fica fora do atendimento de segunda a sexta", function () {
  var r = conversar("oi", {}, { atendimento_ativo: true },
    new Date("2026-03-08T15:00:00Z"));   // domingo, meio-dia em SP
  verdade(r.eventos.indexOf("fora_horario") !== -1);
});

teste(G, "atendimento que atravessa a meia-noite funciona de madrugada", function () {
  // 22h → 6h. Sem o tratamento da janela invertida, ficaria fechado a
  // noite inteira — justamente quando deveria atender.
  var bot = botDeTeste({
    atendimento_ativo: true, atendimento_inicio: "22:00", atendimento_fim: "06:00",
    atendimento_dias: [0, 1, 2, 3, 4, 5, 6]
  });
  verdade(motor.dentroDoHorario(bot, new Date("2026-03-10T05:00:00Z")), "2h deveria estar aberto");
  verdade(!motor.dentroDoHorario(bot, new Date("2026-03-10T15:00:00Z")), "12h deveria estar fechado");
});

teste(G, "o horário respeita o fuso do cliente, não o do servidor", function () {
  // 13:00 UTC, numa terça: 10:00 em São Paulo (dentro de 8h–18h) e
  // 06:00 em Los Angeles (fora). O mesmo instante, dois resultados —
  // que é exatamente o que se perde ao usar a hora do servidor.
  var spo = botDeTeste({ atendimento_ativo: true, fuso: "America/Sao_Paulo" });
  var lax = botDeTeste({ atendimento_ativo: true, fuso: "America/Los_Angeles" });
  var instante = new Date("2026-03-10T13:00:00Z");

  verdade(motor.dentroDoHorario(spo, instante), "São Paulo deveria estar aberto");
  verdade(!motor.dentroDoHorario(lax, instante), "Los Angeles deveria estar fechado");
});

// ── Expiração ───────────────────────────────────────────
teste(G, "conversa parada há muito tempo recomeça do início", function () {
  var r = conversar("3", {
    bloco_chave: "produtos",
    variaveis: { nome: "Ana", pedido: "antigo" },
    ultima_interacao_em: new Date("2026-03-10T10:00:00Z")   // 5h antes
  });

  verdade(r.eventos.indexOf("expirou") !== -1);
  igual(r.conversa.bloco_chave, "menu");
  // As variáveis morrem junto: reaproveitar o pedido de ontem produz
  // resposta confiante e errada.
  igual(r.conversa.variaveis.pedido, undefined);
});

teste(G, "expirar_apos_minutos = 0 desliga a expiração", function () {
  var bot = botDeTeste({ expirar_apos_minutos: 0 });
  var conversa = { ultima_interacao_em: new Date("2020-01-01T00:00:00Z") };
  verdade(!motor.expirou(bot, conversa, new Date()), "não deveria expirar com 0");
});

// ── Bot desligado e fluxo vazio ─────────────────────────
teste(G, "bot desligado não responde nada", function () {
  var r = conversar("oi", {}, { ativo: false });
  igual(r.respostas.length, 0);
  verdade(r.eventos.indexOf("bot_inativo") !== -1);
});

teste(G, "bot ligado sem nenhum bloco ainda responde as boas-vindas", function () {
  // Prova para o dono que a conexão está de pé, e é a única pista que
  // ele tem do que falta fazer.
  var r = motor.processar({
    bot: botDeTeste(), blocos: [], conversa: {}, entrada: "oi", agora: new Date()
  });
  igual(r.respostas.length, 1);
  verdade(r.eventos.indexOf("sem_fluxo") !== -1);
});

// ── Robustez do fluxo ───────────────────────────────────
teste(G, "fluxo circular não trava o servidor", function () {
  // Dois blocos de texto apontando um para o outro. Sem a trava de
  // laço, isto seria um while infinito — e derrubaria o processo, com
  // ele os bots de TODOS os clientes.
  var blocos = [
    { chave: "a", tipo: "texto", mensagem: "A", proxima_chave: "b", inicial: true, ordem: 0, opcoes: [], gatilhos: [] },
    { chave: "b", tipo: "texto", mensagem: "B", proxima_chave: "a", ordem: 1, opcoes: [], gatilhos: [] }
  ];

  var r = motor.processar({ bot: botDeTeste(), blocos: blocos, conversa: {}, entrada: "oi", agora: new Date() });
  verdade(r.eventos.indexOf("laco_detectado") !== -1, "o laço deveria ter sido detectado");
  verdade(r.respostas.length < 10, "parou de gerar respostas");
});

teste(G, "opção apontando para bloco inexistente repete o menu em vez de sumir", function () {
  var blocos = [{
    chave: "menu", tipo: "menu", mensagem: "Escolha:", inicial: true, ordem: 0, gatilhos: [],
    opcoes: [{ rotulo: "Sumida", proxima: "nao-existe" }]
  }];

  var r = motor.processar({
    bot: botDeTeste(), blocos: blocos,
    conversa: { bloco_chave: "menu" }, entrada: "1", agora: new Date()
  });

  verdade(r.eventos.indexOf("opcao_sem_destino") !== -1);
  igual(r.conversa.bloco_chave, "menu");
  verdade(r.respostas.length > 0, "a conversa não pode morrer em silêncio");
});

teste(G, "anexo sem texto cai no fallback, não em erro", function () {
  // Áudio e imagem chegam com texto vazio. O bot precisa responder algo.
  var r = conversar("", { bloco_chave: "menu" });
  verdade(r.eventos.indexOf("fallback") !== -1);
  verdade(r.respostas.length > 0);
});
